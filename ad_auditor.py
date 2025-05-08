import configparser
import mysql.connector
from ldap3 import Server, Connection, ALL
from datetime import date
import smtplib
from email.mime.text import MIMEText
import traceback

# Load config
config = configparser.ConfigParser()
config.read('config.ini')

LDAP_SERVER = config['ldap']['server']
BIND_USER = config['ldap']['bind_user']
BIND_PASS = config['ldap']['bind_password']
BASE_DN = config['ldap']['base_dn']
GROUP_PREFIX = config['ldap']['group_prefix']

EMAIL_MODE = config['email']['mode']
FROM_ADDRESS = config['email']['from_address']

def log(msg):
    print(f"[+] {msg}")

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = FROM_ADDRESS
    msg['To'] = to if isinstance(to, str) else ", ".join(to)

    try:
        if EMAIL_MODE == 'localhost':
            with smtplib.SMTP('localhost') as s:
                s.send_message(msg)
        elif EMAIL_MODE == 'smtp':
            with smtplib.SMTP(config['email']['smtp_server'], config.getint('email', 'smtp_port')) as s:
                s.ehlo()
                try:
                    s.starttls()
                    smtp_user = config['email'].get('smtp_user', '').strip()
                    smtp_pass = config['email'].get('smtp_password', '').strip()
                    if smtp_user and smtp_pass:
                        s.login(smtp_user, smtp_pass)
                except smtplib.SMTPNotSupportedError:
                    log("  [SMTP] TLS not supported, continuing without it.")
                s.send_message(msg)
        print(f"✔ Email sent to {msg['To']}")
    except Exception as e:
        print(f"✘ Failed to send email to {msg['To']}: {e}")

def send_error_email(subject, message):
    recipients = [x.strip() for x in config['alerts']['error_recipients'].split(',')]
    send_email(recipients, subject, message)

def send_minor_error(subject, message):
    if config['alerts'].get('notify_on_minor_errors', 'no').lower() == 'yes':
        send_error_email(subject, message)

try:
    log("Connecting to LDAP server...")
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, BIND_USER, BIND_PASS, auto_bind=True)
    log("LDAP bind successful.")

    log("Connecting to MySQL database...")
    db = mysql.connector.connect(
        host=config['mysql']['host'],
        port=config.getint('mysql', 'port'),
        user=config['mysql']['user'],
        password=config['mysql']['password'],
        database=config['mysql']['database']
    )
    cursor = db.cursor()

    log("Ensuring tables exist...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255),
        manager_email VARCHAR(255),
        last_audited DATE
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_groups (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255),
        group_name VARCHAR(255),
        UNIQUE KEY unique_user_group (username, group_name)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255),
        manager_email VARCHAR(255),
        audit_date DATE
    )
    ''')
    db.commit()

    log(f"Searching for groups starting with prefix: {GROUP_PREFIX}")
    conn.search(BASE_DN, f'(&(objectClass=group)(cn={GROUP_PREFIX}*))', attributes=['member', 'cn'])
    log(f"Found {len(conn.entries)} groups.")

    users_seen = set()

    for group in conn.entries:
        group_name = str(group.cn)
        log(f"\n[Group] {group_name}")
        members = group.member.values if 'member' in group else []

        for member_dn in members:
            log(f"  [User DN] {member_dn}")
            conn.search(member_dn, '(objectClass=person)', attributes=['sAMAccountName', 'mail', 'manager'])

            if not conn.entries:
                log(f"    [-] Failed to fetch user at: {member_dn}")
                continue

            user = conn.entries[0]
            username = str(user.sAMAccountName)
            email = str(user.mail) if 'mail' in user else None
            manager_dn = str(user.manager) if 'manager' in user else None
            manager_email = None

            log(f"    [+] Found user: {username} ({email})")

            if manager_dn and manager_dn.strip():
                log(f"    [Manager DN] {manager_dn}")
                try:
                    conn.search(manager_dn, '(objectClass=person)', attributes=['mail'])
                    if conn.entries:
                        manager_email = str(conn.entries[0].mail)
                        log(f"    [+] Manager Email: {manager_email}")
                except Exception as e:
                    log(f"    [!] Error fetching manager details: {e}")
                    send_minor_error(
                        subject="AD Audit: Manager Lookup Failed",
                        message=f"Failed to lookup manager for user DN: {member_dn}\nError: {e}"
                    )
            else:
                log("    [!] Manager DN is missing or invalid.")

            if username:
                users_seen.add(username)
                log("    [DB] Inserting/Updating user record...")
                cursor.execute('REPLACE INTO users (username, email, manager_email, last_audited) VALUES (%s, %s, %s, %s)',
                               (username, email, manager_email, None))
                log(f"    [DB] Adding group membership: {username} -> {group_name}")
                cursor.execute('INSERT IGNORE INTO user_groups (username, group_name) VALUES (%s, %s)', (username, group_name))

    db.commit()
    log("\n[✓] User and group import completed.\n")

    log("Selecting up to 5 users who haven't been recently audited...")
    cursor.execute('''
    SELECT username, email, manager_email FROM users
    WHERE manager_email IS NOT NULL
    ORDER BY last_audited IS NOT NULL, last_audited ASC
    LIMIT 5
    ''')
    users_to_audit = cursor.fetchall()
    log(f"Will send audit emails for {len(users_to_audit)} users.")

    for username, email, manager_email in users_to_audit:
        log(f"\n[Audit] Preparing audit for {username} ({email})")

        cursor.execute('SELECT group_name FROM user_groups WHERE username = %s', (username,))
        groups = [row[0] for row in cursor.fetchall()]
        log(f"  [Groups] {', '.join(groups) if groups else 'No groups found.'}")

        body = f"""This is an access audit.

User: {username}
Email: {email}
Current Groups:
{chr(10).join(groups)}

Please confirm if this access is still valid.
"""
        send_email(manager_email, f"Access Review: {username}", body)

        log("  [DB] Logging audit action and updating last_audited...")
        cursor.execute('UPDATE users SET last_audited = %s WHERE username = %s', (date.today(), username))
        cursor.execute('INSERT INTO audit_log (username, manager_email, audit_date) VALUES (%s, %s, %s)',
                       (username, manager_email, date.today()))

    db.commit()
    cursor.close()
    db.close()
    conn.unbind()
    log("\n[✓] Audit complete.")

except Exception as e:
    log("[!] Unhandled error occurred.")
    error_details = traceback.format_exc()
    log(error_details)
    send_error_email("AD Audit Script Error", error_details)
    raise
