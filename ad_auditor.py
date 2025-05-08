import configparser
import mysql.connector
from ldap3 import Server, Connection, ALL
from datetime import date
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import traceback
import uuid
from collections import defaultdict
import argparse

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('--dry-run', action='store_true', help='Preview actions without making changes')
args = parser.parse_args()
dry_run = args.dry_run

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
REVIEW_URL = "https://audit.example.com/review?token="

MIN_DAYS = int(config['audit'].get('min_days_between_audits', 30))

# Stats tracking
group_count = 0
user_count = 0
group_memberships = 0
managers_contacted = set()
emails_sent = 0
emails_skipped = 0
audits_logged = 0
dry_run_emails = []

def log(msg):
    print(f"[+] {msg}")

def send_email(to, subject, plain_text, html_content):
    msg = MIMEMultipart("alternative")
    msg['Subject'] = subject
    msg['From'] = FROM_ADDRESS
    msg['To'] = to if isinstance(to, str) else ", ".join(to)

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

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
    send_email(recipients, subject, message, message)

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
        audit_date DATE,
        secret VARCHAR(64)
    )
    ''')
    db.commit()

    log(f"Searching for groups starting with prefix: {GROUP_PREFIX}")
    conn.search(BASE_DN, f'(&(objectClass=group)(cn={GROUP_PREFIX}*))', attributes=['member', 'cn'])
    group_count = len(conn.entries)
    log(f"Found {group_count} groups.")

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
            user_count += 1

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
                cursor.execute('SELECT last_audited FROM users WHERE username = %s', (username,))
                row = cursor.fetchone()
                last_audited = row[0] if row else None

                if row:
                    if dry_run:
                        log(f"    [DRY-RUN] Would update user: {username}")
                    else:
                        cursor.execute('UPDATE users SET email = %s, manager_email = %s WHERE username = %s',
                                       (email, manager_email, username))
                else:
                    if dry_run:
                        log(f"    [DRY-RUN] Would insert new user: {username}")
                    else:
                        cursor.execute('INSERT INTO users (username, email, manager_email, last_audited) VALUES (%s, %s, %s, %s)',
                                       (username, email, manager_email, last_audited))

                if dry_run:
                    log(f"    [DRY-RUN] Would add group: {username} -> {group_name}")
                else:
                    cursor.execute('INSERT IGNORE INTO user_groups (username, group_name) VALUES (%s, %s)', (username, group_name))
                group_memberships += 1

    if not dry_run:
        db.commit()
    log("\n[✓] User and group import completed.\n")

    log(f"Finding users who haven't been audited in the last {MIN_DAYS} days...")
    cursor.execute(f'''
    SELECT u.username, u.email, u.manager_email
    FROM users u
    WHERE u.manager_email IS NOT NULL
    AND (
        u.last_audited IS NULL
        OR DATEDIFF(CURDATE(), u.last_audited) >= %s
    )
    ORDER BY u.last_audited IS NOT NULL, u.last_audited ASC
    ''', (MIN_DAYS,))
    rows = cursor.fetchall()

    manager_batches = defaultdict(list)
    for username, email, manager_email in rows:
        if len(manager_batches[manager_email]) < 5:
            manager_batches[manager_email].append((username, email))

    for manager_email, users in manager_batches.items():
        managers_contacted.add(manager_email)
        log(f"\n[Manager Audit Batch] {manager_email} -> {len(users)} users")

        for username, email in users:
            cursor.execute('SELECT group_name FROM user_groups WHERE username = %s', (username,))
            groups = [row[0] for row in cursor.fetchall()]
            group_list = ''.join(f"<li>{g}</li>" for g in groups)
            plain_groups = '\n'.join(groups)

            secret = uuid.uuid4().hex
            review_link = f"{REVIEW_URL}{secret}"

            plain_text = f"""Access Review Required

User: {username}
Email: {email}
Groups:
{plain_groups}

Please confirm if this access is still valid:
{review_link}

This is an automated message generated by the TechOps Team."""

            html_content = f"""
            <html>
            <body>
                <p><strong>Access Review Required</strong></p>
                <p><strong>User:</strong> {username}<br>
                   <strong>Email:</strong> {email}</p>
                <p><strong>Groups:</strong></p>
                <ul>{group_list}</ul>
                <p>
                    <a href="{review_link}" style="background-color:#1a73e8;color:#fff;padding:10px 20px;
                    text-decoration:none;border-radius:4px;">Review Access</a>
                </p>
                <p style="font-size: small; color: #777;">This is an automated message generated by the TechOps Team.</p>
            </body>
            </html>
            """

            if dry_run:
                dry_run_emails.append((manager_email, username))
                log(f"[DRY-RUN] Would send audit email to {manager_email} for user {username}")
                log(f"[DRY-RUN] Would log audit for {username} with secret {secret}")
                emails_skipped += 1
            else:
                send_email(manager_email, f"Access Review: {username}", plain_text, html_content)
                emails_sent += 1
                cursor.execute('UPDATE users SET last_audited = %s WHERE username = %s', (date.today(), username))
                cursor.execute('INSERT INTO audit_log (username, manager_email, audit_date, secret) VALUES (%s, %s, %s, %s)',
                               (username, manager_email, date.today(), secret))
                audits_logged += 1

    if not dry_run:
        db.commit()
        cursor.close()
        db.close()
        conn.unbind()

    log("\n[✓] Audit complete.\n")

    # Summary
    print("=== Summary ===")
    print(f"Groups matched:      {group_count}")
    print(f"Users processed:     {user_count}")
    print(f"Group mappings:      {group_memberships}")
    print(f"Managers contacted:  {len(managers_contacted)}")
    print(f"Audit emails sent:   {emails_sent}")
    print(f"Audit emails skipped (dry-run): {emails_skipped}")
    print(f"Audit entries added: {audits_logged}")

    if dry_run and dry_run_emails:
        print("\n=== Emails That Would Have Been Sent ===")
        for mgr, user in dry_run_emails:
            print(f"  -> To: {mgr} | For User: {user}")

except Exception as e:
    log("[!] Unhandled error occurred.")
    error_details = traceback.format_exc()
    log(error_details)
    if not dry_run:
        send_error_email("AD Audit Script Error", error_details)
    raise
