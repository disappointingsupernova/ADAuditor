#!/usr/bin/env python3
import configparser
import mysql.connector
from ldap3 import Server, Connection, ALL, Tls
from datetime import date
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import traceback
import uuid
from collections import defaultdict
import argparse
from argparse import RawTextHelpFormatter
import sys
import ssl
import boto3
import json

# Parse arguments
class WideHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=45, width=120)

parser = argparse.ArgumentParser(
    formatter_class=WideHelpFormatter
)

parser.add_argument('--dry-run', action='store_true', help='Preview actions without making changes')
parser.add_argument('--list-managers', action='store_true', help='List unique managers from AD and exit')
parser.add_argument('--list-manager-counts', action='store_true', help='List manager emails and number of users they manage')
parser.add_argument('--send-all-audit-emails', action='store_true', help='Ignore max emails per manager limit')
parser.add_argument('--update-only', action='store_true', help='Only update database, do not send audit emails')
parser.add_argument('--group-prefix', action='append', help='Override default group prefix (can be passed multiple times)')
parser.add_argument('--limit-users', type=int, help='Limit the number of users processed (for testing)')
parser.add_argument('--filter-user-email', type=str, help='Only process a specific user with this email')
args = parser.parse_args()
dry_run = args.dry_run
list_managers_mode = args.list_managers
list_manager_counts_mode = args.list_manager_counts
send_all = args.send_all_audit_emails
update_only = getattr(args, 'update_only', False)
override_group_prefixes = args.group_prefix or []
user_limit = args.limit_users
filter_user_email = args.filter_user_email

# Load config
config = configparser.ConfigParser()
config.read('config.ini')

def get_secret(secret_name, region_name=None):
    try:
        session = boto3.session.Session()
        region = region_name or session.region_name or config.get('aws', 'region', fallback=None)
        if not region:
            raise Exception("You must specify a region for AWS Secrets Manager.")
        client = session.client(service_name='secretsmanager', region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except Exception as e:
        print(f"[!] Failed to retrieve secret {secret_name}: {e}")
        sys.exit(1)

# LDAP configuration
ldap_secret_key = config['ldap'].get('secret_name', fallback=None)
ldap_has_plain = all(k in config['ldap'] for k in ('server', 'bind_user', 'bind_password', 'base_dn'))
if ldap_secret_key and ldap_has_plain:
    print("[!] Both LDAP secret_name and plaintext credentials are configured. Please remove one.")
    sys.exit(1)
if ldap_secret_key:
    ldap_secret = get_secret(ldap_secret_key)
    LDAP_SERVER = ldap_secret['server']
    BIND_USER = ldap_secret['bind_user']
    BIND_PASS = ldap_secret['bind_password']
    BASE_DN = ldap_secret['base_dn']
    SKIP_CERT_VALIDATION = ldap_secret.get('skip_cert_validation', 'false').lower() == 'true'
else:
    LDAP_SERVER = config['ldap']['server']
    BIND_USER = config['ldap']['bind_user']
    BIND_PASS = config['ldap']['bind_password']
    BASE_DN = config['ldap']['base_dn']
    SKIP_CERT_VALIDATION = config['ldap'].getboolean('skip_cert_validation', fallback=False)

# Group prefixes
default_prefixes = config.get('groups', 'prefixes', fallback='SG_AWS').split(',')
GROUP_PREFIXES = [p.strip() for p in override_group_prefixes] if override_group_prefixes else [p.strip() for p in default_prefixes]

# Determine SSL usage and default port
use_ssl = LDAP_SERVER.lower().startswith("ldaps")
default_port = 636 if use_ssl else 389
LDAP_PORT = config['ldap'].getint('port', fallback=default_port)

EMAIL_MODE = config['email']['mode']
FROM_ADDRESS = config['email']['from_address']
REVIEW_URL = "https://audit.example.com/review?token="

MIN_DAYS = int(config['audit'].get('min_days_between_audits', 30))
MAX_EMAILS_PER_MANAGER = config['audit'].getint('max_audits_per_manager_per_day', fallback=5)

# Stats tracking
group_count = 0
user_count = 0
group_memberships = 0
managers_contacted = set()
emails_sent = 0
emails_skipped = 0
audits_logged = 0
dry_run_emails = []
manager_email_counts = defaultdict(int)
user_current_groups = defaultdict(set)

def log(msg):
    print(f"[+] {msg}")

def ldap_connection():
    log("Connecting to LDAP server...")
    log(f"    Protocol: {'LDAPS' if use_ssl else 'LDAP'}")
    log(f"    Certificate Validation: {'Skipped' if SKIP_CERT_VALIDATION else 'Enforced'}")
    tls_config = Tls(validate=ssl.CERT_NONE if SKIP_CERT_VALIDATION else ssl.CERT_REQUIRED)
    server = Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=use_ssl, get_info=ALL, tls=tls_config)
    conn = Connection(server, BIND_USER, BIND_PASS, auto_bind=True)
    log("LDAP bind successful.")
    return conn

def search_groups_by_prefixes(conn, base_dn, prefixes):
    """
    Searches for LDAP groups whose CN starts with any of the given prefixes.
    
    Args:
        conn (ldap3.Connection): An active LDAP connection.
        base_dn (str): The base DN to search under.
        prefixes (list): List of group name prefixes to search for.

    Returns:
        list: All matched group entries across prefixes.
    """
    all_groups = []
    for prefix in prefixes:
        log(f"Searching for groups starting with prefix: {prefix}")
        conn.search(base_dn, f'(&(objectClass=group)(cn={prefix}*))', attributes=['member', 'cn'])
        all_groups.extend(conn.entries)
    return all_groups


def mysql_connection():
    log("Connecting to MySQL database...")
    mysql_secret_key = config['mysql'].get('secret_name', fallback=None)
    mysql_has_plain = all(k in config['mysql'] for k in ('host', 'port', 'user', 'password', 'database'))
    if mysql_secret_key and mysql_has_plain:
        print("[!] Both MySQL secret_name and plaintext credentials are configured. Please remove one.")
        sys.exit(1)
    if mysql_secret_key:
        db_secret = get_secret(mysql_secret_key)
        return mysql.connector.connect(
            host=db_secret['host'],
            port=int(db_secret['port']),
            user=db_secret['user'],
            password=db_secret['password'],
            database=db_secret['database']
        )
    else:
        return mysql.connector.connect(
            host=config['mysql']['host'],
            port=config.getint('mysql', 'port'),
            user=config['mysql']['user'],
            password=config['mysql']['password'],
            database=config['mysql']['database']
        )

def send_email(to, subject, plain_text, html_content):
    msg = MIMEMultipart("alternative")
    msg['Subject'] = subject
    msg['From'] = FROM_ADDRESS
    msg['To'] = to if isinstance(to, str) else ", ".join(to)

    cc_list = [x.strip() for x in config['email'].get('cc', '').split(',') if x.strip()]
    bcc_list = [x.strip() for x in config['email'].get('bcc', '').split(',') if x.strip()]
    if cc_list:
        msg['Cc'] = ", ".join(cc_list)

    recipients = []
    if isinstance(to, str):
        recipients.append(to)
    else:
        recipients.extend(to)
    recipients.extend(cc_list)
    recipients.extend(bcc_list)

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    try:
        if EMAIL_MODE == 'localhost':
            with smtplib.SMTP('localhost') as s:
                s.send_message(msg, to_addrs=recipients)
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
                s.send_message(msg, to_addrs=recipients)
        print(f"✔ Email sent to {msg['To']}")
    except Exception as e:
        print(f"✘ Failed to send email to {msg['To']}: {e}")


def send_error_email(subject, message):
    recipients = [x.strip() for x in config['alerts']['error_recipients'].split(',')]
    send_email(recipients, subject, message, message)

def send_minor_error(subject, message):
    if config['alerts'].get('notify_on_minor_errors', 'no').lower() == 'yes':
        send_error_email(subject, message)

def get_manager_email_from_dn(conn, manager_dn):
    if manager_dn and manager_dn.strip():
        try:
            conn.search(manager_dn, '(objectClass=person)', attributes=['mail'])
            if conn.entries:
                return str(conn.entries[0].mail)
        except Exception as e:
            log(f"    [!] Error fetching manager details for DN {manager_dn}: {e}")
    return None

def list_managers_only():
    conn = ldap_connection()
    for prefix in GROUP_PREFIXES:
        log(f"Searching for groups starting with prefix: {prefix}")
        conn.search(BASE_DN, f'(&(objectClass=group)(cn={prefix}*))', attributes=['member', 'cn'])
        log(f"Found {len(conn.entries)} groups.")

        unique_managers = set()
        for group in conn.entries:
            members = group.member.values if 'member' in group else []
            for member_dn in members:
                conn.search(member_dn, '(objectClass=*)', attributes=['objectClass'])
                if not conn.entries:
                    log(f"    [-] Failed to fetch entry at: {member_dn}")
                    continue

                object_classes = [str(oc).lower() for oc in conn.entries[0]['objectClass']]
                if 'person' not in object_classes:
                    log(f"    [-] Skipping non-user entry: {member_dn} (objectClass: {object_classes})")
                    continue
                conn.search(member_dn, '(objectClass=person)', attributes=['manager'])
                if not conn.entries:
                    continue
                user = conn.entries[0]
                manager_dn = str(user.manager) if 'manager' in user else None
                email = get_manager_email_from_dn(conn, manager_dn)
                if email:
                    unique_managers.add(email)

        print("\n=== Unique Manager Emails ===")
        for email in sorted(unique_managers):
            print(email)
    conn.unbind()

def list_manager_user_counts():
    conn = ldap_connection()
    for prefix in GROUP_PREFIXES:
        log(f"Searching for groups starting with prefix: {prefix}")
        conn.search(BASE_DN, f'(&(objectClass=group)(cn={prefix}*))', attributes=['member', 'cn'])

        manager_user_counts = defaultdict(set)
        for group in conn.entries:
            members = group.member.values if 'member' in group else []
            for member_dn in members:
                conn.search(member_dn, '(objectClass=*)', attributes=['objectClass'])
                if not conn.entries:
                    log(f"    [-] Failed to fetch entry at: {member_dn}")
                    continue

                object_classes = [str(oc).lower() for oc in conn.entries[0]['objectClass']]
                if 'person' not in object_classes:
                    log(f"    [-] Skipping non-user entry: {member_dn} (objectClass: {object_classes})")
                    continue
                
                conn.search(member_dn, '(objectClass=person)', attributes=['manager', 'sAMAccountName'])
                if not conn.entries:
                    continue
                user = conn.entries[0]
                manager_dn = str(user.manager) if 'manager' in user else None
                username = str(user.sAMAccountName) if 'sAMAccountName' in user else None
                if manager_dn and username:
                    email = get_manager_email_from_dn(conn, manager_dn)
                    if email:
                        manager_user_counts[email].add(username)

        print("\n=== Manager Emails and Managed Users Count ===")
        for email, users in sorted(manager_user_counts.items()):
            print(f"{email:<40} | {len(users)} users")
    conn.unbind()

if list_managers_mode:
    list_managers_only()
    sys.exit(0)

if list_manager_counts_mode:
    list_manager_user_counts()
    sys.exit(0)

try:
    conn = ldap_connection()

    db = mysql_connection()
    
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

    log(f"Searching for groups starting with prefix: {GROUP_PREFIXES}")
    groups = search_groups_by_prefixes(conn, BASE_DN, GROUP_PREFIXES)
    log(f"Found {len(groups)} groups.")

    user_display_names = {}

    for group in groups:
        group_name = str(group.cn)
        log(f"\n[Group] {group_name}")
        members = group.member.values if 'member' in group else []

        for member_dn in members:
            conn.search(member_dn, '(objectClass=*)', attributes=['objectClass'])
            if not conn.entries:
                log(f"    [-] Failed to fetch entry at: {member_dn}")
                continue

            object_classes = [str(oc).lower() for oc in conn.entries[0]['objectClass']]
            if 'person' not in object_classes:
                log(f"    [-] Skipping non-user entry: {member_dn} (objectClass: {object_classes})")
                continue
            log(f"  [User DN] {member_dn}")
            conn.search(member_dn, '(objectClass=person)', attributes=['sAMAccountName', 'mail', 'manager', 'givenName', 'sn'])
            if not conn.entries:
                log(f"    [-] Failed to fetch user at: {member_dn}")
                continue

            user = conn.entries[0]
            username = str(user.sAMAccountName)
            email = str(user.mail) if 'mail' in user else None
            given_name = str(user.givenName) if 'givenName' in user else ''
            surname = str(user.sn) if 'sn' in user else ''
            full_name = f"{given_name.capitalize()} {surname.capitalize()}".strip()
            user_display_names[username] = full_name

            manager_dn = str(user.manager) if 'manager' in user else None
            manager_email = None

            log(f"    [+] Found user: {full_name} ({email}, {username})")
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
                    send_minor_error("AD Audit: Manager Lookup Failed", f"Failed to lookup manager for user DN: {member_dn}\nError: {e}")
            else:
                log("    [!] Manager DN is missing or invalid.")

            cursor.execute('SELECT last_audited FROM users WHERE username = %s', (username,))
            row = cursor.fetchone()
            last_audited = row[0] if row else None

            if row:
                cursor.execute('UPDATE users SET email = %s, manager_email = %s WHERE username = %s', (email, manager_email, username))
                if dry_run:
                    log(f"    [DRY-RUN] Updated user: {username}")
            else:
                cursor.execute('INSERT INTO users (username, email, manager_email, last_audited) VALUES (%s, %s, %s, %s)',
                               (username, email, manager_email, last_audited))
                if dry_run:
                    log(f"    [DRY-RUN] Inserted new user: {username}")

            cursor.execute('INSERT IGNORE INTO user_groups (username, group_name) VALUES (%s, %s)', (username, group_name))
            if dry_run:
                log(f"    [DRY-RUN] Inserted group: {username} -> {group_name}")
            group_memberships += 1

            user_current_groups[username].add(group_name)

    log("\n[✓] User and group import completed.\n")

    log("\n[✓] Checking for stale group mappings...")
    cursor.execute('SELECT DISTINCT username FROM user_groups')
    all_usernames = [row[0] for row in cursor.fetchall()]

    for username in all_usernames:
        current_groups = user_current_groups.get(username, set())
        cursor.execute('SELECT group_name FROM user_groups WHERE username = %s', (username,))
        db_groups = set(row[0] for row in cursor.fetchall())

        # Only consider groups that match the provided prefixes
        db_groups_filtered = {
            g for g in db_groups
            if any(g.lower().startswith(p.lower()) for p in GROUP_PREFIXES)
        }

        stale_groups = db_groups_filtered - current_groups

        for stale_group in stale_groups:
            if dry_run:
                log(f"    [DRY-RUN] Would remove group: {username} -> {stale_group}")
            else:
                cursor.execute('DELETE FROM user_groups WHERE username = %s AND group_name = %s', (username, stale_group))
                log(f"    [-] Removed stale group: {username} -> {stale_group}")

    log(f"Finding users who haven't been audited in the last {MIN_DAYS} days...")
    cursor.execute('''
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

    if filter_user_email:
        rows = [r for r in rows if r[1] and r[1].lower() == filter_user_email.lower()]

    if user_limit:
        rows = rows[:user_limit]

    manager_batches = defaultdict(list)
    for username, email, manager_email in rows:
        if len(manager_batches[manager_email]) < 5:
            manager_batches[manager_email].append((username, email))

    today = date.today()
    for manager_email, users in manager_batches.items():
        cursor.execute('SELECT COUNT(*) FROM audit_log WHERE manager_email = %s AND audit_date = %s', (manager_email, today))
        count_today = cursor.fetchone()[0]

        if not send_all and count_today >= MAX_EMAILS_PER_MANAGER:
            log(f"[SKIPPED] {manager_email} has already received {count_today} audit emails today (limit: {MAX_EMAILS_PER_MANAGER})")
            continue

        for username, email in users:
            display_name = user_display_names.get(username, username)
            cursor.execute('SELECT group_name FROM user_groups WHERE username = %s', (username,))
            all_groups = [row[0] for row in cursor.fetchall()]
            groups = [g for g in all_groups if any(g.lower().startswith(p.lower()) for p in GROUP_PREFIXES)]
            group_list = ''.join(f"<li>{g}</li>" for g in groups)
            plain_groups = '\n'.join(groups)

            secret = uuid.uuid4().hex
            review_link = f"{REVIEW_URL}{secret}"

            subject = f"Access Review: {display_name}"
            plain_text = f"""Access Review Required for {display_name} ({username})

Email: {email}
Groups:
{plain_groups}

Please confirm if this access is still valid:
{review_link}

This is an automated message generated by the TechOps Team."""

            html_content = f"""
            <html>
            <body>
                <p><strong>Access Review Required for {display_name} ({username})</strong></p>
                <p><strong>Email:</strong> {email}</p>
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
                log(f"[DRY-RUN] Would send audit email to {manager_email} for user {username} ({display_name})")
                emails_skipped += 1
            elif update_only:
                log(f"[SKIPPED] Email to {manager_email} for {username} skipped due to --update-only")
                emails_skipped += 1
            else:
                send_email(manager_email, subject, plain_text, html_content)
                emails_sent += 1
                cursor.execute('UPDATE users SET last_audited = %s WHERE username = %s', (date.today(), username))
                cursor.execute('INSERT INTO audit_log (username, manager_email, audit_date, secret) VALUES (%s, %s, %s, %s)',
                            (username, manager_email, date.today(), secret))
                audits_logged += 1

            manager_email_counts[manager_email] += 1


    if dry_run:
        db.rollback()
        log("[DRY-RUN] Skipping commit — all changes rolled back.")
    else:
        db.commit()
        cursor.close()
        db.close()
        conn.unbind()

    log("\n[✓] Audit complete.\n")

    print("=== Summary ===")
    print(f"Groups matched:      {group_count}")
    print(f"Users processed:     {user_count}")
    print(f"Group mappings:      {group_memberships}")
    print(f"Managers contacted:  {len(manager_email_counts)}")
    print(f"Audit emails sent:   {emails_sent}")
    print(f"Audit emails skipped (dry-run): {emails_skipped}")
    print(f"Audit entries added: {audits_logged}")

    if dry_run and dry_run_emails:
        print("\n=== Emails That Would Have Been Sent ===")
        for mgr, user in dry_run_emails:
            print(f"  -> To: {mgr} | For User: {user}")

    if manager_email_counts:
        print("\n=== Manager Audit Summary ===")
        print(f"{'Manager Email':<40} | {'# of Audits'}")
        print("-" * 55)
        for mgr, count in sorted(manager_email_counts.items()):
            print(f"{mgr:<40} | {count}")

except Exception as e:
    log("[!] Unhandled error occurred.")
    error_details = traceback.format_exc()
    log(error_details)
    if not dry_run:
        send_error_email("AD Audit Script Error", error_details)
    raise
