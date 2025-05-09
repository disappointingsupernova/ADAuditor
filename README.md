# ADAuditor

ADAuditor is a Python tool that connects to Active Directory via LDAP/LDAPS, extracts users from groups matching a prefix (e.g., `SG_AWS`), sends access review emails to managers, and logs audit entries in a MySQL database.

## 🚀 Features

- Connects to Active Directory over LDAP or LDAPS (with optional cert validation skipping)
- Uses group prefix matching to locate relevant groups
- Sends audit emails to managers listing users and group memberships
- Supports dry-run and summary reporting
- Optionally retrieves LDAP/MySQL credentials from **AWS Secrets Manager**
- Tracks audits in MySQL (`users`, `user_groups`, and `audit_log` tables)

---

## ⚙️ Configuration

### `config.ini`

```ini
[aws]
region=eu-west-2

[ldap]
server = ldaps://domain.local
bind_user = CN=Example,CN=Users,DC=example,DC=local
bind_password = yourpassword
base_dn = DC=example,DC=local
group_prefix = SG_AWS
skip_cert_validation = true
;secret_name = ad_auditor_ldap_secret

[mysql]
host = localhost
port = 3306
user = adaudit
password = yourdbpass
database = ad_audit
;secret_name = ad_auditor_mysql_secret

[email]
mode = smtp
from_address = audit@domain.local
smtp_server = smtp.domain.local
smtp_port = 25
smtp_user =
smtp_password =

[alerts]
error_recipients = alert@example.com
notify_on_minor_errors = yes

[audit]
min_days_between_audits = 30
max_audits_per_manager_per_day = 5
```

> ✅ You can either specify credentials directly in the INI file **or** provide a `secret_name` and store them in AWS Secrets Manager — **not both**.

---

## 🔐 AWS Secrets Manager

To create the required secrets, run:

### LDAP Secret

```bash
aws secretsmanager create-secret \
  --name ad_auditor_ldap_secret \
  --description "AD Auditor LDAP Bind Credentials" \
  --secret-string '{
    "server": "ldaps://domain.local",
    "bind_user": "CN=Example,CN=Users,DC=example,DC=local",
    "bind_password": "yourpassword",
    "base_dn": "DC=example,DC=local",
    "group_prefix": "SG_AWS",
    "skip_cert_validation": "true"
  }'
```

### MySQL Secret

```bash
aws secretsmanager create-secret \
  --name ad_auditor_mysql_secret \
  --description "AD Auditor MySQL Credentials" \
  --secret-string '{
    "host": "localhost",
    "port": "3306",
    "user": "adaudit",
    "password": "yourdbpass",
    "database": "ad_audit"
  }'
```

---

## 🧪 Usage

Run a dry audit with summary only:

```bash
python3 ad_auditor.py --dry-run
```

List unique manager emails:

```bash
python3 ad_auditor.py --list-managers
```

List manager email addresses and how many users they manage:

```bash
python3 ad_auditor.py --list-manager-counts
```

Send audit emails ignoring daily max per manager:

```bash
python3 ad_auditor.py --send-all-audit-emails
```

---

## 📦 Dependencies

- Python 3.7+
- `boto3`
- `ldap3`
- `mysql-connector-python`

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛡️ Security

Avoid storing plaintext credentials in `config.ini`. Use AWS Secrets Manager wherever possible and ensure appropriate IAM permissions are set for access.

---

## 📜 License

MIT License
