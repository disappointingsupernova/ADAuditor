# ADAuditor

ADAuditor is a Python tool that connects to Active Directory via LDAP/LDAPS, extracts users from specified groups, sends access review emails to managers, and logs audit entries in a MySQL database.

---

## 🚀 Features

- Connects to AD over LDAP or LDAPS (optionally skipping certificate validation)
- Uses one or more group name prefixes (e.g., `SG_AWS`) to fetch users
- Sends access review emails to managers with confirmation links
- Logs audit data to MySQL (`users`, `user_groups`, and `audit_log` tables)
- Removes stale group mappings
- Dry-run mode for previewing actions
- Pulls LDAP/MySQL credentials securely from AWS Secrets Manager
- Allows full override of group prefixes via CLI

---

## ⚙️ Configuration

### `config.ini`

```ini
[groups]
prefixes = SG_AWS,SG_DEMO

[aws]
region = eu-west-2

[ldap]
server = ldaps://domain.local
bind_user = CN=Example,CN=Users,DC=example,DC=local
bind_password = yourpassword
base_dn = DC=example,DC=local
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
You can either specify credentials directly in the INI file **or** provide a `secret_name` and store them in AWS Secrets Manager — **not both**.

---

## 🔐 AWS Secrets Manager

If you prefer, you can store credentials securely:

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

### Dry run only

```bash
python3 ad_auditor.py --dry-run
```

### Limit by group prefix (override config)

```bash
python3 ad_auditor.py --group-prefix SG_AWS --group-prefix SG_DEV
```

### Skip sending emails (update DB only)

```bash
python3 ad_auditor.py --update-only
```

### List managers

```bash
python3 ad_auditor.py --list-managers
```

### List manager user counts

```bash
python3 ad_auditor.py --list-manager-counts
```

### Override daily cap on manager emails

```bash
python3 ad_auditor.py --send-all-audit-emails
```

---

## 📦 Requirements

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
