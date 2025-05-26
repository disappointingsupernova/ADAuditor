# ADAuditor

ADAuditor is a combined Python and PHP-based access review system for Active Directory environments. It extracts group memberships, sends access review emails to managers, and provides a web-based frontend for managing and submitting access review responses.

---

## 🚀 Features

### Python Backend
- Connects to Active Directory over LDAP/LDAPS (with optional cert validation skipping)
- Scans for users in groups with specified prefixes (e.g., `SG_AWS`)
- Sends access review emails to managers with unique confirmation links
- Stores audits in MySQL (`users`, `user_groups`, `audit_log`)
- Dry-run mode to preview changes
- Automatically removes group mappings not seen in AD
- Retrieves secrets from AWS Secrets Manager

### PHP Frontend
- SAML-based login using [OneLogin PHP SAML](https://github.com/onelogin/php-saml)
- Displays outstanding access reviews for the logged-in manager
- Allows managers to accept or request removal of specific groups
- Secure tokenized review system using emailed links
- Audit logging for all actions (`ui_logs` table with IP and User Agent)
- Customisable branding and Bootstrap styling
- Sends review outcomes to TechOps via SMTP

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

### PHP SAML Configuration

PHP SAML is set up using OneLogin's library.

- `saml_settings.php` defines IdP metadata and SP settings.
- `acs.php` handles SAML assertion consumption.
- `sls.php` handles logout requests.
- `check_auth.php` verifies SAML login session and populates user info from SAML claims.

Required attributes from IdP:
- `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`
- `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`
- `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`

### PHP `.env`-style Configuration

Defined in `config.php`:

```php
$config['email'] = [
  'smtp_server' => 'smtp.domain.local',
  'smtp_port' => 25,
  'smtp_user' => '',
  'smtp_password' => '',
  'from_address' => 'audit@domain.local',
  'from_name' => 'Access Review Bot',
  'verify_tls' => false
];
```

---

## 📂 PHP Frontend Files

- `index.php` – Main access review interface
- `footer.php` – Page footer with signed-in identity
- `logging.php` – Logs UI events to MySQL (`ui_logs` table)
- `check_auth.php` – Ensures SAML login is valid
- `saml_settings.php`, `acs.php`, `sls.php` – OneLogin PHP SAML integration

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

### Python
- Python 3.7+
- `boto3`, `ldap3`, `mysql-connector-python`

```bash
pip install -r requirements.txt
```

### PHP
Defined in `composer.json`:

```json
{
  "require": {
    "phpmailer/phpmailer": "^6.10",
    "aws/aws-sdk-php": "^3.343",
    "onelogin/php-saml": "^4.2"
  }
}
```

Run:

```bash
composer install
```

---

## 🛡️ Security

- Avoid storing plaintext credentials in `config.ini`. Use AWS Secrets Manager wherever possible and ensure appropriate IAM permissions are set for access.
- PHP and Python code should be deployed behind HTTPS
- Use AWS Secrets Manager instead of plain-text credentials
- SAML authentication is enforced on all frontend routes
- Tokens are securely validated before access is granted


---

## 📜 License

MIT License
