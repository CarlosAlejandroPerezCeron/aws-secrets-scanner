from scanner.base import ScanConfig
from scanner.rules import scan_text

CFG = ScanConfig()

# --- SEC-001 AWS Access Key ---

def test_aws_key_flagged():
    text = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_text(text, "config.py", CFG)
    assert any(f.rule_id == "SEC-001" and f.severity == "CRITICAL" for f in findings)


def test_aws_key_in_env_file_flagged():
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(text, ".env", CFG)
    assert any(f.rule_id == "SEC-001" for f in findings)


def test_non_akia_string_not_flagged():
    text = 'key_id = "AKIB1234567890ABCDEF"'
    findings = scan_text(text, "config.py", CFG)
    sec001 = [f for f in findings if f.rule_id == "SEC-001"]
    assert sec001 == []


def test_aws_key_line_number_correct():
    text = "line1\nline2\nAKIAIOSFODNN7EXAMPLE"
    findings = scan_text(text, "f.py", CFG)
    sec001 = [f for f in findings if f.rule_id == "SEC-001"]
    assert sec001 and sec001[0].line_no == 3


# --- SEC-002 Private Key ---

def test_rsa_private_key_flagged():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    findings = scan_text(text, "key.pem", CFG)
    assert any(f.rule_id == "SEC-002" and f.severity == "CRITICAL" for f in findings)


def test_openssh_private_key_flagged():
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl..."
    findings = scan_text(text, "id_rsa", CFG)
    assert any(f.rule_id == "SEC-002" for f in findings)


def test_public_key_not_flagged():
    text = "-----BEGIN PUBLIC KEY-----\nMIIBI..."
    findings = scan_text(text, "pub.pem", CFG)
    sec002 = [f for f in findings if f.rule_id == "SEC-002"]
    assert sec002 == []


# --- SEC-003 Hardcoded Password ---

def test_password_assignment_flagged():
    text = 'password = "supersecret123"'
    findings = scan_text(text, "settings.py", CFG)
    assert any(f.rule_id == "SEC-003" and f.severity == "HIGH" for f in findings)


def test_secret_colon_flagged():
    text = 'client_secret: "mysecretvalue99"'
    findings = scan_text(text, "config.yml", CFG)
    assert any(f.rule_id == "SEC-003" for f in findings)


def test_password_env_var_not_flagged():
    text = 'password = os.environ["DB_PASSWORD"]'
    findings = scan_text(text, "app.py", CFG)
    sec003 = [f for f in findings if f.rule_id == "SEC-003"]
    assert sec003 == []


def test_short_password_not_flagged():
    text = 'passwd = "abc"'
    findings = scan_text(text, "test.py", CFG)
    sec003 = [f for f in findings if f.rule_id == "SEC-003"]
    assert sec003 == []


# --- SEC-004 DB Connection String ---

def test_postgres_url_flagged():
    text = 'DATABASE_URL = "postgresql://admin:hunter2@db.example.com/mydb"'
    findings = scan_text(text, "settings.py", CFG)
    assert any(f.rule_id == "SEC-004" and f.severity == "HIGH" for f in findings)


def test_mysql_url_flagged():
    text = 'conn = "mysql://root:password@localhost/mydb"'
    findings = scan_text(text, "db.py", CFG)
    assert any(f.rule_id == "SEC-004" for f in findings)


def test_mongodb_url_flagged():
    text = 'uri = "mongodb://user:pass@cluster.mongodb.net/db"'
    findings = scan_text(text, "app.py", CFG)
    assert any(f.rule_id == "SEC-004" for f in findings)


def test_db_url_no_credentials_not_flagged():
    text = 'DATABASE_URL = "postgresql://db.example.com/mydb"'
    findings = scan_text(text, "config.py", CFG)
    sec004 = [f for f in findings if f.rule_id == "SEC-004"]
    assert sec004 == []


# --- SEC-005 API Token ---

def test_api_key_flagged():
    text = 'api_key = "sk-abcdefghij1234567890"'
    findings = scan_text(text, "client.py", CFG)
    assert any(f.rule_id == "SEC-005" and f.severity == "MEDIUM" for f in findings)


def test_access_token_flagged():
    text = 'access_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWX"'
    findings = scan_text(text, "auth.py", CFG)
    assert any(f.rule_id == "SEC-005" for f in findings)


def test_short_token_not_flagged():
    text = 'token = "abc123"'
    findings = scan_text(text, "auth.py", CFG)
    sec005 = [f for f in findings if f.rule_id == "SEC-005"]
    assert sec005 == []


# --- General ---

def test_clean_file_no_findings():
    text = 'DB_HOST = os.environ.get("DB_HOST", "localhost")\nport = 5432\n'
    findings = scan_text(text, "config.py", CFG)
    assert findings == []


def test_severity_order_in_results():
    text = (
        'AKIAIOSFODNN7EXAMPLE\n'
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'api_key = "sk-abcdefghijklmnopqrs"\n'
    )
    findings = scan_text(text, "leak.py", CFG)
    from scanner.base import SEVERITY_ORDER
    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, key=lambda s: SEVERITY_ORDER.get(s, 99))


def test_redis_url_with_password_flagged():
    text = 'CACHE_URL = "redis://user:r3d1sp@ss@cache.internal:6379/0"'
    findings = scan_text(text, "settings.py", CFG)
    assert any(f.rule_id == "SEC-004" for f in findings)
