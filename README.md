# aws-secrets-scanner

Static scanner for hardcoded credentials: AWS keys, private keys, passwords, DB connection strings, and API tokens.

## Rules

| ID | Severity | Description |
|----|----------|-------------|
| SEC-001 | CRITICAL | AWS access key ID hardcoded |
| SEC-002 | CRITICAL | Private key material detected |
| SEC-003 | HIGH | Hardcoded password or secret assignment |
| SEC-004 | HIGH | Database connection string with credentials |
| SEC-005 | MEDIUM | API key or token assigned inline |

## Install

```bash
pip install rich
```

## Usage

```bash
# Scan current directory
python main.py .

# Scan with JSON output
python main.py . --output json

# Scan specific extensions and fail on critical
python main.py src/ --ext py js ts --fail-on-critical

# Write CSV report
python main.py . --csv-path report.csv
```

## Tests

```bash
pip install pytest pytest-cov ruff
ruff check .
pytest tests/ -v --cov=scanner --cov=report
```

## CI

GitHub Actions runs ruff and pytest on every push to main.
# aws-secrets-scanner
Static scanner for hardcoded credentials: AWS keys, private keys, passwords, DB connection strings, and API tokens
