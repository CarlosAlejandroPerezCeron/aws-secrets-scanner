from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    severity: str
    title: str
    regex: re.Pattern[str]
    remediation: str


PATTERNS: list[SecretPattern] = [
    SecretPattern(
        rule_id="SEC-001",
        severity="CRITICAL",
        title="AWS access key ID hardcoded",
        regex=re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        remediation="Deactivate and rotate the key in IAM, then use roles, OIDC federation or Secrets Manager.",
    ),
    SecretPattern(
        rule_id="SEC-002",
        severity="CRITICAL",
        title="Private key material detected",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        remediation="Revoke the key pair, remove it from history (git filter-repo) and store keys in a KMS or vault.",
    ),
    SecretPattern(
        rule_id="SEC-003",
        severity="HIGH",
        title="Hardcoded password or secret assignment",
        regex=re.compile(
            r"(?i)\b\w*(?:password|passwd|pwd|secret)\w*\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"
        ),
        remediation="Load the value from environment or a secrets manager at runtime and rotate the exposed one.",
    ),
    SecretPattern(
        rule_id="SEC-004",
        severity="HIGH",
        title="Database connection string with credentials",
        regex=re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|sqlserver|amqp)"
            r"://[^\s:/\"'@]+:[^\s\"']+@[^\s\"'/]+"
        ),
        remediation="Use IAM database auth or inject the DSN from a secrets manager; rotate the database password.",
    ),
    SecretPattern(
        rule_id="SEC-005",
        severity="MEDIUM",
        title="API key or token assigned inline",
        regex=re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|token)\s*[:=]\s*"
            r"[\"'][A-Za-z0-9_\-\.]{16,}[\"']"
        ),
        remediation="Move the token to a secrets manager, scope it to least privilege and rotate it.",
    ),
]
