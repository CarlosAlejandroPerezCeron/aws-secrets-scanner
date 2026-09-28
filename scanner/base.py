from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

DEFAULT_EXTENSIONS = [".py", ".js", ".ts", ".yaml", ".yml", ".json", ".env", ".tf", ".sh"]


@dataclass
class SecretFinding:
    rule_id: str
    severity: str
    file_path: str
    line_no: int
    title: str
    match: str
    remediation: str


@dataclass
class ScanConfig:
    paths: list[str] = field(default_factory=lambda: ["."])
    extensions: list[str] | None = field(default_factory=lambda: list(DEFAULT_EXTENSIONS))
    min_severity: str = "LOW"
    max_match_len: int = 120
    redact: bool = True
    skip_dirs: tuple[str, ...] = (".git", "node_modules", "venv", ".venv", "__pycache__")
