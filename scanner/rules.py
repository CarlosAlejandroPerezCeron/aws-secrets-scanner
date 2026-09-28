from __future__ import annotations

import os

from .base import SEVERITY_ORDER, ScanConfig, SecretFinding
from .patterns import PATTERNS


def scan_text(text: str, file_path: str, config: ScanConfig) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    lines = text.splitlines()
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            start = match.start()
            line_no = text[:start].count("\n") + 1
            line_text = lines[line_no - 1].strip() if line_no <= len(lines) else ""
            snippet = _redact(line_text, match.group(0)) if config.redact else line_text
            snippet = snippet[: config.max_match_len]
            findings.append(SecretFinding(
                rule_id=pattern.rule_id,
                severity=pattern.severity,
                file_path=file_path,
                line_no=line_no,
                title=pattern.title,
                match=snippet,
                remediation=pattern.remediation,
            ))
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


def _redact(line: str, secret: str) -> str:
    keep = secret[:4]
    return line.replace(secret, keep + "*" * max(len(secret) - 4, 4)) if secret in line else line


def _extension(path: str) -> str:
    name = os.path.basename(path).lower()
    if name == ".env" or name.startswith(".env."):
        return ".env"
    return os.path.splitext(name)[1]


def scan_file(path: str, config: ScanConfig) -> list[SecretFinding]:
    if config.extensions and _extension(path) not in config.extensions:
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, path, config)


def run_all(paths: list[str], config: ScanConfig | None = None) -> list[SecretFinding]:
    if config is None:
        config = ScanConfig()
    results: list[SecretFinding] = []
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in config.skip_dirs]
                for fname in files:
                    results.extend(scan_file(os.path.join(root, fname), config))
        else:
            results.extend(scan_file(path, config))
    threshold = SEVERITY_ORDER.get(config.min_severity, 99)
    results = [f for f in results if SEVERITY_ORDER.get(f.severity, 99) <= threshold]
    return sorted(results, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line_no))
