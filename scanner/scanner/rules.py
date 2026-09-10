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
            snippet = line_text[: config.max_match_len]
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


def scan_file(path: str, config: ScanConfig) -> list[SecretFinding]:
    ext = os.path.splitext(path)[1].lower()
    if config.extensions and ext not in config.extensions:
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
            for root, _, files in os.walk(path):
                for fname in files:
                    results.extend(scan_file(os.path.join(root, fname), config))
        else:
            results.extend(scan_file(path, config))
    return sorted(results, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line_no))
