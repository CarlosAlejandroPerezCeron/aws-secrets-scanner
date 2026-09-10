from __future__ import annotations

import csv
import json

from rich.console import Console
from rich.table import Table

from scanner.base import SecretFinding

SEVERITY_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def print_terminal(findings: list[SecretFinding]) -> None:
    console = Console()
    if not findings:
        console.print("[bold green]\u2713 No secrets found[/bold green]")
        return
    table = Table(title="aws-secrets-scanner", show_lines=True)
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Title")
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f.rule_id, f"[{color}]{f.severity}[/{color}]",
                      f.file_path, str(f.line_no), f.title)
    console.print(table)


def print_json(findings: list[SecretFinding]) -> None:
    data = [{"rule_id": f.rule_id, "severity": f.severity, "file_path": f.file_path,
             "line_no": f.line_no, "title": f.title, "match": f.match,
             "remediation": f.remediation} for f in findings]
    print(json.dumps(data, indent=2))


def write_csv(findings: list[SecretFinding], path: str) -> None:
    fieldnames = ["rule_id", "severity", "file_path", "line_no", "title", "match", "remediation"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({"rule_id": f.rule_id, "severity": f.severity,
                             "file_path": f.file_path, "line_no": f.line_no,
                             "title": f.title, "match": f.match, "remediation": f.remediation})
