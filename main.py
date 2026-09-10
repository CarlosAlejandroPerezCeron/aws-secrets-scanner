from __future__ import annotations

import argparse
import sys

from report import print_json, print_terminal, write_csv
from scanner.base import ScanConfig
from scanner.rules import run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-secrets-scanner",
        description="Scan source files for hardcoded credentials and secrets.",
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="Files or directories to scan (default: current directory)")
    p.add_argument("--ext", nargs="+", metavar="EXT",
                   help="File extensions to include (default: py js ts yaml yml json env tf sh)")
    p.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    p.add_argument("--output", choices=["terminal", "json"], default="terminal")
    p.add_argument("--csv-path", metavar="PATH", help="Also write CSV report to PATH")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="Exit with code 2 if any CRITICAL finding is detected")
    return p


def main() -> None:
    args = build_parser().parse_args()
    config = ScanConfig(
        paths=args.paths,
        extensions=[e if e.startswith(".") else f".{e}" for e in args.ext] if args.ext else None,
        min_severity=args.min_severity,
    )
    findings = run_all(args.paths, config)

    if args.output == "json":
        print_json(findings)
    else:
        print_terminal(findings)

    if args.csv_path:
        write_csv(findings, args.csv_path)

    if args.fail_on_critical and any(f.severity == "CRITICAL" for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
