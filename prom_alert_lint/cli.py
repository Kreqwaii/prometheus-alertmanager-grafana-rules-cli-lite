"""CLI entry point for prometheus-alertmanager-grafana-rules-cli-lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .rules import SEVERITY_ORDER, Finding, lint_paths


def format_text(findings: List[Finding], files_scanned: int) -> str:
    if not findings:
        return f"OK: {files_scanned} file(s) scanned, 0 issues found."
    lines = [f"Scanned {files_scanned} file(s), found {len(findings)} issue(s):", ""]
    for f in findings:
        lines.append(
            f"[{f.severity.upper()}] {f.rule_id} | {f.file} ({f.target}): {f.message}"
        )
    return "\n".join(lines)


def format_json(findings: List[Finding], files_scanned: int) -> str:
    payload = {
        "version": __version__,
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_markdown(findings: List[Finding], files_scanned: int) -> str:
    lines = [
        "# Prometheus & Alertmanager Lint Report",
        "",
        f"- **Files scanned:** {files_scanned}",
        f"- **Total issues:** {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | File | Target | Message |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for f in findings:
        msg = f.message.replace("|", "\\|")
        lines.append(
            f"| {f.severity.upper()} | `{f.rule_id}` | `{f.file}` | `{f.target}` | {msg} |"
        )
    return "\n".join(lines)


def should_fail(findings: List[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER.get(fail_on, 0)
    if threshold == 0:
        return False
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus-alertmanager-grafana-rules-cli-lite",
        description=(
            "Offline stdlib-only linter for Prometheus alert rule YAML files "
            "and Alertmanager routing configurations."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="YAML files or directories to lint.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "info", "warning", "error", "critical"),
        default="error",
        help="Minimum severity that triggers non-zero exit code (default: error).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    paths = [Path(p) for p in args.paths]
    findings, files_scanned = lint_paths(paths)

    if args.format == "json":
        print(format_json(findings, files_scanned))
    elif args.format == "markdown":
        print(format_markdown(findings, files_scanned))
    else:
        print(format_text(findings, files_scanned))

    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
