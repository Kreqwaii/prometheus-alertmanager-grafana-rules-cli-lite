"""Linting rules for Prometheus alert rules and Alertmanager configurations."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .yaml_lite import YamlParseError, parse_yaml

SEVERITY_ORDER = {
    "none": 0,
    "info": 1,
    "warning": 2,
    "error": 3,
    "critical": 4,
}

_RATE_WINDOW_RE = re.compile(r"\b(?:rate|irate|increase)\s*\([^)]*?\[(\d+)([smhdwy])\]")
_EQ_ZERO_RE = re.compile(r"(?<![!<>=])==\s*0(?:\.0+)?\b")

_DURATION_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
    "y": 31536000,
}

_SECRET_KEYS = {
    "url",
    "api_url",
    "service_key",
    "routing_key",
    "api_key",
    "bot_token",
    "bearer_token",
    "password",
    "auth_password",
    "webhook_url",
}

_SAFE_VALUE_PREFIXES = ("$", "{{", "env:", "file:", "<")


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    target: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _duration_to_seconds(amount: int, unit: str) -> int:
    return amount * _DURATION_SECONDS.get(unit, 1)


def _is_hardcoded_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v:
        return False
    if any(v.startswith(p) for p in _SAFE_VALUE_PREFIXES):
        return False
    if "example.com" in v or "localhost" in v or "127.0.0.1" in v:
        return False
    return True


def lint_prometheus_rules(
    data: Dict[str, Any],
    file_path: str,
    seen_alerts: Optional[Dict[str, str]] = None,
) -> List[Finding]:
    """Lint a parsed Prometheus rules YAML document."""
    findings: List[Finding] = []
    if seen_alerts is None:
        seen_alerts = {}

    groups = data.get("groups")
    if not isinstance(groups, list):
        return findings

    for group in groups:
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name", "<unnamed-group>"))
        rules = group.get("rules")
        if not isinstance(rules, list):
            continue

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if "alert" not in rule:
                continue  # recording rule

            alert_name = str(rule.get("alert") or "<unnamed-alert>")
            target = f"{group_name}/{alert_name}"

            # PROM006: Duplicate alert names
            if alert_name in seen_alerts:
                findings.append(
                    Finding(
                        rule_id="PROM006",
                        severity="error",
                        file=file_path,
                        target=target,
                        message=(
                            f"Duplicate alert name '{alert_name}' "
                            f"(already defined in {seen_alerts[alert_name]})."
                        ),
                    )
                )
            else:
                seen_alerts[alert_name] = f"{file_path} ({group_name})"

            # PROM001: Missing `for:` duration
            if not rule.get("for"):
                findings.append(
                    Finding(
                        rule_id="PROM001",
                        severity="warning",
                        file=file_path,
                        target=target,
                        message="Alert is missing 'for:' duration; may cause flapping alerts.",
                    )
                )

            # PROM002: Missing `severity` label
            labels = rule.get("labels")
            if not isinstance(labels, dict) or not labels.get("severity"):
                findings.append(
                    Finding(
                        rule_id="PROM002",
                        severity="error",
                        file=file_path,
                        target=target,
                        message="Alert is missing required 'labels.severity'.",
                    )
                )

            # PROM003: Missing `summary` or `runbook_url` annotations
            annotations = rule.get("annotations")
            missing_ann: List[str] = []
            if not isinstance(annotations, dict):
                missing_ann = ["summary", "runbook_url"]
            else:
                if not annotations.get("summary"):
                    missing_ann.append("summary")
                if not annotations.get("runbook_url"):
                    missing_ann.append("runbook_url")
            if missing_ann:
                findings.append(
                    Finding(
                        rule_id="PROM003",
                        severity="warning",
                        file=file_path,
                        target=target,
                        message=f"Alert annotations missing: {', '.join(missing_ann)}.",
                    )
                )

            expr = str(rule.get("expr") or "")
            # PROM004: Fragile `== 0` comparison
            if _EQ_ZERO_RE.search(expr):
                findings.append(
                    Finding(
                        rule_id="PROM004",
                        severity="warning",
                        file=file_path,
                        target=target,
                        message="Expression uses fragile '== 0' comparison; consider absent() or threshold.",
                    )
                )

            # PROM005: `rate()` / `irate()` / `increase()` window too short (< 2m)
            for match in _RATE_WINDOW_RE.finditer(expr):
                amount = int(match.group(1))
                unit = match.group(2)
                if _duration_to_seconds(amount, unit) < 120:
                    findings.append(
                        Finding(
                            rule_id="PROM005",
                            severity="warning",
                            file=file_path,
                            target=target,
                            message=(
                                f"Range vector '[{amount}{unit}]' in rate/irate/increase is < 2m; "
                                "may miss samples on standard scrape intervals."
                            ),
                        )
                    )

    return findings


def _collect_route_receivers(route: Dict[str, Any], out: Set[str]) -> None:
    rec = route.get("receiver")
    if isinstance(rec, str) and rec.strip():
        out.add(rec.strip())
    sub_routes = route.get("routes")
    if isinstance(sub_routes, list):
        for child in sub_routes:
            if isinstance(child, dict):
                _collect_route_receivers(child, out)


def _scan_secrets(obj: Any, file_path: str, target: str, findings: List[Finding]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_lower = str(k).lower()
            if key_lower in _SECRET_KEYS and _is_hardcoded_secret(v):
                findings.append(
                    Finding(
                        rule_id="AM003",
                        severity="critical",
                        file=file_path,
                        target=target,
                        message=f"Hardcoded secret/URL in '{k}'; use *_file or environment substitution.",
                    )
                )
            else:
                _scan_secrets(v, file_path, target, findings)
    elif isinstance(obj, list):
        for item in obj:
            _scan_secrets(item, file_path, target, findings)


def lint_alertmanager_config(data: Dict[str, Any], file_path: str) -> List[Finding]:
    """Lint a parsed Alertmanager configuration YAML document."""
    findings: List[Finding] = []
    route = data.get("route")
    receivers = data.get("receivers")

    referenced_receivers: Set[str] = set()
    if isinstance(route, dict):
        # AM001: Root route missing group_by or repeat_interval
        missing_route_fields: List[str] = []
        if not route.get("group_by"):
            missing_route_fields.append("group_by")
        if not route.get("repeat_interval"):
            missing_route_fields.append("repeat_interval")
        if missing_route_fields:
            findings.append(
                Finding(
                    rule_id="AM001",
                    severity="warning",
                    file=file_path,
                    target="route",
                    message=f"Root route missing: {', '.join(missing_route_fields)}.",
                )
            )
        _collect_route_receivers(route, referenced_receivers)

    defined_receivers: Set[str] = set()
    if isinstance(receivers, list):
        for rec in receivers:
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("name") or "<unnamed-receiver>")
            defined_receivers.add(name)
            # AM003: Hardcoded secrets in receiver configs
            _scan_secrets(rec, file_path, f"receivers/{name}", findings)

    # AM002: Unreferenced receivers
    for name in sorted(defined_receivers - referenced_receivers):
        findings.append(
            Finding(
                rule_id="AM002",
                severity="error",
                file=file_path,
                target=f"receivers/{name}",
                message=f"Receiver '{name}' is defined but never referenced in route tree.",
            )
        )

    # AM002: Undefined receivers referenced in route
    for name in sorted(referenced_receivers - defined_receivers):
        findings.append(
            Finding(
                rule_id="AM002",
                severity="error",
                file=file_path,
                target="route",
                message=f"Route references undefined receiver '{name}'.",
            )
        )

    return findings


def lint_file(
    path: Path,
    seen_alerts: Optional[Dict[str, str]] = None,
) -> List[Finding]:
    """Parse and lint a single YAML file."""
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            Finding(
                rule_id="IO001",
                severity="error",
                file=file_str,
                target=file_str,
                message=f"Failed to read file: {exc}",
            )
        ]

    try:
        data = parse_yaml(text)
    except YamlParseError as exc:
        return [
            Finding(
                rule_id="YAML001",
                severity="error",
                file=file_str,
                target=file_str,
                message=f"YAML parse error: {exc}",
            )
        ]

    if not isinstance(data, dict):
        return []

    findings: List[Finding] = []
    if "groups" in data:
        findings.extend(lint_prometheus_rules(data, file_str, seen_alerts=seen_alerts))
    if "route" in data or "receivers" in data:
        findings.extend(lint_alertmanager_config(data, file_str))
    return findings


def lint_paths(paths: List[Path]) -> Tuple[List[Finding], int]:
    """Lint a list of files or directories. Returns (findings, files_scanned)."""
    yaml_files: List[Path] = []
    for p in paths:
        if p.is_dir():
            yaml_files.extend(sorted(p.rglob("*.yml")))
            yaml_files.extend(sorted(p.rglob("*.yaml")))
        elif p.is_file():
            yaml_files.append(p)

    seen_alerts: Dict[str, str] = {}
    all_findings: List[Finding] = []
    for yf in yaml_files:
        all_findings.extend(lint_file(yf, seen_alerts=seen_alerts))
    return all_findings, len(yaml_files)
