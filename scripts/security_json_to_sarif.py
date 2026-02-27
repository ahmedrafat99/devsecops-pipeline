#!/usr/bin/env python3
"""Convert non-SARIF security reports into SARIF for GitHub Code Scanning.

Supported inputs in the reports directory:
- trufflehog.json            -> trufflehog.sarif
- npm-audit.json             -> npm-audit.sarif
- safety.json                -> safety.sarif
- pip-audit.json             -> pip-audit.sarif
- zap-baseline-report.json   -> zap-baseline.sarif
- zap-report.json            -> zap-full.sarif
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


SUPPORTED_TOOLS = {
    "trufflehog",
    "npm-audit",
    "safety",
    "pip-audit",
    "zap-baseline",
    "zap-full",
}


def _sanitize_rule_id(raw: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", (raw or "finding").strip())
    cleaned = cleaned.strip("-")
    return (cleaned or "finding")[:120]


def _read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _repo_relative_uri(path: Path) -> str:
    workspace = Path.cwd()
    env_workspace = workspace
    # Prefer GitHub workspace when available in Actions runners.
    if "GITHUB_WORKSPACE" in os.environ:
        env_workspace = Path(os.environ["GITHUB_WORKSPACE"])
    try:
        return path.resolve().relative_to(env_workspace.resolve()).as_posix()
    except Exception:
        try:
            return path.resolve().relative_to(workspace.resolve()).as_posix()
        except Exception:
            return path.name


def _sev_to_level(sev: str) -> str:
    normalized = (sev or "").strip().upper()
    if normalized in {"CRITICAL", "HIGH"}:
        return "error"
    if normalized in {"MEDIUM", "MODERATE"}:
        return "warning"
    return "note"


def _to_int(value: Any, default: int = 1) -> int:
    try:
        iv = int(value)
        return iv if iv > 0 else default
    except (TypeError, ValueError):
        return default


def _mk_finding(
    *,
    rule_id: str,
    rule_name: str,
    message: str,
    level: str,
    uri: str,
    line: int = 1,
    tags: list[str] | None = None,
    help_uri: str | None = None,
) -> dict[str, Any]:
    return {
        "rule_id": _sanitize_rule_id(rule_id),
        "rule_name": rule_name or "Security finding",
        "message": message or "Security finding detected.",
        "level": level or "warning",
        "uri": uri or "unknown",
        "line": _to_int(line, 1),
        "tags": tags or ["security"],
        "help_uri": help_uri,
    }


def _build_sarif(tool_name: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rid = f["rule_id"]
        if rid not in rules:
            rule = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f["rule_name"]},
                "defaultConfiguration": {"level": f["level"]},
                "properties": {"tags": f.get("tags", ["security"])},
            }
            if f.get("help_uri"):
                rule["helpUri"] = f["help_uri"]
            rules[rid] = rule

        result = {
            "ruleId": rid,
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["uri"]},
                        "region": {"startLine": _to_int(f.get("line"), 1)},
                    }
                }
            ],
            "properties": {"tags": f.get("tags", ["security"])},
        }
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _write_sarif(path: Path, tool_name: str, findings: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    sarif = _build_sarif(tool_name, findings)
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return len(findings)


def _parse_trufflehog(report_dir: Path) -> list[dict[str, Any]]:
    path = report_dir / "trufflehog.json"
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if len(lines) == 1 and lines[0] == "[]":
        return []

    objects: list[dict[str, Any]] = []
    for line in lines:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            objects.extend([x for x in parsed if isinstance(x, dict)])
        elif isinstance(parsed, dict):
            objects.append(parsed)

    findings: list[dict[str, Any]] = []
    for obj in objects:
        detector = str(obj.get("DetectorName") or obj.get("DetectorType") or "secret-detected")
        filesystem = (
            (obj.get("SourceMetadata") or {})
            .get("Data", {})
            .get("Filesystem", {})
        )
        uri = str(filesystem.get("file") or obj.get("SourceName") or "repository")
        line = _to_int(filesystem.get("line"), 1)
        verified = bool(obj.get("Verified"))
        sev = "HIGH" if verified else "MEDIUM"
        level = _sev_to_level(sev)
        message = (
            f"Verified secret detected by TruffleHog detector '{detector}'."
            if verified
            else f"Potential secret detected by TruffleHog detector '{detector}'."
        )
        findings.append(
            _mk_finding(
                rule_id=f"trufflehog.{detector.lower()}",
                rule_name="TruffleHog secret detection",
                message=message,
                level=level,
                uri=uri,
                line=line,
                tags=["security", "secret", sev],
            )
        )
    return findings


def _parse_npm_audit(report_dir: Path) -> list[dict[str, Any]]:
    data = _read_json(report_dir / "npm-audit.json")
    if not isinstance(data, dict):
        return []
    if data.get("status") == "missing":
        return []

    vuln_map = data.get("vulnerabilities")
    if not isinstance(vuln_map, dict):
        return []

    findings: list[dict[str, Any]] = []
    for pkg, details in vuln_map.items():
        if not isinstance(details, dict):
            continue
        default_sev = str(details.get("severity") or "medium")
        via = details.get("via") or []
        emitted = False
        for item in via:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or default_sev)
            level = _sev_to_level(sev)
            advisory_id = (
                str(item.get("source") or item.get("cve") or item.get("name") or pkg)
            )
            title = str(item.get("title") or f"npm audit advisory for {pkg}")
            advisory_url = str(item.get("url") or "").strip()
            msg = f"{pkg}: {title}"
            if advisory_url:
                msg += f" ({advisory_url})"
            findings.append(
                _mk_finding(
                    rule_id=f"npm-audit.{advisory_id}",
                    rule_name="npm audit vulnerability",
                    message=msg,
                    level=level,
                    uri="package-lock.json",
                    line=1,
                    tags=["security", "dependency", sev.upper()],
                    help_uri=advisory_url or None,
                )
            )
            emitted = True
        if not emitted:
            sev = default_sev
            findings.append(
                _mk_finding(
                    rule_id=f"npm-audit.{pkg}",
                    rule_name="npm audit vulnerability",
                    message=f"{pkg}: npm audit reported a vulnerable dependency.",
                    level=_sev_to_level(sev),
                    uri="package-lock.json",
                    line=1,
                    tags=["security", "dependency", sev.upper()],
                )
            )
    return findings


def _parse_safety(report_dir: Path) -> list[dict[str, Any]]:
    data = _read_json(report_dir / "safety.json")
    if data is None:
        return []
    if isinstance(data, dict) and data.get("status") == "missing":
        return []

    entries: list[Any]
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        entries = data.get("vulnerabilities", [])
    else:
        entries = []

    findings: list[dict[str, Any]] = []
    for item in entries:
        if isinstance(item, dict):
            vuln_id = str(item.get("vulnerability_id") or item.get("id") or "unknown")
            package = str(item.get("package_name") or item.get("package") or "package")
            advisory = str(item.get("advisory") or item.get("summary") or "Safety reported a vulnerable dependency.")
            severity = str(item.get("severity") or "MEDIUM")
        elif isinstance(item, list):
            vuln_id = str(item[0]) if len(item) > 0 else "unknown"
            package = str(item[1]) if len(item) > 1 else "package"
            advisory = str(item[4]) if len(item) > 4 else "Safety reported a vulnerable dependency."
            severity = "MEDIUM"
        else:
            continue
        findings.append(
            _mk_finding(
                rule_id=f"safety.{vuln_id}",
                rule_name="Safety vulnerability",
                message=f"{package}: {advisory}",
                level=_sev_to_level(severity),
                uri="requirements.txt",
                line=1,
                tags=["security", "dependency", severity.upper()],
            )
        )
    return findings


def _parse_pip_audit(report_dir: Path) -> list[dict[str, Any]]:
    data = _read_json(report_dir / "pip-audit.json")
    if not data:
        return []
    if isinstance(data, dict) and data.get("message"):
        return []

    deps: list[dict[str, Any]] = []
    if isinstance(data, list):
        deps = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        raw_deps = data.get("dependencies")
        if isinstance(raw_deps, list):
            deps = [x for x in raw_deps if isinstance(x, dict)]

    findings: list[dict[str, Any]] = []
    for dep in deps:
        name = str(dep.get("name") or "package")
        vulns = dep.get("vulns") or dep.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vid = str(vuln.get("id") or vuln.get("alias") or "unknown")
            fixes = vuln.get("fix_versions") or []
            fix_text = f" Fixed versions: {', '.join(map(str, fixes))}." if fixes else ""
            severity = str(vuln.get("severity") or "MEDIUM")
            findings.append(
                _mk_finding(
                    rule_id=f"pip-audit.{vid}",
                    rule_name="pip-audit vulnerability",
                    message=f"{name}: advisory {vid}.{fix_text}",
                    level=_sev_to_level(severity),
                    uri="requirements.txt",
                    line=1,
                    tags=["security", "dependency", severity.upper()],
                )
            )
    return findings


def _parse_zap(report_dir: Path, json_name: str, prefix: str) -> list[dict[str, Any]]:
    json_path = report_dir / json_name
    data = _read_json(json_path)
    if not isinstance(data, dict):
        return []
    if data.get("status") in {"missing", "skipped"}:
        return []
    sites = data.get("site")
    if not isinstance(sites, list):
        return []

    risk_to_sev = {
        "3": "HIGH",
        "2": "MEDIUM",
        "1": "LOW",
        "0": "LOW",
    }
    findings: list[dict[str, Any]] = []
    report_uri = _repo_relative_uri(json_path)
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts") or []
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            risk_code = str(alert.get("riskcode") or "")
            sev = risk_to_sev.get(risk_code, "LOW")
            level = _sev_to_level(sev)
            plugin = str(alert.get("pluginid") or alert.get("alertRef") or alert.get("alert") or "alert")
            instances = alert.get("instances") or []
            first_instance = instances[0] if isinstance(instances, list) and instances else {}
            uri = report_uri
            line = 1
            if isinstance(first_instance, dict):
                line = _to_int(first_instance.get("line"), 1)
            count = len(instances) if isinstance(instances, list) and instances else 1
            alert_name = str(alert.get("alert") or "OWASP ZAP finding")
            desc = str(alert.get("desc") or "").strip()
            message = f"{alert_name} (risk={sev}, instances={count})"
            if desc:
                message += f" - {desc[:240]}"
            findings.append(
                _mk_finding(
                    rule_id=f"{prefix}.{plugin}",
                    rule_name=f"OWASP ZAP {prefix} finding",
                    message=message,
                    level=level,
                    uri=uri,
                    line=line,
                    tags=["security", "dast", sev],
                )
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert security JSON reports to SARIF.")
    parser.add_argument("--report-dir", required=True, help="Directory containing report files.")
    parser.add_argument(
        "--tools",
        default="trufflehog",
        help=(
            "Comma-separated tool list. Supported: "
            + ", ".join(sorted(SUPPORTED_TOOLS))
        ),
    )
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    requested = [t.strip() for t in args.tools.split(",") if t.strip()]
    invalid = [t for t in requested if t not in SUPPORTED_TOOLS]
    if invalid:
        raise SystemExit(f"Unsupported tools: {', '.join(invalid)}")

    tool_map = {
        "trufflehog": (
            "TruffleHog",
            report_dir / "trufflehog.sarif",
            lambda: _parse_trufflehog(report_dir),
        ),
        "npm-audit": (
            "npm audit",
            report_dir / "npm-audit.sarif",
            lambda: _parse_npm_audit(report_dir),
        ),
        "safety": (
            "Safety",
            report_dir / "safety.sarif",
            lambda: _parse_safety(report_dir),
        ),
        "pip-audit": (
            "pip-audit",
            report_dir / "pip-audit.sarif",
            lambda: _parse_pip_audit(report_dir),
        ),
        "zap-baseline": (
            "OWASP ZAP Baseline",
            report_dir / "zap-baseline.sarif",
            lambda: _parse_zap(report_dir, "zap-baseline-report.json", "zap-baseline"),
        ),
        "zap-full": (
            "OWASP ZAP Full",
            report_dir / "zap-full.sarif",
            lambda: _parse_zap(report_dir, "zap-report.json", "zap-full"),
        ),
    }

    for tool in requested:
        tool_name, out_file, parser_fn = tool_map[tool]
        findings = parser_fn()
        count = _write_sarif(out_file, tool_name, findings)
        print(f"{tool}: findings={count}; output={out_file.as_posix()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
