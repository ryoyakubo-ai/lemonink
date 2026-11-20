"""Output formats: text (human), json, sarif (for GitHub code scanning)."""

from __future__ import annotations

import json

from . import __version__
from .scanner import SEVERITY_ORDER, Finding

COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
LABEL = {"high": "高", "medium": "中", "low": "低", "info": "情報"}


def text(findings: list[Finding], scanned: int, color: bool = True, errors: list[dict] | None = None) -> str:
    lines = []
    for e in errors or []:
        lines.append(f"[ERROR/未検査] {e['server']}: {e['error']}")
    fs = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.server, f.target, f.rule))
    for f in fs:
        sev = f"[{f.severity.upper()}/{LABEL[f.severity]}]"
        if color:
            sev = COLORS[f.severity] + sev + "\033[0m"
        where = f"{f.server} › {f.target}" if f.server else f.target
        lines.append(f"{sev} {f.rule} {f.title}\n    {where}")
        if f.evidence:
            lines.append(f"    > {f.evidence}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    lines.append("")
    lines.append(f"{scanned} 件を検査 / items scanned. "
                 f"高 high {counts['high']}, 中 medium {counts['medium']}, 低 low {counts['low']}, 情報 info {counts['info']}")
    return "\n".join(lines)


def as_json(findings: list[Finding], scanned: int, errors: list[dict] | None = None) -> str:
    return json.dumps({"tool": "lemonink", "version": __version__, "scanned_items": scanned,
                       "complete": not errors, "errors": errors or [],
                       "findings": [f.to_dict() for f in findings]}, ensure_ascii=False, indent=2)


def sarif(findings: list[Finding], source_uri: str, errors: list[dict] | None = None) -> str:
    level = {"high": "error", "medium": "warning", "low": "note", "info": "none"}
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule, {"id": f.rule, "shortDescription": {"text": f.title}})
        results.append({
            "ruleId": f.rule,
            "level": level[f.severity],
            "message": {"text": f"{f.title}: {f.server + ' ' if f.server else ''}{f.target} {f.evidence}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": source_uri}}}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "lemonink", "version": __version__, "rules": list(rules.values())}},
                  "invocations": [{
                      "executionSuccessful": not errors,
                      "toolExecutionNotifications": [
                          {"level": "error", "message": {"text": f"{e['server']}: not scanned: {e['error']}"}}
                          for e in errors or []],
                  }],
                  "results": results}],
    }, ensure_ascii=False, indent=2)
