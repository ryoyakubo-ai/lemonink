"""Core scanning: walk tools/prompts/resources and report findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

from . import normalize as N
from .permissions import check_tool
from .rules import RULES

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}
LONG_DESCRIPTION = 1500


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    target: str  # e.g. "tool:send_mail" or "tool:send_mail.param:to"
    evidence: str = ""
    obfuscated: bool = False
    server: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    scanned_items: int = 0

    def worst(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


def _bump(sev: str) -> str:
    return {"low": "medium", "medium": "high"}.get(sev, sev)


def _snippet(text: str, start: int, end: int, pad: int = 20) -> str:
    s = text[max(0, start - pad):min(len(text), end + pad)]
    return " ".join(s.split())[:160]


def scan_text(text: str, target: str) -> list[Finding]:
    """Run all description checks on one piece of text."""
    if not text:
        return []
    out: list[Finding] = []
    raw = text.lower()
    norm = N.normalize(text)
    for rule in RULES:
        m = rule.pattern.search(norm)
        if not m:
            continue
        obfuscated = not rule.pattern.search(raw)
        out.append(Finding(
            rule=rule.id,
            severity=_bump(rule.severity) if obfuscated else rule.severity,
            title=rule.title + ("（難読化あり / obfuscated）" if obfuscated else ""),
            target=target,
            evidence=_snippet(norm, m.start(), m.end()),
            obfuscated=obfuscated,
        ))

    h = N.find_hidden(text)
    if h.tag_text:
        out.append(Finding("HID001", "high", "タグ文字に隠したテキスト / Text hidden in Unicode tag characters",
                           target, h.tag_text[:160], True))
    if h.zero_width:
        out.append(Finding("HID002", "medium", "ゼロ幅文字 / Zero-width characters",
                           target, ", ".join(h.zero_width), True))
    if h.bidi:
        out.append(Finding("HID003", "medium", "双方向制御文字 / Bidirectional control characters",
                           target, f"{h.bidi} chars", True))
    if h.mixed_script_words:
        out.append(Finding("HID004", "medium", "ラテン文字とキリル・ギリシャ文字の混在 / Mixed-script words (homoglyphs)",
                           target, ", ".join(h.mixed_script_words[:5]), True))
    if h.fullwidth_runs:
        out.append(Finding("HID005", "info", "全角英字の連続 / Runs of full-width Latin letters",
                           target, ", ".join(h.fullwidth_runs[:5]), True))
    if h.halfwidth_kana_runs:
        out.append(Finding("HID006", "info", "半角カタカナの連続 / Runs of half-width katakana",
                           target, ", ".join(h.halfwidth_kana_runs[:5]), True))
    if len(text) > LONG_DESCRIPTION:
        out.append(Finding("LEN001", "low", "非常に長い説明文 / Unusually long description",
                           target, f"{len(text)} chars"))
    if "\n" * 8 in text.replace("\r", "") or " " * 80 in text:
        out.append(Finding("LEN002", "medium", "大量の空白の後に続く文 / Text pushed out of view by whitespace",
                           target, ""))
    return out


def _walk_schema(schema, path: str):
    """Yield (path, text) for every description/title/default/enum string in a JSON schema."""
    if isinstance(schema, dict):
        for key in ("description", "title", "default", "examples"):
            v = schema.get(key)
            if isinstance(v, str):
                yield f"{path}.{key}", v
            elif isinstance(v, list):
                for i, e in enumerate(v):
                    if isinstance(e, str):
                        yield f"{path}.{key}[{i}]", e
        for k, v in (schema.get("properties") or {}).items():
            yield from _walk_schema(v, f"{path}.param:{k}")
        for key in ("items", "additionalProperties"):
            if isinstance(schema.get(key), dict):
                yield from _walk_schema(schema[key], f"{path}.{key}")
        for key in ("anyOf", "oneOf", "allOf"):
            for i, sub in enumerate(schema.get(key) or []):
                yield from _walk_schema(sub, f"{path}.{key}[{i}]")


def item_texts(kind: str, item: dict):
    name = item.get("name", "?")
    base = f"{kind}:{name}"
    for key in ("description", "title"):
        if isinstance(item.get(key), str):
            yield base if key == "description" else f"{base}.title", item[key]
    if kind == "tool":
        yield from _walk_schema(item.get("inputSchema") or item.get("input_schema") or {}, base)
    if kind == "prompt":
        for a in item.get("arguments") or []:
            if isinstance(a, dict) and isinstance(a.get("description"), str):
                yield f"{base}.arg:{a.get('name', '?')}", a["description"]


def scan_server(data: dict, server: str = "") -> Report:
    """Scan one server snapshot: {"tools": [...], "prompts": [...], "resources": [...], "instructions": "..."}."""
    rep = Report()
    if isinstance(data.get("instructions"), str):
        rep.scanned_items += 1
        rep.findings += scan_text(data["instructions"], "server:instructions")
    for kind, key in (("tool", "tools"), ("prompt", "prompts"), ("resource", "resources")):
        for item in data.get(key) or []:
            if not isinstance(item, dict):
                continue
            rep.scanned_items += 1
            for target, text in item_texts(kind, item):
                rep.findings += scan_text(text, target)
            if kind == "tool":
                for f in check_tool(item):
                    rep.findings.append(Finding(f["rule"], f["severity"], f["title"],
                                                f"tool:{item.get('name', '?')}", f["evidence"]))
    for f in rep.findings:
        f.server = server
    return rep


def fingerprint(data: dict) -> dict[str, str]:
    """Hash each tool/prompt/resource definition so later changes (rug pulls) can be spotted."""
    out = {}
    for key in ("tools", "prompts", "resources"):
        for item in data.get(key) or []:
            if isinstance(item, dict):
                blob = json.dumps(item, sort_keys=True, ensure_ascii=False).encode()
                out[f"{key[:-1]}:{item.get('name', '?')}"] = hashlib.sha256(blob).hexdigest()
    return out


def diff_baseline(old: dict[str, str], new: dict[str, str], server: str = "") -> list[Finding]:
    out = []
    for k, h in new.items():
        if k not in old:
            out.append(Finding("PIN001", "low", "前回なかった項目 / New item since baseline", k, server=server))
        elif old[k] != h:
            out.append(Finding("PIN002", "high", "前回から定義が変わった / Definition changed since baseline (possible rug pull)", k, server=server))
    for k in old:
        if k not in new:
            out.append(Finding("PIN003", "info", "前回あった項目が消えた / Item removed since baseline", k, server=server))
    return out
