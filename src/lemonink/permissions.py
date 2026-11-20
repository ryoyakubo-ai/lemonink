"""Heuristics for tools whose abilities look broader than needed.

These checks look at the tool name, description and input schema. They do not
prove a tool is unsafe; they point a reviewer at tools that deserve a look.
"""

from __future__ import annotations

import re

CAPABILITIES = [
    ("PERM001", "high", "シェル・任意コマンドの実行 / Arbitrary command execution",
     re.compile(r"\b(exec|execute|shell|bash|cmd|powershell|subprocess|run[_ ]?command|eval|terminal)\b|コマンドを実行|シェル", re.I)),
    ("PERM002", "medium", "ファイルの書き込み・削除 / File write or delete",
     re.compile(r"\b(write|delete|remove|unlink|rm|overwrite|move|rename)[_ ]?(file|dir|directory|path)?s?\b|ファイル.{0,6}(書き込|削除|上書)", re.I)),
    ("PERM003", "medium", "任意のURLへの通信 / Arbitrary network requests",
     re.compile(r"\b(fetch|http[_ ]?request|curl|wget|download|webhook|post[_ ]?url)\b|任意のurl|外部に送信", re.I)),
    ("PERM004", "low", "ファイルの読み込み / File read",
     re.compile(r"\b(read[_ ]?file|cat|get[_ ]?file|list[_ ]?(dir|files))\b|ファイル.{0,6}読", re.I)),
]

PATH_PARAM = re.compile(r"^(path|file|filename|filepath|dir|directory|target|dest|destination|src|source)$", re.I)
CMD_PARAM = re.compile(r"^(command|cmd|script|code|shell|args?)$", re.I)
URL_PARAM = re.compile(r"^(url|uri|endpoint|webhook|host)$", re.I)


def _props(schema: dict) -> dict:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _unconstrained(spec: dict) -> bool:
    """A string parameter with no enum, pattern or const accepts anything."""
    if not isinstance(spec, dict):
        return True
    if spec.get("type") not in (None, "string"):
        return False
    return not any(k in spec for k in ("enum", "const", "pattern"))


def check_tool(tool: dict) -> list[dict]:
    name = str(tool.get("name", ""))
    desc = str(tool.get("description", ""))
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    hay = f"{name} {name.replace('_', ' ')} {desc}"
    findings = []
    caps = set()
    for rid, sev, title, pat in CAPABILITIES:
        if pat.search(hay):
            caps.add(rid)
            findings.append({"rule": rid, "severity": sev, "title": title, "evidence": name})

    for pname, spec in _props(schema).items():
        if CMD_PARAM.match(pname) and _unconstrained(spec):
            findings.append({"rule": "PERM101", "severity": "high",
                             "title": "制限のないコマンド引数 / Unconstrained command parameter",
                             "evidence": f"{name}.{pname}"})
        elif PATH_PARAM.match(pname) and _unconstrained(spec) and caps & {"PERM002", "PERM004"}:
            findings.append({"rule": "PERM102", "severity": "medium",
                             "title": "制限のないパス引数 / Unconstrained path parameter",
                             "evidence": f"{name}.{pname}"})
        elif URL_PARAM.match(pname) and _unconstrained(spec):
            findings.append({"rule": "PERM103", "severity": "medium",
                             "title": "制限のないURL引数 / Unconstrained URL parameter",
                             "evidence": f"{name}.{pname}"})

    ann = tool.get("annotations") or {}
    if caps & {"PERM001", "PERM002"} and ann.get("destructiveHint") is False:
        findings.append({"rule": "PERM201", "severity": "medium",
                         "title": "破壊的な操作なのに destructiveHint=false / Destructive tool claims destructiveHint=false",
                         "evidence": name})
    if caps & {"PERM001", "PERM002"} and ann.get("readOnlyHint") is True:
        findings.append({"rule": "PERM202", "severity": "high",
                         "title": "書き込み・実行するのに readOnlyHint=true / Write/exec tool claims readOnlyHint=true",
                         "evidence": name})
    return findings
