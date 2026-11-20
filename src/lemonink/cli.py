"""Command line interface.

  lemonink tools  FILE.json          scan a saved tools/list result (or snapshot)
  lemonink config FILE.json          check a client config; add --connect to also
                                      start each stdio server and scan its tools
  lemonink stdio  -- CMD ARGS...     start one stdio server and scan it

Exit code: 0 if nothing at or above --fail-on, 1 otherwise, 2 on errors
(including any server that could not be started or listed).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, live, report
from .config import check_config, servers_of
from .scanner import SEVERITY_ORDER, Finding, diff_baseline, fingerprint, scan_server


def _load(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    # Accept a raw JSON-RPC response, a bare list of tools, or a snapshot dict.
    if isinstance(data, list):
        return {"tools": data}
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        return data["result"]
    return data


def _snapshots(data: dict) -> dict[str, dict]:
    """A file may hold one server or {"servers": {name: snapshot}}."""
    if isinstance(data.get("servers"), dict) and not any(k in data for k in ("tools", "prompts", "resources")):
        return data["servers"]
    return {"": data}


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="lemonink", description="Offline safety checks for MCP servers (Japanese + English).")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--format", choices=["text", "json", "sarif"], default="text")
        sp.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high")
        sp.add_argument("--min-severity", choices=["info", "low", "medium", "high"], default="low",
                        help="hide findings below this level (default: low)")
        sp.add_argument("--baseline", help="JSON file of hashes from a previous --save-baseline run")
        sp.add_argument("--save-baseline", help="write hashes of every definition to this file")
        sp.add_argument("--no-color", action="store_true")

    sp = sub.add_parser("tools", help="scan a saved tools/list JSON")
    sp.add_argument("file")
    common(sp)

    sp = sub.add_parser("config", help="check an MCP client config file")
    sp.add_argument("file")
    sp.add_argument("--connect", action="store_true",
                    help="start each stdio server and scan what it reports (runs their code)")
    sp.add_argument("--timeout", type=float, default=20.0)
    common(sp)

    sp = sub.add_parser("stdio", help="start one stdio server and scan it (runs its code)")
    sp.add_argument("command", nargs=argparse.REMAINDER)
    sp.add_argument("--timeout", type=float, default=20.0)
    common(sp)

    a = p.parse_args(argv)
    findings: list[Finding] = []
    scanned = 0
    snaps: dict[str, dict] = {}
    errors: list[dict] = []  # servers that could not be scanned
    source = getattr(a, "file", "stdio")

    try:
        if a.cmd == "tools":
            snaps = _snapshots(_load(a.file))
        elif a.cmd == "config":
            cfg = json.loads(Path(a.file).read_text(encoding="utf-8-sig"))
            findings += check_config(cfg)
            scanned += len(servers_of(cfg))
            if a.connect:
                for name, srv in servers_of(cfg).items():
                    if not isinstance(srv, dict) or not srv.get("command"):
                        continue
                    try:
                        snaps[name] = live.snapshot(srv["command"], [str(x) for x in srv.get("args") or []],
                                                    srv.get("env"), a.timeout)
                    except Exception as e:  # keep going with the other servers
                        errors.append({"server": name, "error": str(e) or type(e).__name__})
                        print(f"[error] {name}: not scanned: {e}", file=sys.stderr)
        elif a.cmd == "stdio":
            cmd = [c for c in a.command if c != "--"] if a.command[:1] == ["--"] else a.command
            if not cmd:
                p.error("stdio needs a command, e.g. lemonink stdio -- npx -y some-server@1.0.0")
            snaps = {cmd[0]: live.snapshot(cmd[0], cmd[1:], None, a.timeout)}
    except (OSError, json.JSONDecodeError, TimeoutError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    baseline = json.loads(Path(a.baseline).read_text(encoding="utf-8")) if a.baseline else None
    new_base = {}
    for name, snap in snaps.items():
        rep = scan_server(snap, name)
        findings += rep.findings
        scanned += rep.scanned_items
        fp = fingerprint(snap)
        new_base[name] = fp
        if baseline is not None:
            findings += diff_baseline(baseline.get(name, {}), fp, name)
    if a.save_baseline:
        Path(a.save_baseline).write_text(json.dumps(new_base, indent=2, ensure_ascii=False), encoding="utf-8")

    shown = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[a.min_severity]]
    if a.format == "json":
        print(report.as_json(shown, scanned, errors))
    elif a.format == "sarif":
        print(report.sarif(shown, source, errors))
    else:
        print(report.text(shown, scanned, color=not a.no_color and sys.stdout.isatty(), errors=errors))

    if errors:
        return 2  # some servers were not scanned; never report that as a pass
    if a.fail_on == "never":
        return 0
    return 1 if any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[a.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
