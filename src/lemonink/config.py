"""Checks on MCP client configuration files (Claude Desktop, Claude Code .mcp.json,
VS Code mcp.json, Cursor). Only reads the file; never starts a server."""

from __future__ import annotations

import re

from .scanner import Finding

SECRET_KEY = re.compile(r"(token|secret|password|passwd|api[_-]?key|private[_-]?key|auth)", re.I)
SECRET_VALUE = re.compile(
    r"^(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{20,})$")
PLACEHOLDER = re.compile(r"^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\{input:[^}]+\}|<.*>|x+|\*+|your[_-].*|changeme|)$", re.I)
RUNNERS = {"npx", "npx.cmd", "bunx", "pnpx", "uvx", "pipx"}
BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "c:\\", "c:/", "/home", "/users", "c:\\users"}


def servers_of(cfg: dict) -> dict:
    for key in ("mcpServers", "servers"):
        if isinstance(cfg.get(key), dict):
            return cfg[key]
    mcp = cfg.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


def _redact(v: str) -> str:
    return v[:4] + "…" + f"({len(v)} chars)"


def _package_arg(args: list[str]) -> str | None:
    for a in args:
        if a.startswith("-"):
            continue
        return a
    return None


def _pinned(pkg: str, runner: str) -> bool:
    if runner.startswith(("uvx", "pipx")):
        return "==" in pkg or "@" in pkg
    body = pkg[1:] if pkg.startswith("@") else pkg
    return "@" in body and not body.endswith(("@latest", "@next"))


def check_config(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    for name, srv in servers_of(cfg).items():
        if not isinstance(srv, dict):
            continue
        t = f"config:{name}"
        cmd = str(srv.get("command", ""))
        args = [str(a) for a in srv.get("args") or []]
        base = cmd.replace("\\", "/").rsplit("/", 1)[-1].lower()

        if base in RUNNERS:
            pkg = _package_arg(args)
            if pkg and not _pinned(pkg, base):
                out.append(Finding("CFG001", "medium", "パッケージの版が固定されていない / Package version not pinned",
                                   t, f"{cmd} {pkg}", server=name))

        for k, v in (srv.get("env") or {}).items():
            v = str(v)
            if PLACEHOLDER.match(v.strip()):
                continue
            if SECRET_VALUE.match(v) or (SECRET_KEY.search(k) and len(v) >= 12):
                out.append(Finding("CFG002", "high", "設定ファイルに秘密情報がそのまま書かれている / Plain-text secret in config",
                                   t, f"{k}={_redact(v)}", server=name))
        for h, v in (srv.get("headers") or {}).items():
            v = str(v)
            if not PLACEHOLDER.match(v.strip()) and len(v) >= 12 and ("auth" in h.lower() or "key" in h.lower() or "token" in h.lower()):
                out.append(Finding("CFG002", "high", "設定ファイルに秘密情報がそのまま書かれている / Plain-text secret in config",
                                   t, f"{h}={_redact(v)}", server=name))
        for a in args:
            if SECRET_VALUE.match(a):
                out.append(Finding("CFG002", "high", "コマンド引数に秘密情報 / Secret passed as command argument",
                                   t, _redact(a), server=name))

        url = str(srv.get("url", "") or srv.get("serverUrl", ""))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", url):
            out.append(Finding("CFG003", "high", "暗号化されていない通信（http://） / Remote server over plain http",
                               t, url, server=name))

        joined = " ".join(args)
        if base in ("docker", "podman"):
            if "--privileged" in args:
                out.append(Finding("CFG004", "high", "特権コンテナ / Container runs --privileged", t, "--privileged", server=name))
            if re.search(r"(-v|--volume)[\s=](/|~|\$HOME|\$\{HOME\}|C:\\|/home|/Users):", joined, re.I):
                out.append(Finding("CFG004", "high", "ホスト全体をマウント / Mounts host root or home", t, joined[:120], server=name))
            if "--network=host" in args or ("--network" in args and "host" in args):
                out.append(Finding("CFG004", "medium", "ホストのネットワークを共有 / Uses host network", t, "--network host", server=name))

        for a in args:
            if a.rstrip("/\\").lower() in BROAD_PATHS or a.lower() in BROAD_PATHS:
                out.append(Finding("CFG005", "medium", "ホーム・ルート全体へのアクセスを渡している / Grants access to whole home or root",
                                   t, a, server=name))
        if re.search(r"(curl|wget|iwr|invoke-webrequest)[^|]*\|\s*(sh|bash|iex|python)", f"{cmd} {joined}", re.I):
            out.append(Finding("CFG006", "high", "ダウンロードしたスクリプトをそのまま実行 / Pipes a download into a shell",
                               t, joined[:120], server=name))
    return out
