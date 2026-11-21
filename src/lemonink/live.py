"""Minimal MCP stdio client: start a server, call initialize and the */list
methods, and return the definitions. It never calls a tool.

Starting a server runs its code on your machine, so the CLI only does this
when you pass --connect.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time

from . import __version__

PROTOCOL_VERSION = "2025-06-18"


class StdioSession:
    def __init__(self, command: str, args: list[str], env: dict | None = None, timeout: float = 15.0):
        full_env = os.environ.copy()
        full_env.update({k: str(v) for k, v in (env or {}).items()})
        self.proc = subprocess.Popen(
            [command, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=full_env, text=True, encoding="utf-8", bufsize=1,
            shell=(os.name == "nt"),  # lets Windows resolve npx.cmd and friends
        )
        self.timeout = timeout
        self._id = 0
        self._q: queue.Queue = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    def _send(self, msg: dict):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        # The deadline counts from when the request was sent, so notifications
        # or unrelated messages from the server cannot extend the wait.
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no reply to {method} within {self.timeout:g}s")
            try:
                msg = self._q.get(timeout=remaining)
            except queue.Empty as e:
                raise TimeoutError(f"no reply to {method} within {self.timeout:g}s") from e
            if msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result") or {}

    def notify(self, method: str):
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def snapshot(command: str, args: list[str], env: dict | None = None, timeout: float = 15.0) -> dict:
    s = StdioSession(command, args, env, timeout)
    try:
        init = s.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "lemonink", "version": __version__},
        })
        s.notify("notifications/initialized")
        caps = init.get("capabilities") or {}
        out: dict = {"serverInfo": init.get("serverInfo"), "instructions": init.get("instructions")}
        for cap, method, key in (("tools", "tools/list", "tools"),
                                 ("prompts", "prompts/list", "prompts"),
                                 ("resources", "resources/list", "resources")):
            if cap not in caps:
                continue
            items, cursor = [], None
            for _ in range(50):
                res = s.request(method, {"cursor": cursor} if cursor else {})
                items += res.get(key) or []
                cursor = res.get("nextCursor")
                if not cursor:
                    break
            out[key] = items
        return out
    finally:
        s.close()
