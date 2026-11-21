import json
import sys
from pathlib import Path

import pytest

from lemonink.cli import main
from lemonink.config import check_config
from lemonink.live import snapshot
from lemonink.scanner import diff_baseline, fingerprint, scan_server

FX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FX / name).read_text(encoding="utf-8"))


def rules_for(rep, tool):
    return {f.rule for f in rep.findings if f.target.startswith(f"tool:{tool}")}


@pytest.mark.parametrize("name", ["benign_ja.json", "benign_en.json"])
def test_benign_has_no_medium_or_high(name):
    rep = scan_server(load(name))
    bad = [f for f in rep.findings if f.severity in ("high", "medium")]
    assert bad == [], bad


@pytest.mark.parametrize("tool,expected", [
    ("add_note", {"JA002", "JA004", "JA008"}),
    ("translate", {"JA001"}),
    ("fullwidth", {"EN001"}),
    ("zerowidth", {"JA001", "HID002"}),
    ("kana", {"JA009"}),
    ("tagged", {"HID001", "EN001"}),
    ("steer", {"JA006"}),
    ("exfil", {"JA005"}),
    ("param_poison", {"JA002", "JA007"}),
    ("run_command", {"PERM001", "PERM101", "PERM202"}),
    ("homoglyph", {"HID004"}),
    ("quiet", {"JA003"}),
])
def test_poisoned_detected(tool, expected):
    rep = scan_server(load("poisoned_ja.json"))
    got = rules_for(rep, tool)
    assert expected <= got, (tool, got)


@pytest.mark.parametrize("tool,expected", [
    ("hide", {"EN002"}),
    ("dummy_secret", {"EN003"}),
    ("steer_en", {"EN004"}),
    ("tag_en", {"EN005"}),
    ("secret_en", {"EN006"}),
])
def test_poisoned_en_detected(tool, expected):
    rep = scan_server(load("poisoned_en.json"))
    got = rules_for(rep, tool)
    assert expected <= got, (tool, got)


def test_every_text_rule_has_a_positive_fixture():
    from lemonink.rules import RULES

    hit = set()
    for name in ("poisoned_ja.json", "poisoned_en.json"):
        hit |= {f.rule for f in scan_server(load(name)).findings}
    assert {r.id for r in RULES} <= hit, {r.id for r in RULES} - hit


def test_obfuscation_raises_severity():
    rep = scan_server(load("poisoned_ja.json"))
    f = next(f for f in rep.findings if f.target == "tool:fullwidth" and f.rule == "EN001")
    assert f.obfuscated and f.severity == "high"


def test_config_checks():
    by = {}
    for f in check_config(load("claude_desktop_config.json")):
        by.setdefault(f.server, set()).add(f.rule)
    assert "CFG001" in by["fs"] and "CFG005" in by["fs"]
    assert "pinned" not in by
    assert "CFG002" in by["gh"]
    assert "gh_ok" not in by
    assert "CFG003" in by["remote"]
    assert "CFG004" in by["box"]


def test_token_shaped_value_in_args():
    # Built at run time so no token-shaped literal is stored in the repository.
    fake = "ghp_" + "x" * 36
    cfg = {"mcpServers": {"s": {"command": "example-server", "args": ["--token", fake]}}}
    assert {f.rule for f in check_config(cfg)} == {"CFG002"}


def test_baseline_detects_change():
    data = load("benign_ja.json")
    old = fingerprint(data)
    data["tools"][0]["description"] += " 追加の一文。"
    rules = {f.rule for f in diff_baseline(old, fingerprint(data))}
    assert rules == {"PIN002"}


def test_resources_keyed_by_uri():
    data = {"resources": [{"name": "doc", "uri": "file:///a"}, {"name": "doc", "uri": "file:///b"}]}
    old = fingerprint(data)
    data["resources"][0]["description"] = "changed"
    assert [f.target for f in diff_baseline(old, fingerprint(data))] == ["resource:file:///a"]


def test_timeout_not_extended_by_notifications():
    import time

    start = time.monotonic()
    with pytest.raises(TimeoutError):
        snapshot(sys.executable, [str(Path(__file__).parent / "noisy_server.py")], timeout=1.5)
    assert time.monotonic() - start < 6


def test_connect_failure_is_not_a_pass(tmp_path, capsys):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"mcpServers": {"missing": {"command": "lemonink-no-such-command-xyz", "args": []}}}))
    assert main(["config", str(cfg), "--connect", "--format", "json", "--timeout", "3"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["complete"] is False and out["errors"][0]["server"] == "missing"


def test_live_stdio():
    snap = snapshot(sys.executable, [str(Path(__file__).parent / "fake_server.py")], timeout=10)
    assert "JA002" in rules_for(scan_server(snap), "echo")


def test_cli_exit_codes(capsys):
    assert main(["tools", str(FX / "benign_ja.json")]) == 0
    assert main(["tools", str(FX / "poisoned_ja.json"), "--format", "json"]) == 1
    assert main(["tools", str(FX / "poisoned_ja.json"), "--format", "sarif", "--fail-on", "never"]) == 0
