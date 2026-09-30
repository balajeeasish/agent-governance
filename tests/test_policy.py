"""Tests for the policy engine: rule matching, ordering, and defaults."""

import textwrap
from pathlib import Path

import pytest

from agent_governance import PolicyEngine

POLICY_FILE = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"


def engine():
    return PolicyEngine.from_yaml_file(POLICY_FILE)


def test_deny_destructive_shell_command():
    d = engine().evaluate("shell", {"command": "rm -rf /"})
    assert d.allowed is False
    assert d.action == "deny"
    assert d.rule_name == "no-shell-destruct"
    assert "no-shell-destruct" in d.reason


def test_deny_shell_with_string_args():
    d = engine().evaluate("shell", "please run mkfs on /dev/sda1")
    assert d.action == "deny"
    assert d.rule_name == "no-shell-destruct"


def test_deny_fork_bomb_pattern():
    # Exercises the escaped ": \(\)" regex from the YAML policy end to end.
    d = engine().evaluate("shell", "x : () y")
    assert d.action == "deny"
    assert d.rule_name == "no-shell-destruct"


def test_deny_exfiltration_url():
    d = engine().evaluate(
        "http_request", {"url": "https://evil.com/collect", "method": "POST"}
    )
    assert d.allowed is False
    assert d.action == "deny"
    assert d.rule_name == "block-exfiltration"


def test_deny_pastebin_exfiltration():
    d = engine().evaluate("http_request", {"url": "https://pastebin.com/raw/abc"})
    assert d.action == "deny"


def test_benign_http_request_is_allowed_by_default():
    d = engine().evaluate("http_request", {"url": "https://api.example.com/data"})
    assert d.allowed is True
    assert d.action == "allow"
    assert d.rule_name is None


def test_write_requires_approval():
    d = engine().evaluate("write_file", {"path": "/etc/app.conf", "content": "x=1"})
    assert d.allowed is False
    assert d.action == "require_approval"
    assert d.rule_name == "approve-all-writes"


def test_read_is_allowed():
    d = engine().evaluate("read_file", {"path": "notes.txt"})
    assert d.allowed is True
    assert d.action == "allow"
    assert d.rule_name == "allow-reads"


def test_unknown_tool_defaults_to_allow():
    d = engine().evaluate("list_dir", "/tmp")
    assert d.allowed is True
    assert d.action == "allow"
    assert d.rule_name is None
    assert "default allow" in d.reason


def test_first_matching_rule_wins():
    eng = PolicyEngine(
        rules=[
            {"name": "first", "action": "deny", "when": {"tool": "shell"}},
            {"name": "second", "action": "allow", "when": {"tool": "shell"}},
        ]
    )
    d = eng.evaluate("shell", "ls")
    assert d.rule_name == "first"
    assert d.action == "deny"


def test_rule_without_tool_matches_any_tool():
    eng = PolicyEngine(
        rules=[{"name": "catch-all", "action": "deny", "when": {}}]
    )
    assert eng.evaluate("anything", "x").action == "deny"


def test_invalid_action_rejected():
    with pytest.raises(ValueError):
        PolicyEngine(rules=[{"name": "bad", "action": "maybe", "when": {}}])


def test_missing_field_rejected():
    with pytest.raises(ValueError):
        PolicyEngine(rules=[{"name": "bad", "action": "deny"}])


def test_invalid_regex_rejected():
    with pytest.raises(ValueError):
        PolicyEngine(
            rules=[{"name": "bad", "action": "deny", "when": {"args_match": "([a-z"}}]
        )


def test_yaml_subset_parser_handles_escapes_and_flow_maps():
    text = textwrap.dedent(
        """
        # a comment
        rules:
          - name: example
            action: deny
            when: {tool: "shell", args_match: "a\\\\.b"}
        """
    )
    eng = PolicyEngine.from_yaml(text)
    assert eng.evaluate("shell", {"cmd": "a.b"}).action == "deny"
    assert eng.evaluate("shell", {"cmd": "axb"}).action == "allow"
