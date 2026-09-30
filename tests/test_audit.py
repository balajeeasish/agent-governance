"""Tests for the audit logger: JSONL format, redaction, and tailing."""

import json
from datetime import datetime

from agent_governance import AuditLogger, Decision


def _decision(action="deny", rule="no-shell-destruct"):
    return Decision(
        allowed=action == "allow",
        action=action,
        rule_name=rule,
        reason="test",
    )


def test_log_appends_jsonl_with_required_fields(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log("shell", {"command": "rm -rf /"}, _decision())
    logger.close()

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool"] == "shell"
    assert entry["decision"] == "deny"
    assert entry["rule"] == "no-shell-destruct"
    assert entry["args_redacted"] == {"command": "rm -rf /"}
    # ts must be a parseable ISO-8601 timestamp
    datetime.fromisoformat(entry["ts"])


def test_log_redacts_secret_values(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log(
        "http_request",
        {"url": "https://api.example.com", "api_key": "sk-live-12345"},
        _decision(action="allow", rule="allow-reads"),
    )
    logger.close()

    entry = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert entry["args_redacted"]["api_key"] == "***REDACTED***"
    assert entry["args_redacted"]["url"] == "https://api.example.com"


def test_log_redacts_bearer_tokens_in_strings(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log("shell", "curl -H 'Authorization: Bearer abc123' x", _decision())
    logger.close()

    entry = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert "abc123" not in entry["args_redacted"]
    assert "***REDACTED***" in entry["args_redacted"]


def test_log_is_append_only(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.log("read_file", "a.txt", _decision(action="allow", rule="allow-reads"))
    logger.log("shell", "rm -rf /", _decision())
    logger.close()

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tool"] == "read_file"
    assert json.loads(lines[1])["tool"] == "shell"


def test_tail_returns_last_n_entries(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    for i in range(5):
        logger.log(f"tool_{i}", {}, _decision())
    logger.close()

    entries = AuditLogger(path).tail(2)
    assert [e["tool"] for e in entries] == ["tool_3", "tool_4"]
    AuditLogger(path).close()


def test_context_manager_closes_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    with AuditLogger(path) as logger:
        logger.log("read_file", "a.txt", _decision(action="allow", rule=None))
    assert path.read_text(encoding="utf-8").strip() != ""
