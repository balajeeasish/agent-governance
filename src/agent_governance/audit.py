"""Append-only JSONL audit logging for agent tool calls."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

REDACTED = "***REDACTED***"

_SENSITIVE_KEYS = (
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "auth",
    "credential",
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]+")


def redact(value):
    """Recursively mask secrets in tool args before they reach the audit log."""
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if any(s in str(key).lower() for s in _SENSITIVE_KEYS)
                else redact(val)
            )
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER_RE.sub(r"\1" + REDACTED, value)
    return value


class AuditLogger:
    """Append-only JSONL logger.

    Each line carries: ts, tool, args_redacted, decision, rule.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")

    def log(self, tool: str, args, decision) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "args_redacted": redact(args),
            "decision": decision.action,
            "rule": decision.rule_name,
        }
        self._fh.write(json.dumps(entry) + "\n")
        self._fh.flush()
        return entry

    def tail(self, n: int = 10) -> list[dict]:
        """Return the last ``n`` audit entries as dicts."""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-n:] if line.strip()]

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
