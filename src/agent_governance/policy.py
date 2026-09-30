"""Policy engine: load YAML policies and evaluate agent tool calls.

Supported YAML subset (kept deliberately small so the parser stays honest):
  - a top-level ``rules:`` key holding a list of rules
  - each rule is a mapping with ``name``, ``action``, and ``when``
  - ``when`` is a flow mapping such as ``{tool: "shell", args_match: "rm -rf"}``
  - scalars may be plain, single-quoted, or double-quoted (with escapes)
  - ``#`` comments and blank lines are ignored

No third-party YAML library is required.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

VALID_ACTIONS = ("allow", "deny", "require_approval")


@dataclass
class Decision:
    """Result of evaluating one tool call against the policy set."""

    allowed: bool
    action: str  # one of "allow", "deny", "require_approval"
    rule_name: str | None
    reason: str


# ---------------------------------------------------------------------------
# Minimal YAML subset parser
# ---------------------------------------------------------------------------

_DOUBLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "b": "\b",
    "f": "\f",
    '"': '"',
    "\\": "\\",
    "/": "/",
    " ": " ",
    "_": " ",
}


def _unescape_double_quoted(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(_DOUBLE_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and in_double:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                return line[:i]
        i += 1
    return line


def _split_top_level(text: str, sep: str) -> list[str]:
    """Split on ``sep`` ignoring separators inside quotes or nested braces."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_single = in_double = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and in_double:
            current.append(text[i : i + 2])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
            elif ch == sep and depth == 0:
                parts.append("".join(current))
                current = []
                i += 1
                continue
        current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def _parse_scalar(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return _unescape_double_quoted(text[1:-1])
    if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
        return text[1:-1].replace("''", "'")
    return text


def _parse_value(text: str):
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        result = {}
        for part in _split_top_level(text[1:-1], ","):
            key, _, value = part.partition(":")
            result[key.strip()] = _parse_value(value)
        return result
    return _parse_scalar(text)


def parse_policy_yaml(text: str) -> dict:
    """Parse the supported YAML subset into ``{"rules": [...]}``."""
    rules: list[dict] = []
    current: dict | None = None
    in_rules = False
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            in_rules = stripped == "rules:"
            continue
        if not in_rules:
            continue
        if stripped.startswith("- "):
            current = {}
            rules.append(current)
            rest = stripped[2:].strip()
            if rest:
                key, _, value = rest.partition(":")
                current[key.strip()] = _parse_value(value)
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            current[key.strip()] = _parse_value(value)
    return {"rules": rules}


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Evaluate agent tool calls against an ordered list of rules.

    The first matching rule wins. If no rule matches, the call is allowed.
    """

    def __init__(self, rules: list[dict]):
        self.rules = [self._validate(rule) for rule in rules]

    @classmethod
    def from_yaml(cls, text: str) -> "PolicyEngine":
        return cls(parse_policy_yaml(text)["rules"])

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> "PolicyEngine":
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def from_directory(cls, directory: str | Path) -> "PolicyEngine":
        rules: list[dict] = []
        for path in sorted(Path(directory).glob("*.yaml")):
            rules.extend(parse_policy_yaml(path.read_text(encoding="utf-8"))["rules"])
        return cls(rules)

    @staticmethod
    def _validate(rule: dict) -> dict:
        if not isinstance(rule, dict):
            raise ValueError(f"Rule must be a mapping, got {rule!r}")
        for field in ("name", "action", "when"):
            if field not in rule:
                raise ValueError(f"Rule {rule!r} is missing required field '{field}'")
        if rule["action"] not in VALID_ACTIONS:
            raise ValueError(
                f"Rule '{rule['name']}' has invalid action '{rule['action']}'; "
                f"expected one of {VALID_ACTIONS}"
            )
        if not isinstance(rule["when"], dict):
            raise ValueError(f"Rule '{rule['name']}' field 'when' must be a mapping")
        pattern = rule["when"].get("args_match")
        if pattern:
            try:
                rule = dict(rule)
                rule["_compiled"] = re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"Rule '{rule['name']}' has an invalid regex: {exc}"
                ) from exc
        return rule

    @staticmethod
    def _args_to_text(args) -> str:
        if isinstance(args, str):
            return args
        return json.dumps(args, sort_keys=True, default=str)

    def evaluate(self, tool: str, args) -> Decision:
        """Evaluate a tool call. Returns a Decision; first matching rule wins."""
        args_text = self._args_to_text(args)
        for rule in self.rules:
            when = rule["when"]
            if "tool" in when and when["tool"] != tool:
                continue
            compiled = rule.get("_compiled")
            if compiled is not None and not compiled.search(args_text):
                continue
            return self._decide(rule, tool)
        return Decision(
            allowed=True,
            action="allow",
            rule_name=None,
            reason="No policy rule matched; default allow",
        )

    @staticmethod
    def _decide(rule: dict, tool: str) -> Decision:
        name = rule["name"]
        action = rule["action"]
        pattern = rule["when"].get("args_match")
        if action == "allow":
            return Decision(True, "allow", name, f"Allowed by rule '{name}'")
        if action == "deny":
            detail = (
                f"args matched pattern '{pattern}'"
                if pattern
                else f"tool '{tool}' is blocked"
            )
            return Decision(False, "deny", name, f"Denied by rule '{name}': {detail}")
        return Decision(
            False,
            "require_approval",
            name,
            f"Rule '{name}' requires human approval for tool '{tool}'",
        )
