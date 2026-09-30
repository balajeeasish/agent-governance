"""Human review gates for agent tool calls that require approval."""

from __future__ import annotations


class ApprovalGate:
    """Route a tool call through a human (or programmatic) approver.

    - ``allow`` decisions pass without consulting the approver.
    - ``deny`` decisions are blocked without consulting the approver.
    - ``require_approval`` decisions are put to the approver.
    """

    def __init__(self, approver):
        self.approver = approver

    def request(self, tool: str, args, decision) -> bool:
        if decision.action == "allow":
            return True
        if decision.action == "deny":
            return False
        return bool(self.approver(tool, args, decision))


class CLIApprover:
    """Prompt for approval on stdin. Anything other than y/yes declines."""

    def __call__(self, tool: str, args, decision) -> bool:
        answer = input(f"Approve {tool} with args {args}? [y/N] ").strip().lower()
        return answer in ("y", "yes")


class CallbackApprover:
    """Wrap a plain function ``(tool, args, decision) -> bool`` as an approver."""

    def __init__(self, func):
        self.func = func

    def __call__(self, tool: str, args, decision) -> bool:
        return bool(self.func(tool, args, decision))
