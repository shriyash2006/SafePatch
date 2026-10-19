from __future__ import annotations

from .models import CommandDecision, Finding


POLICY_VERSION = "2026.10.1"


def decision_for(findings: list[Finding]) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "block"
    if any(finding.severity in {"high", "medium"} for finding in findings):
        return "review"
    return "allow"


def build_decision(command_id: str, command_hash: str, findings: list[Finding]) -> CommandDecision:
    decision = decision_for(findings)
    approval_status = "blocked" if decision == "block" else "required" if decision == "review" else "not_required"
    return CommandDecision(
        command_id=command_id,
        decision=decision,  # type: ignore[arg-type]
        findings=findings,
        command_hash=command_hash,
        approval_status=approval_status,
    )


def overall_decision(findings: list[Finding], command_decisions: list[CommandDecision]) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "block"
    if any(decision.decision == "block" for decision in command_decisions):
        return "block"
    if any(finding.severity in {"high", "medium"} for finding in findings):
        return "review"
    if any(decision.decision == "review" for decision in command_decisions):
        return "review"
    return "allow"
