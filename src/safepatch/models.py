from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Severity = Literal["low", "medium", "high", "critical"]
Decision = Literal["allow", "review", "block"]


@dataclass(frozen=True)
class Finding:
    id: str
    category: str
    severity: Severity
    source: str
    rule: str
    message: str
    path: str | None = None
    line: int | None = None
    evidence: str | None = None
    evidence_hash: str | None = None
    recommendation: str = "Review this finding before continuing."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CommandSpec:
    id: str
    argv: list[str]
    cwd: str = "."
    reason: str = ""
    shell: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CommandDecision:
    command_id: str
    decision: Decision
    findings: list[Finding] = field(default_factory=list)
    command_hash: str = ""
    approval_status: str = "not_required"
    execution: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["findings"] = [finding.to_dict() for finding in self.findings]
        return value


@dataclass
class Report:
    report_version: str
    generated_at: str
    repository_path: str
    task: str
    task_hash: str
    plan_hash: str
    plan: dict[str, Any]
    policy_version: str
    scanned_files: list[dict[str, Any]]
    findings: list[Finding]
    command_decisions: list[CommandDecision]
    approval_events: list[dict[str, Any]] = field(default_factory=list)
    execution_results: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    report_sha256: str = ""

    def to_dict(self, include_hash: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "report_version": self.report_version,
            "generated_at": self.generated_at,
            "repository_path": self.repository_path,
            "task": self.task,
            "task_hash": self.task_hash,
            "plan_hash": self.plan_hash,
            "plan": self.plan,
            "policy_version": self.policy_version,
            "scanned_files": self.scanned_files,
            "findings": [finding.to_dict() for finding in self.findings],
            "command_decisions": [decision.to_dict() for decision in self.command_decisions],
            "approval_events": self.approval_events,
            "execution_results": self.execution_results,
            "limitations": self.limitations,
        }
        if include_hash:
            value["report_sha256"] = self.report_sha256
        return value
