from __future__ import annotations

import json
from pathlib import Path

from .hashing import sha256_json
from .models import Report


def finalize(report: Report) -> Report:
    report.report_sha256 = sha256_json(report.to_dict(include_hash=False))
    return report


def save(report: Report, json_path: Path, markdown_path: Path | None = None) -> None:
    finalize(report)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if markdown_path:
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(to_markdown(report), encoding="utf-8")


def load(path: Path) -> Report:
    value = json.loads(path.read_text(encoding="utf-8"))
    report = Report(
        report_version=value["report_version"],
        generated_at=value["generated_at"],
        repository_path=value["repository_path"],
        task=value["task"],
        task_hash=value["task_hash"],
        plan_hash=value["plan_hash"],
        plan=value["plan"],
        policy_version=value["policy_version"],
        scanned_files=value["scanned_files"],
        findings=[],
        command_decisions=[],
        approval_events=value.get("approval_events", []),
        execution_results=value.get("execution_results", []),
        limitations=value.get("limitations", []),
        report_sha256=value.get("report_sha256", ""),
    )
    from .models import CommandDecision, Finding

    report.findings = [Finding(**item) for item in value.get("findings", [])]
    report.command_decisions = [
        CommandDecision(
            command_id=item["command_id"],
            decision=item["decision"],
            findings=[Finding(**finding) for finding in item.get("findings", [])],
            command_hash=item["command_hash"],
            approval_status=item.get("approval_status", "not_required"),
            execution=item.get("execution"),
        )
        for item in value.get("command_decisions", [])
    ]
    return report


def verify(report: Report) -> bool:
    return report.report_sha256 == sha256_json(report.to_dict(include_hash=False))


def to_markdown(report: Report) -> str:
    blocked = sum(decision.decision == "block" for decision in report.command_decisions)
    review = sum(decision.decision == "review" for decision in report.command_decisions)
    lines = [
        "# SafePatch proof report",
        "",
        f"- **Repository:** `{report.repository_path}`",
        f"- **Task:** {report.task}",
        f"- **Policy:** `{report.policy_version}`",
        f"- **Plan hash:** `{report.plan_hash}`",
        f"- **Report hash:** `{report.report_sha256}`",
        f"- **Commands blocked:** {blocked}",
        f"- **Commands requiring review:** {review}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings and not any(decision.findings for decision in report.command_decisions):
        lines.append("No findings were reported.")
    for finding in report.findings + [finding for decision in report.command_decisions for finding in decision.findings]:
        location = f" (`{finding.path}:{finding.line}`)" if finding.path and finding.line else f" (`{finding.path}`)" if finding.path else ""
        lines.extend(
            [
                f"### {finding.severity.upper()}: {finding.rule}",
                f"- **Category:** {finding.category}",
                f"- **Source:** {finding.source}{location}",
                f"- **Message:** {finding.message}",
                f"- **Recommendation:** {finding.recommendation}",
                "",
            ]
        )
    lines.extend(["## Command decisions", ""])
    for decision in report.command_decisions:
        lines.append(
            f"- `{decision.command_id}`: **{decision.decision}**; approval `{decision.approval_status}`; hash `{decision.command_hash}`"
        )
    lines.extend(["", "## Execution results", ""])
    if report.execution_results:
        for result in report.execution_results:
            lines.append(f"- `{result['command_id']}`: **{result['status']}** (exit code: `{result.get('exit_code')}`)")
    else:
        lines.append("No commands were executed by this scan.")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines.append("")
    return "\n".join(lines)
