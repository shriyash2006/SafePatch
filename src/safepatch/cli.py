from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .approval import create_approval, valid_approval
from .command_scanner import command_hash, parse_command, scan_command
from .hashing import sha256_json, sha256_text
from .models import Finding, Report
from .policy import POLICY_VERSION, build_decision, overall_decision
from .prompt_injection_scanner import scan_text as scan_prompt_injection
from .redaction import sanitize_output
from .repository_scanner import scan_repository
from .report import load as load_report
from .report import save as save_report
from .report import verify as verify_report
from .runner import execute, repository_hash
from .secret_scanner import scan_text as scan_secrets


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_output(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    return value


def _task_findings(task: str) -> list[Finding]:
    findings = scan_secrets(Path("task"), task) + scan_prompt_injection(Path("task"), task)
    return [replace(finding, source="task") for finding in findings]


def _commands_from_plan(plan: dict[str, Any]) -> list:
    values = plan.get("commands")
    if not isinstance(values, list) or not values:
        raise ValueError("The plan must contain a non-empty 'commands' list")
    return [parse_command(value, index) for index, value in enumerate(values)]


def _scan(args: argparse.Namespace) -> int:
    repository = Path(args.repo).expanduser().resolve()
    plan = _load_json(Path(args.plan).expanduser().resolve())
    task = args.task if args.task is not None else plan.get("task", "")
    if not isinstance(task, str) or not task.strip():
        raise ValueError("Provide a non-empty task with --task or in the plan JSON")
    commands = _commands_from_plan(plan)
    repository_scan = scan_repository(repository)
    findings = repository_scan.findings + _task_findings(task)
    decisions = []
    for command in commands:
        command_findings = scan_command(command, repository)
        decisions.append(build_decision(command.id, command_hash(command), command_findings))
    stored_plan = _sanitize({**plan, "task": task})
    report = Report(
        report_version="1",
        generated_at=_now(),
        repository_path=str(repository),
        task=sanitize_output(task),
        task_hash=sha256_text(task),
        plan_hash=sha256_json(plan),
        plan=stored_plan,
        policy_version=POLICY_VERSION,
        scanned_files=repository_scan.files,
        findings=findings,
        command_decisions=decisions,
        limitations=[
            "SafePatch performs deterministic static checks; it does not prove that code is safe.",
            "Commands are never executed by scan. Review and approve commands explicitly before running them.",
            "Network access, package lifecycle scripts, containers, and external systems require human review.",
        ],
    )
    report_path = Path(args.report).expanduser()
    markdown_path = Path(args.markdown).expanduser() if args.markdown else report_path.with_suffix(".md")
    save_report(report, report_path, markdown_path)
    decision = overall_decision(findings, decisions)
    print(f"SafePatch scan: {decision.upper()}")
    print(f"Report: {report_path}")
    print(f"Markdown: {markdown_path}")
    print(f"Scanned files: {len(repository_scan.files)}")
    print(f"Findings: {len(findings)}; blocked commands: {sum(item.decision == 'block' for item in decisions)}")
    return 2 if decision == "block" else 0


def _find_decision(report: Report, command_id: str):
    for decision in report.command_decisions:
        if decision.command_id == command_id:
            return decision
    raise ValueError(f"Command not found in report: {command_id}")


def _current_repository_hash(report: Report) -> str:
    current = scan_repository(Path(report.repository_path))
    return repository_hash(current.files)


def _approve(args: argparse.Namespace) -> int:
    report_path = Path(args.report).expanduser()
    report = load_report(report_path)
    if not verify_report(report):
        raise ValueError("Report integrity check failed; rescan before approving anything")
    decision = _find_decision(report, args.command)
    if decision.decision == "block":
        print(f"Command {args.command} is blocked and cannot be approved.", file=sys.stderr)
        return 2
    command = next(command for command in _commands_from_plan(report.plan) if command.id == args.command)
    if command_hash(command) != decision.command_hash:
        raise ValueError("The stored command does not match its recorded hash")
    current_hash = _current_repository_hash(report)
    expected_hash = repository_hash(report.scanned_files)
    if current_hash != expected_hash:
        raise ValueError("Repository changed since the scan; create a fresh scan before approving")
    if not args.yes:
        print(f"Command: {' '.join(command.argv)}")
        print(f"Working directory: {command.cwd}")
        print(f"Reason: {command.reason or 'No reason provided'}")
        print(f"Policy decision: {decision.decision.upper()}")
        for finding in decision.findings:
            print(f"- {finding.severity.upper()}: {finding.message}")
        answer = input("Approve this exact command? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            report.approval_events.append({"event": "approval", "command_id": args.command, "status": "denied", "created_at": _now()})
            save_report(report, report_path, report_path.with_suffix(".md"))
            print("Approval denied.")
            return 1
    event = create_approval(report.plan_hash, decision.command_hash, current_hash, args.command)
    report.approval_events.append(event)
    decision.approval_status = "approved"
    save_report(report, report_path, report_path.with_suffix(".md"))
    print(f"Approved {args.command}. Approval token: {event['approval_token']}")
    return 0


def _run(args: argparse.Namespace) -> int:
    report_path = Path(args.report).expanduser()
    report = load_report(report_path)
    if not verify_report(report):
        raise ValueError("Report integrity check failed; rescan before running anything")
    decision = _find_decision(report, args.command)
    if decision.decision == "block":
        print(f"Command {args.command} is blocked and cannot run.", file=sys.stderr)
        return 2
    command = next(command for command in _commands_from_plan(report.plan) if command.id == args.command)
    if command_hash(command) != decision.command_hash:
        raise ValueError("The stored command does not match its recorded hash")
    current_hash = _current_repository_hash(report)
    if current_hash != repository_hash(report.scanned_files):
        raise ValueError("Repository changed since the scan; create a fresh scan before running")
    if decision.decision == "review":
        approvals = [event for event in report.approval_events if event.get("command_id") == args.command and event.get("status") == "approved"]
        if not approvals or not valid_approval(approvals[-1], report.plan_hash, decision.command_hash, current_hash):
            raise ValueError("This command requires a valid approval for the exact current plan and repository")
    result = execute(command, Path(report.repository_path), timeout=args.timeout)
    decision.execution = result
    report.execution_results.append(result)
    save_report(report, report_path, report_path.with_suffix(".md"))
    print(f"Command {args.command}: {result['status'].upper()}")
    return 0 if result["status"] == "confirmed" else 1


def _verify(args: argparse.Namespace) -> int:
    report = load_report(Path(args.report).expanduser())
    valid = verify_report(report)
    print("Report integrity: VALID" if valid else "Report integrity: INVALID")
    return 0 if valid else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safepatch", description="Safety gate and proof report for AI coding agents")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    scan = subparsers.add_parser("scan", help="Scan a repository and command plan without executing commands")
    scan.add_argument("--repo", required=True, help="Repository directory to scan")
    scan.add_argument("--plan", required=True, help="JSON task plan")
    scan.add_argument("--task", help="Override the task from the plan")
    scan.add_argument("--report", default="artifacts/report.json", help="JSON report path")
    scan.add_argument("--markdown", help="Markdown report path")
    scan.set_defaults(handler=_scan)

    approve = subparsers.add_parser("approve", help="Approve one reviewable command after showing its controls")
    approve.add_argument("--report", required=True)
    approve.add_argument("--command", required=True)
    approve.add_argument("--yes", action="store_true", help="Approve non-interactively")
    approve.set_defaults(handler=_approve)

    run = subparsers.add_parser("run", help="Run one scanned command after policy and approval checks")
    run.add_argument("--report", required=True)
    run.add_argument("--command", required=True)
    run.add_argument("--timeout", type=int, default=30)
    run.set_defaults(handler=_run)

    verify = subparsers.add_parser("verify", help="Verify a report's tamper-evident hash")
    verify.add_argument("--report", required=True)
    verify.set_defaults(handler=_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, ValueError, json.JSONDecodeError, StopIteration) as exc:
        print(f"SafePatch error: {exc}", file=sys.stderr)
        return 1
