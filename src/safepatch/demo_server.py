from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .cli import main as cli_main
from .policy import overall_decision
from .report import load as load_report
from .report import verify as verify_report


SCENARIOS = {
    "clean": "clean_plan.json",
    "risky": "risky_plan.json",
}


@dataclass
class DemoSession:
    scenario: str
    report_path: Path
    output: str = ""


class DemoApplication:
    """Small, allowlisted application layer used by the local browser demo."""

    def __init__(self, project_root: Path | None = None) -> None:
        self.project_root = (project_root or Path(__file__).resolve().parents[2]).resolve()
        self.demo_repo = self.project_root / "examples" / "demo_repo"
        self.plans = self.project_root / "examples"
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="safepatch-demo-")
        self.report_directory = Path(self._temporary_directory.name)
        self.sessions: dict[str, DemoSession] = {}
        self.lock = threading.RLock()

    def close(self) -> None:
        self._temporary_directory.cleanup()

    def _plan_path(self, scenario: str) -> Path:
        try:
            filename = SCENARIOS[scenario]
        except KeyError as exc:
            raise ValueError("Scenario must be 'clean' or 'risky'") from exc
        return self.plans / filename

    @staticmethod
    def _invoke(arguments: list[str]) -> tuple[int, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(arguments)
        output = stdout.getvalue()
        if stderr.getvalue():
            output += stderr.getvalue()
        return exit_code, output.strip()

    @staticmethod
    def _command_payload(report: Any, decision: Any) -> dict[str, Any]:
        commands = report.plan.get("commands", [])
        command = next((item for item in commands if item.get("id") == decision.command_id), {})
        return {
            "command_id": decision.command_id,
            "argv": command.get("argv", []),
            "cwd": command.get("cwd", "."),
            "reason": command.get("reason", ""),
            "decision": decision.decision,
            "approval_status": decision.approval_status,
            "command_hash": decision.command_hash,
            "findings": [finding.to_dict() for finding in decision.findings],
            "execution": decision.execution,
        }

    def _payload(self, scan_id: str, session: DemoSession, output: str = "") -> dict[str, Any]:
        report = load_report(session.report_path)
        findings = report.findings + [
            finding
            for decision in report.command_decisions
            for finding in decision.findings
        ]
        return {
            "scan_id": scan_id,
            "scenario": session.scenario,
            "task": report.task,
            "decision": overall_decision(report.findings, report.command_decisions),
            "report_hash": report.report_sha256,
            "plan_hash": report.plan_hash,
            "report_valid": verify_report(report),
            "scanned_files": len(report.scanned_files),
            "findings_count": len(findings),
            "blocked_commands": sum(item.decision == "block" for item in report.command_decisions),
            "review_commands": sum(item.decision == "review" for item in report.command_decisions),
            "findings": [finding.to_dict() for finding in findings],
            "commands": [self._command_payload(report, item) for item in report.command_decisions],
            "execution_results": report.execution_results,
            "output": output or session.output,
        }

    def scan(self, scenario: str) -> dict[str, Any]:
        with self.lock:
            plan_path = self._plan_path(scenario)
            scan_id = uuid.uuid4().hex
            report_path = self.report_directory / f"{scan_id}.json"
            arguments = [
                "scan",
                "--repo",
                str(self.demo_repo),
                "--plan",
                str(plan_path),
                "--report",
                str(report_path),
            ]
            exit_code, output = self._invoke(arguments)
            if not report_path.exists():
                raise RuntimeError(output or "SafePatch did not create a report")
            session = DemoSession(scenario=scenario, report_path=report_path, output=output)
            self.sessions[scan_id] = session
            payload = self._payload(scan_id, session)
            payload["cli_exit_code"] = exit_code
            return payload

    def _session(self, scan_id: str) -> DemoSession:
        try:
            return self.sessions[scan_id]
        except KeyError as exc:
            raise ValueError("Scan not found; run a new demo scan") from exc

    def approve(self, scan_id: str, command_id: str) -> dict[str, Any]:
        with self.lock:
            session = self._session(scan_id)
            exit_code, output = self._invoke(
                [
                    "approve",
                    "--report",
                    str(session.report_path),
                    "--command",
                    command_id,
                    "--yes",
                ]
            )
            session.output = output
            payload = self._payload(scan_id, session)
            payload["cli_exit_code"] = exit_code
            return payload

    def run(self, scan_id: str, command_id: str) -> dict[str, Any]:
        with self.lock:
            session = self._session(scan_id)
            exit_code, output = self._invoke(
                [
                    "run",
                    "--report",
                    str(session.report_path),
                    "--command",
                    command_id,
                ]
            )
            session.output = output
            payload = self._payload(scan_id, session)
            payload["cli_exit_code"] = exit_code
            return payload

    def verify(self, scan_id: str) -> dict[str, Any]:
        with self.lock:
            session = self._session(scan_id)
            report = load_report(session.report_path)
            return {
                "scan_id": scan_id,
                "valid": verify_report(report),
                "report_hash": report.report_sha256,
            }


class DemoRequestHandler(BaseHTTPRequestHandler):
    server: "SafePatchDemoServer"

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the terminal focused on the URL and lifecycle messages.
        return

    def _send_json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Asset not found"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 16_384:
            raise ValueError("Request body is too large")
        value = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object")
        return value

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_file(self.server.asset_directory / "index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._send_file(self.server.asset_directory / "app.js", "text/javascript; charset=utf-8")
            return
        if parsed.path == "/styles.css":
            self._send_file(self.server.asset_directory / "styles.css", "text/css; charset=utf-8")
            return
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "scans"]:
            try:
                self._send_json(HTTPStatus.OK, self.server.application._payload(parts[2], self.server.application._session(parts[2])))
            except (OSError, ValueError, KeyError) as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            return
        if len(parts) == 4 and parts[:2] == ["api", "scans"] and parts[3] == "verify":
            try:
                self._send_json(HTTPStatus.OK, self.server.application.verify(parts[2]))
            except (OSError, ValueError, KeyError) as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parts = [part for part in urlparse(self.path).path.split("/") if part]
        try:
            body = self._read_json()
            if parts == ["api", "scans"]:
                result = self.server.application.scan(str(body.get("scenario", "")))
            elif len(parts) == 4 and parts[:2] == ["api", "scans"] and parts[3] in {"approve", "run"}:
                command_id = body.get("command_id")
                if not isinstance(command_id, str) or not command_id:
                    raise ValueError("command_id is required")
                action = self.server.application.approve if parts[3] == "approve" else self.server.application.run
                result = action(parts[2], command_id)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                return
            self._send_json(HTTPStatus.OK, result)
        except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


class SafePatchDemoServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], application: DemoApplication) -> None:
        self.application = application
        self.asset_directory = Path(__file__).with_name("web")
        super().__init__(address, DemoRequestHandler)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    application = DemoApplication()
    server = SafePatchDemoServer((host, port), application)
    print(f"SafePatch demo: http://{host}:{server.server_port}")
    print("Press Ctrl+C to stop the demo server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SafePatch demo.")
    finally:
        server.server_close()
        application.close()
