from __future__ import annotations

import re
import shlex
from pathlib import Path

from .hashing import sha256_json
from .models import CommandSpec, Finding
from .redaction import sanitize_output


SHELL_OPERATORS = re.compile(r"(?:&&|\|\||[|;&<>`]|\$\(|\n)")
DESTRUCTIVE_BINARIES = {"rm", "rmdir", "mkfs", "fdisk", "format", "dd", "shred"}
PRIVILEGE_BINARIES = {"sudo", "doas", "su"}
REMOTE_BINARIES = {"curl", "wget", "fetch"}
NETWORK_BINARIES = REMOTE_BINARIES | {"ssh", "scp", "sftp", "nc", "netcat"}
SAFE_LOCAL_PREFIXES = {
    "python",
    "python3",
    "pytest",
    "unittest",
    "node",
    "npm",
    "yarn",
    "pnpm",
    "go",
    "cargo",
    "ruby",
    "bundle",
    "make",
    "git",
}


def parse_command(value: object, index: int) -> CommandSpec:
    if not isinstance(value, dict):
        raise ValueError(f"Command {index + 1} must be an object")
    command_id = value.get("id", f"command-{index + 1}")
    argv = value.get("argv")
    if not isinstance(command_id, str) or not command_id.strip():
        raise ValueError(f"Command {index + 1} has an invalid id")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError(f"Command {command_id} must provide a non-empty argv list of strings")
    cwd = value.get("cwd", ".")
    reason = value.get("reason", "")
    shell = value.get("shell")
    if not isinstance(cwd, str) or not isinstance(reason, str):
        raise ValueError(f"Command {command_id} has invalid cwd or reason")
    if shell is not None and not isinstance(shell, str):
        raise ValueError(f"Command {command_id} has an invalid shell value")
    return CommandSpec(id=command_id, argv=argv, cwd=cwd, reason=reason, shell=shell)


def command_hash(command: CommandSpec) -> str:
    return sha256_json(command.to_dict())


def _finding(command: CommandSpec, rule: str, severity: str, message: str, recommendation: str) -> Finding:
    return Finding(
        id=f"command-{command.id}-{rule}",
        category="command",
        severity=severity,  # type: ignore[arg-type]
        source="plan",
        rule=rule,
        message=message,
        evidence=sanitize_output(" ".join(shlex.quote(part) for part in command.argv[:8])),
        evidence_hash=command_hash(command),
        recommendation=recommendation,
    )


def scan_command(command: CommandSpec, repository: Path) -> list[Finding]:
    findings: list[Finding] = []
    if command.shell is not None:
        findings.append(
            _finding(
                command,
                "shell_string",
                "critical",
                "Shell command strings are not executable in SafePatch because their behavior is ambiguous.",
                "Convert the command into an explicit argv list and review each argument.",
            )
        )
    if any(SHELL_OPERATORS.search(argument) for argument in command.argv):
        findings.append(
            _finding(
                command,
                "shell_operator",
                "critical",
                "Shell operators or command substitution were found in a structured argument.",
                "Remove shell syntax and execute a single explicit program with argv.",
            )
        )

    cwd = (repository / command.cwd).resolve()
    try:
        cwd.relative_to(repository.resolve())
    except ValueError:
        findings.append(
            _finding(
                command,
                "cwd_outside_repository",
                "critical",
                "The command working directory is outside the protected repository.",
                "Use a working directory inside the repository.",
            )
        )
    if not cwd.exists() or not cwd.is_dir():
        findings.append(
            _finding(
                command,
                "cwd_missing",
                "high",
                "The command working directory does not exist or is not a directory.",
                "Choose an existing repository directory.",
            )
        )

    executable = Path(command.argv[0]).name.lower()
    arguments = " ".join(command.argv[1:])
    if executable in DESTRUCTIVE_BINARIES:
        findings.append(
            _finding(
                command,
                "destructive_command",
                "critical",
                f"{executable} can irreversibly destroy data.",
                "Do not grant an AI agent permission to run destructive commands.",
            )
        )
    if executable in PRIVILEGE_BINARIES:
        findings.append(
            _finding(
                command,
                "privilege_escalation",
                "critical",
                f"{executable} requests elevated privileges.",
                "Remove privilege escalation and use a least-privilege workflow.",
            )
        )
    if executable in REMOTE_BINARIES:
        piped_to_shell = bool(re.search(r"(?i)\b(?:sh|bash|zsh|fish|powershell)\b", arguments))
        findings.append(
            _finding(
                command,
                "remote_script" if piped_to_shell else "network_download",
                "critical" if piped_to_shell else "medium",
                "A remote download is being requested; remote scripts are blocked by default." if piped_to_shell else "The command accesses the network and downloads remote content.",
                "Use a pinned, reviewed local dependency or request a human review.",
            )
        )
    if executable in {"ssh", "scp", "sftp", "nc", "netcat"}:
        findings.append(
            _finding(
                command,
                "external_side_effect",
                "high",
                "The command can communicate with or modify an external system.",
                "Keep the first run local and require explicit human review for external access.",
            )
        )
    if executable == "git" and any(part in {"push", "reset", "clean"} for part in command.argv[1:]):
        findings.append(
            _finding(
                command,
                "git_side_effect",
                "high",
                "This Git operation can publish changes or remove local work.",
                "Review the exact diff and keep the operation in a temporary branch.",
            )
        )
    if executable in {"docker", "podman"}:
        findings.append(
            _finding(
                command,
                "container_control",
                "high",
                "Container commands can access the host or network depending on their flags.",
                "Use a restricted container and require review before execution.",
            )
        )
    if executable in {"npm", "pnpm", "yarn", "pip", "pip3", "poetry", "cargo"} and any(
        part in {"install", "add", "update", "upgrade"} for part in command.argv[1:]
    ):
        findings.append(
            _finding(
                command,
                "dependency_install",
                "medium",
                "Dependency installation may execute package lifecycle scripts or change the environment.",
                "Review the lockfile and package source before approving installation.",
            )
        )
    if executable in {"env", "printenv", "set"} or any(
        token in arguments.lower() for token in (".env", ".aws/credentials", "id_rsa", "secret", "token", "password")
    ):
        findings.append(
            _finding(
                command,
                "credential_access",
                "critical",
                "The command appears to access environment variables or credential material.",
                "Use an explicit allowlist of non-sensitive environment variables and never expose credentials to an agent.",
            )
        )
    if executable not in SAFE_LOCAL_PREFIXES and not findings:
        findings.append(
            _finding(
                command,
                "unknown_executable",
                "medium",
                f"The executable {executable!r} is not in SafePatch's reviewed local command list.",
                "Review the executable and its provenance before approving it.",
            )
        )
    return findings
