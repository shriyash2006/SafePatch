from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from .hashing import sha256_text
from .models import CommandSpec
from .redaction import sanitize_output


def repository_hash(files: list[dict]) -> str:
    meaningful = [
        {key: entry[key] for key in ("path", "size", "sha256") if key in entry}
        for entry in files
        if entry.get("scanned")
    ]
    from .hashing import sha256_json

    return sha256_json(meaningful)


def execute(command: CommandSpec, repository: Path, timeout: int = 30) -> dict:
    root = repository.resolve()
    cwd = (root / command.cwd).resolve()
    try:
        cwd.relative_to(root)
    except ValueError as exc:
        raise ValueError("Command working directory is outside the repository") from exc
    if command.shell is not None:
        raise ValueError("Shell command strings are not executable")
    started = time.monotonic()
    safe_environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(root),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        completed = subprocess.run(
            command.argv,
            cwd=cwd,
            env=safe_environment,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        status = "confirmed" if completed.returncode == 0 else "failed"
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return {
            "command_id": command.id,
            "status": status,
            "exit_code": completed.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": sanitize_output(stdout),
            "stderr": sanitize_output(stderr),
            "stdout_sha256": sha256_text(stdout),
            "stderr_sha256": sha256_text(stderr),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "command_id": command.id,
            "status": "unknown",
            "exit_code": None,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": sanitize_output(stdout),
            "stderr": sanitize_output(stderr),
            "stdout_sha256": sha256_text(stdout),
            "stderr_sha256": sha256_text(stderr),
            "message": "The command timed out; its external outcome is unknown.",
        }
