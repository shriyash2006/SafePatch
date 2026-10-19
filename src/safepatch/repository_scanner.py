from __future__ import annotations

import os
from pathlib import Path

from .hashing import sha256_bytes, sha256_file
from .models import Finding
from .prompt_injection_scanner import scan_text as scan_prompt_injection
from .secret_scanner import scan_sensitive_path, scan_text as scan_secrets


SKIP_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "artifacts"}
MAX_FILE_SIZE = 1024 * 1024


class RepositoryScan:
    def __init__(self, root: Path, files: list[dict], findings: list[Finding]):
        self.root = root
        self.files = files
        self.findings = findings


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def scan_repository(root: Path) -> RepositoryScan:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")

    files: list[dict] = []
    findings: list[Finding] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name for name in directories if name not in SKIP_DIRECTORIES and not (current_path / name).is_symlink()
        ]
        for filename in sorted(filenames):
            path = current_path / filename
            relative = _relative(root, path)
            if path.is_symlink():
                files.append({"path": relative, "scanned": False, "reason": "symlink_skipped"})
                continue
            stat = path.stat()
            if stat.st_size > MAX_FILE_SIZE:
                files.append({"path": relative, "size": stat.st_size, "scanned": False, "reason": "file_too_large"})
                continue
            digest = sha256_file(path)
            entry = {"path": relative, "size": stat.st_size, "sha256": digest, "scanned": True}
            try:
                raw = path.read_bytes()
            except OSError as exc:
                entry.update({"scanned": False, "reason": f"read_error:{type(exc).__name__}"})
                files.append(entry)
                continue
            if b"\x00" in raw:
                entry["reason"] = "binary_skipped"
                files.append(entry)
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                entry["scanned"] = False
                entry["reason"] = "non_utf8_skipped"
                files.append(entry)
                continue
            files.append(entry)
            sensitive = scan_sensitive_path(Path(relative))
            if sensitive:
                findings.append(sensitive)
            findings.extend(scan_secrets(Path(relative), text))
            findings.extend(scan_prompt_injection(Path(relative), text))
    return RepositoryScan(root, files, findings)
