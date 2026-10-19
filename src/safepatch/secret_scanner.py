from __future__ import annotations

import re
from pathlib import Path

from .hashing import sha256_text
from .models import Finding
from .redaction import redact_line, redact_secret_assignments


SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "critical"),
    ("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "critical"),
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b", "high"),
    ("openai_key", r"\bsk-[A-Za-z0-9]{20,}\b", "high"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{20,}\b", "high"),
)

_compiled_patterns = tuple(
    (name, re.compile(pattern), severity) for name, pattern, severity in SECRET_PATTERNS
)
_assignment_pattern = re.compile(
    r"(?i)\b(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)\b\s*[=:]\s*([^\s,;#]{12,})"
)


def _finding(
    *, path: str, line_number: int, rule: str, severity: str, message: str, evidence: str, raw: str
) -> Finding:
    return Finding(
        id=f"secret-{rule}-{line_number}",
        category="secret",
        severity=severity,  # type: ignore[arg-type]
        source="repository",
        rule=rule,
        message=message,
        path=path,
        line=line_number,
        evidence=evidence,
        evidence_hash=sha256_text(raw),
        recommendation="Remove the credential, rotate it if real, and keep secrets outside the repository.",
    )


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    relative = path.as_posix()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern, severity in _compiled_patterns:
            match = pattern.search(line)
            if match:
                findings.append(
                    _finding(
                        path=relative,
                        line_number=line_number,
                        rule=rule,
                        severity=severity,
                        message=f"Possible {rule.replace('_', ' ')} found in repository content.",
                        evidence=redact_line(line, [match.span()]),
                        raw=match.group(0),
                    )
                )
        assignment = _assignment_pattern.search(line)
        if assignment:
            raw_value = assignment.group(1)
            findings.append(
                _finding(
                    path=relative,
                    line_number=line_number,
                    rule="sensitive_assignment",
                    severity="high",
                    message="A sensitive-looking assignment contains a value that may be a credential.",
                    evidence=redact_secret_assignments(line),
                    raw=raw_value,
                )
            )
    return findings


def scan_sensitive_path(path: Path) -> Finding | None:
    name = path.as_posix().lower()
    sensitive = ("/.env", "/.npmrc", "/.pypirc", "/.aws/credentials", "/.ssh/id_")
    if any(marker in name or name.endswith(marker.lstrip("/")) for marker in sensitive):
        return Finding(
            id=f"secret-sensitive-path-{path.as_posix()}",
            category="secret",
            severity="high",
            source="repository",
            rule="sensitive_path",
            message="A file path commonly used for credentials was included in the scan.",
            path=path.as_posix(),
            recommendation="Do not commit this file; remove it from the repository and rotate any credentials it contains.",
        )
    return None
