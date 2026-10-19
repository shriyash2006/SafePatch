from __future__ import annotations

import re


_OUTPUT_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
)


def redact_match(value: str, start: int, end: int) -> str:
    return f"{value[:start]}[REDACTED]{value[end:]}"


def redact_line(line: str, spans: list[tuple[int, int]]) -> str:
    redacted = line
    for start, end in sorted(spans, reverse=True):
        redacted = redact_match(redacted, start, end)
    return redacted


def redact_secret_assignments(line: str) -> str:
    pattern = re.compile(
        r"(?i)(\b(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)\b\s*[=:]\s*)([^\s,;]+)"
    )
    return pattern.sub(r"\1[REDACTED]", line)


def sanitize_output(value: str, limit: int = 4000) -> str:
    sanitized = value
    for pattern in _OUTPUT_SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)
    sanitized = "\n".join(redact_secret_assignments(line) for line in sanitized.splitlines())
    return sanitized[:limit]
