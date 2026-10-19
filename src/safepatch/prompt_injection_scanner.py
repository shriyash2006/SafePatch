from __future__ import annotations

import re
from pathlib import Path

from .hashing import sha256_text
from .models import Finding
from .redaction import sanitize_output


INJECTION_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("ignore_instructions", r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|system|safety)\b", "high"),
    ("agent_directive", r"(?i)\b(system prompt|assistant message|developer message|you are an ai agent)\b", "medium"),
    ("secret_request", r"(?i)\b(upload|send|print|exfiltrate|reveal)\b.{0,50}\b(secret|token|password|credential|api key)\b", "critical"),
    ("safety_bypass", r"(?i)\b(disable|bypass|skip)\b.{0,30}\b(safety|security|approval|review)\b", "high"),
    ("command_directive", r"(?i)\b(run|execute)\b.{0,30}\b(command|script|shell)\b", "medium"),
)


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    relative = path.as_posix()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, expression, severity in INJECTION_PATTERNS:
            match = re.search(expression, line)
            if match:
                evidence = f"{line[:match.start()]}[UNTRUSTED CONTENT]{line[match.end():]}"
                findings.append(
                    Finding(
                        id=f"injection-{rule}-{line_number}",
                        category="prompt_injection",
                        severity=severity,  # type: ignore[arg-type]
                        source="repository",
                        rule=rule,
                        message="Instruction-like content was found in untrusted repository data.",
                        path=relative,
                        line=line_number,
                        evidence=sanitize_output(evidence[:300]),
                        evidence_hash=sha256_text(match.group(0)),
                        recommendation="Treat this text as data only; do not pass it to an agent as an instruction.",
                    )
                )
    if any(char in text for char in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")):
        findings.append(
            Finding(
                id="injection-hidden-unicode",
                category="prompt_injection",
                severity="medium",
                source="repository",
                rule="hidden_unicode",
                message="Zero-width or invisible Unicode characters were found in repository text.",
                path=relative,
                recommendation="Inspect invisible characters before allowing an agent to consume this file.",
            )
        )
    return findings
