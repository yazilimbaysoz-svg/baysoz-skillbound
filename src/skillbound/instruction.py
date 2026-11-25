"""Multilingual instruction-integrity and exfiltration directives.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from .model import Finding, Severity

URL_RE = re.compile(r"https?://[^\s\"'<>)`\]]+", re.IGNORECASE)
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

DIRECTIVE_RULES: tuple[tuple[str, Severity, str, str], ...] = (
    (
        "SB-INS-001",
        Severity.CRITICAL,
        r"\b(?:ignore|disregard|override|forget|bypass|yok\s+say|görmezden\s+gel|unut|ignorier|vergiss)\b"
        r".{0,60}\b(?:previous|prior|earlier|above|system|developer|your|the|any|önceki|daha\s+önceki|"
        r"vorherig|vorherigen)\b.{0,40}\b(?:instruction|rule|prompt|guideline|direction|talimat|kural|"
        r"anweisung|regel|systemnachricht)\w*",
        "Treat the bundle as untrusted: instruction overrides are not enforceable.",
    ),
    (
        "SB-INS-001",
        Severity.CRITICAL,
        r"\b(?:previous|prior|earlier|above|system|developer|önceki\w*|vorherig\w*)\b"
        r".{0,50}\b(?:instructions?|rules?|prompt|talimat\w*|anweisung\w*|regeln)\b"
        r".{0,40}\b(?:ignore|disregard|forget|bypass|yok\s+say|görmezden\s+gel|"
        r"ignorier\w*|vergiss\w*)\b",
        "Treat the bundle as untrusted: instruction overrides are not enforceable.",
    ),
    (
        "SB-INS-003",
        Severity.HIGH,
        r"\b(?:api[\s_-]?key|secret|token|password|credential|parola|şifre|geheimnis)\b.{0,50}"
        r"\b(?:env|environment|\.env|print|reveal|expose|göster|sızdır|yaz|ausgeben)\b",
        "Remove credential-disclosure wording and rotate any exposed secret.",
    ),
    (
        "SB-INS-003",
        Severity.HIGH,
        r"\b(?:print|reveal|show|expose|read|göster|sızdır|ausgeben)\b.{0,50}"
        r"\b(?:api[\s_-]?key|secret|token|password|credential|parola|şifre|geheimnis)\b",
        "Remove credential-disclosure wording and rotate any exposed secret.",
    ),
    (
        "SB-INS-004",
        Severity.HIGH,
        r"\b(?:reveal|print|show|return|dump|expose|göster|sızdır|ausgeben)\b.{0,50}"
        r"\b(?:system prompt|developer message|hidden instruction|gizli talimat|sistem mesajı|"
        r"systemnachricht|versteckte anweisung)\b",
        "Remove directives that request hidden instruction disclosure.",
    ),
    (
        "SB-INS-005",
        Severity.HIGH,
        r"\b(?:tool|mcp|araç)\s+(?:description|metadata|schema|açıklama)\b.{0,80}"
        r"\b(?:hidden|concealed|gizli|ignore|yok say|versteckt)\b",
        "Review tool metadata for poisoned descriptions before publication.",
    ),
)

EXFIL_VERB_RE = re.compile(
    r"\b(?:send|upload|post|exfiltrate|forward|transmit|gönder|yükle|sızdır|"
    r"aktar|senden|hochladen)\b",
    re.IGNORECASE,
)


def _mask_fences(text: str) -> list[str]:
    """Replace fenced code lines with blanks while preserving line positions."""

    result: list[str] = []
    inside = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
            result.append("")
            continue
        result.append("" if inside else line)
    return result


def _external_host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return "" if host in LOCAL_HOSTS else host


def scan_instruction_file(root: Path, path: Path, findings: list[Finding]) -> None:
    """Scan one prose file and append evidence-backed instruction findings."""

    relative = str(path.relative_to(root))
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    lines = _mask_fences(text)
    seen: set[tuple[str, int, str]] = set()
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule_id, severity, pattern, remediation in DIRECTIVE_RULES:
            if re.search(pattern, stripped, re.IGNORECASE):
                key = (rule_id, line_number, stripped[:80])
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            path=relative,
                            line=line_number,
                            message=f"{rule_id} matched an untrusted instruction directive",
                            evidence=stripped[:160],
                            remediation=remediation,
                            tags=("instruction-integrity",),
                        )
                    )
        for match in URL_RE.finditer(stripped):
            host = _external_host(match.group(0))
            if not host:
                continue
            window = stripped[max(0, match.start() - 100) : match.end() + 40]
            if not EXFIL_VERB_RE.search(window):
                continue
            key = ("SB-INS-002", line_number, host)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id="SB-INS-002",
                    severity=Severity.HIGH,
                    path=relative,
                    line=line_number,
                    message=f"Instruction requests data transfer to external host {host}",
                    evidence=stripped[:160],
                    remediation="Remove the endpoint or pin it in the deployment allowlist.",
                    tags=("exfiltration",),
                )
            )


def scan_instructions(root: Path, findings: list[Finding]) -> None:
    """Scan all prose files in a skill bundle for hostile directives."""

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in {".git", ".venv", "node_modules"} for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in {".md", ".txt"}:
            continue
        scan_instruction_file(root, path, findings)
