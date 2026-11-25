"""Findings, observations and report model.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"
VERSION = "0.1.0"
PROJECT = "baysoz-skillbound"

CAPABILITY_DESCRIPTIONS = {
    "NETWORK": "Outbound network or socket activity",
    "FILESYSTEM_READ": "Reads files outside the bundle payload",
    "FILESYSTEM_WRITE": "Creates, modifies or removes files",
    "ENV_ACCESS": "Reads process environment variables",
    "PROCESS_EXEC": "Spawns external processes",
    "DYNAMIC_CODE": "Evaluates dynamically assembled code",
    "CREDENTIAL_ACCESS": "Reads keyrings, tokens or credential stores",
}

CAPABILITY_SEVERITY = {
    "CREDENTIAL_ACCESS": "critical",
    "DYNAMIC_CODE": "critical",
    "NETWORK": "high",
    "FILESYSTEM_WRITE": "high",
    "PROCESS_EXEC": "high",
    "ENV_ACCESS": "high",
    "FILESYSTEM_READ": "medium",
}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

RULE_TITLES = {
    "SB-MAN-001": "Missing or invalid skill manifest",
    "SB-MAN-002": "Manifest field cannot be parsed",
    "SB-CAP-001": "Observed capability is not declared",
    "SB-CAP-002": "Declared capability has no static evidence",
    "SB-CAP-003": "Forbidden capability is present",
    "SB-INS-001": "Instruction override directive",
    "SB-INS-002": "External exfiltration endpoint",
    "SB-INS-003": "Credential disclosure directive",
    "SB-INS-004": "Hidden instruction extraction directive",
    "SB-INS-005": "Tool-description poisoning directive",
    "SB-PATH-001": "Symlink escapes bundle root",
    "SB-PATH-002": "Broken symlink in skill bundle",
    "SB-BUD-001": "File exceeds static-analysis byte budget",
}


def fingerprint(value: str) -> str:
    """Return a stable SHA-256 fingerprint for a finding identity string."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    line: int
    message: str
    evidence: str = ""
    column: int = 1
    remediation: str = ""
    tags: tuple[str, ...] = ()

    @property
    def title(self) -> str:
        return RULE_TITLES.get(self.rule_id, self.rule_id)

    @property
    def identity(self) -> str:
        return fingerprint(f"{self.rule_id}|{self.path}|{self.line}|{self.evidence}")

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "fingerprint": self.identity,
        }


@dataclass(frozen=True, slots=True)
class CapabilityObservation:
    capability: str
    path: str
    line: int
    column: int
    evidence: str
    mechanism: str

    def to_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "mechanism": self.mechanism,
        }


@dataclass(slots=True)
class Manifest:
    name: str
    description: str
    declared: frozenset[str]
    forbidden: frozenset[str]
    allow_external_symlinks: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "declared_capabilities": sorted(self.declared),
            "forbidden_capabilities": sorted(self.forbidden),
            "allow_external_symlinks": self.allow_external_symlinks,
        }


@dataclass(slots=True)
class BundleReport:
    root: str
    manifest: Manifest
    observations: tuple[CapabilityObservation, ...] = ()
    findings: tuple[Finding, ...] = ()
    stats: dict[str, int] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        result = {level.value: 0 for level in Severity}
        for finding in self.findings:
            result[str(finding.severity)] += 1
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": PROJECT,
            "attribution": ATTRIBUTION,
            "version": VERSION,
            "root": self.root,
            "manifest": self.manifest.to_dict(),
            "observations": [item.to_dict() for item in self.observations],
            "findings": [item.to_dict() for item in self.findings],
            "counts": self.counts(),
            "stats": dict(sorted(self.stats.items())),
        }
