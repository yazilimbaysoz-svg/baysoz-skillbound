"""Deterministic analysis engine and capability-contract evaluation.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from pathlib import Path

from .capabilities import IGNORED_DIRS, infer_capabilities
from .manifest import load_manifest, locate_token
from .model import (
    CAPABILITY_DESCRIPTIONS,
    CAPABILITY_SEVERITY,
    ATTRIBUTION,
    BundleReport,
    Finding,
    Manifest,
    SEVERITY_RANK,
    Severity,
)
from .paths import scan_paths
from .instruction import scan_instructions


def _observed_set(observations: tuple) -> set[str]:
    return {item.capability for item in observations}


def _contract_findings(
    root: Path, manifest: Manifest, observations: tuple, findings: list[Finding]
) -> None:
    observed = _observed_set(observations)
    by_capability: dict[str, list] = {}
    for item in observations:
        by_capability.setdefault(item.capability, []).append(item)

    for capability in sorted(observed - manifest.declared - manifest.forbidden):
        examples = by_capability[capability]
        first = examples[0]
        findings.append(
            Finding(
                rule_id="SB-CAP-001",
                severity=Severity(CAPABILITY_SEVERITY.get(capability, "medium")),
                path=first.path,
                line=first.line,
                column=first.column,
                message=(
                    f"Capability {capability} is observed in {len(examples)} location(s) "
                    "but not declared in the skill manifest"
                ),
                evidence=first.evidence,
                remediation=f"Declare {capability} or remove the observed behaviour.",
                tags=("capability-contract", capability),
            )
        )

    for capability in sorted(manifest.declared - observed):
        line, evidence = locate_token(root, capability)
        findings.append(
            Finding(
                rule_id="SB-CAP-002",
                severity=Severity.LOW,
                path="SKILL.md",
                line=line,
                message=f"Declared capability {capability} has no static evidence",
                evidence=evidence,
                remediation="Remove the stale declaration or document why it is required.",
                tags=("capability-contract", "over-declaration"),
            )
        )

    for capability in sorted(manifest.forbidden & observed):
        examples = by_capability[capability]
        first = examples[0]
        findings.append(
            Finding(
                rule_id="SB-CAP-003",
                severity=Severity.CRITICAL,
                path=first.path,
                line=first.line,
                column=first.column,
                message=(
                    f"Forbidden capability {capability} is present in {len(examples)} location(s)"
                ),
                evidence=first.evidence,
                remediation=f"Remove {capability} from the bundle or from the forbidden policy.",
                tags=("capability-contract", "forbidden", capability),
            )
        )

    for capability in sorted(manifest.forbidden & manifest.declared):
        line, evidence = locate_token(root, capability)
        findings.append(
            Finding(
                rule_id="SB-CAP-003",
                severity=Severity.CRITICAL,
                path="SKILL.md",
                line=line,
                message=f"Capability {capability} is both declared and forbidden",
                evidence=evidence,
                remediation="Resolve the contradictory capability contract.",
                tags=("capability-contract", "forbidden"),
            )
        )


def _stats(root: Path, observations: tuple) -> dict[str, int]:
    files = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and not any(part in IGNORED_DIRS for part in path.relative_to(root).parts)
    ]
    return {
        "files": len(files),
        "code_files": sum(
            1
            for path in files
            if path.suffix.lower()
            in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".sh", ".bash"}
        ),
        "prose_files": sum(1 for path in files if path.suffix.lower() in {".md", ".txt"}),
        "symlinks": sum(1 for path in root.rglob("*") if path.is_symlink()),
        "observations": len(observations),
        "capabilities": len(_observed_set(observations)),
        "catalog_size": len(CAPABILITY_DESCRIPTIONS),
    }


def analyze_bundle(root: Path, policy: Path | None = None) -> BundleReport:
    """Analyze a skill bundle and return a complete deterministic report."""

    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"skill bundle path is not a directory: {root}")
    findings: list[Finding] = []
    manifest = load_manifest(root, findings, policy)
    observations = infer_capabilities(root, findings)
    scan_instructions(root, findings)
    scan_paths(root, findings, manifest.allow_external_symlinks)
    _contract_findings(root, manifest, observations, findings)
    ordered = tuple(
        sorted(
            findings,
            key=lambda item: (
                SEVERITY_RANK[item.severity],
                item.rule_id,
                item.path,
                item.line,
                item.evidence,
            ),
        )
    )
    return BundleReport(
        root=str(root),
        manifest=manifest,
        observations=observations,
        findings=ordered,
        stats=_stats(root, observations),
    )


def attribution() -> str:
    """Return the mandatory Baysöz Labs attribution string."""

    return ATTRIBUTION
