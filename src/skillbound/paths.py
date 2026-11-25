"""Symlink and bundle-boundary integrity checks.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from pathlib import Path

from .model import Finding, Severity


def scan_paths(root: Path, findings: list[Finding], allow_external: bool = False) -> None:
    """Detect symlinks that escape the bundle root or dangle."""

    boundary = root.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_symlink():
            continue
        relative = str(path.relative_to(root))
        try:
            target = path.readlink()
            resolved = (path.parent / target).resolve()
        except (OSError, RuntimeError):
            findings.append(
                Finding(
                    rule_id="SB-PATH-002",
                    severity=Severity.LOW,
                    path=relative,
                    line=1,
                    message="Symlink cannot be resolved",
                    tags=("path-integrity",),
                )
            )
            continue
        if not resolved.exists():
            findings.append(
                Finding(
                    rule_id="SB-PATH-002",
                    severity=Severity.LOW,
                    path=relative,
                    line=1,
                    message="Symlink target does not exist",
                    evidence=str(target),
                    tags=("path-integrity",),
                )
            )
        try:
            resolved.relative_to(boundary)
        except ValueError:
            if allow_external:
                continue
            findings.append(
                Finding(
                    rule_id="SB-PATH-001",
                    severity=Severity.CRITICAL,
                    path=relative,
                    line=1,
                    message="Symlink resolves outside the skill bundle root",
                    evidence=str(target),
                    remediation="Replace the link with a checked-in file or relax policy.",
                    tags=("path-integrity", "escape"),
                )
            )
