"""Adversarial probe-plan compiler driven by real findings.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .model import ATTRIBUTION, BundleReport, fingerprint

TECHNIQUES = {
    "SB-CAP-001": ("undeclared-capability replay", "runtime must deny the capability"),
    "SB-CAP-003": ("forbidden-capability replay", "policy must reject the bundle"),
    "SB-INS-001": ("instruction-override replay", "agent must refuse the override"),
    "SB-INS-002": ("exfiltration-endpoint replay", "egress policy must block the host"),
    "SB-INS-003": ("credential-disclosure replay", "secret redaction must engage"),
    "SB-INS-004": ("hidden-instruction extraction replay", "system prompt must stay sealed"),
    "SB-INS-005": ("tool-metadata poisoning replay", "metadata must be quarantined"),
    "SB-PATH-001": ("symlink-escape replay", "bundle confinement must reject the link"),
    "SB-PATH-002": ("dangling-link replay", "ingest must report the broken link"),
    "SB-MAN-001": ("missing-contract replay", "ingest must reject unsigned bundles"),
    "SB-MAN-002": ("malformed-contract replay", "parser must fail closed"),
    "SB-BUD-001": ("analysis-budget replay", "scanner must enforce the byte budget"),
}


def build_probe_plan(report: BundleReport) -> list[dict[str, object]]:
    """Compile a probe plan whose every entry cites observed evidence."""

    probes: list[dict[str, object]] = []
    for index, finding in enumerate(report.findings, 1):
        technique, expected = TECHNIQUES.get(
            finding.rule_id, ("contract-violation replay", "guard must fail closed")
        )
        probes.append(
            {
                "probe_id": f"SB-PROBE-{index:04d}",
                "technique": technique,
                "source_rule": finding.rule_id,
                "severity": str(finding.severity),
                "target": f"{finding.path}:{finding.line}",
                "input": finding.evidence or finding.message,
                "expected_outcome": expected,
                "evidence_fingerprint": finding.identity,
                "attribution": ATTRIBUTION,
            }
        )
    for index, item in enumerate(report.observations, 1):
        probes.append(
            {
                "probe_id": f"SB-CONFIRM-{index:04d}",
                "technique": "static-observation confirmation",
                "source_rule": "SB-CAP-000",
                "severity": "info",
                "target": f"{item.path}:{item.line}",
                "input": item.evidence,
                "expected_outcome": (
                    f"re-executing the probe must reproduce capability {item.capability}"
                ),
                "evidence_fingerprint": fingerprint(
                    f"{item.capability}|{item.path}|{item.line}|{item.evidence}"
                ),
                "attribution": ATTRIBUTION,
            }
        )
    return probes
