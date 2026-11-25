"""Command-line interface for Baysöz Labs skillbound.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import analyze_bundle
from .model import (
    ATTRIBUTION,
    PROJECT,
    SEVERITY_RANK,
    VERSION,
    BundleReport,
    CAPABILITY_DESCRIPTIONS,
)
from .probes import build_probe_plan
from .sarif import to_sarif

FAIL_LEVELS = ("critical", "high", "medium", "low", "info", "never")
EPILOG = f"{PROJECT} {VERSION} — {ATTRIBUTION}. Offline analysis only."


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillbound",
        description=(
            "Offline capability-contract oracle for AI agent skill bundles. "
            "Built by Baysöz Labs <baysozlabs@proton.me>."
        ),
        epilog=EPILOG,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"skillbound {VERSION} — {ATTRIBUTION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="scan a skill bundle and emit a report",
        description="Scan a skill bundle without network access.",
        epilog=EPILOG,
    )
    scan.add_argument("path", type=Path, help="path to the skill bundle directory")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--fail-on", choices=FAIL_LEVELS, default="high")
    scan.add_argument("--policy", type=Path, default=None, help="override .skillbound.toml")
    scan.add_argument("--output", type=Path, default=None, help="write report to a file")

    probe = subparsers.add_parser(
        "probe",
        help="compile an evidence-backed adversarial probe plan",
        description="Compile probes from findings observed in the target bundle.",
        epilog=EPILOG,
    )
    probe.add_argument("path", type=Path, help="path to the skill bundle directory")
    probe.add_argument("--format", choices=("text", "json"), default="text")
    probe.add_argument("--policy", type=Path, default=None)

    rules = subparsers.add_parser(
        "rules",
        help="print the capability and rule catalog",
        description="Print the static capability catalog and rule identifiers.",
        epilog=EPILOG,
    )
    rules.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _render_text(report: BundleReport) -> str:
    lines = [
        f"{PROJECT} {VERSION} — {ATTRIBUTION}",
        f"Bundle: {report.root}",
        f"Manifest: {report.manifest.name}",
        "Declared capabilities: " + (", ".join(sorted(report.manifest.declared)) or "none"),
        "Observed capabilities: "
        + (", ".join(sorted({item.capability for item in report.observations})) or "none"),
    ]
    counts = report.counts()
    lines.append(
        "Findings: "
        + str(len(report.findings))
        + " ("
        + ", ".join(f"{key}={value}" for key, value in counts.items())
        + ")"
    )
    for finding in report.findings:
        lines.append(
            f"  [{finding.severity.upper():<8}] {finding.rule_id} {finding.path}:{finding.line}"
        )
        lines.append(f"      {finding.message}")
        if finding.evidence:
            lines.append(f"      Evidence: {finding.evidence}")
    lines.append(f"Attribution: {ATTRIBUTION}")
    return "\n".join(lines)


def _render_probe_text(probes: list[dict[str, object]]) -> str:
    lines = [f"{PROJECT} probe plan — {ATTRIBUTION}", f"Probes: {len(probes)}"]
    for probe in probes:
        lines.append(f"  {probe['probe_id']} [{probe['severity']}] {probe['technique']}")
        lines.append(f"      Target: {probe['target']}")
        lines.append(f"      Input: {probe['input']}")
        lines.append(f"      Expect: {probe['expected_outcome']}")
    lines.append(f"Attribution: {ATTRIBUTION}")
    return "\n".join(lines)


def _render_rules(format_name: str) -> str:
    catalog = {
        "capabilities": CAPABILITY_DESCRIPTIONS,
        "rules": {
            "SB-MAN-001": "missing or invalid manifest",
            "SB-MAN-002": "malformed manifest or policy",
            "SB-CAP-001": "capability observed but not declared",
            "SB-CAP-002": "capability declared but not observed",
            "SB-CAP-003": "forbidden capability present",
            "SB-INS-001": "instruction override directive",
            "SB-INS-002": "external exfiltration endpoint",
            "SB-INS-003": "credential disclosure directive",
            "SB-INS-004": "hidden instruction extraction directive",
            "SB-INS-005": "tool-description poisoning directive",
            "SB-PATH-001": "symlink escapes bundle root",
            "SB-PATH-002": "dangling symlink",
            "SB-BUD-001": "analysis byte budget exceeded",
        },
        "attribution": ATTRIBUTION,
        "version": VERSION,
    }
    if format_name == "json":
        return json.dumps(catalog, indent=2, sort_keys=True, ensure_ascii=False)
    lines = [f"{PROJECT} catalog — {ATTRIBUTION}", "Capabilities:"]
    lines.extend(f"  {key}: {value}" for key, value in sorted(catalog["capabilities"].items()))
    lines.append("Rules:")
    lines.extend(f"  {key}: {value}" for key, value in sorted(catalog["rules"].items()))
    lines.append(f"Attribution: {ATTRIBUTION}")
    return "\n".join(lines)


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        print(text)
        return
    output.write_text(text + "\n", encoding="utf-8")


def _failed(report: BundleReport, threshold: str) -> bool:
    if threshold == "never":
        return False
    limit = SEVERITY_RANK[threshold.lower()]
    return any(SEVERITY_RANK[item.severity] <= limit for item in report.findings)


def main(argv: list[str] | None = None) -> int:
    """Run the skillbound CLI and return a process exit code."""

    args = _parser().parse_args(argv)
    try:
        if args.command == "rules":
            _emit(_render_rules(args.format), None)
            return 0
        report = analyze_bundle(args.path, args.policy)
        if args.command == "scan":
            if args.format == "json":
                text = json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)
            elif args.format == "sarif":
                text = json.dumps(to_sarif(report), indent=2, sort_keys=True, ensure_ascii=False)
            else:
                text = _render_text(report)
            _emit(text, args.output)
            return 1 if _failed(report, args.fail_on) else 0
        probes = build_probe_plan(report)
        text = (
            json.dumps(
                {"probes": probes, "attribution": ATTRIBUTION},
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            if args.format == "json"
            else _render_probe_text(probes)
        )
        _emit(text, None)
        return 0
    except (ValueError, OSError) as exc:
        print(f"skillbound error: {exc} — {ATTRIBUTION}", file=sys.stderr)
        return 2
