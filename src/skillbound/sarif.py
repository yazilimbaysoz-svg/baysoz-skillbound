"""SARIF 2.1.0 emitter with stable finding fingerprints.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from .model import (
    ATTRIBUTION,
    PROJECT,
    RULE_TITLES,
    SARIF_LEVEL,
    VERSION,
    BundleReport,
)


def _uri(path: str) -> str:
    return path.split("#", 1)[0]


def _driver(report: BundleReport) -> dict[str, object]:
    rule_ids = sorted({item.rule_id for item in report.findings})
    rules = []
    for rule_id in rule_ids:
        title = RULE_TITLES.get(rule_id, rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {"text": title},
                "fullDescription": {
                    "text": f"{title}. Published by Baysöz Labs <baysozlabs@proton.me>"
                },
                "defaultConfiguration": {"level": "warning"},
            }
        )
    return {
        "name": PROJECT,
        "version": VERSION,
        "organization": ATTRIBUTION,
        "informationUri": "https://github.com/yazilimbaysoz-svg/baysoz-skillbound",
        "properties": {"attribution": ATTRIBUTION},
        "rules": rules,
    }


def to_sarif(report: BundleReport) -> dict[str, object]:
    """Convert a bundle report to a valid SARIF 2.1.0 document."""

    results = []
    for finding in report.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(finding.path)},
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                            },
                        }
                    }
                ],
                "partialFingerprints": {"skillbound/v1": finding.identity},
                "properties": {
                    "severity": str(finding.severity),
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "tags": list(finding.tags),
                    "attribution": ATTRIBUTION,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": _driver(report)},
                "results": results,
                "properties": {
                    "attribution": ATTRIBUTION,
                    "bundle": report.root,
                    "counts": report.counts(),
                },
            }
        ],
    }
