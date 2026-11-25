"""Model and fingerprint tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from skillbound.model import (
    ATTRIBUTION,
    CAPABILITY_DESCRIPTIONS,
    RULE_TITLES,
    SARIF_LEVEL,
    SEVERITY_RANK,
    VERSION,
    BundleReport,
    CapabilityObservation,
    Finding,
    Manifest,
    Severity,
    fingerprint,
)


def test_attribution_is_explicit() -> None:
    assert "Baysöz Labs" in ATTRIBUTION
    assert "baysozlabs@proton.me" in ATTRIBUTION
    assert VERSION == "0.1.0"


def test_fingerprint_is_stable_and_sensitive() -> None:
    assert fingerprint("abc") == fingerprint("abc")
    assert fingerprint("abc") != fingerprint("abd")
    assert len(fingerprint("abc")) == 64


def test_severity_rank_order() -> None:
    assert [SEVERITY_RANK[level] for level in Severity] == [0, 1, 2, 3, 4]


def test_sarif_level_mapping() -> None:
    assert SARIF_LEVEL[Severity.CRITICAL] == "error"
    assert SARIF_LEVEL[Severity.MEDIUM] == "warning"
    assert SARIF_LEVEL[Severity.LOW] == "note"


def test_finding_dict_contains_evidence_and_fingerprint() -> None:
    finding = Finding("SB-CAP-001", Severity.HIGH, "script.py", 7, "undeclared", "fetch()")
    payload = finding.to_dict()
    assert payload["rule_id"] == "SB-CAP-001"
    assert payload["title"] == RULE_TITLES["SB-CAP-001"]
    assert payload["evidence"] == "fetch()"
    assert payload["fingerprint"] == finding.identity


def test_bundle_report_counts_and_dict() -> None:
    report = BundleReport(
        root="/tmp/bundle",
        manifest=Manifest("demo", "", frozenset({"NETWORK"}), frozenset()),
        observations=(CapabilityObservation("NETWORK", "a.py", 2, 1, "fetch()", "python call"),),
        findings=(
            Finding("SB-CAP-001", Severity.HIGH, "a.py", 2, "undeclared"),
            Finding("SB-CAP-002", Severity.LOW, "SKILL.md", 1, "stale"),
        ),
        stats={"files": 2},
    )
    assert report.counts()["high"] == 1
    assert report.counts()["low"] == 1
    payload = report.to_dict()
    assert payload["attribution"] == ATTRIBUTION
    assert payload["observations"][0]["capability"] == "NETWORK"
    assert payload["stats"] == {"files": 2}


def test_rule_titles_cover_every_documented_rule() -> None:
    expected = {
        "SB-MAN-001",
        "SB-MAN-002",
        "SB-CAP-001",
        "SB-CAP-002",
        "SB-CAP-003",
        "SB-INS-001",
        "SB-INS-002",
        "SB-INS-003",
        "SB-INS-004",
        "SB-INS-005",
        "SB-PATH-001",
        "SB-PATH-002",
        "SB-BUD-001",
    }
    assert expected <= set(RULE_TITLES)


def test_capability_catalog_is_nonempty() -> None:
    assert len(CAPABILITY_DESCRIPTIONS) >= 7
