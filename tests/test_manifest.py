"""Manifest and policy parser tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

from skillbound.engine import analyze_bundle
from skillbound.manifest import load_manifest, normalize_capability
from skillbound.model import Finding, Severity
from tests.conftest import make_bundle


def test_normalize_capability() -> None:
    assert normalize_capability(' "file-system write" ') == "FILE_SYSTEM_WRITE"
    assert normalize_capability("network") == "NETWORK"


def test_inline_capability_list(clean_bundle: Path) -> None:
    findings: list[Finding] = []
    manifest = load_manifest(clean_bundle, findings)
    assert manifest.name == "clean-skill"
    assert manifest.declared == frozenset({"FILESYSTEM_READ"})
    assert findings == []


def test_block_capability_list(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "block",
        {
            "SKILL.md": (
                "---\n"
                "name: block-skill\n"
                "capabilities:\n"
                "  - NETWORK\n"
                "  - ENV_ACCESS\n"
                "description: Block list demo\n"
                "---\n"
                "Body\n"
            )
        },
    )
    manifest = load_manifest(root, [])
    assert manifest.declared == frozenset({"NETWORK", "ENV_ACCESS"})


def test_policy_toml_forbidden_and_symlink_flag(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "policy",
        {
            "SKILL.md": "---\nname: policy-skill\n---\nBody\n",
            ".skillbound.toml": (
                "[policy]\n"
                'forbidden = ["NETWORK", "PROCESS_EXEC"]\n'
                'declared = ["FILESYSTEM_READ"]\n'
                "allow_external_symlinks = true\n"
            ),
        },
    )
    manifest = load_manifest(root, [])
    assert manifest.forbidden == frozenset({"NETWORK", "PROCESS_EXEC"})
    assert manifest.declared == frozenset({"FILESYSTEM_READ"})
    assert manifest.allow_external_symlinks is True


def test_unknown_capability_is_reported(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "unknown",
        {"SKILL.md": "---\nname: demo\ncapabilities: [TELEPATHY]\n---\nBody\n"},
    )
    findings: list[Finding] = []
    manifest = load_manifest(root, findings)
    assert manifest.declared == frozenset()
    assert any(item.rule_id == "SB-MAN-002" for item in findings)


def test_missing_manifest_is_reported(tmp_path: Path) -> None:
    root = make_bundle(tmp_path / "missing", {"tool.py": "x = 1\n"})
    findings: list[Finding] = []
    manifest = load_manifest(root, findings)
    assert manifest.name == "missing"
    assert findings[0].rule_id == "SB-MAN-001"
    assert findings[0].severity == Severity.HIGH


def test_malformed_front_matter_is_reported(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "malformed",
        {"SKILL.md": "---\nname demo\n---\nBody\n"},
    )
    findings: list[Finding] = []
    load_manifest(root, findings)
    assert any(item.rule_id == "SB-MAN-002" for item in findings)


def test_undersized_manifest_budget_is_not_reported(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "tiny",
        {"SKILL.md": "---\nname: tiny\ncapabilities: []\n---\nBody\n"},
    )
    report = analyze_bundle(root)
    assert not any(item.rule_id == "SB-BUD-001" for item in report.findings)


def test_policy_override_path(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "override",
        {"SKILL.md": "---\nname: demo\n---\nBody\n"},
    )
    policy = (
        make_bundle(
            tmp_path / "external",
            {"policy.toml": '[policy]\nforbidden = ["NETWORK"]\n'},
        )
        / "policy.toml"
    )
    manifest = load_manifest(root, [], policy)
    assert manifest.forbidden == frozenset({"NETWORK"})


def test_manifest_attribution() -> None:
    from skillbound.manifest import manifest_attribution

    assert "baysozlabs@proton.me" in manifest_attribution()
