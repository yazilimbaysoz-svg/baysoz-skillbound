"""Bundle boundary and symlink tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

from skillbound.engine import analyze_bundle
from skillbound.model import Finding, Severity
from skillbound.paths import scan_paths
from tests.conftest import make_bundle


def test_external_symlink_is_critical(tmp_path: Path) -> None:
    outside = make_bundle(tmp_path / "outside", {"secret.txt": "not a real secret\n"})
    root = make_bundle(
        tmp_path / "bundle",
        {"SKILL.md": "---\nname: demo\n---\nBody\n"},
        {"link.txt": str(outside / "secret.txt")},
    )
    findings: list[Finding] = []
    scan_paths(root, findings)
    escape = [item for item in findings if item.rule_id == "SB-PATH-001"]
    assert len(escape) == 1
    assert escape[0].severity == Severity.CRITICAL
    assert escape[0].path == "link.txt"


def test_internal_symlink_is_allowed(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "internal",
        {"data.txt": "safe\n", "SKILL.md": "---\nname: demo\n---\nBody\n"},
        {"link.txt": "data.txt"},
    )
    findings: list[Finding] = []
    scan_paths(root, findings)
    assert not any(item.rule_id == "SB-PATH-001" for item in findings)


def test_dangling_symlink_is_reported(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "dangling",
        {"SKILL.md": "---\nname: demo\n---\nBody\n"},
        {"link.txt": "does-not-exist.txt"},
    )
    findings: list[Finding] = []
    scan_paths(root, findings)
    assert any(item.rule_id == "SB-PATH-002" for item in findings)


def test_policy_can_allow_external_symlinks(tmp_path: Path) -> None:
    outside = make_bundle(tmp_path / "outside", {"data.txt": "safe\n"})
    root = make_bundle(
        tmp_path / "bundle",
        {
            "SKILL.md": "---\nname: demo\n---\nBody\n",
            ".skillbound.toml": "[policy]\nallow_external_symlinks = true\n",
        },
        {"link.txt": str(outside / "data.txt")},
    )
    report = analyze_bundle(root)
    assert not any(item.rule_id == "SB-PATH-001" for item in report.findings)


def test_bundle_root_is_resolved(tmp_path: Path) -> None:
    root = make_bundle(tmp_path / "resolved", {"SKILL.md": "---\nname: demo\n---\nBody\n"})
    report = analyze_bundle(root)
    assert report.root == str(root.resolve())
