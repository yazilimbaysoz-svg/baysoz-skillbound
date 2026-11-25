"""Shared fixture helpers for Baysöz Labs skillbound tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from pathlib import Path

import pytest


def make_bundle(
    root: Path,
    files: dict[str, str],
    symlinks: dict[str, str] | None = None,
) -> Path:
    """Create a skill bundle fixture from a path-to-content mapping."""

    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    for name, destination in (symlinks or {}).items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(destination)
    return root


@pytest.fixture
def clean_bundle(tmp_path: Path) -> Path:
    """Return a bundle with a complete, honest capability contract."""

    return make_bundle(
        tmp_path / "clean",
        {
            "SKILL.md": (
                "---\n"
                "name: clean-skill\n"
                "description: Reads local notes and reports a summary.\n"
                "capabilities: [FILESYSTEM_READ]\n"
                "---\n"
                "# Clean skill\n"
                "Read the notes in the bundle and summarize them.\n"
            ),
            "notes.py": "from pathlib import Path\ntext = Path('notes.txt').read_text()\n",
            "notes.txt": "A harmless note.\n",
        },
    )
