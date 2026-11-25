"""Capability inference tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

from skillbound.capabilities import infer_capabilities
from skillbound.model import Finding
from tests.conftest import make_bundle


def _caps(root: Path) -> set[str]:
    return {item.capability for item in infer_capabilities(root, [])}


def test_python_import_and_url(clean_bundle: Path) -> None:
    assert "FILESYSTEM_READ" in _caps(clean_bundle)


def test_python_network_call(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "net",
        {
            "SKILL.md": "---\nname: net\ncapabilities: [NETWORK]\n---\nBody\n",
            "net.py": 'import urllib.request\nurllib.request.urlopen("https://api.example.test/v1")\n',
        },
    )
    observations = infer_capabilities(root, [])
    assert "NETWORK" in {item.capability for item in observations}
    assert any(item.line == 2 for item in observations)


def test_python_exec_env_and_dynamic_code(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "exec",
        {
            "SKILL.md": "---\nname: exec\n---\nBody\n",
            "run.py": (
                "import os\nimport subprocess\n"
                'value = os.getenv("API_KEY")\n'
                'os.system("echo ok")\n'
                'eval("1 + 1")\n'
            ),
        },
    )
    caps = _caps(root)
    assert {"ENV_ACCESS", "PROCESS_EXEC", "DYNAMIC_CODE", "CREDENTIAL_ACCESS"} <= caps


def test_python_filesystem_write(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "write",
        {"tool.py": 'open("out.txt", "w").write("x")\n'},
    )
    assert "FILESYSTEM_WRITE" in _caps(root)


def test_javascript_capabilities(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "js",
        {
            "SKILL.md": "---\nname: js\n---\nBody\n",
            "tool.js": (
                'const r = await fetch("https://api.example.test");\n'
                "console.log(process.env.REGION);\n"
                'const { exec } = require("child_process");\n'
                'fs.writeFileSync("out.txt", "x");\n'
            ),
        },
    )
    assert {
        "NETWORK",
        "ENV_ACCESS",
        "PROCESS_EXEC",
        "FILESYSTEM_WRITE",
    } <= _caps(root)


def test_go_capabilities(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "go",
        {
            "main.go": (
                'import "net/http"\n'
                'resp, _ := http.Get("https://api.example.test")\n'
                'key := os.Getenv("REGION")\n'
            ),
        },
    )
    assert {"NETWORK", "ENV_ACCESS"} <= _caps(root)


def test_shell_capabilities(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "shell",
        {
            "run.sh": (
                "#!/bin/sh\ncurl https://api.example.test > out.txt\nprintenv HOME\nvalue=$(date)\n"
            ),
        },
    )
    assert {"NETWORK", "FILESYSTEM_WRITE", "ENV_ACCESS", "PROCESS_EXEC"} <= _caps(root)


def test_fenced_code_has_file_and_line_evidence(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "fence",
        {
            "SKILL.md": (
                "---\nname: fence\ncapabilities: [NETWORK]\n---\n"
                "# Demo\n\n"
                "```python\n"
                "import socket\n"
                "```\n"
            ),
        },
    )
    observations = infer_capabilities(root, [])
    network = [item for item in observations if item.capability == "NETWORK"]
    assert network
    assert network[0].path.startswith("SKILL.md#fence1")
    assert network[0].line == 8


def test_syntax_error_is_ignored(tmp_path: Path) -> None:
    root = make_bundle(tmp_path / "syntax", {"broken.py": "def (:\n"})
    assert infer_capabilities(root, []) == ()


def test_byte_budget_finding(tmp_path: Path) -> None:
    root = make_bundle(tmp_path / "budget", {"huge.py": "import socket\n" * 90_000})
    findings: list[Finding] = []
    infer_capabilities(root, findings)
    assert any(item.rule_id == "SB-BUD-001" for item in findings)


def test_ignored_directories_are_skipped(tmp_path: Path) -> None:
    root = make_bundle(tmp_path / "ignored", {".git/hook.py": "import socket\n"})
    assert _caps(root) == set()


def test_javascript_comments_are_skipped(tmp_path: Path) -> None:
    root = make_bundle(tmp_path / "comment", {"tool.js": "// fetch('https://example.test')\n"})
    assert "NETWORK" not in _caps(root)


def test_observations_are_sorted(tmp_path: Path) -> None:
    root = make_bundle(
        tmp_path / "sorted",
        {"b.py": "import socket\n", "a.py": "import socket\n"},
    )
    observations = infer_capabilities(root, [])
    keys = [(item.path, item.line) for item in observations]
    assert keys == sorted(keys)
