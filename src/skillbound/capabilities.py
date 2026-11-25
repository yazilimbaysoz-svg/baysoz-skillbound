"""Multi-language static capability inference for skill bundles.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import ast
import re
from dataclasses import replace
from pathlib import Path

from .model import CapabilityObservation, Finding, Severity

MAX_FILE_BYTES = 1024 * 1024
IGNORED_DIRS = frozenset(
    {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache", ".ruff_cache"}
)
CODE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".sh", ".bash"})
FENCE_SUFFIXES = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "go": ".go",
    "bash": ".sh",
    "shell": ".sh",
    "sh": ".sh",
}
URL_RE = re.compile(r"https?://[^\s\"'<>)`\]]+", re.IGNORECASE)
CREDENTIAL_RE = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key)", re.I
)

PY_IMPORT_CAPABILITIES = {
    "socket": "NETWORK",
    "urllib": "NETWORK",
    "http": "NETWORK",
    "requests": "NETWORK",
    "httpx": "NETWORK",
    "aiohttp": "NETWORK",
    "ftplib": "NETWORK",
    "smtplib": "NETWORK",
    "shutil": "FILESYSTEM_WRITE",
    "tempfile": "FILESYSTEM_WRITE",
    "subprocess": "PROCESS_EXEC",
    "keyring": "CREDENTIAL_ACCESS",
    "importlib": "DYNAMIC_CODE",
}

PY_CALL_CAPABILITIES = {
    "read_text": "FILESYSTEM_READ",
    "read_bytes": "FILESYSTEM_READ",
    "readlines": "FILESYSTEM_READ",
    "write_text": "FILESYSTEM_WRITE",
    "write_bytes": "FILESYSTEM_WRITE",
    "writelines": "FILESYSTEM_WRITE",
    "mkdir": "FILESYSTEM_WRITE",
    "rmdir": "FILESYSTEM_WRITE",
    "unlink": "FILESYSTEM_WRITE",
    "rmtree": "FILESYSTEM_WRITE",
    "copyfile": "FILESYSTEM_WRITE",
    "copytree": "FILESYSTEM_WRITE",
    "move": "FILESYSTEM_WRITE",
    "rename": "FILESYSTEM_WRITE",
    "replace": "FILESYSTEM_WRITE",
    "remove": "FILESYSTEM_WRITE",
    "getenv": "ENV_ACCESS",
    "system": "PROCESS_EXEC",
    "popen": "PROCESS_EXEC",
    "eval": "DYNAMIC_CODE",
    "exec": "DYNAMIC_CODE",
    "compile": "DYNAMIC_CODE",
    "import_module": "DYNAMIC_CODE",
}

PY_DOTTED_CAPABILITIES = (
    ("requests.", "NETWORK"),
    ("httpx.", "NETWORK"),
    ("urllib.request.", "NETWORK"),
    ("socket.", "NETWORK"),
    ("os.environ", "ENV_ACCESS"),
    ("subprocess.", "PROCESS_EXEC"),
    ("keyring.", "CREDENTIAL_ACCESS"),
)

TEXT_RULES: dict[str, tuple[tuple[str, str, str], ...]] = {
    ".js": (
        (
            r"\b(?:fetch|XMLHttpRequest|WebSocket|net\.connect|https?\.request)\b",
            "NETWORK",
            "network API call",
        ),
        (
            r"\brequire\(\s*['\"](?:fs|node:fs|fs/promises|http|https|net)['\"]",
            "FILESYSTEM_READ",
            "node module import",
        ),
        (r"\bfs\.(?:readFile|readFileSync|readdir)\b", "FILESYSTEM_READ", "fs read call"),
        (
            r"\bfs\.(?:writeFile\w*|appendFile\w*|unlink|mkdir|rm\w*)",
            "FILESYSTEM_WRITE",
            "fs write call",
        ),
        (r"\bprocess\.env\b", "ENV_ACCESS", "environment access"),
        (
            r"\b(?:child_process|execSync|exec\(|spawn\(|execFile\()",
            "PROCESS_EXEC",
            "child process call",
        ),
        (r"\b(?:eval\(|new Function\()", "DYNAMIC_CODE", "dynamic code call"),
    ),
    ".go": (
        (r"\"net/http\"|\"net\"|\"net/url\"", "NETWORK", "network package import"),
        (r"\bhttp\.(?:Get|Post|Do|NewRequest)\b", "NETWORK", "http client call"),
        (r"\bos\.(?:Open|ReadFile|ReadDir)\b", "FILESYSTEM_READ", "os read call"),
        (r"\bos\.(?:WriteFile|Mkdir|Remove|Create)\b", "FILESYSTEM_WRITE", "os write call"),
        (r"\bos\.Getenv\b|\bos\.LookupEnv\b", "ENV_ACCESS", "environment access"),
        (r"\"os/exec\"|\bexec\.Command\b", "PROCESS_EXEC", "os/exec call"),
    ),
    ".sh": (
        (r"(?<!://)\b(?:curl|wget|nc|ncat|scp|rsync)\b", "NETWORK", "network CLI"),
        (
            r"(?:\b(?:tee|rm|mv|cp|install|dd)\s|>>?\s*\S)",
            "FILESYSTEM_WRITE",
            "filesystem mutation CLI",
        ),
        (r"\b(?:cat|head|tail|grep)\s+[~/]", "FILESYSTEM_READ", "filesystem read CLI"),
        (
            r"(?:\$\{?[A-Z][A-Z0-9_]*\}?|\bprintenv\b|\benv\b)",
            "ENV_ACCESS",
            "environment reference",
        ),
        (r"\$\(|`", "PROCESS_EXEC", "command substitution"),
    ),
}
TEXT_RULES[".ts"] = TEXT_RULES[".js"]
TEXT_RULES[".tsx"] = TEXT_RULES[".js"]
TEXT_RULES[".mjs"] = TEXT_RULES[".js"]
TEXT_RULES[".cjs"] = TEXT_RULES[".js"]
TEXT_RULES[".bash"] = TEXT_RULES[".sh"]


def _rel(root: Path, path: str) -> str:
    return path if "#" in path else str(Path(path).relative_to(root))


def _evidence(line: str) -> str:
    return line.strip()[:160]


def _add(
    observations: list[CapabilityObservation],
    capability: str,
    path: str,
    line: int,
    column: int,
    evidence: str,
    mechanism: str,
) -> None:
    observations.append(CapabilityObservation(capability, path, line, column, evidence, mechanism))


def _python_call_name(node: ast.AST) -> tuple[str, str]:
    if isinstance(node, ast.Name):
        return node.id, node.id
    if isinstance(node, ast.Attribute):
        try:
            dotted = ast.unparse(node)
        except (ValueError, TypeError):
            dotted = node.attr
        return node.attr, dotted
    return "", ""


def _python_walk(tree: ast.Module, path: str, observations: list[CapabilityObservation]) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                capability = PY_IMPORT_CAPABILITIES.get(alias.name.split(".")[0])
                if capability:
                    _add(
                        observations,
                        capability,
                        path,
                        node.lineno,
                        node.col_offset + 1,
                        f"import {alias.name}",
                        "python import",
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            capability = PY_IMPORT_CAPABILITIES.get(node.module.split(".")[0])
            if capability:
                _add(
                    observations,
                    capability,
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    f"from {node.module} import ...",
                    "python import",
                )
        elif isinstance(node, ast.Call):
            name, dotted = _python_call_name(node.func)
            capability = PY_CALL_CAPABILITIES.get(name)
            if name == "open":
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for keyword in node.keywords:
                    if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                        mode = str(keyword.value.value)
                capability = (
                    "FILESYSTEM_WRITE"
                    if any(flag in mode for flag in "wax+")
                    else "FILESYSTEM_READ"
                )
            if name == "run" and dotted.startswith("subprocess."):
                capability = "PROCESS_EXEC"
            for prefix, mapped in PY_DOTTED_CAPABILITIES:
                if dotted.startswith(prefix):
                    capability = mapped
                    break
            if capability:
                _add(
                    observations,
                    capability,
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    dotted[:160],
                    "python call",
                )
            if name == "getenv" and node.args and isinstance(node.args[0], ast.Constant):
                if CREDENTIAL_RE.search(str(node.args[0].value)):
                    _add(
                        observations,
                        "CREDENTIAL_ACCESS",
                        path,
                        node.lineno,
                        node.col_offset + 1,
                        dotted[:160],
                        "credential environment lookup",
                    )
        elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            if ast.unparse(node.value) == "os.environ" and isinstance(node.slice, ast.Constant):
                _add(
                    observations,
                    "ENV_ACCESS",
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    f"os.environ[{node.slice.value!r}]"[:160],
                    "environment access",
                )
                if CREDENTIAL_RE.search(str(node.slice.value)):
                    _add(
                        observations,
                        "CREDENTIAL_ACCESS",
                        path,
                        node.lineno,
                        node.col_offset + 1,
                        f"os.environ[{node.slice.value!r}]"[:160],
                        "credential environment lookup",
                    )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = URL_RE.search(node.value)
            if match:
                _add(
                    observations,
                    "NETWORK",
                    path,
                    node.lineno,
                    node.col_offset + 1,
                    match.group(0)[:160],
                    "embedded URL literal",
                )


def _comment_prefix(suffix: str) -> str:
    return "#" if suffix in {".sh", ".bash"} else "//"


def _text_walk(
    text: str,
    suffix: str,
    path: str,
    observations: list[CapabilityObservation],
) -> None:
    rules = TEXT_RULES.get(suffix, ())
    if not rules:
        return
    in_block = False
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if in_block:
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("/*"):
            in_block = "*/" not in stripped
            continue
        prefix = _comment_prefix(suffix)
        if stripped.startswith(prefix) or stripped.startswith("*"):
            continue
        for pattern, capability, mechanism in rules:
            match = re.search(pattern, stripped, re.IGNORECASE)
            if match:
                _add(
                    observations,
                    capability,
                    path,
                    line_number,
                    match.start() + 1,
                    _evidence(stripped),
                    mechanism,
                )
        if suffix in {".sh", ".bash"}:
            continue
        match = URL_RE.search(stripped)
        if match:
            _add(
                observations,
                "NETWORK",
                path,
                line_number,
                match.start() + 1,
                match.group(0)[:160],
                "embedded URL literal",
            )


def _fenced_blocks(text: str) -> list[tuple[str, str, int]]:
    blocks: list[tuple[str, str, int]] = []
    current: list[str] = []
    language = ""
    start_line = 1
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            if current or language:
                suffix = FENCE_SUFFIXES.get(language.lower())
                if suffix:
                    blocks.append((suffix, "\n".join(current), start_line))
                current = []
                language = ""
            else:
                language = line.strip()[3:].strip().split(maxsplit=1)[0]
                start_line = number + 1
            continue
        if current or language:
            current.append(line)
    return blocks


def infer_in_text(
    text: str,
    suffix: str,
    path: str,
    observations: list[CapabilityObservation],
    line_offset: int = 0,
) -> None:
    """Infer capabilities from one source text and append observations."""

    before = len(observations)
    if suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return
        _python_walk(tree, path, observations)
    else:
        _text_walk(text, suffix, path, observations)
    if line_offset:
        for index in range(before, len(observations)):
            item = observations[index]
            observations[index] = replace(item, line=item.line + line_offset)


def infer_capabilities(root: Path, findings: list[Finding]) -> tuple[CapabilityObservation, ...]:
    """Infer all observable capabilities of a skill bundle."""

    observations: list[CapabilityObservation] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in CODE_SUFFIXES and suffix != ".md":
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                findings.append(
                    Finding(
                        rule_id="SB-BUD-001",
                        severity=Severity.MEDIUM,
                        path=_rel(root, str(path)),
                        line=1,
                        message=(
                            f"File is {path.stat().st_size} bytes and exceeds the "
                            f"{MAX_FILE_BYTES} byte budget"
                        ),
                        tags=("budget",),
                    )
                )
                continue
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        relative = _rel(root, str(path))
        if suffix == ".md":
            for index, (fence_suffix, content, start) in enumerate(_fenced_blocks(text), 1):
                infer_in_text(
                    content,
                    fence_suffix,
                    f"{relative}#fence{index}",
                    observations,
                    start - 1,
                )
        else:
            infer_in_text(text, suffix, relative, observations)
    return tuple(
        sorted(
            observations,
            key=lambda item: (item.path, item.line, item.capability, item.evidence),
        )
    )
