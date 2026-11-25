"""Safe, dependency-free manifest and policy parsing.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from .model import (
    ATTRIBUTION,
    CAPABILITY_DESCRIPTIONS,
    Finding,
    Manifest,
    Severity,
)

MAX_MANIFEST_BYTES = 256 * 1024
DECLARED_KEYS = frozenset(
    {"capabilities", "allowed-capabilities", "allowed_capabilities", "permissions"}
)
FORBIDDEN_KEYS = frozenset({"forbidden-capabilities", "forbidden_capabilities"})
DESCRIPTION_KEYS = frozenset({"description", "summary"})
NAME_KEYS = frozenset({"name", "id"})


def normalize_capability(raw: str) -> str:
    """Normalize a capability token to its uppercase canonical identifier."""

    return raw.strip().strip("'\"").upper().replace("-", "_").replace(" ", "_")


def _strip_comment(value: str) -> str:
    quote = ""
    for index, char in enumerate(value):
        if char in "\"'":
            quote = "" if quote == char else (quote or char)
        elif char == "#" and not quote:
            return value[:index].strip()
    return value.strip()


def _parse_list(value: str) -> list[str]:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    elif value and not value.startswith("["):
        return [value.strip("'\"")]
    return [item.strip().strip("'\"") for item in value.split(",") if item.strip()]


def _parse_front_matter(text: str) -> dict[str, object]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("SKILL.md does not start with YAML front matter")
    end = next(
        (index for index, line in enumerate(lines[1:], 1) if line.strip() == "---"),
        None,
    )
    if end is None:
        raise ValueError("unterminated SKILL.md front matter")
    fields: dict[str, object] = {}
    current = ""
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current:
            existing = fields.get(current, [])
            if not isinstance(existing, list):
                raise ValueError(f"list item for scalar field {current!r}")
            existing.append(_strip_comment(stripped[2:]).strip("'\""))
            continue
        if ":" not in stripped:
            raise ValueError(f"invalid front-matter line: {stripped!r}")
        key, raw = stripped.split(":", 1)
        current = key.strip().lower()
        if current in DECLARED_KEYS or current in FORBIDDEN_KEYS:
            fields[current] = _parse_list(_strip_comment(raw))
        else:
            fields[current] = _strip_comment(raw)
    return fields


def locate_token(root: Path, token: str) -> tuple[int, str]:
    """Return the real manifest line that mentions a capability token."""

    for name in ("SKILL.md", "skill.md"):
        path = root / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, 1):
            if token.upper() in line.upper():
                return number, line.strip()[:160]
    return 1, ""


def _validate_capabilities(
    root: Path,
    values: list[str],
    fields: dict[str, object],
    key: str,
    findings: list[Finding],
) -> frozenset[str]:
    normalized = {normalize_capability(item) for item in values}
    invalid = sorted(normalized - set(CAPABILITY_DESCRIPTIONS))
    for item in invalid:
        line, evidence = locate_token(root, item)
        findings.append(
            Finding(
                rule_id="SB-MAN-002",
                severity=Severity.MEDIUM,
                path="SKILL.md",
                line=line,
                message=f"Unknown capability token {item!r} in {key}",
                evidence=evidence,
                remediation="Use a capability from the published catalog (`skillbound rules`).",
                tags=("manifest",),
            )
        )
    invalid = normalized - set(CAPABILITY_DESCRIPTIONS)
    valid = normalized - invalid
    fields[key] = sorted(valid)
    return frozenset(valid)


def _read_bundle_manifest(root: Path, findings: list[Finding]) -> dict[str, object]:
    candidates = sorted(root.glob("SKILL.md")) + sorted(root.glob("skill.md"))
    if not candidates:
        candidates = sorted(root.glob("*/SKILL.md"))
    if not candidates:
        findings.append(
            Finding(
                rule_id="SB-MAN-001",
                severity=Severity.HIGH,
                path="SKILL.md",
                line=1,
                message="No SKILL.md manifest found in the skill bundle",
                remediation="Add SKILL.md with front matter declaring capabilities.",
                tags=("manifest",),
            )
        )
        return {}
    path = candidates[0]
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        findings.append(
            Finding(
                rule_id="SB-BUD-001",
                severity=Severity.MEDIUM,
                path=str(path.relative_to(root)),
                line=1,
                message=(
                    f"Manifest is {size} bytes and exceeds the {MAX_MANIFEST_BYTES} byte budget"
                ),
                tags=("budget",),
            )
        )
        return {}
    try:
        return _parse_front_matter(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, OSError) as exc:
        findings.append(
            Finding(
                rule_id="SB-MAN-002",
                severity=Severity.HIGH,
                path=str(path.relative_to(root)),
                line=1,
                message=f"Cannot parse front matter: {exc}",
                remediation="Use a '---' delimited key/value front-matter block.",
                tags=("manifest",),
            )
        )
        return {}


def _read_policy(root: Path, findings: list[Finding], override: Path | None) -> dict[str, object]:
    path = override or root / ".skillbound.toml"
    if not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as exc:
        findings.append(
            Finding(
                rule_id="SB-MAN-002",
                severity=Severity.MEDIUM,
                path=str(path),
                line=1,
                message=f"Cannot parse policy TOML: {exc}",
                tags=("manifest",),
            )
        )
        return {}
    policy = data.get("policy", {})
    return policy if isinstance(policy, dict) else {}


def load_manifest(root: Path, findings: list[Finding], override: Path | None = None) -> Manifest:
    """Load the declared capability contract from SKILL.md and policy TOML."""

    fields = _read_bundle_manifest(root, findings)
    policy = _read_policy(root, findings, override)

    declared_values: list[str] = []
    for key in DECLARED_KEYS:
        value = fields.get(key, [])
        if isinstance(value, list):
            declared_values.extend(str(item) for item in value)
        elif isinstance(value, str) and value:
            declared_values.append(value)
    policy_declared = policy.get("declared", [])
    if isinstance(policy_declared, list):
        declared_values.extend(str(item) for item in policy_declared)

    forbidden_values: list[str] = []
    for key in FORBIDDEN_KEYS:
        value = fields.get(key, [])
        if isinstance(value, list):
            forbidden_values.extend(str(item) for item in value)
    policy_forbidden = policy.get("forbidden", [])
    if isinstance(policy_forbidden, list):
        forbidden_values.extend(str(item) for item in policy_forbidden)

    declared = _validate_capabilities(root, declared_values, fields, "capabilities", findings)
    forbidden = _validate_capabilities(
        root, forbidden_values, fields, "forbidden_capabilities", findings
    )

    name = ""
    description = ""
    for key in NAME_KEYS:
        value = fields.get(key)
        if isinstance(value, str) and value:
            name = value
            break
    for key in DESCRIPTION_KEYS:
        value = fields.get(key)
        if isinstance(value, str) and value:
            description = value
            break

    allow_external = policy.get("allow_external_symlinks", False)
    return Manifest(
        name=name or root.name,
        description=description,
        declared=declared,
        forbidden=forbidden,
        allow_external_symlinks=allow_external is True,
    )


def manifest_attribution() -> str:
    """Return the mandatory Baysöz Labs attribution string."""

    return ATTRIBUTION
