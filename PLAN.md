# Plan — Baysöz Labs <baysozlabs@proton.me>

Project: `baysoz-skillbound` · Owner: Baysöz Labs <baysozlabs@proton.me>

## Phase 0 — Research (complete)

- Audited 36 existing repositories to eliminate redundancy.
- Mined live GitHub stars/issues across agent-security scanners and adjacent
  appsec tools; captured 11+ concrete open-issue pain points.
- Selected the declared-vs-observed capability contract gap for skill bundles.

## Phase 1 — Core engine (complete)

- `model.py`: findings, observations, manifest, report, severity catalog.
- `manifest.py`: safe front-matter parser + TOML policy validation.
- `capabilities.py`: Python AST, JS/TS/Go/shell regex, Markdown fences,
  byte budgets.
- `instruction.py`: multilingual directive and exfiltration detection.
- `paths.py`: symlink escape/dangling checks.
- `engine.py`: deterministic orchestration and contract evaluation.

## Phase 2 — Interfaces (complete)

- `cli.py`: `scan`, `probe`, `rules`; text/JSON/SARIF; threshold exit codes.
- `sarif.py`: SARIF 2.1.0 with SHA-256 fingerprints.
- `probes.py`: adversarial probe plan derived from observed evidence.

## Phase 3 — Quality gates (active)

- `uv venv`, `uv pip install -e .`, `uv pip install pytest`, `uv run pytest -q`.
- `ruff check --select E,F,W,S,B .` — zero findings.
- `semgrep --config p/default --error .` — zero findings.
- CI workflow reproduces all gates on Python 3.13 with `uv`.

## Phase 4 — Supreme Grand Jury Tribunal (complete: UNANIMOUS PASS)

- Live CLI runs against hostile, multilingual and clean-control bundles at
  `/tmp/opencode/skillbound-demo` verified undeclared capabilities, Turkish and
  German overrides, external exfiltration endpoints, cross-language network
  and write capabilities, and an escaping symlink.
- Every emitted finding and observation was programmatically checked against
  the real file line (or symlink target) at the reported position; every probe
  target maps back to a real finding/observation and carries a 64-char SHA-256
  fingerprint; SARIF fingerprints and rule IDs were validated.
- Verdict: Capability juror PASS · Instruction juror PASS · Boundary juror
  PASS · Determinism juror PASS · Evidence juror PASS.
- Zero hallucinated findings, zero stubs, unanimous PASS.

## Phase 5 — Release

- Publish `yazilimbaysoz-svg/baysoz-skillbound` as a public repository with
  crisp description and topics.
- Write the factory result JSON without touching unrelated showcase files.

## Backlog (deliberately out of scope for 0.1.0)

- MCP server config graph resolution across multiple project files.
- SARIF baseline suppression files with reviewer identity.
- Additional language front ends (Rust, C++23) behind the same observation
  model.

Maintained by Baysöz Labs <baysozlabs@proton.me>.
