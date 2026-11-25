# Changelog — Baysöz Labs <baysozlabs@proton.me>

All notable changes to `baysoz-skillbound` are documented here.
Maintainer: **Baysöz Labs <baysozlabs@proton.me>**.

## [0.1.0] — 2026-11-25

### Added

- Safe `SKILL.md` front-matter parser and `.skillbound.toml` policy support.
- Capability inference for Python (`ast`), JavaScript/TypeScript, Go, shell,
  and fenced code blocks in Markdown with real line offsets.
- Multilingual instruction-override, credential-disclosure, hidden-prompt,
  tool-poisoning and external-exfiltration detection.
- Symlink escape and dangling-link checks against the bundle boundary.
- Declared-vs-observed capability contract evaluation with stable severity.
- `skillbound scan`, `skillbound probe`, `skillbound rules` commands with
  text, JSON and SARIF 2.1.0 output and threshold-based exit codes.
- Deterministic SHA-256 finding fingerprints for CI triage.
- CI workflow, MIT license, architecture, market research and security policy.

### Notes

- Zero network calls, zero services, zero local LLMs.
- Python 3.13+, installed and tested with `uv`.

© Baysöz Labs <baysozlabs@proton.me>.
