# Architecture — Baysöz Labs <baysozlabs@proton.me>

Project: `baysoz-skillbound` · Version 0.1.0 · Python 3.13+

## 1. System shape

```
src/skillbound/
  __init__.py     public version + attribution
  __main__.py     python -m skillbound entry point
  model.py        Finding, Observation, Manifest, BundleReport, severity catalog
  manifest.py     safe SKILL.md front-matter + .skillbound.toml policy parser
  capabilities.py Python AST + JS/TS/Go/shell + Markdown-fence inference
  instruction.py  multilingual instruction/exfiltration directive scanner
  paths.py        symlink resolution and bundle-boundary checks
  engine.py       orchestration + declared/observed contract evaluation
  sarif.py        SARIF 2.1.0 emitter
  probes.py       evidence-backed adversarial probe-plan compiler
  cli.py          argparse commands and exit-code policy
```

The dependency graph is strictly layered: `model` → domain modules →
`engine` → `sarif`/`probes` → `cli`. No module reaches the network, imports a
model, spawns a process, or reads outside the analyzed root except for an
explicit `--policy` path and symlink target resolution.

## 2. Analysis pipeline

1. **Manifest load.** `manifest.py` reads YAML-style front matter from
   `SKILL.md` with a hand-written, non-executing scalar/list parser (no
   `eval`, no `yaml.load`) and merges `[policy]` from `.skillbound.toml` via
   `tomllib`. Capability tokens are normalized (`"file-system write"` →
   `FILE_SYSTEM_WRITE`).
2. **Capability inference.** Python sources are parsed with `ast`; imports,
   calls, attribute chains, `os.environ` subscripts and URL literals become
   typed observations with file/line/column. JS/TS, Go and shell use
   comment-aware regex rules with real line numbers. Fenced code blocks in
   Markdown are analyzed with their original line offsets preserved. Files
   over 1 MiB are recorded as `SB-BUD-001` rather than silently skipped.
3. **Instruction integrity.** Prose lines (fenced code masked, line positions
   preserved) are matched against English, Turkish and German override,
   credential, hidden-prompt and tool-metadata poisoning patterns. External
   URLs within 100 characters of a send-like verb become `SB-INS-002`;
   loopback hosts are excluded.
4. **Boundary integrity.** Every symlink under the bundle root is resolved;
   targets outside the root produce a critical finding unless policy opts in.
   Dangling links produce a low finding.
5. **Contract evaluation.** Observed capabilities beyond the declaration
   produce severity-ranked `SB-CAP-001`; declarations without evidence produce
   `SB-CAP-002`; forbidden capabilities and contradictory contracts produce
   `SB-CAP-003`. Findings are sorted by severity rank, rule id, path, line and
   evidence for byte-stable output.
6. **Rendering.** `text`, `json` and `sarif` are pure functions of the report.
   SARIF results carry SHA-256 partial fingerprints and full evidence in
   properties. `probe` is derived from the same findings and observations, so
   every probe cites a real artifact; nothing is generated from a model.

## 3. Trust model

- The analyzed bundle is untrusted. Source text is parsed as data; no code
  from the bundle is imported or executed.
- Symlinks are read with `Path.readlink()` and resolved lexically; target
  contents are never opened by this tool.
- Policy TOML is parsed with `tomllib` and validated; unknown capability
  tokens are reported, not silently trusted.
- Output files are written only when `--output` is supplied.

## 4. Determinism and CI contract

- No timestamps, no random IDs, no absolute environment-dependent paths
  inside findings (the report root is the resolved bundle path).
- Exit codes: `0` clean under threshold, `1` threshold met, `2` input error.
- `--fail-on never` is available for report-only pipelines.
- Stable fingerprints allow CI systems to distinguish new regressions from
  known accepted findings.

## 5. Non-goals

No dynamic execution of skill code, no LLM judging, no registry access, no
advisory feed, no daemon, no database. Differential HTTP/MCP/SSRF analysis is
covered by other Baysöz Labs tools; this project stays focused on the skill
bundle artifact and its declared permission contract.

## 6. Baysöz Labs attribution

All public files, package metadata, CLI `--help`, CLI `--version`, report
payloads and SARIF tool metadata explicitly attribute
**Baysöz Labs <baysozlabs@proton.me>**.
