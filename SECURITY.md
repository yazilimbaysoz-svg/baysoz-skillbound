# Security — Baysöz Labs <baysozlabs@proton.me>

Project: `baysoz-skillbound` · Maintainer: <baysozlabs@proton.me>

## Supported versions

| Version | Status |
| --- | --- |
| 0.1.x | Supported |

## Reporting a vulnerability

Email **<baysozlabs@proton.me>** with a description, reproduction bundle,
affected version and impact assessment. Do not open a public issue for an
exploitable finding. Baysöz Labs will acknowledge receipt and coordinate a fix
and disclosure timeline with the reporter.

## Security design commitments

- **No code execution from analyzed bundles.** Python is parsed with `ast`;
  other languages are scanned as text. No `eval`, `exec`, `import` of bundle
  modules, or subprocess invocation of bundle scripts.
- **No network access.** The CLI does not resolve, fetch or post to any
  endpoint. URL strings are inspected as evidence only.
- **No local LLM.** Detection is deterministic pattern and AST analysis.
- **Confinement.** Symlink targets are resolved against the bundle root;
  external targets are critical findings unless explicitly allowed by policy.
- **Safe parsing.** Front matter is a restricted key/value subset; TOML uses
  the standard library `tomllib`. Files above 1 MiB are reported rather than
  read into the analyzer.
- **Non-secret output.** Evidence is clipped to 160 characters; findings do
  not emit file contents beyond the matched line fragment.
- **Fail-closed CI.** Findings at or above `--fail-on` (default `high`) exit
  with status 1; malformed input exits with status 2.

## Residual risk

Static analysis cannot prove absence of behaviour hidden by obfuscation,
native binaries or generated code. `skillbound` is a gate, not a sandbox.
Use it together with runtime isolation and human review for untrusted skills.

## Attribution

Security contact and copyright: **Baysöz Labs <baysozlabs@proton.me>**.
No legal entity suffix is used.
