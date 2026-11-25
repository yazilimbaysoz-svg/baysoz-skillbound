# Market research — Baysöz Labs <baysozlabs@proton.me>

Project: `baysoz-skillbound` · Research date: 2026-11-25 · Method: live
`gh search repos`, `gh search issues`, `gh api`, plus a redundancy audit of
`/home/runner/work/_temp/existing-repos.json` (36 prior projects).

## 1. Signal: agent skills became a top-tier supply-chain surface

Live GitHub queries returned a concentrated, high-star cluster:

| Repository | Stars | Open issues | What it does |
| --- | ---: | ---: | --- |
| [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) | 27,641 | 154 | Scans agent skills for prompt injection, data exfiltration, MCP/skill supply-chain risk |
| [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | 7,743 | 26 | Full-stack AI red-teaming: agent, skills, MCP, infra, jailbreak evaluation |
| [snyk/agent-scan](https://github.com/snyk/agent-scan) | 3,278 | 26 | Security scanner for agents, MCP servers and skills |
| [hashgraph-online/hol-guard](https://github.com/hashgraph-online/hol-guard) | 1,124 | — | Runtime blocklist for risky tools, secrets, MCP servers, skills |
| [pipelab-org/pipelock](https://github.com/pipelab-org/pipelock) | 1,023 | — | Agent firewall for MCP/A2A/WebSocket traffic with signed action receipts |

These are not toy repositories: the category leader alone has ~28k stars and
was pushed on the research date. Agent skill bundles are now installed at
scale into developer machines and CI runners, with Markdown instructions,
embedded scripts and MCP configuration acting as executable policy. That makes
the bundle a first-class artifact for red teams and CI gates.

## 2. Pain points mined from open issues (not hypothetical)

The following open issues were read via `gh search issues` on 2026-11-25:

- [SkillSpector#1197](https://github.com/NVIDIA/SkillSpector/issues/1197):
  `return rules` in JavaScript is reported as prompt extraction while the same
  Python function is clean — cross-language semantic inconsistency.
- [SkillSpector#1174](https://github.com/NVIDIA/SkillSpector/issues/1174):
  OSV advisory query batches are never packed across calls, so later
  dependency files lose advisory coverage — incomplete evidence.
- [SkillSpector#1165](https://github.com/NVIDIA/SkillSpector/issues/1165):
  bounded static parser reports limits on valid JS template literals, shell
  builtins, XML fixtures and f-strings — parser false positives.
- [SkillSpector#1157](https://github.com/NVIDIA/SkillSpector/issues/1157):
  `AS2` misses MCP config reads via `expanduser`, `Path.home` or `HOME`.
- [SkillSpector#1149](https://github.com/NVIDIA/SkillSpector/issues/1149):
  `P1` misses "your/the/any/prior" in "Ignore your previous instructions" —
  exactly the linguistic gap our multilingual directive engine closes.
- [SkillSpector#1147](https://github.com/NVIDIA/SkillSpector/issues/1147):
  least-privilege and tool-poisoning analyzers skip `.mcp.json` project config.
- [SkillSpector#1141](https://github.com/NVIDIA/SkillSpector/issues/1141):
  symlinks inside bundles and symlink creation in scripts are never reported.
- [SkillSpector#1139](https://github.com/NVIDIA/SkillSpector/issues/1139):
  vendored wheels are blanket-flagged as concealed executables.
- [SkillSpector#1113](https://github.com/NVIDIA/SkillSpector/issues/1113):
  static prompt-injection patterns only match English wording.
- [SkillSpector#1112](https://github.com/NVIDIA/SkillSpector/issues/1112):
  the reviewed artifact differs from the installed artifact — provenance drift.
- [SkillSpector#1189](https://github.com/NVIDIA/SkillSpector/issues/1189) and
  [#1196](https://github.com/NVIDIA/SkillSpector/issues/1196): false positives
  from single-space markers and benign "send to" wording — evidence quality
  matters more than rule count.
- [SkillSpector#1175](https://github.com/NVIDIA/SkillSpector/issues/1175) and
  [#1160](https://github.com/NVIDIA/SkillSpector/issues/1160): configurable
  byte/time budgets and analysis-completeness accounting are operational
  requirements, not nice-to-haves.

Adjacent ecosystem signals confirm the same theme of parser/profile
divergence and identity trust:

- [mcp-radar#608](https://github.com/Danyw24/mcp-radar/issues/608): OAuth
  redirect-URI validation bypass in FastMCP (2026-11-22).
- [mcp-radar#553](https://github.com/Danyw24/mcp-radar/issues/553) and
  [RustSecJP/incidents#186](https://github.com/RustSecJP/incidents/issues/186):
  DNS rebinding in MCP servers (`RUSTSEC-2026-0189`, `rmcp`).
- [Hackmanit/Web-Cache-Vulnerability-Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)
  (1,214 stars) shows differential-parser red teaming is valued in appsec.
- [anchore/grype](https://github.com/anchore/grype) (13,345 stars) and
  [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track)
  (4,520 stars) show that SBOM/artifact analysis is a durable category, but
  neither models the *declared-vs-observed capability contract* of an agent
  skill.

## 3. Gap analysis against prior Baysöz Labs work

The 36 existing repositories already cover Kubernetes CEL/NetworkPolicy/Gateway
routing, GraphQL cost, JOSE confusion, SSRF canonicalization, HTTP desync,
PromQL, OTel cardinality, Terraform blast radius, GitHub Actions lockfiles,
MCP tool contracts, Python CVE reachability, archive confinement, log masking
and several env-file utilities. Rebuilding any of those would be redundant.

`baysoz-skillbound` is distinct:

- `baysoz-mcpcontract` gates **MCP tool schemas**; this gates **agent skill
  bundles** (Markdown instructions + embedded source + MCP config + symlinks)
  and their *declared permission contract*.
- `baysoz-reachoracle` maps **CVE reachability**; this maps **capability
  reachability** from source to contract, with no advisory database.
- `baysoz-archivebound` confines **archive extraction**; this confines
  **symlink resolution inside an installed skill directory**.
- `baysoz-logmask` masks PII in logs; this detects instructions that request
  disclosure of credentials or hidden prompts.

## 4. Product thesis for 2026-2027

1. **Contract-first, not pattern-first.** Declare `FILESYSTEM_READ`, prove it
   statically, fail on drift. This inverts the false-positive economics seen
   in issue #1139 and #1196.
2. **Evidence-grade output.** Every finding carries file, line, column,
   matched text and a stable SHA-256 fingerprint; SARIF 2.1.0 is a first-class
   output for CI adoption.
3. **Cross-language parity.** Python uses `ast`; JS/TS, Go and shell use
   comment-aware token rules; Markdown fenced blocks are analyzed with real
   line offsets — a direct answer to #1197, #1149 and #1113.
4. **Boundary integrity.** Symlink targets are resolved against the bundle
   root; external links are critical unless explicitly allowed (#1141).
5. **Operational determinism.** No network, no LLM, no heavy services, byte
   budgets, sorted outputs and pinned fingerprints. `uv` + Python 3.13 keep
   the developer loop reproducible.
6. **Red-team handoff.** `skillbound probe` compiles each observed finding
   into an executable-style probe plan with explicit expected outcomes, so
   findings translate into test cases without hallucinated payloads.

## 5. Decision

Build `baysoz-skillbound` as a MIT-licensed Python 3.13 CLI/library by
**Baysöz Labs** <baysozlabs@proton.me>. It is deep enough for production CI,
grounded in measurable 2026 ecosystem pain, and non-redundant with the
existing portfolio.
