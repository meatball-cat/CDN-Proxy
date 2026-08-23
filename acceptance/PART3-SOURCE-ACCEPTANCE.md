# Part 3 Source Acceptance — Phase 5–6

This document is the auditable requirement matrix and execution record for the
Phase 5–6 source-only candidate. It does not claim installation, real runtime,
staging, infrastructure access, or product acceptance.

## Scope boundary

- Authorized: source, tests, package construction, and hermetic lifecycle/loader
  checks using temporary roots and fake adapters.
- Forbidden in this round: real 3x-ui, SSH origin, Cloudflare, DNS, Nginx,
  Keychain, production adapters, real credentials, authenticated staging
  traffic, and staging E2E.
- A green hermetic source suite is not evidence of a real run.

## Hard prerequisite gate

| Check | Exit | Actual result |
|---|---:|---|
| `git status --short` | 0 | PASS — empty output |
| `git diff --check` | 0 | PASS — empty output |
| `git log -1 --oneline` | 0 | PASS — `3b5db3e chore(phase2): align phase 0-4 metadata` |
| `shasum -a 256 -c SHA256SUMS.txt` | 0 | PASS — all eight frozen handoff files reported `OK` |
| `node validation/spec-invariants.cjs --all` | 0 | PASS — 19 invariants plus all mutation controls, trajectories, and attack cases |

## Requirement matrix

`NOT_EXECUTED` is intentional until the named current-candidate evidence has
actually run. A row can become `PASS` only from its mapped behavior test, not
from an unrelated full-suite result.

| 冻结需求 ID | 原文位置 | 实现文件 | 正向测试 | 负向控制 | 实际结果 |
|---|---|---|---|---|---|
| P5-HOOK-01 | `01` §10; `03` §3; `05` §2.5 | `hooks/hooks.json`; `hooks/catalog.cjs`; `hooks/handler.cjs` | exact six-event order and command-only config | `hook-catalog-event` | PASS — exact ordered six-event catalog and command-only handlers |
| P5-HOOK-02 | `03` §2 | `hooks/hooks.json`; `hooks/trust.cjs` | default discovery, session-cwd independence, fixed plugin-root resolution | untrusted plugin root and missing env cases | PASS — installed root succeeds from unrelated cwd; absent/wrong root is fixed fail-closed |
| P5-HOOK-03 | `03` §4 | `hooks/trust.cjs`; `lifecycle/activeset.cjs` | manifest/config/script/layout/Node/owner/mode/symlink trust tuple | wrong owner/runtime identity and layout drift | PASS — receipt, Node, owner, mode, and symlink drift all returned `HOOK_UNAVAILABLE` |
| P5-HOOK-04 | `03` §§4–5 | `hooks/handler.cjs`; `hooks/redaction.cjs` | closed JSON, bounded stdin/depth, fixed masked output | malformed/oversized/unknown event | PASS — one bounded JSON output, empty stderr, no input echo |
| P5-HOOK-05 | `03` §§3, 6 | `hooks/policy.cjs` | active `cdn-node` call is reported without granting server authority | deferred Tool, second server, arbitrary command/path, production-adapter selector | PASS — all non-active or execution-shaped calls denied |
| P5-HOOK-06 | `03` §§3, 6–7 | `hooks/policy.cjs`; `hooks/state.cjs` | plan/challenge and close projection consistency | `hook-authority-widening` | PASS — matching projection only requests host decision; mismatch denies; Hook never allows |
| P5-HOOK-07 | `03` §§3, 5 | `hooks/redaction.cjs`; `hooks/state.cjs` | safe structured result projection | `hook-output-leak` | PASS — schema-valid results project; synthetic deployment-shaped output blocks with fixed text |
| P5-HOOK-08 | `03` §7 | `hooks/policy.cjs`; `hooks/state.cjs` | Stop reports only cached redacted server facts and insufficient-evidence boundary | incomplete/stale/recursive Stop cases | PASS — server enums project; completion is not acceptance; recursion and missing evidence stop safely |
| P5-HOOK-09 | `03` §§3, 8 | `hooks/state.cjs` | SessionEnd only cleans Hook-owned bounded temporary records | foreign/product data preservation | PASS — Hook state removed; foreign and product data preserved byte-for-byte |
| P5-HOOK-10 | `03` §8 | `hooks/state.cjs` | canonical replay and exclusive lock behavior | duplicate/reordered/concurrent events | PASS — duplicate no-op, reordered approval denied, four concurrent Stop handlers bounded |
| P5-HOOK-11 | `01` §5; `03` §§1, 6 | all `hooks/*.cjs` | Hook module import/spawn registry has no network, shell, broker, second MCP, or adapter call | `hook-authority-widening` | PASS — production import and execution-surface scanners passed |
| P5-HOOK-12 | `03` §§3, 8–9 | Hook suite plus ledger/runtime snapshots | Hook calls leave ActiveSet, ledger, approvals, leases, receipts, and server state unchanged | mutation snapshot comparison | PASS — ActiveSet, version tree, and product data snapshots unchanged |
| P5-HOOK-13 | `01` Phase 5; `02` §§8, 11 | Hook fixed status output; README/Skill/manifest status | source/hermetic result stays distinct from real E2E | phase/status mutation | PASS — `HOOK_READY_HERMETIC_SOURCE_ONLY`; real E2E remains explicitly unexecuted |
| P5-E2E-REAL | `01` Phase 5 exit; `05` §§2.7, 4 | none in this round | none authorized | none authorized | NOT_EXECUTED — real authenticated staging traffic is outside this round |
| P6-PKG-01 | `01` §§11, Phase 6; `05` §§2.1, 3 | plugin manifest, `.mcp.json`, Skill, hooks, lifecycle, README, package allowlist | source package layout and plugin manifest validation | missing/extra/deferred package entry | NOT_EXECUTED |
| P6-META-01 | `01` Phase 6; user Part 3 §3 | manifest, `package.json`, lockfile, Skill, README, MCP initialize | all actual parsed/returned versions and phase labels agree | `manifest-phase`; `lock-or-server-version` | NOT_EXECUTED |
| P6-MCP-01 | `02` §§0, 3 | `.mcp.json`; `mcp/core/server-core.cjs`; `mcp/server.cjs` | real stdio initialize and tools/list: one server, exact name/version/31 order | `mcp-catalog-parity` | NOT_EXECUTED |
| P6-LIFE-01 | `01` §§9, 11, Phase 6; `05` §§2.1, 3 | `runtime/`; `lifecycle/` | temp-root install, doctor, update, explicit rollback, uninstall, restart/recovery | `lifecycle-isolation` | NOT_EXECUTED |
| P6-LIFE-02 | `03` §§4, 8–9 | `lifecycle/`; Hook trust receipt | update/uninstall preserve ledger, artifacts, Hook evidence, and foreign data | deletion/no-clobber cases | NOT_EXECUTED |
| P6-SEC-01 | `01` §§7, 11, 13; `02` §§11–12; `05` §§3, 5 | package scanner and package allowlist | generated tarball entries, types, modes, imports, values, credentials, and Future-v2 scan | `package-security` | NOT_EXECUTED |
| P6-SBOM-01 | `05` §3 | generated SBOM/equivalent dependency manifest | lockfile closure, license list, declared dependency parity | undeclared dependency mutation | NOT_EXECUTED |
| P6-LOADER-01 | `01` Phase 6; `05` §3 | isolated local marketplace fixture and generated package | host-supported non-interactive loader check under temporary Codex home | malformed manifest/package rejection | NOT_EXECUTED |
| P6-CLEAN-MACHINE | `01` Phase 6; `05` §§3, 5 | none in this round | none available in the current checkout | none | NOT_EXECUTED — no clean-machine installation evidence exists |
| P6-RUNTIME-REAL | `05` §§4–5 | none in this round | none authorized | none authorized | NOT_EXECUTED — real installed-product and staging checks require explicit authorization |

## Required negative controls

Each command will create an isolated temporary copy, apply exactly one mutation,
run the smallest mapped test, require a non-zero exit with the named guard text,
then remove the copy. The current candidate is never mutated.

| Control | Command | Required failure text | Broken-copy result | Restored-candidate result |
|---|---|---|---|---|
| manifest phase/version -> phase1 | `node tests/negative-controls.cjs manifest-phase` | `phase metadata guard` | NOT_EXECUTED | NOT_EXECUTED |
| lock or server version -> phase1 | `node tests/negative-controls.cjs lock-or-server-version` | `initialize version guard` | NOT_EXECUTED | NOT_EXECUTED |
| delete/rename frozen Hook event | `node tests/negative-controls.cjs hook-catalog-event` | `Hook catalog guard` | PASS — exit 1 with named guard | PASS — exit 0 |
| Hook allows deferred Tool/production adapter | `node tests/negative-controls.cjs hook-authority-widening` | `Hook authority guard` | PASS — exit 1 with named guard | PASS — exit 0 |
| Hook output gets synthetic secret/path | `node tests/negative-controls.cjs hook-output-leak` | `Hook redaction guard` | PASS — exit 1 with named guard | PASS — exit 0 |
| package gets absolute path/private-key/deployment-like value | `node tests/negative-controls.cjs package-security` | `package security guard` | NOT_EXECUTED | NOT_EXECUTED |
| tools/list order/count drifts | `node tests/negative-controls.cjs mcp-catalog-parity` | `MCP catalog guard` | NOT_EXECUTED | NOT_EXECUTED |
| lifecycle writes outside runtime root | `node tests/negative-controls.cjs lifecycle-isolation` | `lifecycle isolation guard` | NOT_EXECUTED | NOT_EXECUTED |

## Final verification ledger

| Command | Exit | Actual output summary |
|---|---:|---|
| `npm test` | NOT_EXECUTED | fresh final-candidate run pending |
| `npm pack --dry-run` | NOT_EXECUTED | fresh final-candidate run pending |
| `node lifecycle/verify.cjs` with frozen spec path | NOT_EXECUTED | fresh final-candidate run pending |
| `node lifecycle/doctor.cjs` | NOT_EXECUTED | fresh final-candidate run pending |
| handoff checksum verification | NOT_EXECUTED | fresh final-candidate run pending |
| handoff invariants `--all` | NOT_EXECUTED | fresh final-candidate run pending |
| isolated Codex loader/plugin validation | NOT_EXECUTED | host interface evaluation pending |

## Status conclusion

```yaml
SOURCE_IMPLEMENTATION: NOT_EXECUTED
HERMETIC_VALIDATION: NOT_EXECUTED
CODEX_LOADER_VALIDATION: NOT_EXECUTED
REAL_STAGING_E2E: NOT_EXECUTED — explicit authorization required
INSTALLABLE: NOT_CLAIMED unless loader and clean-machine installation evidence exist
RUNNABLE_REAL_INFRASTRUCTURE: NOT_CLAIMED
ACCEPTED: NOT_CLAIMED
```
