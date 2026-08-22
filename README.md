# 3x-ui CDN Operator — Core v1 (Phase 0–1 build)

Codex-only plugin with exactly one local stdio MCP server, `cdn-node`, for
auditing or configuring one registered Linux origin as one Cloudflare-fronted
3x-ui/Xray WebSocket node.

## Status — honest scope of this build

This repository implements **Phase 0 (scaffold and local lifecycle) and
Phase 1 (executable contract, ledger, and audit journey) only**.

- `INSTALLABLE`: **NOT_CLAIMED**
- `RUNNABLE` (against real infrastructure): **NOT_CLAIMED**
- `ACCEPTED`: **NOT_CLAIMED**

Every external adapter (SSH, Cloudflare, 3x-ui, Nginx, Keychain broker) is a
phase-gated stub that fails closed before dispatch. No real server,
Cloudflare zone, DNS record, certificate, kernel, or Keychain item can be
read or mutated by this build. Phases 2–6 are not started.

## Contract authority

The frozen handoff document `02-mcp-tool-plan.md`
(SHA-256 `a4bf469b9f5ccd61a03b73b7b61cfb8a962de280e107afe56442a43a0c542ea0`)
is the sole authority for the 31-tool catalog, all 93 closed schemas, error
vocabulary, states, and policy. `scripts/extract-contract.cjs` extracts its
two embedded executable modules byte-exactly into `contract/`; the server
serves those frozen objects directly and the tests re-extract and
byte-compare on every run. No hand-written second catalog exists.

Re-extract (read-only against the frozen package):

```sh
CDN_OPERATOR_SPEC_PATH=/path/to/handoff/02-mcp-tool-plan.md node scripts/extract-contract.cjs
```

## Layout

- `.codex-plugin/plugin.json`, `.mcp.json` (single `cdn-node` stdio server),
  `skills/cdn-node-operator/SKILL.md`, `hooks/hooks.json` (empty Phase 5 stub)
- `contract/` — vendored frozen contract modules plus provenance digests
- `mcp/` — server entry, strict Ajv 2020-12 validation before every handler,
  dispatch, closed adapter/keychain registry, SQLite WAL ledger, 31 handlers
- `runtime/`, `lifecycle/` — controlled per-user runtime root, ActiveSet
  receipts, atomic install/update/explicit-rollback/uninstall, doctor, verify
- `tests/` — contract parity, 93-schema positive/negative instances,
  pre-handler rejection, audit journey, ledger/WAL/idempotency/recovery,
  configure minimal closed loop, lifecycle, and static security scans

## Running

```sh
npm install          # installs the single dependency: ajv 8.20.0
npm test             # full suite (fake adapters, temp data dirs only)
node lifecycle/doctor.cjs
```

Requires Node.js >= 24 (uses the built-in `node:sqlite` and `node:test`).
