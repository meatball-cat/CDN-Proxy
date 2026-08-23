# 3x-ui CDN Operator — Core v1 (Phase 0–4 build)

Codex-only plugin with exactly one local stdio MCP server, `cdn-node`, for
auditing or configuring one registered Linux origin as one Cloudflare-fronted
3x-ui/Xray WebSocket node.

## Status — honest scope of this build

This repository implements **Phase 0–4**: scaffold and local lifecycle, the
executable contract and ledger, the audit journey, the clean-host installer
and broker credential flow, the full node journey with authenticated
end-to-end verification, and the optional BBR branch with both rollback
graphs.

- `INSTALLABLE`: **NOT_CLAIMED**
- `RUNNABLE` (against real infrastructure): **NOT_CLAIMED**
- `ACCEPTED`: **NOT_CLAIMED**

Every external adapter (SSH, Cloudflare, 3x-ui, Nginx, Keychain broker) is
still an injected seam. The production adapter set is phase-gated and fails
closed before dispatch, so no real server, Cloudflare zone, DNS record,
certificate, kernel, or Keychain item can be read or mutated by this build.
Phase 5 (Core Hooks) and Phase 6 (packaging, install, real runtime/E2E) are
not started.

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

## What this build enforces

- **Clean-host install only through a pinned adapter.** One build-time
  allowlisted, digest-pinned adapter, resolved server-side from inventory
  facts. No caller command, argv, script, URL, path, username, password,
  port, or payload exists anywhere on the installer surface. Existing,
  partial, drifted, ambiguous, and unsupported installations all deny before
  any effect.
- **Broker-owned credentials.** The server holds only opaque `SecretRef`s and
  masked metadata. Generation, custody, and use of panel administrator
  credentials, client credentials, profile runtime secrets, the WebSocket
  path, and the Origin CA private key all live behind the Keychain seam; a
  broker that offers key bytes back is refused, not redacted.
- **One dedicated hostname, bound everywhere.** The Cloudflare record, the
  certificate SAN, the Nginx `server_name`, and the client profile's address,
  SNI, and WebSocket Host must all name the same registered hostname, and the
  WebSocket path must be byte-identical across inbound, route, and profile.
  The apex, the management hostname, and any ambiguous name are refused.
- **Create-only, no-clobber.** Every resource this run creates is
  exclusive-created against a proven-absent slot. Nothing is adopted, backed
  up, replaced, or restored. A concurrent third-party digest stops the write
  and goes to manual.
- **Cloudflare is read-only at the zone level.** Strict-compatible mode and
  WebSockets are prerequisites to observe, never settings to change; Core v1
  performs no zone-wide write at all.
- **Proof before proxy.** The node record is created unproxied; the proxy is
  enabled only after a direct-origin TLS+WebSocket proof bound to the current
  route.
- **Authenticated end-to-end, or nothing.** Acceptance needs a real
  authenticated proxy request whose observed public egress equals the origin's
  own expected egress at the same allowlisted destination, compared as opaque
  HMAC digests under a per-install key. Latency, an open port, a certificate,
  a TLS handshake, an HTTP 101, and a static profile are each explicitly
  insufficient.
- **Supported-kernel BBR only.** One exclusive-created owned drop-in with the
  exact `bbr`/`fq` keys. Core v1 never installs or upgrades a
  kernel, never edits a bootloader or a shared sysctl file, and never reboots.
- **Rollback reverses only what this run owns.** Eight logical graph nodes
  expand to the frozen eleven ordered atomic stages (plus BBR's four); each
  stage commits a durable receipt after its own readback and before the next;
  the final stage receipt and the aggregate receipt commit both-or-neither. A
  proven contiguous prefix resumes from its exact remaining suffix and a
  completed stage never replays. Imported credentials are never disposed.
- **No forward resume.** An expired effective approval revokes all forward
  authority and takes the three-way split: zero commits return to
  `INVENTORIED`, owned commits create a recovery obligation and
  `ROLLBACK_REQUIRED`, unknown or third-party observations go to manual.

## Layout

- `.codex-plugin/plugin.json`, `.mcp.json` (single `cdn-node` stdio server),
  `skills/cdn-node-operator/SKILL.md`, `hooks/hooks.json` (empty Phase 5 stub)
- `contract/` — vendored frozen contract modules plus provenance digests
- `mcp/` — server entry, strict Ajv 2020-12 validation before every handler,
  dispatch, closed adapter/manifest/broker/Keychain registry, forward-dispatch
  gate, domain identity binding, low-entropy HMAC binder, rollback stage
  engine, SQLite WAL ledger, 31 handlers
- `runtime/`, `lifecycle/` — controlled per-user runtime root, ActiveSet
  receipts, atomic install/update/explicit-rollback/uninstall, doctor, verify
- `tests/` — contract parity, 93-schema instances, pre-handler rejection,
  audit journey, ledger/WAL/idempotency/recovery, install journey, broker
  credential boundary, node journey, authenticated E2E, BBR, rollback,
  expiry/drift/reconciliation recovery, and static security scans

## Running

```sh
npm install          # installs the single dependency: ajv 8.20.0
npm test             # full suite (fake adapters, temp data dirs only)
npm run acceptance   # full suite plus frozen-package re-verification
node lifecycle/doctor.cjs
```

Requires Node.js >= 24 (uses the built-in `node:sqlite` and `node:test`).
