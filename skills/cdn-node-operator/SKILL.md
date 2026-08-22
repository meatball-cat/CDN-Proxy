---
name: cdn-node-operator
description: Operate the cdn-node MCP server to audit or configure one registered Linux origin as one Cloudflare-fronted 3x-ui/Xray WebSocket node. Use for run lifecycle, inventories, plans, approvals, evidence, and closure through the frozen Core-v1 31-Tool catalog.
---

# cdn-node operator (Core v1)

This Skill only explains and orders calls to the single local `cdn-node` MCP
server. It cannot mint leases, refs, evidence, success, or rollback authority,
and it never substitutes for the host-mediated approval prompt.

## Authority

- The executable contract frozen in the handoff document `02-mcp-tool-plan.md`
  is the sole authority for Tool names, order, schemas, states, and policy.
  This build vendors that contract verbatim under `contract/` and the server
  serves it unchanged.
- Current build state: Phase 0-1. The ledger, schemas, and audit journey are
  implemented; every external mutation adapter is phase-gated and inactive.
  Do not claim the plugin is INSTALLABLE, RUNNABLE against real
  infrastructure, or ACCEPTED.

## Run modes

- `audit`: read-only. Begin with `run_begin(mode=audit, enable_bbr=false)`,
  run the four inventories (`origin_inventory`, `cloudflare_inventory`,
  `xui_inventory`, `client_inventory`) and `old_line_verify`, then
  `completion_evaluate` and `run_close(scope=main, outcome=audit_complete)`.
  Audit can never compile or authorize a plan, obtain a lease, request BBR,
  or invoke an external mutator; the server rejects those calls.
- `configure`: mutation journeys require `plan_compile`, a host-mediated
  `plan_authorize` for the exact displayed plan digest, and ordered execution
  of server-resolved operations. Caller text is never consent.

## Rules the operator must respect

- Only registered targets and server-minted opaque refs. Never paste raw
  hostnames, paths, commands, URLs, or credentials into Tool input.
- Display plan impact digests to the user exactly as returned before
  `plan_authorize`.
- Report evidence as masked summaries only. Never claim end-to-end success
  from latency, TLS, HTTP 101, or static profile fields alone.
- An error result names its closed error code; do not retry
  non-retryable codes without the state the contract requires.
