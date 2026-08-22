"use strict";

// Acceptance: the audit journey runs end to end against fake adapters and a
// temporary data dir; audit can never obtain a plan, challenge, lease, BBR
// branch, external mutator, or rollback path; the fake external adapter's
// mutation call count stays zero.

const test = require("node:test");
const assert = require("node:assert/strict");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const { makeFixture } = require("./helpers/fixture.cjs");
const { sample } = require("./helpers/sample.cjs");

function beginAudit(fx) {
  const begun = fx.callTool("run_begin", fx.runBeginInput("audit"));
  assert.equal(begun.status, "ok");
  assert.equal(begun.data.run_mode, "audit");
  assert.equal(begun.data.bbr_phase, "BBR_NOT_REQUESTED");
  return begun.data.run_ref;
}

function runInventories(fx, runId) {
  for (const tool of ["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory"]) {
    const result = fx.callTool(tool, { run_id: runId, refresh: false });
    assert.equal(result.status, "ok", `${tool}: ${JSON.stringify(result.error)}`);
  }
  const oldLine = fx.callTool("old_line_verify", {
    run_id: runId,
    probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: "audit-old-line-0001",
  });
  assert.equal(oldLine.status, "ok", JSON.stringify(oldLine.error));
  assert.equal(oldLine.data.protected_line_status, "healthy");
  assert.equal(oldLine.data.binding_scope, "pre_change");
}

test("complete audit journey: begin -> inventories -> completion -> close", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginAudit(fx);
  runInventories(fx, runId);

  const status = fx.callTool("run_status", { run_id: runId });
  assert.equal(status.data.main_phase, "INVENTORIED");

  const completion = fx.callTool("completion_evaluate", {
    run_id: runId,
    expected_ledger_digest: status.data.ledger_digest,
    idempotency_key: "audit-completion-0001",
  });
  assert.equal(completion.status, "ok", JSON.stringify(completion.error));
  assert.equal(completion.data.label, "audit_complete");
  assert.equal(completion.data.all_required_true, true);
  assert.equal(completion.data.satisfied_requirement_ids.length, 5);
  assert.equal(completion.data.residual_disclosure_ref, null);

  const after = fx.callTool("run_status", { run_id: runId });
  const closed = fx.callTool("run_close", {
    run_id: runId,
    scope: "main",
    outcome: "audit_complete",
    expected_ledger_digest: after.data.ledger_digest,
    idempotency_key: "audit-close-000001",
  });
  assert.equal(closed.status, "ok", JSON.stringify(closed.error));
  assert.equal(closed.data.outcome, "audit_complete");
  assert.equal(closed.data.bound_completion_label, "audit_complete");
  assert.equal(closed.data.bound_completion_report_digest, completion.data.report_digest);
  assert.equal(closed.data.residual_disclosure_ref, null);

  const final = fx.callTool("run_status", { run_id: runId });
  assert.equal(final.data.main_phase, "CLOSED");

  // Zero external mutation across the whole journey.
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
  assert.equal(fx.fakeCalls.filter((c) => c.kind === "helper-mutating").length, 0);
});

test("audit cannot reach any tool outside the frozen audit allowlist", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginAudit(fx);
  runInventories(fx, runId);

  const allowed = contracts.RUN_MODE_POLICY.audit.allowedTools;
  const blocked = contracts.FROZEN_TOOL_NAMES.filter((name) => !allowed.includes(name));
  assert.equal(blocked.length, 21);

  for (const tool of blocked) {
    const schema = contracts.TOOLS_BY_NAME[tool].inputSchema;
    const input = sample(schema, 0);
    if ("run_id" in input) input.run_id = runId;
    const result = fx.callTool(tool, input);
    assert.equal(result.status, "error", tool);
    assert.equal(result.error.code, "WRONG_STATE", `${tool}: ${JSON.stringify(result.error)}`);
  }

  // No plan, challenge, approval/lease, operation, ownership row, or
  // reconciliation obligation exists anywhere in the ledger.
  const db = fx.ctx.ledger.db;
  for (const table of ["plans", "challenges", "approvals", "operations", "ownership", "reconciliation_obligations"]) {
    const row = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get();
    assert.equal(row.n, 0, `${table} must stay empty for audit`);
  }
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
});

test("audit run_begin structurally cannot request BBR", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const rejected = fx.callTool("run_begin",
    { ...fx.runBeginInput("audit"), enable_bbr: true });
  assert.equal(rejected.status, "error");
  assert.equal(rejected.error.code, "INVALID_INPUT");
});

test("audit output is masked: no observation leaks beyond schema-bound fields", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginAudit(fx);
  const inventory = fx.callTool("origin_inventory", { run_id: runId, refresh: false });
  // The frozen closed schema is the masking boundary: every key must be a
  // declared schema property (additionalProperties=false was already applied
  // by the output validator, this asserts the concrete instance).
  const allowedKeys = Object.keys(
    contracts.TOOLS_BY_NAME.origin_inventory.dataSchema.properties);
  for (const key of Object.keys(inventory.data)) {
    assert.ok(allowedKeys.includes(key), `unexpected key ${key}`);
  }
  // Evidence listing exposes only refs and bounded masked summaries.
  const listed = fx.callTool("evidence_list", { run_id: runId, cursor: null, max_items: 10 });
  for (const row of listed.data.rows) {
    assert.deepEqual(Object.keys(row).sort(), ["evidence_ref", "masked_summary"]);
    assert.ok(row.masked_summary.length <= 128);
  }
});

test("unregistered onboarding refs are rejected at run_begin", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const rejected = fx.callTool("run_begin", {
    ...fx.runBeginInput("audit"),
    origin_target_ref: "target:unregisteredxxxx",
  });
  assert.equal(rejected.status, "error");
  assert.equal(rejected.error.code, "UNAUTHORIZED_TARGET");
  const rejected2 = fx.callTool("run_begin", {
    ...fx.runBeginInput("audit"),
    ssh_identity_secret_ref: "secret:unregisteredxxxx",
  });
  assert.equal(rejected2.error.code, "DEPENDENCY_MISSING");
});
