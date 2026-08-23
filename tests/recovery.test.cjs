"use strict";

// Phase 3/4: expiry, drift, and reconciliation recovery.
//
// The invariant across all of these is that forward execution never resumes.
// An expired or drifted authority is revoked and the run takes one of exactly
// three destinations depending on what it has actually committed.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
  refreshCheckpoint,
} = require("./helpers/fixture.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");

const WRITE_EXPIRY = contracts.ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER;

function startConfigure(fx) {
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  return { runId, compiled, approved };
}

test("forward resume is structurally impossible after a write expiry", () => {
  assert.equal(WRITE_EXPIRY.forwardResume, false);
  assert.equal(WRITE_EXPIRY.inheritedPlanTemplateCursorRemainingOperationsApprovalOrLease, false);
  assert.deepEqual([...Object.keys(WRITE_EXPIRY.rows)].sort(), [
    "SAME_RUN_OWNED_COMMITTED_CHANGES", "UNKNOWN_OR_THIRD_DIGEST", "ZERO_COMMITTED_CHANGES",
  ]);
});

test("zero committed changes: expiry revokes everything and returns to INVENTORIED", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  fx.advanceClock(6 * 60 * 1000);
  const next = fx.ctx.ledger.planOperations(compiled.plan_ref)
    .find((row) => row.tool === "xui_create_inbound");
  const attempted = fx.callTool("xui_create_inbound", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("i"),
  });
  assert.equal(attempted.status, "error");
  assert.equal(attempted.error.code, "APPROVAL_STALE");
  const run = fx.ctx.ledger.getRun(runId);
  assert.equal(run.main_phase, "INVENTORIED");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  assert.equal(fx.ctx.ledger.getApproval(approved.approval_ref).status, "invalidated");
  assert.equal(fx.ctx.ledger.currentRecoveryObligation(runId, "main"), null,
    "zero commits create no recovery obligation");
  assert.equal(fx.adapters.externalMutationCallCount(), 0);

  // The old approval cannot be reused after a fresh plan either.
  runInventories(fx, runId);
  const second = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  const stale = fx.callTool("xui_create_inbound", {
    run_id: runId, plan_ref: second.compiled.plan_ref,
    operation_ref: second.compiled.operation_refs[1],
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("i2"),
  });
  assert.equal(stale.status, "error");
  assert.equal(stale.error.code, "APPROVAL_REQUIRED");
});

test("owned committed changes: expiry creates a recovery obligation and ROLLBACK_REQUIRED", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node03" });
  assert.ok(fx.ctx.ledger.committedMainChanges(runId).length >= 1);

  fx.advanceClock(6 * 60 * 1000);
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const attempted = fx.callTool(next.tool, {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("n"),
  });
  assert.equal(attempted.status, "error");
  assert.equal(attempted.error.code, "ROLLBACK_REQUIRED");
  const run = fx.ctx.ledger.getRun(runId);
  assert.equal(run.main_phase, "ROLLBACK_REQUIRED");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  const obligation = fx.ctx.ledger.currentRecoveryObligation(runId, "main");
  assert.ok(obligation, "an owned committed graph must create a recovery obligation");
  assert.match(obligation.bound_graph_digest, /^sha256:[a-f0-9]{64}$/);
});

test("an unknown commit at expiry goes to manual with a reconciliation obligation", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node02" });
  fx.ctx.ledger.setScalar(runId, "unknown_commit_open", true);
  fx.advanceClock(6 * 60 * 1000);
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const attempted = fx.callTool(next.tool, {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("n"),
  });
  assert.equal(attempted.status, "error");
  assert.equal(attempted.error.code, "MANUAL_ACTION_REQUIRED");
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "MANUAL_ACTION_REQUIRED");
  assert.ok(fx.ctx.ledger.openReconciliationObligation(runId));
});

test("a checkpoint refresh with no drift preserves plan, cursor, and approval", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node02" });
  const cursorBefore = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const approvalBefore = fx.ctx.ledger.getApproval(approved.approval_ref);

  refreshCheckpoint(fx, runId);

  assert.equal(fx.ctx.ledger.currentPlan(runId).plan_ref, compiled.plan_ref);
  assert.equal(fx.ctx.ledger.cursorNext(compiled.plan_ref).operation_ref,
    cursorBefore.operation_ref, "a refresh must not advance the cursor");
  const approvalAfter = fx.ctx.ledger.getApproval(approved.approval_ref);
  assert.equal(approvalAfter.expires_at, approvalBefore.expires_at,
    "a refresh must not extend the lease");
  assert.equal(approvalAfter.status, "active");
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "APPLYING");
});

test("a checkpoint that observes third-party drift goes to manual without overwriting", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node02" });
  // A third party takes over the public TLS listener.
  fx.host.publicTlsListenerOwner = "foreign";
  fx.ctx.ledger.setScalar(runId, "unknown_commit_open", true);
  refreshCheckpoint(fx, runId);

  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "MANUAL_ACTION_REQUIRED");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  assert.ok(fx.ctx.ledger.openReconciliationObligation(runId));
  assert.equal(fx.host.nginxIncludePresent, false, "no route may be written after drift");
});

test("reconciliation reports STILL_UNKNOWN and stays manual when it cannot prove anything", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node02" });
  fx.ctx.ledger.setScalar(runId, "unknown_commit_open", true);
  fx.advanceClock(6 * 60 * 1000);
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  fx.callTool(next.tool, {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("n"),
  });
  // No observer verdict is available.
  fx.host.reconcileObservation = null;
  const reconciled = fx.ok("reconcile_status", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("r"),
  });
  assert.equal(reconciled.data.observation, "STILL_UNKNOWN");
  assert.equal(reconciled.data.observed_digest_relation, "unresolved");
  assert.equal(reconciled.data.next_action, "STAY_MANUAL_NO_RETRY_OR_CLOSE");
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "MANUAL_ACTION_REQUIRED");
  assert.ok(fx.ctx.ledger.openReconciliationObligation(runId),
    "an unresolved obligation stays open");
});

test("reconciliation of a proven-committed main rollback projects ROLLED_BACK", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);
  fx.ok("run_close", { run_id: runId, scope: "bbr", outcome: "not_requested",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("b") });
  const rb = compileAndAuthorize(fx, runId, "rollback", "rollback_owned_changes");
  fx.ok("rollback_run", {
    run_id: runId, plan_ref: rb.compiled.plan_ref, approval_ref: rb.approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("rb"),
  });
  // Simulate a lost response: an obligation is opened over a rollback that in
  // fact completed.
  fx.ctx.ledger.insertReconciliationObligation({
    obligationRef: "runtime:lostresponsetest000001", runId,
    originalTool: "rollback_run", failureContext: "UNKNOWN_COMMIT",
  });
  fx.ctx.ledger.setPhases(runId, { mainPhase: "MANUAL_ACTION_REQUIRED" });
  fx.host.reconcileObservation = "PROVEN_COMMITTED";
  const reconciled = fx.ok("reconcile_status", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("r"),
  });
  assert.equal(reconciled.data.observation, "PROVEN_COMMITTED");
  assert.equal(reconciled.data.original_operation_class, "MAIN_ROLLBACK_EXECUTOR");
  assert.equal(reconciled.data.next_action, "PROJECT_MAIN_ROLLED_BACK_THEN_POST_ROLLBACK_OLD_LINE");
  const proof = reconciled.data.main_rollback_committed_proof;
  assert.equal(proof.final_stage_and_aggregate_receipt_same_local_ledger_transaction, true);
  assert.equal(proof.finalization_receipts_both_visible, true);
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "ROLLED_BACK");
});

test("a concurrent third digest during reconciliation never overwrites", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = startConfigure(fx);
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node02" });
  fx.ctx.ledger.setScalar(runId, "unknown_commit_open", true);
  fx.advanceClock(6 * 60 * 1000);
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  fx.callTool(next.tool, {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("n"),
  });
  fx.host.reconcileObservation = "CONCURRENT_THIRD_DIGEST";
  const writesBefore = fx.adapters.externalMutationCallCount();
  const reconciled = fx.ok("reconcile_status", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("r"),
  });
  assert.equal(reconciled.data.observation, "CONCURRENT_THIRD_DIGEST");
  assert.equal(reconciled.data.observed_digest_relation, "third_digest");
  assert.equal(reconciled.data.next_action, "STAY_MANUAL_RECONCILE_NO_OVERWRITE");
  assert.equal(fx.adapters.externalMutationCallCount(), writesBefore);
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "MANUAL_ACTION_REQUIRED");
});

test("reconcile_status requires exactly one open obligation", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId } = startConfigure(fx);
  fx.ctx.ledger.setPhases(runId, { mainPhase: "MANUAL_ACTION_REQUIRED" });
  const attempted = fx.callTool("reconcile_status", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("r"),
  });
  assert.equal(attempted.status, "error");
  assert.equal(attempted.error.code, "WRONG_STATE");
});
