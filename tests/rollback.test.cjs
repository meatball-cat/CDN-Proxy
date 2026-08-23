"use strict";

// Phase 4: main and BBR rollback.
//
// The properties under test are ownership ("only what this run created"),
// currency ("only if the bytes still match the receipt"), atomicity ("final
// stage receipt and aggregate receipt together or not at all"), and
// no-replay ("a completed stage never runs twice").

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
} = require("./helpers/fixture.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const rollbackEngine = require("../mcp/core/rollback.cjs");

const MAIN_STAGE_IDS = rollbackEngine.MAIN_STAGE_IDS;
const BBR_STAGE_IDS = rollbackEngine.BBR_STAGE_IDS;

function deliverMain(fx, hostOverrides = {}) {
  Object.assign(fx.host, hostOverrides);
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);
  return runId;
}

function closeBbrNotRequested(fx, runId) {
  fx.ok("run_close", { run_id: runId, scope: "bbr", outcome: "not_requested",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("bbr") });
}

function compileMainRollback(fx, runId) {
  return compileAndAuthorize(fx, runId, "rollback", "rollback_owned_changes");
}

function executeMainRollback(fx, runId, plan, approval) {
  return fx.callTool("rollback_run", {
    run_id: runId, plan_ref: plan.plan_ref, approval_ref: approval.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("rb"),
  });
}

test("the frozen graph is eleven ordered main stages and four ordered BBR stages", () => {
  assert.equal(MAIN_STAGE_IDS.length, 11);
  assert.equal(BBR_STAGE_IDS.length, 4);
  assert.equal(new Set(MAIN_STAGE_IDS).size, 11);
  // The eight logical graph nodes expand to those eleven atomic stages.
  assert.equal(contracts.CORE_ROLLBACK_POLICY.order.length, 8);
  // Neither template may ever carry the other's stage ids.
  for (const id of BBR_STAGE_IDS) assert.ok(!MAIN_STAGE_IDS.includes(id));
});

test("main rollback reverses only same-run owned resources, in dependency-reverse order", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx, { safeStableCertificateReuseEligible: false });
  closeBbrNotRequested(fx, runId);
  const { compiled, approved } = compileMainRollback(fx, runId);
  assert.equal(compiled.template_id, "MAIN_ROLLBACK_V1");
  // No install happened and the panel admin is imported, so rb10 and rb11
  // are structurally absent from the selection.
  assert.ok(!compiled.rollback_atomic_stage_ids.includes("rb10_xui_install_uninstall"));
  assert.ok(!compiled.rollback_atomic_stage_ids.includes("rb11_xui_panel_admin_revoke"));
  // The selection is an ordered subsequence of the frozen order.
  const positions = compiled.rollback_atomic_stage_ids.map((id) => MAIN_STAGE_IDS.indexOf(id));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  assert.equal(compiled.bbr_rollback_stage_ids.length, 0);
  assert.equal(compiled.bbr_rollback_stage_selection_digest, null);

  const result = executeMainRollback(fx, runId, compiled, approved);
  assert.equal(result.status, "ok", JSON.stringify(result.error));
  const data = result.data;
  assert.deepEqual(data.completed_atomic_stage_ids, compiled.rollback_atomic_stage_ids);
  assert.equal(data.atomic_stage_receipt_refs.length, data.completed_atomic_stage_ids.length);
  assert.equal(data.atomic_stage_and_receipt_cardinality_equal, true);
  assert.equal(data.atomic_stage_set_exactly_equals_frozen_plan_selection, true);
  assert.equal(data.final_atomic_stage_id, compiled.rollback_atomic_stage_ids.at(-1));
  assert.equal(data.final_stage_and_aggregate_receipt_same_local_ledger_transaction, true);
  assert.equal(data.finalization_receipts_both_visible, true);
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "ROLLED_BACK");
});

test("an install run also reverses the install and the generated panel admin", (t) => {
  const fx = makeFixture({ xuiCase: "ABSENT_CLEAN_ELIGIBLE" });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const install = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  driveTemplate(fx, runId, install.compiled.plan_ref, install.approved.approval_ref);
  runInventories(fx, runId);
  const node = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  driveTemplate(fx, runId, node.compiled.plan_ref, node.approved.approval_ref);
  closeBbrNotRequested(fx, runId);

  const { compiled, approved } = compileMainRollback(fx, runId);
  assert.ok(compiled.rollback_atomic_stage_ids.includes("rb10_xui_install_uninstall"));
  assert.ok(compiled.rollback_atomic_stage_ids.includes("rb11_xui_panel_admin_revoke"));
  // The uninstall comes after every dependent reversal.
  assert.ok(compiled.rollback_atomic_stage_ids.indexOf("rb10_xui_install_uninstall") >
    compiled.rollback_atomic_stage_ids.indexOf("rb08_xui_inbound_remove"));

  const result = executeMainRollback(fx, runId, compiled, approved);
  assert.equal(result.status, "ok", JSON.stringify(result.error));
  assert.equal(fx.host.xuiInstallationStatus, "absent");
  // The generated panel administrator credential is revoked; imported
  // onboarding credentials are untouched.
  const dispositions = fx.ctx.ledger.secretDispositions(runId);
  assert.ok(dispositions.some((row) => row.role === "xui-panel-admin"));
  for (const row of dispositions) {
    const secret = fx.ctx.ledger.getSecretRef(row.secret_ref);
    assert.equal(secret.provenance, "same-run-generated",
      "an imported credential must never be disposed");
  }
});

test("an imported panel administrator credential is never revoked", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  closeBbrNotRequested(fx, runId);
  const { compiled, approved } = compileMainRollback(fx, runId);
  assert.ok(!compiled.rollback_atomic_stage_ids.includes("rb11_xui_panel_admin_revoke"));
  executeMainRollback(fx, runId, compiled, approved);
  const imported = fx.ctx.ledger.getSecretRef(fx.refs.existing_xui_admin_secret_ref);
  assert.equal(imported.disposition, "current");
  assert.equal(fx.keychain.dispositionOf(fx.refs.existing_xui_admin_secret_ref), "current");
});

test("a third-party digest stops the rollback at that stage without clobbering", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  closeBbrNotRequested(fx, runId);
  fx.host.thirdPartyDigestOn = "rb03_nginx_route_delete";
  const { compiled, approved } = compileMainRollback(fx, runId);
  const result = executeMainRollback(fx, runId, compiled, approved);
  assert.equal(result.status, "error");
  assert.equal(result.error.code, "CONFLICT_DETECTED");
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "MANUAL_ACTION_REQUIRED");
  // The route the third party touched still exists: nothing was overwritten.
  assert.equal(fx.host.nginxIncludePresent, true);
  // Only the stages before it committed receipts.
  const receipts = fx.ctx.ledger.stageReceiptIds(runId, rollbackEngine.MAIN_FAMILY);
  assert.deepEqual(receipts, ["rb01_cf_proxy_restore", "rb02_cf_record_delete"]);
  assert.equal(fx.ctx.ledger.aggregateReceipt(runId, "MAIN_ROLLBACK_RECEIPT"), null,
    "no aggregate receipt may exist for an incomplete rollback");
});

test("a proven prefix resumes from its exact remaining suffix and never replays", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  closeBbrNotRequested(fx, runId);

  // First attempt stops mid-graph, leaving a contiguous two-stage prefix.
  fx.host.thirdPartyDigestOn = "rb03_nginx_route_delete";
  const first = compileMainRollback(fx, runId);
  executeMainRollback(fx, runId, first.compiled, first.approved);
  const prefix = fx.ctx.ledger.stageReceiptIds(runId, rollbackEngine.MAIN_FAMILY);
  assert.deepEqual(prefix, ["rb01_cf_proxy_restore", "rb02_cf_record_delete"]);

  // The obstruction clears; reconciliation proves the prefix.
  fx.host.thirdPartyDigestOn = null;
  fx.host.reconcileObservation = "PROVEN_INVERSE_PREFIX";
  const reconciled = fx.ok("reconcile_status", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("rec"),
  });
  assert.equal(reconciled.data.observation, "PROVEN_INVERSE_PREFIX");
  assert.equal(reconciled.data.next_action,
    "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK_REMAINING_SUFFIX");
  const proof = reconciled.data.main_rollback_inverse_prefix_proof;
  assert.deepEqual(proof.completed_prefix_stage_ids, prefix);
  assert.equal(proof.completed_prefix_receipt_and_stage_cardinality_equal, true);

  // The fresh plan contains only the remaining suffix.
  const second = compileMainRollback(fx, runId);
  for (const completed of prefix) {
    assert.ok(!second.compiled.rollback_atomic_stage_ids.includes(completed),
      `${completed} must never be replanned`);
  }
  assert.equal(second.compiled.rollback_atomic_stage_ids[0], "rb03_nginx_route_delete");

  const result = executeMainRollback(fx, runId, second.compiled, second.approved);
  assert.equal(result.status, "ok", JSON.stringify(result.error));
  // Every stage receipt across both attempts is present exactly once.
  const all = fx.ctx.ledger.stageReceiptIds(runId, rollbackEngine.MAIN_FAMILY);
  assert.equal(new Set(all).size, all.length, "no completed stage may be replayed");
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "ROLLED_BACK");
});

test("a non-contiguous stage receipt set is refused into manual, not resumed", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  closeBbrNotRequested(fx, runId);
  // Forge a receipt for a later stage with no prefix behind it.
  fx.ctx.ledger.insertStageReceipt({
    receiptRef: "receipt:forgednoncontiguous001", runId,
    family: rollbackEngine.MAIN_FAMILY, operationRef: "operation:forged00000001",
    stageId: "rb04_certificate_slots_delete",
    stageIndex: MAIN_STAGE_IDS.indexOf("rb04_certificate_slots_delete"),
    readbackDigest: `sha256:${"5".repeat(64)}`,
  });
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "rollback", intent: "rollback_owned_changes",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.status, "error");
  assert.equal(compiled.error.code, "MANUAL_ACTION_REQUIRED");
  assert.match(compiled.error.message, /not a contiguous prefix/);
});

test("main zero-dispatch lease expiry mints an admission receipt and replans in full", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  closeBbrNotRequested(fx, runId);
  const { compiled, approved } = compileMainRollback(fx, runId);
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "ROLLING_BACK");

  // The ROLLBACK lease is PT15M and nothing has been dispatched.
  fx.advanceClock(16 * 60 * 1000);
  const expired = executeMainRollback(fx, runId, compiled, approved);
  assert.equal(expired.status, "error");
  assert.equal(expired.error.code, "APPROVAL_STALE");
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "ROLLBACK_REQUIRED");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  assert.equal(fx.ctx.ledger.stageReceipts(runId, rollbackEngine.MAIN_FAMILY).length, 0);
  // A durable admission receipt, and no reconciliation obligation.
  const admission = fx.ctx.ledger.currentAdmissionReceipt(
    runId, "MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY_ADMISSION_RECEIPT");
  assert.ok(admission, "a durable zero-dispatch admission receipt must exist");
  assert.equal(fx.ctx.ledger.openReconciliationObligation(runId), null);

  // A fresh full-graph plan and a new host prompt follow.
  const second = compileMainRollback(fx, runId);
  assert.deepEqual(second.compiled.rollback_atomic_stage_ids,
    compiled.rollback_atomic_stage_ids);
  assert.notEqual(second.approved.approval_ref, approved.approval_ref);
  const result = executeMainRollback(fx, runId, second.compiled, second.approved);
  assert.equal(result.status, "ok", JSON.stringify(result.error));
});

test("main rollback is denied while a committed BBR change is still raw", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const bbr = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  driveTemplate(fx, runId, bbr.compiled.plan_ref, bbr.approved.approval_ref, { stopAfter: "bbr01" });
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_APPLIED");

  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "rollback", intent: "rollback_owned_changes",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  // The request resolves to the dedicated BBR path, never to a main graph
  // rollback that would leave the BBR drop-in behind.
  assert.ok(compiled.status === "error" || compiled.data.template_id === "BBR_ROLLBACK_V1",
    "a raw committed BBR change must not admit a main rollback");
});

test("BBR rollback runs the four frozen stages with per-stage receipts", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const bbr = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  driveTemplate(fx, runId, bbr.compiled.plan_ref, bbr.approved.approval_ref, { stopAfter: "bbr02" });

  const rb = compileAndAuthorize(fx, runId, "rollback", "rollback_owned_changes");
  assert.equal(rb.compiled.template_id, "BBR_ROLLBACK_V1");
  assert.deepEqual(rb.compiled.bbr_rollback_stage_ids, [...BBR_STAGE_IDS]);
  assert.equal(rb.compiled.rollback_atomic_stage_ids.length, 0);
  assert.equal(rb.compiled.rollback_atomic_stage_selection_digest, null);

  const result = fx.callTool("bbr_rollback", {
    run_id: runId, plan_ref: rb.compiled.plan_ref,
    operation_ref: fx.ctx.ledger.cursorNext(rb.compiled.plan_ref).operation_ref,
    approval_ref: rb.approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("br"),
  });
  assert.equal(result.status, "ok", JSON.stringify(result.error));
  const data = result.data;
  assert.deepEqual(data.selected_bbr_stage_ids, [...BBR_STAGE_IDS]);
  assert.equal(data.bbr_stage_receipt_refs.length, 4);
  assert.equal(data.each_stage_receipt_committed_after_exact_readback_before_next_stage, true);
  assert.equal(data.final_bbr_stage_id, "bbr_rb04_final_exact_readback");
  assert.equal(data.final_bbr_stage_and_aggregate_receipt_same_local_ledger_transaction, true);
  assert.equal(data.owned_dropin_removed, true);
  assert.equal(data.inverse_readback_matches_recorded_prior, true);
  // The host is back at exactly the recorded prior values.
  assert.equal(fx.host.ownedDropinPresent, false);
  assert.equal(fx.host.liveCongestionControl, "cubic");
  assert.equal(fx.host.persistentQdisc, "pfifo_fast");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_ROLLED_BACK");
});

test("BBR zero-stage lease expiry supersedes the episode and inherits one baseline", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const bbr = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  driveTemplate(fx, runId, bbr.compiled.plan_ref, bbr.approved.approval_ref, { stopAfter: "bbr02" });
  const rb = compileAndAuthorize(fx, runId, "rollback", "rollback_owned_changes");
  const priorEpisodes = fx.ctx.ledger.currentBbrSourceEpisodes(runId);
  assert.equal(priorEpisodes.length, 1);
  const priorBaseline = priorEpisodes[0];

  fx.advanceClock(16 * 60 * 1000);
  const expired = fx.callTool("bbr_rollback", {
    run_id: runId, plan_ref: rb.compiled.plan_ref,
    operation_ref: fx.ctx.ledger.cursorNext(rb.compiled.plan_ref).operation_ref,
    approval_ref: rb.approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("br"),
  });
  assert.equal(expired.status, "error");
  assert.equal(expired.error.code, "APPROVAL_STALE");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_MANUAL_ACTION_REQUIRED");
  assert.equal(fx.ctx.ledger.stageReceipts(runId, rollbackEngine.BBR_FAMILY).length, 0);

  // Exactly one new current episode, carrying the same one baseline binding,
  // with its own durable zero-stage cause and no reconciliation evidence.
  const episodes = fx.ctx.ledger.currentBbrSourceEpisodes(runId);
  assert.equal(episodes.length, 1);
  assert.equal(episodes[0].source_row_id, "BBR_ZERO_STAGE_BEFORE_DISPATCH");
  assert.equal(episodes[0].durable_cause, "BBR_ZERO_STAGE_BEFORE_DISPATCH");
  assert.equal(episodes[0].baseline_kind, priorBaseline.baseline_kind);
  assert.equal(episodes[0].baseline_receipt_ref, priorBaseline.baseline_receipt_ref);
  assert.equal(episodes[0].baseline_change_ref, priorBaseline.baseline_change_ref);
  assert.notEqual(episodes[0].episode_ref, priorBaseline.episode_ref);
  assert.equal(fx.ctx.ledger.openReconciliationObligation(runId), null,
    "zero-stage recovery creates no reconciliation evidence");
  assert.equal(fx.ctx.ledger.currentAdmissionReceipt(
    runId, "MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY_ADMISSION_RECEIPT"), null,
  "the BBR path never reuses the main admission receipt");

  // A fresh full-stage plan and prompt follow.
  const second = compileAndAuthorize(fx, runId, "rollback", "rollback_owned_changes");
  assert.deepEqual(second.compiled.bbr_rollback_stage_ids, [...BBR_STAGE_IDS]);
});

test("more than one current BBR source episode denies the plan and stays manual", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const bbr = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  driveTemplate(fx, runId, bbr.compiled.plan_ref, bbr.approved.approval_ref, { stopAfter: "bbr01" });
  fx.host.bbrVerifyFalse = true;
  fx.callTool("bbr_verify", {
    run_id: runId, bbr_change_ref: fx.ctx.ledger.getScalar(runId, "bbr_change_ref"),
    probe_destination_ref: fx.refs.probe_destination_ref, idempotency_key: fx.idemKey("v"),
  });
  // A second current episode is injected: the source is now ambiguous.
  fx.ctx.ledger.insertBbrSourceEpisode({
    episodeRef: "runtime:secondepisodetest00001", runId,
    sourceRowId: "FRESH_RECONCILIATION_OUTCOME", durableCause: "FRESH_RECONCILIATION_OUTCOME",
    baselineKind: "RECONCILED_APPLY_CHANGE",
    baselineReceiptRef: "receipt:secondbaseline0000001",
    baselineChangeRef: "change:secondbaseline000001",
    baselineBindingDigest: `sha256:${"7".repeat(64)}`,
  });
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "rollback", intent: "rollback_owned_changes",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.status, "error");
  assert.equal(compiled.error.code, "MANUAL_ACTION_REQUIRED");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_MANUAL_ACTION_REQUIRED");
});

test("a stage whose readback cannot be verified stops before the aggregate receipt", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const bbr = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  driveTemplate(fx, runId, bbr.compiled.plan_ref, bbr.approved.approval_ref, { stopAfter: "bbr02" });
  fx.host.failStage = "bbr_rb03_prior_persistent_restore";
  const rb = compileAndAuthorize(fx, runId, "rollback", "rollback_owned_changes");
  const result = fx.callTool("bbr_rollback", {
    run_id: runId, plan_ref: rb.compiled.plan_ref,
    operation_ref: fx.ctx.ledger.cursorNext(rb.compiled.plan_ref).operation_ref,
    approval_ref: rb.approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("br"),
  });
  assert.equal(result.status, "error");
  assert.equal(result.error.code, "ROLLBACK_UNSAFE");
  // A two-stage prefix is durable; neither the final receipt nor the
  // aggregate exists, so the pair is visibly "neither".
  const receipts = fx.ctx.ledger.stageReceiptIds(runId, rollbackEngine.BBR_FAMILY);
  assert.deepEqual(receipts, ["bbr_rb01_owned_dropin_remove", "bbr_rb02_prior_live_restore"]);
  assert.ok(receipts.length <=
    contracts.BBR_ROLLBACK_FINALIZATION_TRANSACTION.beforeTransactionCommitCrash
      .maximumVisibleProperPrefixLength);
  assert.equal(fx.ctx.ledger.aggregateReceipt(runId, "BBR_ROLLBACK_RECEIPT"), null);
});

test("the post-rollback old-line proof binds the aggregate receipt and re-runs no inverse", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  closeBbrNotRequested(fx, runId);
  const { compiled, approved } = compileMainRollback(fx, runId);
  const result = executeMainRollback(fx, runId, compiled, approved);
  const aggregate = fx.ctx.ledger.aggregateReceipt(runId, "MAIN_ROLLBACK_RECEIPT");
  assert.equal(result.data.rollback_receipt_ref, aggregate.receipt_ref);

  const inversesBefore = fx.adapters.mutationCalls.length;
  const proof = fx.ok("old_line_verify", {
    run_id: runId, probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: fx.idemKey("post"),
  });
  assert.equal(proof.data.binding_scope, "post_main_rollback");
  assert.equal(proof.data.bound_rollback_receipt_ref, aggregate.receipt_ref);
  assert.equal(proof.data.bound_current_route_digest, null);
  assert.equal(fx.adapters.mutationCalls.length, inversesBefore,
    "the post-rollback proof must re-execute no inverse");
});

test("rollback_run exposes no caller operation selector at all", () => {
  const inputProperties = Object.keys(
    contracts.TOOLS_BY_NAME.rollback_run.inputSchema.properties);
  assert.ok(!inputProperties.includes("operation_ref"));
  assert.ok(!inputProperties.includes("stage_id"));
  assert.ok(!inputProperties.includes("rollback_atomic_stage_ids"));
  assert.equal(contracts.CORE_ROLLBACK_POLICY.callerSelectableRows, false);
});
