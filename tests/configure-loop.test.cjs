"use strict";

// Acceptance: the minimal configure closed loop over the local ledger -
// registered targets, run, plan, challenge, lease, operation cursor,
// idempotency, evidence, ownership - all against fake adapters and a
// temporary data dir. External mutation succeeds only through the injected
// fake; a missing fake fails closed with no state change.

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeFixture } = require("./helpers/fixture.cjs");

function beginConfigure(fx) {
  const begun = fx.callTool("run_begin", fx.runBeginInput("configure"));
  assert.equal(begun.status, "ok", JSON.stringify(begun.error));
  return begun.data.run_ref;
}

function inventoriesAndBaseline(fx, runId) {
  for (const tool of ["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory"]) {
    assert.equal(fx.callTool(tool, { run_id: runId, refresh: false }).status, "ok", tool);
  }
  const oldLine = fx.callTool("old_line_verify", {
    run_id: runId,
    probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: "cfg-old-line-00001",
  });
  assert.equal(oldLine.status, "ok", JSON.stringify(oldLine.error));
}

function compileAndAuthorize(fx, runId) {
  const status = fx.callTool("run_status", { run_id: runId });
  const plan = fx.callTool("plan_compile", {
    run_id: runId,
    scope: "node_p2",
    intent: "configure_existing",
    expected_ledger_digest: status.data.ledger_digest,
    idempotency_key: "cfg-plan-00000001",
  });
  assert.equal(plan.status, "ok", JSON.stringify(plan.error));
  assert.equal(plan.data.template_id, "NODE_P2_REUSE_V1");
  assert.equal(plan.data.lease_class, "NODE_P2");
  assert.equal(plan.data.certificate_strategy, "reuse");
  assert.equal(plan.data.operation_refs.length, 13);

  const afterCompile = fx.callTool("run_status", { run_id: runId });
  assert.equal(afterCompile.data.main_phase, "PLAN_READY");

  const approval = fx.callTool("plan_authorize", {
    run_id: runId,
    plan_ref: plan.data.plan_ref,
    approval_challenge_ref: plan.data.approval_challenge_ref,
    displayed_impact_digest: plan.data.impact_digest,
    expected_ledger_digest: afterCompile.data.ledger_digest,
    idempotency_key: "cfg-approve-000001",
  });
  assert.equal(approval.status, "ok", JSON.stringify(approval.error));
  assert.equal(approval.data.lease_class, "NODE_P2");
  assert.deepEqual(approval.data.approved_operation_refs, plan.data.operation_refs);
  return { plan: plan.data, approval: approval.data };
}

test("configure minimal closed loop: plan -> lease -> cursor -> owned mutation", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginConfigure(fx);
  inventoriesAndBaseline(fx, runId);
  const { plan, approval } = compileAndAuthorize(fx, runId);

  // Step node01 is a planned read probe (old_line_verify): advances cursor.
  const step1 = fx.callTool("old_line_verify", {
    run_id: runId,
    probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: "cfg-old-line-00002",
  });
  assert.equal(step1.status, "ok", JSON.stringify(step1.error));

  // Wrong operation_ref (node03's ref) must be rejected without dispatch.
  const status1 = fx.callTool("run_status", { run_id: runId });
  const mutationBefore = fx.adapters.externalMutationCallCount();
  const wrongStep = fx.callTool("xui_create_inbound", {
    run_id: runId,
    plan_ref: plan.plan_ref,
    operation_ref: plan.operation_refs[2],
    approval_ref: approval.approval_ref,
    expected_ledger_digest: status1.data.ledger_digest,
    idempotency_key: "cfg-inbound-wrong1",
  });
  assert.equal(wrongStep.status, "error");
  assert.equal(wrongStep.error.code, "WRONG_STATE");
  assert.equal(fx.adapters.externalMutationCallCount(), mutationBefore);

  // Correct step node02: xui_create_inbound through the fake adapter.
  const status2 = fx.callTool("run_status", { run_id: runId });
  const inboundInput = {
    run_id: runId,
    plan_ref: plan.plan_ref,
    operation_ref: plan.operation_refs[1],
    approval_ref: approval.approval_ref,
    expected_ledger_digest: status2.data.ledger_digest,
    idempotency_key: "cfg-inbound-000001",
  };
  const inbound = fx.callTool("xui_create_inbound", inboundInput);
  assert.equal(inbound.status, "ok", JSON.stringify(inbound.error));
  assert.equal(inbound.data.committed, true);
  assert.equal(inbound.data.rollback_class, "exact_inverse");
  assert.match(inbound.data.ownership_receipt_ref, /^receipt:/);
  assert.equal(fx.adapters.externalMutationCallCount(), mutationBefore + 1);

  const afterInbound = fx.callTool("run_status", { run_id: runId });
  assert.equal(afterInbound.data.main_phase, "APPLYING");
  // Cursor advanced past node01+node02: 11 pending operations remain.
  assert.equal(afterInbound.data.pending_operation_refs.length, 11);

  // Ownership receipt is durable in the ledger.
  const owned = fx.ctx.ledger.ownershipByRun(runId);
  assert.equal(owned.filter((row) => row.object_kind === "OWNED_XUI_CREATE_INBOUND").length, 1);

  // Canonical idempotent replay: same key + same input (including the same
  // expected_ledger_digest) returns no_op and dispatches nothing.
  const replay = fx.callTool("xui_create_inbound", inboundInput);
  assert.equal(replay.status, "no_op");
  assert.deepEqual(replay.data, inbound.data);
  assert.equal(fx.adapters.externalMutationCallCount(), mutationBefore + 1);

  // Next step (node03 xui_profile_publish) executes and advances the cursor.
  const status3 = fx.callTool("run_status", { run_id: runId });
  const publish = fx.callTool("xui_profile_publish", {
    run_id: runId,
    plan_ref: plan.plan_ref,
    operation_ref: plan.operation_refs[2],
    approval_ref: approval.approval_ref,
    expected_ledger_digest: status3.data.ledger_digest,
    idempotency_key: "cfg-publish-000001",
  });
  assert.equal(publish.status, "ok", JSON.stringify(publish.error));
  assert.equal(publish.data.artifact_mode, "0600");
  const after = fx.callTool("run_status", { run_id: runId });
  assert.equal(after.data.main_phase, "APPLYING");
  assert.equal(after.data.pending_operation_refs.length, 10);
});

test("an unavailable downstream adapter fails closed with no cursor advance", (t) => {
  // Same journey, but the profile-publish broker operation is absent. The
  // step must abort before any observable effect and leave the cursor,
  // phase, and mutation count exactly where they were.
  const fx = makeFixture({ removeBrokerOperations: ["xui.profile_publish_derive_store.v1"] });
  t.after(() => fx.cleanup());
  const runId = beginConfigure(fx);
  inventoriesAndBaseline(fx, runId);
  const { plan, approval } = compileAndAuthorize(fx, runId);
  fx.callTool("old_line_verify", {
    run_id: runId, probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: "unavail-old-line-01",
  });
  fx.callTool("xui_create_inbound", {
    run_id: runId, plan_ref: plan.plan_ref, operation_ref: plan.operation_refs[1],
    approval_ref: approval.approval_ref,
    expected_ledger_digest: fx.callTool("run_status", { run_id: runId }).data.ledger_digest,
    idempotency_key: "unavail-inbound-001",
  });
  const before = fx.callTool("run_status", { run_id: runId });
  const mutationsBefore = fx.adapters.externalMutationCallCount();
  const publish = fx.callTool("xui_profile_publish", {
    run_id: runId, plan_ref: plan.plan_ref, operation_ref: plan.operation_refs[2],
    approval_ref: approval.approval_ref,
    expected_ledger_digest: before.data.ledger_digest,
    idempotency_key: "unavail-publish-001",
  });
  assert.equal(publish.status, "error");
  assert.equal(publish.error.code, "UPSTREAM_UNAVAILABLE");
  const after = fx.callTool("run_status", { run_id: runId });
  assert.equal(after.data.main_phase, before.data.main_phase);
  assert.equal(after.data.pending_operation_refs.length, before.data.pending_operation_refs.length);
  assert.equal(fx.adapters.externalMutationCallCount(), mutationsBefore);
});

test("challenge replay and impact-digest drift are rejected", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginConfigure(fx);
  inventoriesAndBaseline(fx, runId);
  const status = fx.callTool("run_status", { run_id: runId });
  const plan = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_p2", intent: "configure_existing",
    expected_ledger_digest: status.data.ledger_digest,
    idempotency_key: "replay-plan-000001",
  });
  const s2 = fx.callTool("run_status", { run_id: runId });
  const drifted = fx.callTool("plan_authorize", {
    run_id: runId,
    plan_ref: plan.data.plan_ref,
    approval_challenge_ref: plan.data.approval_challenge_ref,
    displayed_impact_digest: `sha256:${"1".repeat(64)}`,
    expected_ledger_digest: s2.data.ledger_digest,
    idempotency_key: "replay-approve-0001",
  });
  assert.equal(drifted.error.code, "APPROVAL_STALE");

  const ok = fx.callTool("plan_authorize", {
    run_id: runId,
    plan_ref: plan.data.plan_ref,
    approval_challenge_ref: plan.data.approval_challenge_ref,
    displayed_impact_digest: plan.data.impact_digest,
    expected_ledger_digest: s2.data.ledger_digest,
    idempotency_key: "replay-approve-0002",
  });
  assert.equal(ok.status, "ok", JSON.stringify(ok.error));

  const s3 = fx.callTool("run_status", { run_id: runId });
  const replayed = fx.callTool("plan_authorize", {
    run_id: runId,
    plan_ref: plan.data.plan_ref,
    approval_challenge_ref: plan.data.approval_challenge_ref,
    displayed_impact_digest: plan.data.impact_digest,
    expected_ledger_digest: s3.data.ledger_digest,
    idempotency_key: "replay-approve-0003",
  });
  assert.equal(replayed.error.code, "APPROVAL_REPLAYED");
});

test("zero-commit lease expiry revokes old authority and returns to INVENTORIED", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginConfigure(fx);
  inventoriesAndBaseline(fx, runId);
  const { plan, approval } = compileAndAuthorize(fx, runId);

  // NODE_P2 nominal lease is PT45M but effective expiry is bounded by the
  // PT5M protected-line evidence; advancing 6 minutes expires the approval.
  fx.advanceClock(6 * 60 * 1000);
  const status = fx.callTool("run_status", { run_id: runId });
  const expired = fx.callTool("xui_create_inbound", {
    run_id: runId,
    plan_ref: plan.plan_ref,
    operation_ref: plan.operation_refs[1],
    approval_ref: approval.approval_ref,
    expected_ledger_digest: status.data.ledger_digest,
    idempotency_key: "expiry-inbound-0001",
  });
  assert.equal(expired.status, "error");
  assert.equal(expired.error.code, "APPROVAL_STALE");

  const after = fx.callTool("run_status", { run_id: runId });
  assert.equal(after.data.main_phase, "INVENTORIED");
  assert.equal(after.data.plan_ref, null);
  assert.equal(after.data.pending_operation_refs.length, 0);
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
});

test("BBR branch minimal loop: pending -> inventoried -> closed receipt gates main close", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const begun = fx.callTool("run_begin",
    fx.runBeginInput("configure", { enable_bbr: true }));
  const runId = begun.data.run_ref;
  assert.equal(begun.data.bbr_phase, "BBR_PENDING");
  inventoriesAndBaseline(fx, runId);

  const bbrInventory = fx.callTool("bbr_inventory", { run_id: runId, refresh: false });
  assert.equal(bbrInventory.status, "ok", JSON.stringify(bbrInventory.error));
  assert.equal(bbrInventory.data.eligible, true);

  // Main close is barred until the BBR branch closes.
  const s1 = fx.callTool("run_status", { run_id: runId });
  assert.equal(s1.data.bbr_phase, "BBR_INVENTORIED");
  const barred = fx.callTool("run_close", {
    run_id: runId, scope: "main", outcome: "abandoned",
    expected_ledger_digest: s1.data.ledger_digest,
    idempotency_key: "bbr-main-close-001",
  });
  assert.equal(barred.error.code, "WRONG_STATE");

  const bbrClose = fx.callTool("run_close", {
    run_id: runId, scope: "bbr", outcome: "partial",
    expected_ledger_digest: fx.callTool("run_status", { run_id: runId }).data.ledger_digest,
    idempotency_key: "bbr-close-00000001",
  });
  assert.equal(bbrClose.status, "ok", JSON.stringify(bbrClose.error));
  assert.match(bbrClose.data.residual_disclosure_ref, /^evidence:/);

  const s2 = fx.callTool("run_status", { run_id: runId });
  assert.equal(s2.data.bbr_phase, "BBR_CLOSED");
  const mainClose = fx.callTool("run_close", {
    run_id: runId, scope: "main", outcome: "abandoned",
    expected_ledger_digest: s2.data.ledger_digest,
    idempotency_key: "bbr-main-close-002",
  });
  assert.equal(mainClose.status, "ok", JSON.stringify(mainClose.error));
  assert.equal(fx.callTool("run_status", { run_id: runId }).data.main_phase, "CLOSED");
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
});

test("configure completion is barred before the BBR branch closes, then honestly pending", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = beginConfigure(fx);
  inventoriesAndBaseline(fx, runId);

  // The configure-only BBR barrier makes completion illegal, not pending.
  const barred = fx.callTool("completion_evaluate", {
    run_id: runId,
    expected_ledger_digest: fx.callTool("run_status", { run_id: runId }).data.ledger_digest,
    idempotency_key: "cfg-completion-0000",
  });
  assert.equal(barred.status, "error");
  assert.equal(barred.error.code, "WRONG_STATE");

  fx.callTool("run_close", {
    run_id: runId, scope: "bbr", outcome: "not_requested",
    expected_ledger_digest: fx.callTool("run_status", { run_id: runId }).data.ledger_digest,
    idempotency_key: "cfg-bbr-close-0001",
  });

  // With the branch closed but no verification evidence, the honest label is
  // configured_not_verified with nothing sealed.
  const completion = fx.callTool("completion_evaluate", {
    run_id: runId,
    expected_ledger_digest: fx.callTool("run_status", { run_id: runId }).data.ledger_digest,
    idempotency_key: "cfg-completion-0001",
  });
  assert.equal(completion.status, "pending");
  assert.equal(completion.data.label, "configured_not_verified");
  assert.equal(completion.data.all_required_true, false);
  assert.equal(completion.data.report_ref, null);
  assert.ok(completion.data.satisfied_requirement_ids.length <= 6);
});
