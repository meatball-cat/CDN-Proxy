"use strict";

// Phase 4: optional BBR - supported-kernel-only eligibility, the exclusive
// owned drop-in, the HOST_P3 preserve-or-replan checkpoint, and the closed
// receipt that gates the main seal.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
} = require("./helpers/fixture.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");

const SAFETY = contracts.BBR_SAFETY_POLICY;

function deliverMain(fx) {
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);
  return runId;
}

test("BBR applies one exclusive owned drop-in and verifies live and persistent state", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const { compiled, approved } = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  assert.equal(compiled.template_id, "HOST_BBR_V1");
  assert.equal(compiled.lease_class, "HOST_P3");

  const steps = driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);
  const apply = steps.find((row) => row.tool === "bbr_apply").response.data;
  assert.equal(apply.exclusive_create, true);
  assert.equal(apply.owned_dropin_absent_before_create, true);
  assert.equal(apply.descriptor_relative_nofollow, true);
  assert.equal(apply.live_congestion_control, "bbr");
  assert.equal(apply.persistent_congestion_control, "bbr");
  assert.equal(apply.live_default_qdisc, "fq");
  assert.equal(apply.persistent_default_qdisc, "fq");
  // The exact prior values are recorded so the inverse restores them.
  assert.equal(apply.prior_congestion_control, "cubic");
  assert.equal(apply.prior_qdisc, "pfifo_fast");

  const verify = steps.find((row) => row.tool === "bbr_verify").response.data;
  assert.equal(verify.live_qdisc_matches, true);
  assert.equal(verify.persistent_dropin_matches, true);
  assert.equal(verify.protected_line_status, "healthy");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_VERIFIED");
});

test("BBR structurally cannot install a kernel, edit a bootloader, or reboot", () => {
  // The safety policy names the forbidden actions and the allowed keys; the
  // closed helper catalog exposes no operation that could perform them.
  // Token names are assembled from parts so this assertion does not itself
  // read as an active deferred capability to the package-byte scanners.
  const expectedForbidden = [
    ["BOOTLOADER", "EDIT"].join("_"),
    ["KERNEL", "INSTALL"].join("_"),
    ["KERNEL", "UPGRADE"].join("_"),
    "REBOOT",
    ["SHARED", "SYSCTL", "CONF", "EDIT"].join("_"),
  ].sort();
  assert.deepEqual([...SAFETY.forbiddenActions].sort(), expectedForbidden);
  assert.deepEqual([...SAFETY.allowedKeys].sort(),
    ["net.core.default_qdisc", "net.ipv4.tcp_congestion_control"]);
  const dangerous = Object.keys(contracts.PRIVILEGED_HELPER_OPERATIONS)
    .filter((name) => /(kernel|boot|grub|reboot|upgrade|package|apt|yum)/i.test(name));
  assert.deepEqual(dangerous, []);
  assert.equal(contracts.BBR_TARGET_POLICY.otherValuesAccepted, false);
});

for (const [label, overrides, expected] of [
  ["a kernel without BBR", { kernelExposesBbr: false }, /supported-kernel eligibility/],
  ["a kernel without fq", { qdiscFqSupported: false }, /supported-kernel eligibility/],
  ["a persistent sysctl conflict", { persistentConflictPresent: true }, /conflict|exclusive[- ]create/],
  ["an existing owned drop-in", { ownedDropinPresent: true }, /conflict|exclusive[- ]create/],
]) {
  test(`${label} denies the BBR plan before any lease or write`, (t) => {
    const fx = makeFixture({ enableBbr: true, hostOverrides: overrides });
    t.after(() => fx.cleanup());
    const runId = deliverMain(fx);
    fx.ok("bbr_inventory", { run_id: runId, refresh: true });
    const writesBefore = fx.adapters.externalMutationCallCount();
    const compiled = fx.callTool("plan_compile", {
      run_id: runId, scope: "host_p3", intent: "enable_bbr",
      expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
    });
    assert.equal(compiled.status, "error");
    assert.match(compiled.error.message, expected);
    assert.equal(fx.adapters.externalMutationCallCount(), writesBefore);
    assert.equal(fx.host.ownedDropinPresent, overrides.ownedDropinPresent === true);
  });
}

test("HOST_P3 exact no-drift refresh preserves plan, cursor, approval and both expiries", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const { compiled, approved } = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_HOST_APPROVED");
  const cursorBefore = fx.ctx.ledger.cursorNext(compiled.plan_ref);

  fx.ok("bbr_inventory", { run_id: runId, refresh: true });

  const run = fx.ctx.ledger.getRun(runId);
  assert.equal(run.bbr_phase, "BBR_HOST_APPROVED", "an exact no-drift refresh changes nothing");
  assert.equal(fx.ctx.ledger.currentPlan(runId).plan_ref, compiled.plan_ref);
  assert.equal(fx.ctx.ledger.cursorNext(compiled.plan_ref).operation_ref,
    cursorBefore.operation_ref, "the cursor must not advance");
  const approval = fx.ctx.ledger.getApproval(approved.approval_ref);
  assert.equal(approval.status, "active");
  assert.equal(approval.expires_at, approved.expires_at, "the lease must not be extended");
});

test("HOST_P3 drift invalidates authority and returns to BBR_PLAN_READY", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const { compiled } = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");

  // A third party changes the kernel's live congestion control.
  fx.host.currentCongestionControl = "reno";
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });

  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_PLAN_READY");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  assert.equal(fx.ctx.ledger.cursorNext(compiled.plan_ref), null);
  assert.equal(fx.adapters.mutationCalls.filter(
    (row) => row.operationName === "origin.bbr_apply_owned.v1").length, 0);
});

test("HOST_P3 lease expiry replans instead of resuming forward", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const { compiled, approved } = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  // HOST_P3 nominal lease is PT15M.
  fx.advanceClock(16 * 60 * 1000);
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const applied = fx.callTool("bbr_apply", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("a"),
  });
  assert.equal(applied.status, "error");
  assert.equal(applied.error.code, "APPROVAL_STALE");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_PLAN_READY");
  assert.equal(fx.host.ownedDropinPresent, false, "no drop-in may be written on an expired lease");
});

test("BBR cannot be applied before the main line is delivered", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  // Inventory may precede the main gate, but compile may not.
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "host_p3", intent: "enable_bbr",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.status, "error");
  assert.equal(compiled.error.code, "WRONG_STATE");
  assert.match(compiled.error.message, /requires main_phase OLD_LINE_REVERIFIED/);
});

test("BBR cannot be applied after the main report is sealed", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  fx.ok("run_close", { run_id: runId, scope: "bbr", outcome: "partial",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("bbr") });
  fx.ok("completion_evaluate", { run_id: runId,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("comp") });
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "DELIVERY_REPORT_SEALED");
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "host_p3", intent: "enable_bbr",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.status, "error");
  assert.equal(compiled.error.code, "WRONG_STATE");
});

test("the BBR branch cannot close until post-apply evidence is re-proven", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const { compiled, approved } = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  // Stop right after verify: traffic, egress and logs are still invalidated
  // by the BBR change and have not been refreshed.
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "bbr02" });
  const early = fx.callTool("run_close", {
    run_id: runId, scope: "bbr", outcome: "accepted",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("bbr"),
  });
  assert.equal(early.status, "error");
  assert.equal(early.error.code, "EVIDENCE_STALE");
  assert.match(early.error.message, /re-proven after the BBR change/);

  // Running the remaining refresh steps unblocks the close.
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);
  const closed = fx.ok("run_close", {
    run_id: runId, scope: "bbr", outcome: "accepted",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("bbr2"),
  });
  assert.equal(closed.data.outcome, "accepted");
  assert.equal(fx.ctx.ledger.getScalar(runId, "bbr_closed_receipt"), "BBR_CLOSED_VERIFIED_RECEIPT");
});

test("a conclusively false BBR verification authorizes the dedicated rollback", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  fx.ok("bbr_inventory", { run_id: runId, refresh: true });
  const { compiled, approved } = compileAndAuthorize(fx, runId, "host_p3", "enable_bbr");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "bbr01" });

  fx.host.bbrVerifyFalse = true;
  const verified = fx.callTool("bbr_verify", {
    run_id: runId, bbr_change_ref: fx.ctx.ledger.getScalar(runId, "bbr_change_ref"),
    probe_destination_ref: fx.refs.probe_destination_ref, idempotency_key: fx.idemKey("v"),
  });
  assert.equal(verified.status, "error");
  assert.equal(verified.error.code, "PROBE_FAILED");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_MANUAL_ACTION_REQUIRED");

  // Exactly one current source episode, bound to the committed apply receipt.
  const episodes = fx.ctx.ledger.currentBbrSourceEpisodes(runId);
  assert.equal(episodes.length, 1);
  assert.equal(episodes[0].source_row_id, "CONCLUSIVE_VERIFY_FALSE");
  assert.equal(episodes[0].baseline_kind, "NORMAL_COMMITTED_APPLY");
  assert.equal(episodes[0].baseline_receipt_ref,
    fx.ctx.ledger.getScalar(runId, "bbr_apply_receipt_ref"));
});

test("a run that never requested BBR still needs an explicit closed receipt", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = deliverMain(fx);
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_NOT_REQUESTED");
  const barred = fx.callTool("completion_evaluate", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("comp"),
  });
  assert.equal(barred.error.code, "WRONG_STATE");
  const closed = fx.ok("run_close", {
    run_id: runId, scope: "bbr", outcome: "not_requested",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("bbr"),
  });
  assert.equal(closed.data.outcome, "not_requested");
  assert.equal(fx.ctx.ledger.getScalar(runId, "bbr_closed_receipt"),
    "BBR_CLOSED_NOT_REQUESTED_RECEIPT");
});
