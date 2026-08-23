"use strict";

// Phase 2: clean-host installer, broker-owned panel credentials, install
// ownership, and the gated dependent replan.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
} = require("./helpers/fixture.cjs");
const manifest = require("../mcp/adapters/manifest.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");

function beginCleanHost(fx) {
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  return runId;
}

test("clean-host install: fixed digest-pinned adapter, owned receipt, loopback panel", (t) => {
  const fx = makeFixture({ xuiCase: "ABSENT_CLEAN_ELIGIBLE" });
  t.after(() => fx.cleanup());
  const runId = beginCleanHost(fx);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  assert.equal(compiled.template_id, "NODE_INSTALL_V1");
  assert.equal(compiled.lease_class, "NODE_INSTALL_P3");

  const steps = driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);
  const install = steps.find((row) => row.tool === "xui_install").response;
  assert.equal(install.status, "ok", JSON.stringify(install.error));
  assert.equal(install.data.service_active, true);
  assert.equal(install.data.panel_loopback_only, true);
  assert.ok(manifest.PINNED_DIGESTS.includes(install.data.adapter_digest),
    "install must report a build-time allowlisted adapter digest");
  assert.match(install.data.installation_ownership_receipt_ref, /^receipt:/);
  assert.match(install.data.panel_admin_secret_ref, /^secret:/);

  // Ownership is committed before any dependent mutation exists.
  const owned = fx.ctx.ledger.ownershipByRun(runId)
    .filter((row) => row.object_kind === "OWNED_XUI_INSTALLATION");
  assert.equal(owned.length, 1);
  assert.equal(JSON.parse(owned[0].details).sameRunOwned, true);

  // The post-install protected-line proof is bound to the exact install
  // receipt, and only then does the install cursor complete.
  const postInstall = steps.find((row) => row.tool === "old_line_verify").response;
  assert.equal(postInstall.data.binding_scope, "post_xui_install");
  assert.equal(postInstall.data.bound_prerequisite_effect_digest, owned[0].after_digest);
  assert.equal(fx.ctx.ledger.cursorNext(compiled.plan_ref), null);
});

test("install caller input carries no command, path, credential, or port selector", () => {
  // The installer's public input schema is the whole caller surface. Every
  // execution-shaped field the policy forbids must be structurally absent.
  const inputProperties = Object.keys(
    contracts.TOOLS_BY_NAME.xui_install.inputSchema.properties);
  for (const forbidden of contracts.XUI_INSTALL_POLICY.callerForbiddenFields) {
    assert.ok(!inputProperties.includes(forbidden),
      `xui_install input must not expose ${forbidden}`);
  }
  assert.equal(contracts.TOOLS_BY_NAME.xui_install.inputSchema.additionalProperties, false);
  // And the manifest itself resolves server-side with no caller influence.
  assert.throws(() => manifest.assertNoCallerExecutionSelector({ command: "x" }),
    /caller-controlled field command/);
});

for (const [caseName, expectedCode] of [
  ["COMPATIBLE_EXISTING_WITH_IMPORTED_ADMIN", "INSTALL_NOT_ELIGIBLE"],
  ["INCOMPATIBLE_EXISTING", "INSTALL_NOT_ELIGIBLE"],
  ["AMBIGUOUS_OR_DRIFTED", "CONFLICT_DETECTED"],
  ["SAME_RUN_OWNERSHIP_DRIFTED", "CONFLICT_DETECTED"],
  ["ABSENT_NOT_INSTALL_ELIGIBLE", "INSTALL_NOT_ELIGIBLE"],
  ["MISSING_REQUIRED_ADMIN_SECRET", "SECRET_REF_MISSING"],
]) {
  test(`install denies ${caseName} before any effect`, (t) => {
    const fx = makeFixture({ xuiCase: caseName });
    t.after(() => fx.cleanup());
    const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
    runInventories(fx, runId);
    const compiled = fx.callTool("plan_compile", {
      run_id: runId, scope: "node_install_p3", intent: "install_then_configure",
      expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
    });
    assert.equal(compiled.status, "error");
    assert.equal(compiled.error.code, expectedCode);
    // Nothing was planned, leased, or dispatched.
    assert.equal(fx.ctx.ledger.currentPlan(runId), null);
    assert.equal(fx.adapters.externalMutationCallCount(), 0);
    assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "INVENTORIED");
  });
}

test("an unsupported host family has no eligible pinned adapter and never installs", (t) => {
  const fx = makeFixture({
    xuiCase: "ABSENT_CLEAN_ELIGIBLE",
    hostOverrides: { osFamily: "unsupported" },
  });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_install_p3", intent: "install_then_configure",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.error.code, "INSTALL_ADAPTER_UNTRUSTED");
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
});

test("an install readback outside the pinned allowlist is rejected as untrusted", (t) => {
  const fx = makeFixture({
    xuiCase: "ABSENT_CLEAN_ELIGIBLE",
    hostOverrides: { adapterDigest: `sha256:${"c".repeat(64)}` },
  });
  t.after(() => fx.cleanup());
  const runId = beginCleanHost(fx);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const install = fx.callTool("xui_install", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("i"),
  });
  assert.equal(install.status, "error");
  assert.equal(install.error.code, "INSTALL_ADAPTER_UNTRUSTED");
  // The local commit rolled back with the readback: no ownership receipt.
  assert.equal(fx.ctx.ledger.ownershipByRun(runId)
    .filter((row) => row.object_kind === "OWNED_XUI_INSTALLATION").length, 0);
});

test("the dependent node plan requires a fresh install-bound protected-line proof", (t) => {
  const fx = makeFixture({ xuiCase: "ABSENT_CLEAN_ELIGIBLE" });
  t.after(() => fx.cleanup());
  const runId = beginCleanHost(fx);
  const install = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  driveTemplate(fx, runId, install.compiled.plan_ref, install.approved.approval_ref);

  // Invalidating the install-bound proof must block the dependent plan.
  fx.ctx.ledger.invalidateEvidenceFamily(runId, "PROTECTED_LINE_HEALTH");
  const blocked = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_p2", intent: "configure_existing",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(blocked.status, "error");
  assert.equal(blocked.error.code, "EVIDENCE_STALE");

  // Re-proving it, with fresh inventories, admits exactly one dependent plan.
  runInventories(fx, runId);
  const node = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  assert.match(node.compiled.template_id, /^NODE_P2_/);
  assert.equal(node.compiled.lease_class, "NODE_P2");
  // The install lease is never inherited.
  assert.notEqual(node.approved.approval_ref, install.approved.approval_ref);
});

test("a dependent plan is refused while a recovery obligation is open", (t) => {
  const fx = makeFixture({ xuiCase: "ABSENT_CLEAN_ELIGIBLE" });
  t.after(() => fx.cleanup());
  const runId = beginCleanHost(fx);
  const install = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  driveTemplate(fx, runId, install.compiled.plan_ref, install.approved.approval_ref);
  runInventories(fx, runId);

  fx.ctx.ledger.insertRecoveryObligation({
    obligationRef: "runtime:openobligationtest0001",
    runId, column: "main", cause: "TEST_OPEN_OBLIGATION", boundGraphDigest: null,
  });
  const blocked = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_p2", intent: "configure_existing",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(blocked.status, "error");
  assert.match(blocked.error.message, /NO_UNKNOWN_COMMIT_OR_RECOVERY_OBLIGATION/);
});

test("the panel credential is minted by the registered broker operation, not the installer", (t) => {
  const fx = makeFixture({ xuiCase: "ABSENT_CLEAN_ELIGIBLE" });
  t.after(() => fx.cleanup());
  const runId = beginCleanHost(fx);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);

  // Both edges are registered adapter operations, dispatched in order
  // through the closed registry with the install as their bound caller.
  const installEdges = fx.adapters.externalCalls.filter((row) => row.callerTool === "xui_install");
  assert.deepEqual(installEdges.map((row) => row.operationName), [
    contracts.XUI_INSTALL_POLICY.helperOperation,
    contracts.XUI_INSTALL_POLICY.brokerOperation,
  ]);
  // And the broker operation is not callable by any other tool.
  const spec = contracts.BROKER_OPERATIONS[contracts.XUI_INSTALL_POLICY.brokerOperation];
  assert.deepEqual([...spec.callers], ["xui_install"]);
  assert.equal(spec.plaintextResult, false);
  assert.equal(spec.producesSecretRole, "xui-panel-admin");
});

test("an unavailable credential broker aborts the install without an ownership receipt", (t) => {
  const fx = makeFixture({
    xuiCase: "ABSENT_CLEAN_ELIGIBLE",
    removeBrokerOperations: [contracts.XUI_INSTALL_POLICY.brokerOperation],
  });
  t.after(() => fx.cleanup());
  const runId = beginCleanHost(fx);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const install = fx.callTool("xui_install", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("i"),
  });
  assert.equal(install.status, "error");
  assert.equal(install.error.code, "UPSTREAM_UNAVAILABLE");
  // No install ownership was committed, so no dependent step can proceed and
  // no inverse can later claim to own an installation.
  assert.equal(fx.ctx.ledger.latestOwnership(runId, "OWNED_XUI_INSTALLATION"), null);
  assert.equal(fx.ctx.ledger.getScalar(runId, "install_receipt_ref"), null);
});
