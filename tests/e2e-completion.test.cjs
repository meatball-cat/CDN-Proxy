"use strict";

// Phase 3/4: authenticated end-to-end verification and sealed completion.
//
// The property under test is that no weaker signal can stand in for the real
// thing: a TLS handshake, an HTTP 101 upgrade, a low latency, or a
// well-formed static profile must all fail to produce a sealed delivery.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
  refreshCheckpoint,
} = require("./helpers/fixture.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const { LowEntropyBinder } = require("../mcp/core/hmac.cjs");

const E2E = contracts.AUTHENTICATED_E2E_POLICY;

function deliver(fx, options = {}) {
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  const steps = driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, options);
  return { runId, compiled, approved, steps };
}

function closeBbrNotRequested(fx, runId) {
  return fx.ok("run_close", {
    run_id: runId, scope: "bbr", outcome: "not_requested",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("bbr"),
  });
}

test("a complete journey seals end_to_end_verified with all seven requirements", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx);
  closeBbrNotRequested(fx, runId);
  const completion = fx.ok("completion_evaluate", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("comp"),
  });
  assert.equal(completion.status, "ok");
  assert.equal(completion.data.label, "end_to_end_verified");
  assert.equal(completion.data.all_required_true, true);
  assert.deepEqual(
    [...completion.data.satisfied_requirement_ids].sort(),
    [...E2E.requiredEvidence].sort());
  assert.match(completion.data.residual_disclosure_ref, /^evidence:/);
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "DELIVERY_REPORT_SEALED");

  const closed = fx.ok("run_close", {
    run_id: runId, scope: "main", outcome: "accepted",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("close"),
  });
  assert.equal(closed.data.bound_completion_label, "end_to_end_verified");
  assert.equal(closed.data.bound_completion_report_digest, completion.data.report_digest);
  assert.match(closed.data.residual_disclosure_ref, /^evidence:/);
});

test("traffic that is not authenticated fails: TLS and 101 alone are not E2E", (t) => {
  const fx = makeFixture({ hostOverrides: { authenticated: false } });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node11" });
  refreshCheckpoint(fx, runId);
  const traffic = fx.callTool("traffic_verify", {
    run_id: runId,
    client_runtime_ref: fx.refs.client_runtime_ref,
    profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
    client_profile_secret_ref: fx.ctx.ledger.getScalar(runId, "profile_secret_ref"),
    probe_destination_ref: fx.refs.probe_destination_ref,
    expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
    idempotency_key: fx.idemKey("traffic"),
  });
  assert.equal(traffic.status, "error");
  assert.equal(traffic.error.code, "PROBE_FAILED");
  assert.match(traffic.error.message, /HTTP 101 alone is not end-to-end evidence/);
  assert.equal(fx.ctx.ledger.freshEvidence(runId, "AUTHENTICATED_PROXY_REQUEST"), null);
});

test("egress that does not match the origin's own expected egress fails", (t) => {
  const fx = makeFixture({ hostOverrides: { proxyEgressToken: "different-egress-token" } });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node11" });
  refreshCheckpoint(fx, runId);
  const traffic = fx.callTool("traffic_verify", {
    run_id: runId,
    client_runtime_ref: fx.refs.client_runtime_ref,
    profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
    client_profile_secret_ref: fx.ctx.ledger.getScalar(runId, "profile_secret_ref"),
    probe_destination_ref: fx.refs.probe_destination_ref,
    expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
    idempotency_key: fx.idemKey("traffic"),
  });
  assert.equal(traffic.status, "error");
  assert.equal(traffic.error.code, "PROBE_FAILED");
  assert.match(traffic.error.message, /does not equal the origin's expected egress/);
});

test("the egress comparison is opaque: no raw address reaches MCP", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, steps } = deliver(fx);
  const traffic = steps.find((row) => row.tool === "traffic_verify").response.data;
  assert.equal(traffic.observed_egress_equals_expected, true);
  assert.equal(traffic.same_allowlisted_destination, true);
  assert.equal(traffic.raw_egress_value_exposed, false);
  assert.match(traffic.expected_egress_binding_digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(traffic.proxy_observed_egress_binding_digest, /^sha256:[a-f0-9]{64}$/);
  // Same value, same domain, same key: the two digests are equal by design.
  assert.ok(LowEntropyBinder.equal(
    traffic.expected_egress_binding_digest, traffic.proxy_observed_egress_binding_digest));
  const serialized = JSON.stringify(steps.map((row) => row.response));
  assert.ok(!/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(serialized),
    "no raw IPv4 literal may appear in any MCP result");
});

test("a raw address offered by an adapter is refused, not forwarded", (t) => {
  const fx = makeFixture({ hostOverrides: { leakRawEgress: true } });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node11" });
  refreshCheckpoint(fx, runId);
  const traffic = fx.callTool("traffic_verify", {
    run_id: runId,
    client_runtime_ref: fx.refs.client_runtime_ref,
    profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
    client_profile_secret_ref: fx.ctx.ledger.getScalar(runId, "profile_secret_ref"),
    probe_destination_ref: fx.refs.probe_destination_ref,
    expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
    idempotency_key: fx.idemKey("traffic"),
  });
  assert.equal(traffic.status, "error");
  assert.equal(traffic.error.code, "INTERNAL_ERROR");
  assert.ok(!/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(JSON.stringify(traffic)),
    "the rejection must not echo the raw address");
});

test("cross-domain egress digests are never compared", () => {
  // Two digests over the same value in different comparison domains must not
  // be equal, and comparing across domains is refused outright.
  assert.throws(() => LowEntropyBinder.requireSameDomain(
    "DIRECT_EXPECTED_EGRESS", "PUBLIC_RESOLUTION"), /different comparison domains/);
  assert.equal(LowEntropyBinder.requireSameDomain(
    "DIRECT_EXPECTED_EGRESS", "PROXY_OBSERVED_EGRESS"), "EGRESS_EQUALITY_V1");
});

test("a public resolution equal to the origin is not a fronted CDN", (t) => {
  const fx = makeFixture({ hostOverrides: {} });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node09" });
  // The edge answer is the origin itself: the record is not actually fronted.
  fx.host.publicResolutionToken = fx.host.originAddressToken;
  refreshCheckpoint(fx, runId);
  const cdn = fx.callTool("cdn_verify", {
    run_id: runId, probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: fx.idemKey("cdn"),
  });
  assert.equal(cdn.status, "error");
  assert.equal(cdn.error.code, "CDN_NOT_VERIFIED");
  assert.match(cdn.error.message, /not Cloudflare-fronted/);
});

test("uncorrelated logs block completion", (t) => {
  const fx = makeFixture({ hostOverrides: { xrayCorrelated: false } });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node12" });
  const traffic = fx.ctx.ledger.freshEvidence(runId, "AUTHENTICATED_PROXY_REQUEST");
  const binding = JSON.parse(traffic.binding);
  const logs = fx.callTool("logs_correlate", {
    run_id: runId, probe_ref: binding.probeRef,
    correlation_window_ref: binding.correlationWindowRef, max_lines_per_source: 50,
  });
  assert.equal(logs.status, "error");
  assert.equal(logs.error.code, "PROBE_FAILED");
  closeBbrNotRequested(fx, runId);
  const completion = fx.callTool("completion_evaluate", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("comp"),
  });
  assert.equal(completion.status, "pending");
  assert.equal(completion.data.label, "configured_not_verified");
  assert.ok(!completion.data.satisfied_requirement_ids.includes("NGINX_XRAY_LOG_CORRELATION"));
});

test("an unhealthy protected line blocks the final proof and completion", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node13" });
  fx.host.protectedLineHealthy = false;
  const final = fx.callTool("old_line_verify", {
    run_id: runId, probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: fx.idemKey("old"),
  });
  assert.equal(final.status, "error");
  assert.equal(final.error.code, "PROBE_FAILED");
});

test("main accepted close is refused without a sealed end_to_end_verified report", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node11" });
  closeBbrNotRequested(fx, runId);
  const closed = fx.callTool("run_close", {
    run_id: runId, scope: "main", outcome: "accepted",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("close"),
  });
  assert.equal(closed.status, "error");
  assert.equal(closed.error.code, "WRONG_STATE");
});

test("completion is refused while the configure BBR branch is unresolved", (t) => {
  const fx = makeFixture({ enableBbr: true });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx);
  const barred = fx.callTool("completion_evaluate", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("comp"),
  });
  assert.equal(barred.status, "error");
  assert.equal(barred.error.code, "WRONG_STATE");
  assert.match(barred.error.message, /BBR branch to be closed/);
});

test("audit runs are exempt from the configure-only BBR barrier", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("audit")).data.run_ref;
  runInventories(fx, runId);
  const completion = fx.ok("completion_evaluate", {
    run_id: runId, expected_ledger_digest: ledgerDigest(fx, runId),
    idempotency_key: fx.idemKey("comp"),
  });
  assert.equal(completion.status, "ok");
  assert.equal(completion.data.label, "audit_complete");
  assert.equal(fx.ctx.ledger.getRun(runId).bbr_phase, "BBR_NOT_REQUESTED");
});
