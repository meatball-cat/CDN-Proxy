"use strict";

// Phase 3: the existing-host node journey - hostname selection, loopback
// inbound, certificate decision, nginx route, Cloudflare record and proxy
// gate, and the create-only/no-clobber rule that governs all of them.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
  refreshCheckpoint,
} = require("./helpers/fixture.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const identity = require("../mcp/core/identity.cjs");

function deliver(fx, options = {}) {
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  const steps = driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, options);
  return { runId, compiled, approved, steps };
}

test("the node journey binds one hostname across record, SAN, server_name, and client", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, steps } = deliver(fx);
  assert.equal(fx.ctx.ledger.getRun(runId).main_phase, "OLD_LINE_REVERIFIED");

  const bound = fx.ctx.ledger.identityBindings(runId);
  for (const field of contracts.DOMAIN_IDENTITY_BINDING_POLICY.equalityFields) {
    assert.equal(bound[field], fx.identityDigest,
      `${field} must bind the one registered dedicated node hostname`);
  }
  // The profile's address, SNI and websocket Host are all the same field set.
  const inspect = steps.find((row) => row.tool === "xui_profile_inspect").response.data;
  assert.equal(inspect.address_matches_node_hostname, true);
  assert.equal(inspect.sni_matches_node_hostname, true);
  assert.equal(inspect.websocket_host_matches_node_hostname, true);
  assert.equal(inspect.websocket_path_digest_matches, true);
});

test("the inbound is loopback-only plain WebSocket with a frozen CSPRNG path", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, steps } = deliver(fx, { stopAfter: "node02" });
  const inbound = steps.find((row) => row.tool === "xui_create_inbound").response.data;
  assert.equal(inbound.listen_loopback_only, true);
  assert.equal(inbound.inbound_protocol, "vless");
  assert.equal(inbound.inbound_transport, "ws");
  assert.equal(inbound.inbound_tls, "none");
  assert.equal(inbound.proxy_protocol_enabled, false);
  assert.equal(inbound.websocket_host, "");
  assert.equal(inbound.inbound_public_domain, null);
  // Only the digest crosses MCP; the raw path stays in broker custody.
  assert.match(inbound.websocket_path_digest, /^sha256:[a-f0-9]{64}$/);
  const serialized = JSON.stringify(inbound);
  assert.ok(!/"\/[A-Za-z0-9_-]{32}"/.test(serialized),
    "the raw websocket path must never enter MCP");
  assert.equal(fx.ctx.ledger.websocketPathDigest(runId), inbound.websocket_path_digest);
});

test("the client profile is created no-clobber at mode 0600 with a residual disclosure", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { steps } = deliver(fx, { stopAfter: "node03" });
  const profile = steps.find((row) => row.tool === "xui_profile_publish").response.data;
  assert.equal(profile.artifact_mode, "0600");
  assert.equal(profile.artifact_absent_before_create, true);
  assert.equal(profile.descriptor_relative_nofollow_o_excl, true);
  assert.equal(profile.created_same_run_artifact, true);
  assert.equal(profile.allow_insecure, false);
  assert.equal(profile.public_port, 443);
  assert.match(profile.residual_disclosure_ref, /^evidence:/);
});

test("a reuse-eligible certificate is reused with no certificate write", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { compiled, steps } = deliver(fx);
  assert.equal(compiled.certificate_strategy, "reuse");
  assert.equal(compiled.template_id, "NODE_P2_REUSE_V1");
  assert.ok(!steps.some((row) => row.tool === "certificate_issue_origin_ca"));
  assert.ok(!steps.some((row) => row.tool === "certificate_deploy"));
});

test("a certificate too close to expiry is not reused: Origin CA takes over", (t) => {
  // P30D minimum remaining validity on the trusted server clock.
  const fx = makeFixture({ hostOverrides: { certificateNotAfter: "2026-09-05T00:00:00Z" } });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  assert.equal(compiled.certificate_strategy, "origin_ca");
});

test("no safe reuse and no Origin CA eligibility denies before any plan or lease", (t) => {
  const fx = makeFixture({
    hostOverrides: {
      safeStableCertificateReuseEligible: false,
      originCaDedicatedSlotStatus: "foreign",
    },
  });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_p2", intent: "configure_existing",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.error.code, "CERTIFICATE_NOT_READY");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
});

test("a slot occupied between issuance and deploy revokes authority before any write", (t) => {
  const fx = makeFixture({ hostOverrides: { safeStableCertificateReuseEligible: false } });
  t.after(() => fx.cleanup());
  const { runId, compiled } = deliver(fx, { stopAfter: "node04" });
  const writesBefore = fx.adapters.externalMutationCallCount();

  // A third party occupies the dedicated slot between issuance and deploy.
  fx.host.originCaDedicatedSlotStatus = "preexisting";
  refreshCheckpoint(fx, runId);

  // The coordinated checkpoint sees the drift and takes the owned-commit
  // branch: forward authority is revoked, a recovery obligation exists, and
  // no certificate byte was ever written over the occupied slot.
  const run = fx.ctx.ledger.getRun(runId);
  assert.equal(run.main_phase, "ROLLBACK_REQUIRED");
  assert.equal(fx.ctx.ledger.currentPlan(runId), null);
  assert.ok(fx.ctx.ledger.currentRecoveryObligation(runId, "main"));
  assert.equal(fx.adapters.externalMutationCallCount(), writesBefore);
  assert.equal(fx.ctx.ledger.latestOwnership(runId, "OWNED_CERTIFICATE_SLOTS"), null);
  assert.equal(fx.ctx.ledger.cursorNext(compiled.plan_ref), null);
});

test("the deploy preflight itself refuses a slot that is not absent and root-owned", (t) => {
  // Exercises the pre-dispatch guard directly, without the checkpoint in
  // front of it, so the deploy-time rule is proven on its own.
  const fx = makeFixture({ hostOverrides: { safeStableCertificateReuseEligible: false } });
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node04" });
  const { MUTATORS } = require("../mcp/handlers/mutators.cjs");
  const run = fx.ctx.ledger.getRun(runId);
  for (const occupied of ["preexisting", "foreign", "unsafe", "unavailable"]) {
    // Re-mint the origin observation with the slot occupied.
    fx.ctx.ledger.invalidateEvidenceFamily(runId, "ORIGIN_INVENTORY");
    fx.ctx.ledger.putEvidence({
      runId, evidenceType: "ORIGIN_INVENTORY", ttl: "PT15M",
      maskedSummary: "occupied slot observation",
      payload: { origin_ca_dedicated_slot_status: occupied },
      binding: { observation: { origin_ca_dedicated_slot_status: occupied } },
    });
    assert.throws(
      () => MUTATORS.certificate_deploy.preflight(fx.ctx, run, {}),
      (error) => error.code === "CONFLICT_DETECTED" &&
        /refusing to back up, replace, or adopt/.test(error.message),
      `slot status ${occupied} must be refused`);
  }
});

for (const [mode, expectedCode] of [
  ["off", "SSL_MODE_NOT_STRICT_COMPATIBLE"],
  ["flexible", "SSL_MODE_NOT_STRICT_COMPATIBLE"],
  ["full", "SSL_MODE_NOT_STRICT_COMPATIBLE"],
  ["unknown", "SSL_MODE_NOT_STRICT_COMPATIBLE"],
]) {
  test(`zone mode ${mode} denies before any plan, lease, or write`, (t) => {
    const fx = makeFixture({ hostOverrides: { sslMode: mode } });
    t.after(() => fx.cleanup());
    const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
    runInventories(fx, runId);
    const compiled = fx.callTool("plan_compile", {
      run_id: runId, scope: "node_p2", intent: "configure_existing",
      expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
    });
    assert.equal(compiled.error.code, expectedCode);
    assert.equal(fx.ctx.ledger.currentPlan(runId), null);
    assert.equal(fx.adapters.externalMutationCallCount(), 0);
  });
}

test("disabled WebSockets deny before any plan, lease, or write", (t) => {
  const fx = makeFixture({ hostOverrides: { websocketsEnabled: false } });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_p2", intent: "configure_existing",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.error.code, "DEPENDENCY_MISSING");
  assert.match(compiled.error.message, /WebSockets are not enabled/);
});

test("Core-v1 performs no zone-wide Cloudflare setting write", () => {
  // Structural: the closed broker catalog contains no operation that could
  // change a zone-wide value, and the forward gate declares such writes
  // out of Core-v1 scope entirely.
  const zoneWriters = Object.keys(contracts.BROKER_OPERATIONS)
    .filter((name) => /zone/i.test(name) && /(write|set|update|patch|enable)/i.test(name));
  assert.deepEqual(zoneWriters, []);
  assert.equal(
    contracts.PLAN_OPERATION_RESOLVER.cloudflareForwardGate.zoneWideWritesInCoreV1, false);
  assert.equal(contracts.PLAN_OPERATION_RESOLVER.cloudflareForwardGate.callerOverride, false);
});

for (const recordCase of ["FOREIGN_OR_STALE", "AMBIGUOUS_MULTIPLE"]) {
  test(`a ${recordCase} record is never overwritten or adopted`, (t) => {
    const fx = makeFixture({ hostOverrides: { recordObservationCase: recordCase } });
    t.after(() => fx.cleanup());
    const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
    runInventories(fx, runId);
    const compiled = fx.callTool("plan_compile", {
      run_id: runId, scope: "node_p2", intent: "configure_existing",
      expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
    });
    assert.equal(compiled.status, "error");
    assert.match(compiled.error.message, /CLOUDFLARE_RECORD_CASE/);
    assert.equal(fx.adapters.externalMutationCallCount(), 0);
  });
}

test("the record is created unproxied and the proxy waits for the origin proof", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, compiled, approved, steps } = deliver(fx, { stopAfter: "node06" });
  const record = steps.find((row) => row.tool === "cf_node_record_apply").response.data;
  assert.equal(record.proxied, false, "the record must be created unproxied");
  assert.equal(record.create_only, true);
  assert.equal(record.absent_before_create, true);
  assert.equal(record.prior_record_observation_case, "ABSENT_AVAILABLE");
  assert.equal(record.record_value_source, "server_registered_current_origin_address");
  // The origin address is an opaque HMAC digest, never a raw address.
  assert.match(record.origin_address_binding_digest, /^sha256:[a-f0-9]{64}$/);

  // Attempting the proxy before the direct-origin proof fails closed.
  refreshCheckpoint(fx, runId);
  const proxyOperation = fx.ctx.ledger.planOperations(compiled.plan_ref)
    .find((row) => row.tool === "cf_proxy_enable");
  const early = fx.callTool("cf_proxy_enable", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: proxyOperation.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("p"),
  });
  assert.equal(early.status, "error");
  assert.ok(["ORIGIN_NOT_VERIFIED", "WRONG_STATE"].includes(early.error.code),
    `unexpected code ${early.error.code}`);
  assert.equal(fx.host.recordProxied, false, "no proxy may be enabled without the origin proof");
});

test("a failed direct-origin probe blocks the proxy and never fabricates a proof", (t) => {
  const fx = makeFixture({ hostOverrides: { originRouteReached: false } });
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = deliver(fx, { stopAfter: "node06" });
  refreshCheckpoint(fx, runId);
  const probe = fx.callTool("origin_verify", {
    run_id: runId, idempotency_key: fx.idemKey("ov"),
  });
  assert.equal(probe.status, "error");
  assert.equal(probe.error.code, "PROBE_FAILED");
  assert.equal(fx.ctx.ledger.freshEvidence(runId, "DIRECT_ORIGIN_TLS_WEBSOCKET"), null);
  assert.equal(fx.host.recordProxied, false);
});

test("nginx is never installed and a non-supported nginx denies the route", (t) => {
  const fx = makeFixture({ hostOverrides: { nginxInstallationStatus: "absent" } });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const compiled = fx.callTool("plan_compile", {
    run_id: runId, scope: "node_p2", intent: "configure_existing",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
  });
  assert.equal(compiled.error.code, "DEPENDENCY_MISSING");
  assert.match(compiled.error.message, /SUPPORTED_EXISTING_NGINX/);
  assert.equal(contracts.NGINX_ROUTE_POLICY.installNginx, false);
});

test("an occupied include slot or a name/path conflict denies the route", (t) => {
  for (const override of [
    { ownedIncludeSlotAvailable: false, expect: /CREATE_ONLY_OWNED_INCLUDE_SLOT/ },
    { nodeServerNameConflict: true, expect: /NO_SERVER_NAME_OR_WEBSOCKET_PATH_CONFLICT/ },
    { websocketPathConflict: true, expect: /NO_SERVER_NAME_OR_WEBSOCKET_PATH_CONFLICT/ },
    { publicTlsListenerOwner: "foreign", expect: /SAFE_PUBLIC_TLS_443_LISTENER_OWNERSHIP/ },
  ]) {
    const { expect, ...hostOverrides } = override;
    const fx = makeFixture({ hostOverrides });
    try {
      const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
      runInventories(fx, runId);
      const compiled = fx.callTool("plan_compile", {
        run_id: runId, scope: "node_p2", intent: "configure_existing",
        expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("c"),
      });
      assert.equal(compiled.status, "error");
      assert.match(compiled.error.message, expect);
      assert.equal(fx.adapters.externalMutationCallCount(), 0);
    } finally { fx.cleanup(); }
  }
});

test("a concurrent third-party digest stops a create-only write without clobbering", (t) => {
  const fx = makeFixture({ hostOverrides: { thirdPartyDigestOn: "nginx_route_apply" } });
  t.after(() => fx.cleanup());
  const { runId, compiled, approved } = deliver(fx, { stopAfter: "node03" });
  refreshCheckpoint(fx, runId);
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  assert.equal(next.tool, "nginx_route_apply");
  const applied = fx.callTool("nginx_route_apply", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("n"),
  });
  assert.equal(applied.status, "error");
  assert.equal(applied.error.code, "CONFLICT_DETECTED");
  assert.match(applied.error.message, /third-party digest|refusing to adopt or overwrite/);
  assert.equal(fx.ctx.ledger.latestOwnership(runId, "OWNED_NGINX_ROUTE"), null);
});

for (const [flagName, flags, expectedCode] of [
  ["the zone apex", { apex: true }, "UNAUTHORIZED_TARGET"],
  ["the management hostname", { management_hostname: true }, "UNAUTHORIZED_TARGET"],
  ["an ambiguous name", { ambiguous: true }, "CONFLICT_DETECTED"],
  ["an unregistered dedicated name", { dedicated_node_hostname: false }, "UNAUTHORIZED_TARGET"],
]) {
  test(`${flagName} can never be registered as the node hostname`, (t) => {
    const fx = makeFixture({ hostnameFlags: flags });
    t.after(() => fx.cleanup());
    const begun = fx.callTool("run_begin", fx.runBeginInput("configure"));
    assert.equal(begun.status, "error");
    assert.equal(begun.error.code, expectedCode);
  });
}

test("a node hostname outside the registered zone is refused", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  // Re-register the hostname under a different zone than the run's.
  const foreignZone = "target:foreignzonetestref0001";
  fx.ctx.ledger.db.prepare("UPDATE onboarding_refs SET flags = ? WHERE ref = ?")
    .run(JSON.stringify({
      dedicated_node_hostname: true, apex: false, management_hostname: false,
      ambiguous: false, zone_target_ref: foreignZone,
      hostname_identity_digest: fx.identityDigest,
    }), fx.refs.node_hostname_ref);
  const begun = fx.callTool("run_begin", fx.runBeginInput("configure"));
  assert.equal(begun.status, "error");
  assert.equal(begun.error.code, "UNAUTHORIZED_TARGET");
});

test("a client field that names a different hostname is rejected", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId, steps } = deliver(fx, { stopAfter: "node10" });
  // The profile projection now claims a different identity than the record,
  // the certificate, and the nginx server_name already bound.
  fx.host.profileIdentityDigest = `sha256:${"9".repeat(64)}`;
  const inspected = fx.callTool("xui_profile_inspect", {
    run_id: runId,
    profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
    expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
  });
  assert.equal(inspected.status, "error");
  assert.equal(inspected.error.code, "CONFLICT_DETECTED");
});

test("a client websocket path that differs from the created inbound is rejected", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const { runId } = deliver(fx, { stopAfter: "node10" });
  fx.host.profilePathDigestOverride = `sha256:${"8".repeat(64)}`;
  const inspected = fx.callTool("xui_profile_inspect", {
    run_id: runId,
    profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
    expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
  });
  assert.equal(inspected.status, "error");
  assert.equal(inspected.error.code, "CONFLICT_DETECTED");
  assert.match(inspected.error.message, /websocket path/);
});
