"use strict";

// Phase 2: the broker/Keychain credential boundary.
//
// The rule under test is one-directional: plaintext goes into broker custody
// and never comes back out. Everything the MCP surface, the ledger, the
// event log, a report, a fixture, or a test failure message can see must be
// an opaque ref or non-reversible masked metadata.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
} = require("./helpers/fixture.cjs");
const { InMemoryKeychain } = require("../mcp/secrets/keychain.cjs");
const { CredentialBroker, csprngBase64Url } = require("../mcp/secrets/broker.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");

const POLICY = contracts.GENERATED_SECRET_POLICY;

test("generated credentials follow the frozen CSPRNG policy exactly", () => {
  const broker = new CredentialBroker(new InMemoryKeychain());
  const admin = broker.generatePanelAdmin();
  assert.match(admin.secretRef, /^secret:/);
  assert.equal(admin.masked.username_length, POLICY.panelAdminUsername.outputCharacters);
  assert.equal(admin.masked.password_length, POLICY.panelAdminPassword.outputCharacters);
  assert.equal(admin.masked.username_entropy_bits, POLICY.panelAdminUsername.entropyBits);
  assert.equal(admin.masked.password_entropy_bits, POLICY.panelAdminPassword.entropyBits);
  assert.equal(admin.masked.encoding, "BASE64URL_WITHOUT_PADDING");

  const client = broker.generateVlessClientId();
  assert.equal(client.masked.format, POLICY.vlessClientId.format);
  assert.equal(client.masked.version, 4);

  const path = broker.generateWebsocketPath();
  assert.match(path.pathDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(path.masked.query_allowed, false);
  assert.equal(path.masked.fragment_allowed, false);
});

test("the broker never returns plaintext and the keychain never serializes it", () => {
  const keychain = new InMemoryKeychain();
  const broker = new CredentialBroker(keychain);
  const admin = broker.generatePanelAdmin();
  const path = broker.generateWebsocketPath();

  // No public broker return value carries the plaintext it just stored.
  const client = broker.generateVlessClientId();
  for (const value of [admin, path, client]) {
    const ref = value.secretRef || value.pathRef;
    const plaintext = keychain.use(keychain.custodyToken, ref);
    assert.equal(typeof plaintext, "string", "custody must hold the plaintext");
    const serialized = JSON.stringify(value);
    assert.ok(!serialized.includes(plaintext),
      "a broker result must never carry the plaintext it stored");
    // Nor any substantial fragment of it.
    assert.ok(!serialized.includes(plaintext.slice(0, 12)),
      "a broker result must never carry a fragment of the plaintext");
  }
  // The seam itself exposes only a count.
  assert.deepEqual(JSON.parse(JSON.stringify(keychain)),
    { keychain: "opaque", entries: keychain.custodyRefs().length });
  // And the custody token gate refuses a non-broker caller outright.
  assert.throws(() => keychain.use(Symbol("forged"), admin.secretRef),
    /only the credential broker may use plaintext/);
  assert.throws(() => keychain.put(Symbol("forged"), {
    secretRef: "secret:x", role: "xui-panel-admin", provenance: "same-run-generated", bytes: "p",
  }), /only the credential broker may store plaintext/);
});

test("generated values are unique within a scope", () => {
  const broker = new CredentialBroker(new InMemoryKeychain());
  const seen = new Set();
  for (let i = 0; i < 32; i += 1) {
    const path = broker.generateWebsocketPath();
    assert.ok(!seen.has(path.pathDigest), "websocket paths must be unique in scope");
    seen.add(path.pathDigest);
  }
  const value = csprngBase64Url(POLICY.websocketPath.randomBytes, 32);
  assert.equal(value.length, 32);
  assert.match(`/${value}`, new RegExp(POLICY.websocketPath.exactPattern));
});

test("a full install+configure run leaks no secret into MCP, ledger, or events", (t) => {
  const fx = makeFixture({ xuiCase: "ABSENT_CLEAN_ELIGIBLE" });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const install = compileAndAuthorize(fx, runId, "node_install_p3", "install_then_configure");
  const responses = driveTemplate(fx, runId, install.compiled.plan_ref, install.approved.approval_ref)
    .map((row) => row.response);
  runInventories(fx, runId);
  const node = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  responses.push(...driveTemplate(fx, runId, node.compiled.plan_ref, node.approved.approval_ref)
    .map((row) => row.response));

  // Reconstruct every plaintext the broker actually generated, then prove
  // none of it appears anywhere the caller or an operator can observe.
  const plaintexts = [];
  for (const ref of fx.keychain.custodyRefs()) {
    const bytes = fx.keychain.use(fx.keychain.custodyToken, ref);
    if (typeof bytes === "string") plaintexts.push(bytes);
  }
  assert.ok(plaintexts.length >= 4, "the run must have generated credential material");

  const surfaces = {
    "mcp results": JSON.stringify(responses),
    "ledger events": JSON.stringify(
      fx.ctx.ledger.db.prepare("SELECT event_type, payload FROM ledger_events WHERE run_id = ?").all(runId)),
    "evidence rows": JSON.stringify(
      fx.ctx.ledger.db.prepare("SELECT masked_summary, binding FROM evidence WHERE run_id = ?").all(runId)),
    "ownership receipts": JSON.stringify(fx.ctx.ledger.ownershipByRun(runId)),
    "residual disclosures": JSON.stringify(fx.ctx.ledger.residualsByRun(runId)),
  };
  for (const [surfaceName, serialized] of Object.entries(surfaces)) {
    for (const plaintext of plaintexts) {
      // Compare on a substantial slice so an accidental short collision does
      // not hide a real leak or invent a false one.
      const probe = plaintext.length > 16 ? plaintext.slice(0, 16) : plaintext;
      assert.ok(!serialized.includes(probe),
        `${surfaceName} must not contain generated credential material`);
    }
    assert.ok(!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(serialized),
      `${surfaceName} must not contain a private-key container`);
  }
});

test("a broker that returns private-key bytes is rejected, not redacted", (t) => {
  const fx = makeFixture({
    hostOverrides: { safeStableCertificateReuseEligible: false, leakPrivateKey: true },
  });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  const steps = driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref,
    { stopAfter: "node03" });
  assert.equal(steps.at(-1).tool, "xui_profile_publish");

  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const issued = fx.callTool("certificate_issue_origin_ca", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("issue"),
  });
  // The offer itself is the violation: the server refuses the result rather
  // than quietly dropping the field.
  assert.equal(issued.status, "error");
  assert.equal(issued.error.code, "SECRET_SCOPE_MISMATCH");
  assert.ok(!/-----BEGIN/.test(JSON.stringify(issued)),
    "the rejection itself must not echo private-key bytes");
});

test("secret refs are role-scoped: a wrong-role ref is refused", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node03" });

  // The profile runtime SecretRef is bound to client-profile-runtime; the
  // panel administrator ref is a different role and must not substitute.
  const profileRef = fx.ctx.ledger.getScalar(runId, "profile_ref");
  const wrongRole = fx.callTool("traffic_verify", {
    run_id: runId,
    client_runtime_ref: fx.refs.client_runtime_ref,
    profile_ref: profileRef,
    client_profile_secret_ref: fx.refs.existing_xui_admin_secret_ref,
    probe_destination_ref: fx.refs.probe_destination_ref,
    expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
    idempotency_key: fx.idemKey("traffic"),
  });
  assert.equal(wrongRole.status, "error");
  assert.ok(["SECRET_SCOPE_MISMATCH", "WRONG_STATE"].includes(wrongRole.error.code),
    `unexpected code ${wrongRole.error.code}`);
});
