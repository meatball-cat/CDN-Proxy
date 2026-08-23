"use strict";

// Phase 2-4 negative security matrix.
//
// Each test names a dangerous path and proves it is unreachable, denied
// before any effect, or confined to an explicit recovery state. None of them
// asserts a warning: every one asserts a refusal.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest,
} = require("./helpers/fixture.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const { AdapterRegistry } = require("../mcp/adapters/registry.cjs");

const {
  ROOT: REPO_ROOT, SCANNER_FILES, isScannerFile, isToolingFile,
} = require("./helpers/scanner-scope.cjs");

function productionFiles() {
  const roots = ["mcp", "lifecycle", "runtime", "scripts"];
  const found = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".cjs") &&
               !full.includes(`${path.sep}contract${path.sep}`) &&
               !isToolingFile(full)) {
        found.push(full);
      }
    }
  };
  for (const root of roots) walk(path.join(REPO_ROOT, root));
  return found;
}

test("no caller-supplied command, URL, path, script, or payload reaches any adapter", () => {
  // Every public input schema is closed, and none of them carries an
  // execution-shaped field the installer policy forbids.
  const forbidden = contracts.XUI_INSTALL_POLICY.callerForbiddenFields;
  for (const tool of contracts.TOOL_LIST) {
    assert.equal(tool.inputSchema.additionalProperties, false,
      `${tool.name} input schema must be closed`);
    for (const property of Object.keys(tool.inputSchema.properties || {})) {
      assert.ok(!forbidden.includes(property),
        `${tool.name} must not expose the caller-controlled field ${property}`);
    }
  }
});

test("the adapter registry admits no operation outside the frozen catalog", () => {
  assert.throws(() => new AdapterRegistry({ helpers: { "evil.op.v1": () => {} }, broker: {} }),
    /unknown helper operation injected/);
  assert.throws(() => new AdapterRegistry({ helpers: {}, broker: { "evil.broker": () => {} } }),
    /unknown broker operation injected/);
});

test("a tool that is not a registered caller cannot invoke an operation", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  // xui_install is not a registered caller of the Cloudflare record writer.
  assert.throws(() => fx.adapters.callBroker("cf.dns_create_owned", "xui_install", {}),
    /is not a registered caller/);
  assert.throws(() => fx.adapters.callHelper("origin.xui_uninstall_owned.v1", "cf_proxy_enable", {}),
    /is not a registered caller/);
});

test("audit runs cannot reach any mutator, plan, lease, or BBR path", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("audit")).data.run_ref;
  runInventories(fx, runId);
  const allowed = contracts.RUN_MODE_POLICY.audit.allowedTools;
  const forbidden = contracts.FROZEN_TOOL_NAMES.filter((name) => !allowed.includes(name));
  assert.ok(forbidden.length > 0);
  for (const name of forbidden) {
    const response = fx.callTool(name, buildMinimalInput(name, fx, runId));
    assert.equal(response.status, "error", `${name} must be unreachable from an audit run`);
    assert.ok(["WRONG_STATE", "INVALID_INPUT"].includes(response.error.code),
      `${name} returned ${response.error.code}`);
  }
  assert.equal(fx.adapters.externalMutationCallCount(), 0);
});

function buildMinimalInput(toolName, fx, runId) {
  const schema = contracts.TOOLS_BY_NAME[toolName].inputSchema;
  const input = {};
  for (const key of schema.required || []) {
    if (key === "run_id") input[key] = runId;
    else if (key === "idempotency_key") input[key] = fx.idemKey("neg");
    else if (key === "probe_destination_ref") input[key] = fx.refs.probe_destination_ref;
    else if (key === "client_runtime_ref") input[key] = fx.refs.client_runtime_ref;
    else if (key === "expected_ledger_digest") input[key] = ledgerDigest(fx, runId);
    else if (key === "refresh") input[key] = true;
    else if (key === "max_items" || key === "max_lines_per_source") input[key] = 10;
    else if (key === "scope") input[key] = "node_p2";
    else if (key === "intent") input[key] = "configure_existing";
    else if (key === "outcome") input[key] = "abandoned";
    else if (key.endsWith("_digest")) input[key] = `sha256:${"0".repeat(64)}`;
    else if (key.endsWith("_ref")) {
      const kind = key.replace(/_ref$/, "").split("_").pop();
      const prefix = ["plan", "approval", "operation", "profile", "change", "runtime", "probe"]
        .includes(kind) ? kind : "runtime";
      input[key] = `${prefix}:${"a".repeat(24)}`;
    } else input[key] = "unused";
  }
  return input;
}

test("an audit run structurally cannot request BBR", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const attempted = fx.callTool("run_begin", fx.runBeginInput("audit", { enable_bbr: true }));
  assert.equal(attempted.status, "error");
  assert.equal(attempted.error.code, "INVALID_INPUT");
  assert.equal(contracts.RUN_MODE_POLICY.audit.enableBbr, false);
  assert.equal(contracts.RUN_MODE_POLICY.audit.externalMutation, "FORBIDDEN");
});

test("no deferred Future-v2 capability exists in the catalog or the runtime", () => {
  const deferredNames = /(acme|certbot|lets_?encrypt|renew|reissue|revoke_remote|surge|privacy|rotation)/i;
  for (const name of contracts.FROZEN_TOOL_NAMES) {
    assert.ok(!deferredNames.test(name), `${name} is a deferred Future-v2 entry point`);
  }
  for (const name of Object.keys(contracts.PRIVILEGED_HELPER_OPERATIONS)) {
    assert.ok(!/(acme|certbot|renew|reissue|surge)/i.test(name), `${name} is deferred`);
  }
  for (const name of Object.keys(contracts.BROKER_OPERATIONS)) {
    assert.ok(!/(acme|certbot|renew|reissue|surge)/i.test(name), `${name} is deferred`);
  }
});

test("production code has no shell, spawn, eval, dynamic import, or network surface", () => {
  const banned = [
    /require\(\s*["']child_process["']\s*\)/,
    /require\(\s*["']node:child_process["']\s*\)/,
    /\bexecSync\b/, /\bspawnSync\b/, /\bexecFile\b/,
    /\beval\s*\(/, /new\s+Function\s*\(/,
    /\bimport\s*\(/,
    /require\(\s*["']node:https?["']\s*\)/,
    /require\(\s*["'](node:)?net["']\s*\)/,
    /\bfetch\s*\(/,
  ];
  for (const file of productionFiles()) {
    const source = fs.readFileSync(file, "utf8");
    for (const pattern of banned) {
      assert.ok(!pattern.test(source),
        `${path.relative(REPO_ROOT, file)} matches banned pattern ${pattern}`);
    }
  }
});

test("the scanner exclusion set is exactly the two scanner files", () => {
  assert.equal(SCANNER_FILES.length, 2);
  assert.ok(SCANNER_FILES.includes(__filename));
  for (const file of SCANNER_FILES) assert.ok(fs.existsSync(file));
});

test("no durable byte contains a private-key container or a real deployment value", () => {
  const files = [...productionFiles(),
    ...fs.readdirSync(path.join(REPO_ROOT, "tests"))
      .filter((name) => name.endsWith(".cjs"))
      .map((name) => path.join(REPO_ROOT, "tests", name)),
    ...fs.readdirSync(path.join(REPO_ROOT, "tests", "helpers"))
      .map((name) => path.join(REPO_ROOT, "tests", "helpers", name)),
  ].filter((file) => !isScannerFile(file));
  assert.ok(files.length >= 15, "the scan must cover the whole repository");
  const containers = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /PuTTY-User-Key-File/,
    /BEGIN PGP PRIVATE KEY BLOCK/,
    /^SSH PRIVATE KEY/m,
  ];
  const ipv4 = /\b(?!0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.|10\.|192\.168\.)\d{1,3}(?:\.\d{1,3}){3}\b/;
  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    for (const pattern of containers) {
      assert.ok(!pattern.test(source),
        `${path.relative(REPO_ROOT, file)} contains a private-key container`);
    }
    const ipMatch = ipv4.exec(source);
    assert.equal(ipMatch, null,
      `${path.relative(REPO_ROOT, file)} contains a non-local IPv4 literal: ${ipMatch && ipMatch[0]}`);
  }
});

test("closure acknowledgement is a server-recorded host prompt, not caller data", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  // There is no acknowledgement, confirmation, or approval field a caller can
  // set on run_close: the host prompt boundary is the server's own record.
  const closeInput = Object.keys(contracts.TOOLS_BY_NAME.run_close.inputSchema.properties);
  for (const forbidden of ["acknowledged", "acknowledgement", "confirm", "confirmed", "approved_by"]) {
    assert.ok(!closeInput.includes(forbidden));
  }
  runInventories(fx, runId);
  fx.ok("run_close", { run_id: runId, scope: "bbr", outcome: "not_requested",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("b") });
  fx.ok("run_close", { run_id: runId, scope: "main", outcome: "abandoned",
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("m") });
  const events = fx.ctx.ledger.db
    .prepare("SELECT event_type, payload FROM ledger_events WHERE run_id = ? AND event_type = ?")
    .all(runId, "HOST_CLOSURE_ACKNOWLEDGEMENT");
  assert.equal(events.length, 2);
  for (const row of events) {
    assert.equal(JSON.parse(row.payload).recordedBy, "server_host_prompt_boundary");
  }
});

test("a mutator cannot dispatch without the exact current approved step", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  const writesBefore = fx.adapters.externalMutationCallCount();
  // A later step's operation ref, out of order.
  const later = compiled.operation_refs.at(-1);
  const attempted = fx.callTool("nginx_route_apply", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: later,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("n"),
  });
  assert.equal(attempted.status, "error");
  assert.equal(attempted.error.code, "WRONG_STATE");
  assert.equal(fx.adapters.externalMutationCallCount(), writesBefore);

  // A forged approval ref from no plan at all.
  const forged = fx.callTool("xui_create_inbound", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: compiled.operation_refs[1],
    approval_ref: `approval:${"z".repeat(24)}`,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("i"),
  });
  assert.equal(forged.error.code, "APPROVAL_REQUIRED");
  assert.equal(fx.adapters.externalMutationCallCount(), writesBefore);
});

test("every mutating adapter call is bound to a plan, approval, lease, and receipt", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref);

  const MUTATOR_TOOLS = contracts.PLAN_OPERATION_RESOLVER.cursorEnforcement.explicitOperationRefTools;
  const events = fx.ctx.ledger.db
    .prepare("SELECT event_type, payload FROM ledger_events WHERE run_id = ? ORDER BY seq ASC")
    .all(runId);
  const intents = events.filter((row) => row.event_type === "MUTATION_INTENT_DURABLE");
  const commits = events.filter((row) => row.event_type === "MUTATION_COMMITTED");
  assert.ok(commits.length >= 5, "the journey must have performed external mutations");
  assert.equal(intents.length, commits.length,
    "every dispatched mutation must be preceded by exactly one durable intent");

  // No mutator reached an adapter outside a durable, plan-bound intent.
  const mutatorCalls = fx.adapters.externalCalls
    .filter((row) => MUTATOR_TOOLS.includes(row.callerTool));
  assert.equal(mutatorCalls.length, intents.length,
    "a mutator must reach an adapter only through a durable intent");
  const planOperations = new Set(
    fx.ctx.ledger.planOperations(compiled.plan_ref).map((row) => row.operation_ref));
  for (const row of commits) {
    const payload = JSON.parse(row.payload);
    assert.ok(planOperations.has(payload.operationRef),
      "every commit must name an approved template operation");
    assert.match(payload.receiptRef, /^receipt:/);
    assert.match(payload.changeRef, /^change:/);
  }
  // Each committed change is reversible by exactly one owned rollback stage.
  const owned = fx.ctx.ledger.committedMainChanges(runId);
  for (const row of owned) {
    assert.equal(JSON.parse(row.details).sameRunOwned, true);
    assert.match(row.after_digest, /^sha256:[a-f0-9]{64}$/);
  }
});

test("an error envelope never carries an unmasked upstream detail", (t) => {
  const fx = makeFixture({ removeBrokerOperations: ["cf.dns_create_owned"] });
  t.after(() => fx.cleanup());
  const runId = fx.ok("run_begin", fx.runBeginInput("configure")).data.run_ref;
  runInventories(fx, runId);
  const { compiled, approved } = compileAndAuthorize(fx, runId, "node_p2", "configure_existing");
  driveTemplate(fx, runId, compiled.plan_ref, approved.approval_ref, { stopAfter: "node05" });
  const next = fx.ctx.ledger.cursorNext(compiled.plan_ref);
  const failed = fx.callTool("cf_node_record_apply", {
    run_id: runId, plan_ref: compiled.plan_ref, operation_ref: next.operation_ref,
    approval_ref: approved.approval_ref,
    expected_ledger_digest: ledgerDigest(fx, runId), idempotency_key: fx.idemKey("r"),
  });
  assert.equal(failed.status, "error");
  assert.ok(contracts.ERROR_CODES.includes(failed.error.code));
  assert.ok(failed.error.message.length <= 256);
  assert.ok(!/\bat \/|\bat Object\.|node:internal/.test(failed.error.message),
    "an error message must not leak a stack frame or an internal path");
  assert.equal(fx.ctx.ledger.latestOwnership(runId, "OWNED_CF_RECORD"), null);
});
