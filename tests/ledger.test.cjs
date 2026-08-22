"use strict";

// Acceptance: WAL journal mode, transactional atomicity, idempotent replay
// semantics, hash-chained digests, evidence TTL behavior, and basic crash
// recovery (reopen from the same data dir).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Ledger } = require("../mcp/ledger/ledger.cjs");
const { makeFixture } = require("./helpers/fixture.cjs");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "cdn-ledger-test-"));
}

test("ledger opens in WAL journal mode", (t) => {
  const dir = tempDir();
  const ledger = new Ledger({ dataDir: dir });
  t.after(() => { ledger.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  assert.equal(ledger.journalMode(), "wal");
});

test("transactions are atomic: a throwing transaction leaves no partial writes", (t) => {
  const dir = tempDir();
  const ledger = new Ledger({ dataDir: dir });
  t.after(() => { ledger.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  ledger.createRun({
    runId: "run:atomictestrun1", runMode: "audit", mainPhase: "NEW",
    bbrPhase: "BBR_NOT_REQUESTED", enableBbr: false, binding: {},
    targetSetDigest: `sha256:${"a".repeat(64)}`, nodeBindingDigest: `sha256:${"b".repeat(64)}`,
  });
  const before = ledger.getRun("run:atomictestrun1").ledger_digest;
  assert.throws(() => ledger.transaction(() => {
    ledger.appendEvent("run:atomictestrun1", "WILL_ROLL_BACK", {});
    ledger.putEvidence({
      runId: "run:atomictestrun1", evidenceType: "ORIGIN_INVENTORY", ttl: "PT15M",
      maskedSummary: "will roll back", payload: {},
    });
    throw new Error("boom");
  }));
  assert.equal(ledger.getRun("run:atomictestrun1").ledger_digest, before);
  assert.equal(ledger.freshEvidence("run:atomictestrun1", "ORIGIN_INVENTORY"), null);
  const events = ledger.db.prepare(
    "SELECT COUNT(*) AS n FROM ledger_events WHERE event_type = 'WILL_ROLL_BACK'").get();
  assert.equal(events.n, 0);
});

test("idempotency: exact replay is no_op with the original binding; drifted input conflicts", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const input = fx.runBeginInput("audit");
  const first = fx.callTool("run_begin", input);
  assert.equal(first.status, "ok");
  const replay = fx.callTool("run_begin", input);
  assert.equal(replay.status, "no_op");
  assert.deepEqual(replay.data, first.data);
  const conflicting = fx.callTool("run_begin", { ...input, enable_bbr: false, mode: "audit",
    output_dir_ref: input.output_dir_ref, cf_node_dns_secret_ref: null });
  assert.equal(conflicting.status, "error");
  assert.equal(conflicting.error.code, "IDEMPOTENCY_CONFLICT");
});

test("recovery: reopening the same data dir preserves runs, chain digests, and evidence", (t) => {
  const dir = tempDir();
  let ledger = new Ledger({ dataDir: dir });
  ledger.createRun({
    runId: "run:recoverytest01", runMode: "configure", mainPhase: "NEW",
    bbrPhase: "BBR_PENDING", enableBbr: true, binding: { marker: 1 },
    targetSetDigest: `sha256:${"c".repeat(64)}`, nodeBindingDigest: `sha256:${"d".repeat(64)}`,
  });
  ledger.appendEvent("run:recoverytest01", "MARKER", { step: 1 });
  const evidenceRef = ledger.putEvidence({
    runId: "run:recoverytest01", evidenceType: "ORIGIN_INVENTORY", ttl: "PT15M",
    maskedSummary: "masked", payload: { masked: true },
  });
  const digestBefore = ledger.getRun("run:recoverytest01").ledger_digest;
  ledger.close();

  ledger = new Ledger({ dataDir: dir });
  t.after(() => { ledger.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const run = ledger.getRun("run:recoverytest01");
  assert.equal(run.ledger_digest, digestBefore);
  assert.equal(run.bbr_phase, "BBR_PENDING");
  assert.equal(run.binding.marker, 1);
  const evidence = ledger.freshEvidence("run:recoverytest01", "ORIGIN_INVENTORY");
  assert.equal(evidence.evidence_ref, evidenceRef);
});

test("phase writes extend the hash chain deterministically", (t) => {
  const dir = tempDir();
  const ledger = new Ledger({ dataDir: dir });
  t.after(() => { ledger.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  ledger.createRun({
    runId: "run:chaintest00001", runMode: "audit", mainPhase: "NEW",
    bbrPhase: "BBR_NOT_REQUESTED", enableBbr: false, binding: {},
    targetSetDigest: `sha256:${"a".repeat(64)}`, nodeBindingDigest: `sha256:${"b".repeat(64)}`,
  });
  const d0 = ledger.getRun("run:chaintest00001").ledger_digest;
  const d1 = ledger.setPhases("run:chaintest00001", { mainPhase: "INVENTORIED" });
  assert.notEqual(d0, d1);
  assert.match(d1, /^sha256:[a-f0-9]{64}$/);
  const rows = ledger.db.prepare(
    "SELECT digest FROM ledger_events WHERE run_id = ? ORDER BY seq").all("run:chaintest00001");
  assert.equal(rows[rows.length - 1].digest, d1);
});

test("evidence TTL: stale evidence stops satisfying completion", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const begun = fx.callTool("run_begin", fx.runBeginInput("audit"));
  const runId = begun.data.run_ref;
  for (const tool of ["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory"]) {
    assert.equal(fx.callTool(tool, { run_id: runId, refresh: false }).status, "ok");
  }
  assert.equal(fx.callTool("old_line_verify", {
    run_id: runId,
    probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: "ttl-old-line-00001",
  }).status, "ok");

  // Protected-line health has PT5M TTL; advance past it.
  fx.advanceClock(6 * 60 * 1000);
  const status = fx.callTool("run_status", { run_id: runId });
  assert.ok(status.data.stale_evidence_refs.length >= 1);
  const stale = fx.callTool("completion_evaluate", {
    run_id: runId,
    expected_ledger_digest: status.data.ledger_digest,
    idempotency_key: "ttl-completion-0001",
  });
  assert.equal(stale.status, "error");
  assert.equal(stale.error.code, "EVIDENCE_STALE");
});

test("expected_ledger_digest drift is rejected as BASELINE_DRIFT", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const begun = fx.callTool("run_begin", fx.runBeginInput("audit"));
  assert.equal(fx.callTool("origin_inventory",
    { run_id: begun.data.run_ref, refresh: false }).status, "ok");
  const drifted = fx.callTool("completion_evaluate", {
    run_id: begun.data.run_ref,
    expected_ledger_digest: `sha256:${"0".repeat(64)}`,
    idempotency_key: "drift-completion-01",
  });
  assert.equal(drifted.status, "error");
  assert.equal(drifted.error.code, "BASELINE_DRIFT");
});
