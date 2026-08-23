"use strict";

// Local SQLite WAL ledger. Owns runs, immutable target/onboarding records,
// plans, challenges, approvals (leases), operation cursor, idempotency,
// evidence, reports, closures, ownership receipts, and reconciliation
// obligations. No secret bytes are ever stored here - only opaque refs and
// masked metadata.

const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { mintRef, digestOf } = require("../core/refs.cjs");

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS onboarding_refs (
  ref TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  role TEXT NOT NULL,
  masked_label TEXT NOT NULL,
  flags TEXT NOT NULL DEFAULT '{}',
  registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  run_mode TEXT NOT NULL CHECK (run_mode IN ('audit','configure')),
  main_phase TEXT NOT NULL,
  bbr_phase TEXT NOT NULL,
  enable_bbr INTEGER NOT NULL,
  binding TEXT NOT NULL,
  target_set_digest TEXT NOT NULL,
  node_binding_digest TEXT NOT NULL,
  ledger_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
  plan_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  intent TEXT NOT NULL,
  template_id TEXT NOT NULL,
  lease_class TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  baseline_digest TEXT NOT NULL,
  impact_digest TEXT NOT NULL,
  certificate_strategy TEXT NOT NULL,
  node_binding_digest TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'current',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
  challenge_ref TEXT PRIMARY KEY,
  plan_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  approval_ref TEXT PRIMARY KEY,
  plan_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  lease_class TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
  operation_ref TEXT PRIMARY KEY,
  plan_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  step_index INTEGER NOT NULL,
  step_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
  run_scope TEXT NOT NULL,
  tool TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_scope, tool, idem_key)
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  ttl_seconds INTEGER,
  masked_summary TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  binding TEXT NOT NULL DEFAULT '{}',
  invalidated INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
  report_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  label TEXT NOT NULL,
  report_digest TEXT NOT NULL,
  sealed INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS closures (
  closure_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  outcome TEXT NOT NULL,
  closure_digest TEXT NOT NULL,
  residual_disclosure_ref TEXT,
  bound_completion_label TEXT,
  bound_completion_report_digest TEXT,
  final_ledger_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ownership (
  receipt_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  object_kind TEXT NOT NULL,
  change_ref TEXT NOT NULL,
  before_digest TEXT,
  after_digest TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reconciliation_obligations (
  obligation_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  original_tool TEXT NOT NULL,
  failure_context TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_refs (
  secret_ref TEXT PRIMARY KEY,
  run_id TEXT,
  role TEXT NOT NULL,
  provenance TEXT NOT NULL,
  disposition TEXT NOT NULL DEFAULT 'current',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_bindings (
  run_id TEXT NOT NULL,
  field TEXT NOT NULL,
  identity_digest TEXT NOT NULL,
  bound_at TEXT NOT NULL,
  PRIMARY KEY (run_id, field)
);
CREATE TABLE IF NOT EXISTS run_scalars (
  run_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (run_id, key)
);
CREATE TABLE IF NOT EXISTS stage_receipts (
  receipt_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  family TEXT NOT NULL CHECK (family IN ('MAIN_ROLLBACK_STAGE_RECEIPT','BBR_ROLLBACK_STAGE_RECEIPT')),
  operation_ref TEXT NOT NULL,
  stage_id TEXT NOT NULL,
  stage_index INTEGER NOT NULL,
  readback_digest TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aggregate_receipts (
  receipt_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  receipt_type TEXT NOT NULL,
  operation_ref TEXT NOT NULL,
  selection_digest TEXT NOT NULL,
  stage_receipt_refs TEXT NOT NULL,
  commit_digest TEXT NOT NULL,
  final_digest TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_obligations (
  obligation_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  column_name TEXT NOT NULL CHECK (column_name IN ('main','bbr')),
  cause TEXT NOT NULL,
  bound_graph_digest TEXT,
  status TEXT NOT NULL DEFAULT 'current',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bbr_source_episodes (
  episode_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  source_row_id TEXT NOT NULL,
  durable_cause TEXT NOT NULL,
  baseline_kind TEXT NOT NULL,
  baseline_receipt_ref TEXT NOT NULL,
  baseline_change_ref TEXT NOT NULL,
  baseline_binding_digest TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'current',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admission_receipts (
  receipt_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  receipt_type TEXT NOT NULL,
  binding_digest TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS residuals (
  residual_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  masked_summary TEXT NOT NULL,
  binding_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_dispositions (
  receipt_ref TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  secret_ref TEXT NOT NULL,
  role TEXT NOT NULL,
  disposition TEXT NOT NULL,
  residual_ref TEXT,
  created_at TEXT NOT NULL
);
`;

function parseIsoDurationSeconds(ttl) {
  if (!ttl || ttl === "NO_TTL") return null;
  const match = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(ttl);
  if (!match) return null;
  return (Number(match[1] || 0) * 3600) + (Number(match[2] || 0) * 60) + Number(match[3] || 0);
}

class Ledger {
  constructor({ dataDir, now = () => Date.now() } = {}) {
    if (!dataDir) throw new Error("ledger requires an explicit dataDir");
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.dbPath = path.join(dataDir, "ledger.sqlite3");
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec("PRAGMA journal_mode=WAL");
    this.db.exec("PRAGMA foreign_keys=ON");
    this.db.exec("PRAGMA synchronous=FULL");
    this.db.exec(SCHEMA_SQL);
    this.now = now;
  }

  close() {
    this.db.close();
  }

  journalMode() {
    return this.db.prepare("PRAGMA journal_mode").get().journal_mode;
  }

  nowIso() {
    return new Date(this.now()).toISOString();
  }

  transaction(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  // --- onboarding registry (immutable target/runtime/secret records) ---

  registerOnboardingRef({ ref, kind, role, maskedLabel, flags = {} }) {
    this.db.prepare(
      "INSERT INTO onboarding_refs (ref, kind, role, masked_label, flags, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(ref, kind, role, maskedLabel, JSON.stringify(flags), this.nowIso());
  }

  getOnboardingRef(ref) {
    const row = this.db.prepare("SELECT * FROM onboarding_refs WHERE ref = ?").get(ref);
    if (!row) return null;
    return { ...row, flags: JSON.parse(row.flags) };
  }

  // --- runs and hash-chained events ---

  createRun({ runId, runMode, mainPhase, bbrPhase, enableBbr, binding, targetSetDigest, nodeBindingDigest }) {
    const genesis = digestOf({ runId, runMode, binding });
    this.db.prepare(
      `INSERT INTO runs (run_id, run_mode, main_phase, bbr_phase, enable_bbr, binding,
        target_set_digest, node_binding_digest, ledger_digest, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(runId, runMode, mainPhase, bbrPhase, enableBbr ? 1 : 0, JSON.stringify(binding),
      targetSetDigest, nodeBindingDigest, genesis, this.nowIso());
    return this.getRun(runId);
  }

  getRun(runId) {
    const row = this.db.prepare("SELECT * FROM runs WHERE run_id = ?").get(runId);
    if (!row) return null;
    return { ...row, enable_bbr: row.enable_bbr === 1, binding: JSON.parse(row.binding) };
  }

  appendEvent(runId, eventType, payload = {}) {
    const run = this.getRun(runId);
    if (!run) throw new Error(`unknown run ${runId}`);
    const digest = digestOf({ prev: run.ledger_digest, eventType, payload });
    this.db.prepare(
      "INSERT INTO ledger_events (run_id, event_type, payload, digest, created_at) VALUES (?, ?, ?, ?, ?)",
    ).run(runId, eventType, JSON.stringify(payload), digest, this.nowIso());
    this.db.prepare("UPDATE runs SET ledger_digest = ? WHERE run_id = ?").run(digest, runId);
    return digest;
  }

  setPhases(runId, { mainPhase, bbrPhase }) {
    const run = this.getRun(runId);
    if (!run) throw new Error(`unknown run ${runId}`);
    const nextMain = mainPhase || run.main_phase;
    const nextBbr = bbrPhase || run.bbr_phase;
    this.db.prepare("UPDATE runs SET main_phase = ?, bbr_phase = ? WHERE run_id = ?")
      .run(nextMain, nextBbr, runId);
    return this.appendEvent(runId, "PHASE_WRITE", { mainPhase: nextMain, bbrPhase: nextBbr });
  }

  // --- idempotency ---

  findIdempotent(runScope, tool, idemKey) {
    const row = this.db.prepare(
      "SELECT * FROM idempotency WHERE run_scope = ? AND tool = ? AND idem_key = ?",
    ).get(runScope, tool, idemKey);
    if (!row) return null;
    return { inputDigest: row.input_digest, result: JSON.parse(row.result) };
  }

  saveIdempotent(runScope, tool, idemKey, inputDigest, result) {
    this.db.prepare(
      "INSERT INTO idempotency (run_scope, tool, idem_key, input_digest, result, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(runScope, tool, idemKey, inputDigest, JSON.stringify(result), this.nowIso());
  }

  // --- evidence ---

  putEvidence({ runId, evidenceType, ttl, maskedSummary, payload, binding = {} }) {
    const evidenceRef = mintRef("evidence");
    this.db.prepare(
      `INSERT INTO evidence (evidence_ref, run_id, evidence_type, ttl_seconds, masked_summary,
        payload_digest, binding, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(evidenceRef, runId, evidenceType, parseIsoDurationSeconds(ttl), maskedSummary,
      digestOf(payload ?? {}), JSON.stringify(binding), this.nowIso());
    return evidenceRef;
  }

  freshEvidence(runId, evidenceType) {
    const rows = this.db.prepare(
      "SELECT * FROM evidence WHERE run_id = ? AND evidence_type = ? AND invalidated = 0 ORDER BY rowid DESC",
    ).all(runId, evidenceType);
    const nowMs = this.now();
    for (const row of rows) {
      if (row.ttl_seconds === null) return row;
      if (Date.parse(row.created_at) + row.ttl_seconds * 1000 > nowMs) return row;
    }
    return null;
  }

  listEvidence(runId, afterRef = null, maxItems = 100) {
    const all = this.db.prepare(
      "SELECT evidence_ref, masked_summary FROM evidence WHERE run_id = ? ORDER BY rowid ASC",
    ).all(runId);
    let start = 0;
    if (afterRef) {
      const idx = all.findIndex((row) => row.evidence_ref === afterRef);
      start = idx >= 0 ? idx + 1 : all.length;
    }
    const rows = all.slice(start, start + maxItems);
    const last = rows.length > 0 ? rows[rows.length - 1].evidence_ref : afterRef;
    return { rows, hasMore: start + rows.length < all.length, lastRef: last, total: all.length };
  }

  staleEvidenceRefs(runId) {
    const rows = this.db.prepare(
      "SELECT evidence_ref, ttl_seconds, created_at FROM evidence WHERE run_id = ? AND invalidated = 0",
    ).all(runId);
    const nowMs = this.now();
    return rows
      .filter((row) => row.ttl_seconds !== null &&
        Date.parse(row.created_at) + row.ttl_seconds * 1000 <= nowMs)
      .map((row) => row.evidence_ref);
  }

  // --- plans, challenges, approvals, operations ---

  currentPlan(runId) {
    const row = this.db.prepare(
      "SELECT * FROM plans WHERE run_id = ? AND status = 'current' ORDER BY rowid DESC LIMIT 1",
    ).get(runId);
    return row || null;
  }

  invalidateCurrentPlan(runId) {
    const plan = this.currentPlan(runId);
    if (!plan) return;
    this.db.prepare("UPDATE plans SET status = 'invalidated' WHERE plan_ref = ?").run(plan.plan_ref);
    this.db.prepare("UPDATE challenges SET status = 'invalidated' WHERE plan_ref = ? AND status = 'open'").run(plan.plan_ref);
    this.db.prepare("UPDATE approvals SET status = 'invalidated' WHERE plan_ref = ? AND status = 'active'").run(plan.plan_ref);
    this.db.prepare("UPDATE operations SET status = 'invalidated' WHERE plan_ref = ? AND status = 'pending'").run(plan.plan_ref);
  }

  insertPlan(plan) {
    this.db.prepare(
      `INSERT INTO plans (plan_ref, run_id, scope, intent, template_id, lease_class, plan_digest,
        baseline_digest, impact_digest, certificate_strategy, node_binding_digest, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'current', ?)`,
    ).run(plan.planRef, plan.runId, plan.scope, plan.intent, plan.templateId, plan.leaseClass,
      plan.planDigest, plan.baselineDigest, plan.impactDigest, plan.certificateStrategy,
      plan.nodeBindingDigest, this.nowIso());
  }

  insertChallenge({ challengeRef, planRef, runId, expiresAt }) {
    this.db.prepare(
      "INSERT INTO challenges (challenge_ref, plan_ref, run_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    ).run(challengeRef, planRef, runId, expiresAt, this.nowIso());
  }

  getChallenge(challengeRef) {
    return this.db.prepare("SELECT * FROM challenges WHERE challenge_ref = ?").get(challengeRef) || null;
  }

  consumeChallenge(challengeRef) {
    this.db.prepare("UPDATE challenges SET status = 'consumed' WHERE challenge_ref = ?").run(challengeRef);
  }

  insertApproval({ approvalRef, planRef, runId, leaseClass, expiresAt }) {
    this.db.prepare(
      "INSERT INTO approvals (approval_ref, plan_ref, run_id, lease_class, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(approvalRef, planRef, runId, leaseClass, expiresAt, this.nowIso());
  }

  getApproval(approvalRef) {
    return this.db.prepare("SELECT * FROM approvals WHERE approval_ref = ?").get(approvalRef) || null;
  }

  insertOperations(runId, planRef, steps) {
    const stmt = this.db.prepare(
      "INSERT INTO operations (operation_ref, plan_ref, run_id, step_index, step_id, tool, mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const refs = [];
    steps.forEach((step, index) => {
      const operationRef = mintRef("operation");
      stmt.run(operationRef, planRef, runId, index, step.stepId, step.tool, step.mode, this.nowIso());
      refs.push(operationRef);
    });
    return refs;
  }

  planOperations(planRef) {
    return this.db.prepare(
      "SELECT * FROM operations WHERE plan_ref = ? ORDER BY step_index ASC",
    ).all(planRef);
  }

  cursorNext(planRef) {
    return this.db.prepare(
      "SELECT * FROM operations WHERE plan_ref = ? AND status = 'pending' ORDER BY step_index ASC LIMIT 1",
    ).get(planRef) || null;
  }

  completeOperation(operationRef) {
    this.db.prepare("UPDATE operations SET status = 'complete' WHERE operation_ref = ?").run(operationRef);
  }

  pendingOperationRefs(runId) {
    return this.db.prepare(
      "SELECT operation_ref FROM operations WHERE run_id = ? AND status = 'pending' ORDER BY step_index ASC",
    ).all(runId).map((row) => row.operation_ref);
  }

  // --- reports, closures, ownership, reconciliation, secrets ---

  insertReport({ reportRef, runId, label, reportDigest }) {
    this.db.prepare(
      "INSERT INTO reports (report_ref, run_id, label, report_digest, created_at) VALUES (?, ?, ?, ?, ?)",
    ).run(reportRef, runId, label, reportDigest, this.nowIso());
  }

  latestReport(runId, label = null) {
    if (label) {
      return this.db.prepare(
        "SELECT * FROM reports WHERE run_id = ? AND label = ? ORDER BY rowid DESC LIMIT 1",
      ).get(runId, label) || null;
    }
    return this.db.prepare(
      "SELECT * FROM reports WHERE run_id = ? ORDER BY rowid DESC LIMIT 1",
    ).get(runId) || null;
  }

  insertClosure(closure) {
    this.db.prepare(
      `INSERT INTO closures (closure_ref, run_id, scope, outcome, closure_digest,
        residual_disclosure_ref, bound_completion_label, bound_completion_report_digest,
        final_ledger_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(closure.closureRef, closure.runId, closure.scope, closure.outcome, closure.closureDigest,
      closure.residualDisclosureRef, closure.boundCompletionLabel,
      closure.boundCompletionReportDigest, closure.finalLedgerDigest, this.nowIso());
  }

  getClosure(runId, scope) {
    return this.db.prepare(
      "SELECT * FROM closures WHERE run_id = ? AND scope = ? ORDER BY rowid DESC LIMIT 1",
    ).get(runId, scope) || null;
  }

  insertOwnership({ receiptRef, runId, objectKind, changeRef, beforeDigest, afterDigest, details = {} }) {
    this.db.prepare(
      `INSERT INTO ownership (receipt_ref, run_id, object_kind, change_ref, before_digest,
        after_digest, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(receiptRef, runId, objectKind, changeRef, beforeDigest, afterDigest,
      JSON.stringify(details), this.nowIso());
  }

  ownershipByRun(runId) {
    return this.db.prepare("SELECT * FROM ownership WHERE run_id = ? ORDER BY rowid ASC").all(runId);
  }

  openReconciliationObligation(runId) {
    return this.db.prepare(
      "SELECT * FROM reconciliation_obligations WHERE run_id = ? AND status = 'open' LIMIT 1",
    ).get(runId) || null;
  }

  insertReconciliationObligation({ obligationRef, runId, originalTool, failureContext }) {
    this.db.prepare(
      "INSERT INTO reconciliation_obligations (obligation_ref, run_id, original_tool, failure_context, created_at) VALUES (?, ?, ?, ?, ?)",
    ).run(obligationRef, runId, originalTool, failureContext, this.nowIso());
  }

  registerSecretRef({ secretRef, runId = null, role, provenance }) {
    this.db.prepare(
      "INSERT INTO secret_refs (secret_ref, run_id, role, provenance, created_at) VALUES (?, ?, ?, ?, ?)",
    ).run(secretRef, runId, role, provenance, this.nowIso());
  }

  getSecretRef(secretRef) {
    return this.db.prepare("SELECT * FROM secret_refs WHERE secret_ref = ?").get(secretRef) || null;
  }

  // --- identity bindings and per-run scalars (Phase 3) ---

  recordIdentityBinding(runId, field, identityDigest) {
    this.db.prepare(
      "INSERT INTO identity_bindings (run_id, field, identity_digest, bound_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(run_id, field) DO UPDATE SET identity_digest = excluded.identity_digest, bound_at = excluded.bound_at",
    ).run(runId, field, identityDigest, this.nowIso());
  }

  identityBindings(runId) {
    const rows = this.db.prepare("SELECT field, identity_digest FROM identity_bindings WHERE run_id = ?").all(runId);
    return Object.fromEntries(rows.map((row) => [row.field, row.identity_digest]));
  }

  setScalar(runId, key, value) {
    this.db.prepare(
      "INSERT INTO run_scalars (run_id, key, value, updated_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(run_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    ).run(runId, key, JSON.stringify(value), this.nowIso());
  }

  getScalar(runId, key) {
    const row = this.db.prepare("SELECT value FROM run_scalars WHERE run_id = ? AND key = ?").get(runId, key);
    return row ? JSON.parse(row.value) : null;
  }

  recordWebsocketPathDigest(runId, digest) {
    this.setScalar(runId, "websocket_path_digest", digest);
  }

  websocketPathDigest(runId) {
    return this.getScalar(runId, "websocket_path_digest");
  }

  // --- ownership lookups used by the rollback graph ---

  ownershipByKind(runId, objectKind) {
    return this.db.prepare(
      "SELECT * FROM ownership WHERE run_id = ? AND object_kind = ? ORDER BY rowid ASC",
    ).all(runId, objectKind);
  }

  latestOwnership(runId, objectKind) {
    const rows = this.ownershipByKind(runId, objectKind);
    return rows.length > 0 ? rows[rows.length - 1] : null;
  }

  // Committed external mutations owned by this run, in commit order. The
  // BBR drop-in is tracked separately and is never part of the main graph.
  committedMainChanges(runId) {
    return this.db.prepare(
      "SELECT * FROM ownership WHERE run_id = ? AND object_kind LIKE 'OWNED_%' AND object_kind != 'OWNED_BBR_APPLY' ORDER BY rowid ASC",
    ).all(runId);
  }

  // --- durable rollback stage receipts ---

  insertStageReceipt({ receiptRef, runId, family, operationRef, stageId, stageIndex, readbackDigest, details = {} }) {
    this.db.prepare(
      "INSERT INTO stage_receipts (receipt_ref, run_id, family, operation_ref, stage_id, stage_index, readback_digest, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(receiptRef, runId, family, operationRef, stageId, stageIndex, readbackDigest, JSON.stringify(details), this.nowIso());
  }

  stageReceipts(runId, family) {
    return this.db.prepare(
      "SELECT * FROM stage_receipts WHERE run_id = ? AND family = ? ORDER BY stage_index ASC, rowid ASC",
    ).all(runId, family);
  }

  stageReceiptIds(runId, family) {
    return this.stageReceipts(runId, family).map((row) => row.stage_id);
  }

  insertAggregateReceipt({ receiptRef, runId, receiptType, operationRef, selectionDigest, stageReceiptRefs, commitDigest, finalDigest, details = {} }) {
    this.db.prepare(
      "INSERT INTO aggregate_receipts (receipt_ref, run_id, receipt_type, operation_ref, selection_digest, stage_receipt_refs, commit_digest, final_digest, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(receiptRef, runId, receiptType, operationRef, selectionDigest, JSON.stringify(stageReceiptRefs), commitDigest, finalDigest, JSON.stringify(details), this.nowIso());
  }

  aggregateReceipt(runId, receiptType) {
    const row = this.db.prepare(
      "SELECT * FROM aggregate_receipts WHERE run_id = ? AND receipt_type = ? ORDER BY rowid DESC LIMIT 1",
    ).get(runId, receiptType);
    if (!row) return null;
    return { ...row, stage_receipt_refs: JSON.parse(row.stage_receipt_refs), details: JSON.parse(row.details) };
  }

  // --- recovery obligations ---

  insertRecoveryObligation({ obligationRef, runId, column, cause, boundGraphDigest = null }) {
    this.db.prepare(
      "INSERT INTO recovery_obligations (obligation_ref, run_id, column_name, cause, bound_graph_digest, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(obligationRef, runId, column, cause, boundGraphDigest, this.nowIso());
  }

  currentRecoveryObligation(runId, column) {
    return this.db.prepare(
      "SELECT * FROM recovery_obligations WHERE run_id = ? AND column_name = ? AND status = 'current' ORDER BY rowid DESC LIMIT 1",
    ).get(runId, column) || null;
  }

  consumeRecoveryObligation(obligationRef) {
    this.db.prepare("UPDATE recovery_obligations SET status = 'consumed' WHERE obligation_ref = ?").run(obligationRef);
  }

  // --- BBR rollback source obligation episodes ---

  insertBbrSourceEpisode({ episodeRef, runId, sourceRowId, durableCause, baselineKind, baselineReceiptRef, baselineChangeRef, baselineBindingDigest }) {
    this.db.prepare(
      "INSERT INTO bbr_source_episodes (episode_ref, run_id, source_row_id, durable_cause, baseline_kind, baseline_receipt_ref, baseline_change_ref, baseline_binding_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(episodeRef, runId, sourceRowId, durableCause, baselineKind, baselineReceiptRef, baselineChangeRef, baselineBindingDigest, this.nowIso());
  }

  currentBbrSourceEpisodes(runId) {
    return this.db.prepare(
      "SELECT * FROM bbr_source_episodes WHERE run_id = ? AND status = 'current' ORDER BY rowid ASC",
    ).all(runId);
  }

  consumeBbrSourceEpisode(episodeRef, status = "consumed") {
    this.db.prepare("UPDATE bbr_source_episodes SET status = ? WHERE episode_ref = ?").run(status, episodeRef);
  }

  supersedeAllBbrSourceEpisodes(runId) {
    this.db.prepare("UPDATE bbr_source_episodes SET status = 'superseded' WHERE run_id = ? AND status = 'current'").run(runId);
  }

  // --- durable admission receipts (main zero-dispatch lease expiry) ---

  insertAdmissionReceipt({ receiptRef, runId, receiptType, bindingDigest }) {
    this.db.prepare(
      "INSERT INTO admission_receipts (receipt_ref, run_id, receipt_type, binding_digest, created_at) VALUES (?, ?, ?, ?, ?)",
    ).run(receiptRef, runId, receiptType, bindingDigest, this.nowIso());
  }

  currentAdmissionReceipt(runId, receiptType) {
    return this.db.prepare(
      "SELECT * FROM admission_receipts WHERE run_id = ? AND receipt_type = ? AND consumed = 0 ORDER BY rowid DESC LIMIT 1",
    ).get(runId, receiptType) || null;
  }

  consumeAdmissionReceipt(receiptRef) {
    this.db.prepare("UPDATE admission_receipts SET consumed = 1 WHERE receipt_ref = ?").run(receiptRef);
  }

  // --- residual disclosures and secret dispositions ---

  insertResidual({ residualRef, runId, kind, maskedSummary, bindingDigest }) {
    this.db.prepare(
      "INSERT INTO residuals (residual_ref, run_id, kind, masked_summary, binding_digest, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(residualRef, runId, kind, maskedSummary, bindingDigest, this.nowIso());
  }

  residualsByRun(runId) {
    return this.db.prepare("SELECT * FROM residuals WHERE run_id = ? ORDER BY rowid ASC").all(runId);
  }

  insertSecretDisposition({ receiptRef, runId, secretRef, role, disposition, residualRef = null }) {
    this.db.prepare(
      "INSERT INTO secret_dispositions (receipt_ref, run_id, secret_ref, role, disposition, residual_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).run(receiptRef, runId, secretRef, role, disposition, residualRef, this.nowIso());
    this.db.prepare("UPDATE secret_refs SET disposition = ? WHERE secret_ref = ?").run(disposition, secretRef);
  }

  secretDispositions(runId) {
    return this.db.prepare("SELECT * FROM secret_dispositions WHERE run_id = ? ORDER BY rowid ASC").all(runId);
  }

  // Same-run generated secrets are the only ones a rollback may ever
  // dispose; imported onboarding secrets carry no run_id and are therefore
  // structurally invisible to this query.
  sameRunGeneratedSecrets(runId, role = null) {
    if (role) {
      return this.db.prepare(
        "SELECT * FROM secret_refs WHERE run_id = ? AND role = ? AND provenance = 'same-run-generated' ORDER BY rowid ASC",
      ).all(runId, role);
    }
    return this.db.prepare(
      "SELECT * FROM secret_refs WHERE run_id = ? AND provenance = 'same-run-generated' ORDER BY rowid ASC",
    ).all(runId);
  }

  currentSameRunSecret(runId, role) {
    const rows = this.sameRunGeneratedSecrets(runId, role).filter((row) => row.disposition === "current");
    return rows.length > 0 ? rows[rows.length - 1] : null;
  }

  // --- reconciliation obligation lifecycle ---

  resolveReconciliationObligation(obligationRef, status = "resolved") {
    this.db.prepare("UPDATE reconciliation_obligations SET status = ? WHERE obligation_ref = ?").run(status, obligationRef);
  }

  invalidateEvidenceFamily(runId, evidenceType) {
    this.db.prepare("UPDATE evidence SET invalidated = 1 WHERE run_id = ? AND evidence_type = ?").run(runId, evidenceType);
  }

  evidenceRow(evidenceRef) {
    return this.db.prepare("SELECT * FROM evidence WHERE evidence_ref = ?").get(evidenceRef) || null;
  }
}

module.exports = { Ledger, parseIsoDurationSeconds };
