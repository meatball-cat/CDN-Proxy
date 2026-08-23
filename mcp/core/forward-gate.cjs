"use strict";

// Forward mutation dispatch control (FORWARD_MUTATION_DISPATCH_CONTROL).
//
// Every external mutation must satisfy, immediately before dispatch:
//   1. the coordinated four-inventory checkpoint (all finite families the
//      remaining plan consumes are currently fresh, from the same checkpoint);
//   2. an unexpired *effective* approval, which is the minimum of the nominal
//      lease expiry and every currently consumed finite evidence expiry;
//   3. exact no-drift against the immutable plan baseline projected forward
//      through the same-run receipts committed up to the current cursor.
//
// A refresh never advances the cursor and never extends a lease. An expired
// effective approval at the pre-dispatch boundary never resumes forward
// execution: it revokes all forward authority and takes the three-way split
// of ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("./errors.cjs");
const { mintRef, digestOf } = require("./refs.cjs");
const { parseIsoDurationSeconds } = require("../ledger/ledger.cjs");

const CHECKPOINT = contracts.ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT;
const EXPIRY_POLICY = contracts.PLAN_OPERATION_RESOLVER.forwardApprovalEffectiveExpiry;
const WRITE_EXPIRY = contracts.ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER;
const HOST_P3_CHECKPOINT = contracts.PLAN_OPERATION_RESOLVER.hostP3BbrEvidenceRefreshCheckpoint;

// The concrete ledger evidence families behind each scope's consumed finite
// set. The contract names some sub-facts (strict-compatible mode, websockets)
// that this build carries inside the cloudflare inventory observation, so the
// family list below is the exact set of TTL-bearing rows they live in.
const CONSUMED_FAMILIES_BY_LEASE_CLASS = Object.freeze({
  NODE_INSTALL_P3: Object.freeze([
    "ORIGIN_INVENTORY", "CLOUDFLARE_INVENTORY", "XUI_INVENTORY",
    "CLIENT_INVENTORY", "PROTECTED_LINE_HEALTH",
  ]),
  NODE_P2: Object.freeze([
    "ORIGIN_INVENTORY", "CLOUDFLARE_INVENTORY", "XUI_INVENTORY",
    "CLIENT_INVENTORY", "PROTECTED_LINE_HEALTH",
  ]),
  HOST_P3: Object.freeze(["BBR_INVENTORY", "PROTECTED_LINE_HEALTH"]),
});

// Fields whose change constitutes baseline drift. Everything else in an
// inventory observation is informational and may move freely.
const DRIFT_FIELDS = Object.freeze({
  ORIGIN_INVENTORY: Object.freeze([
    "host_fingerprint_digest", "os_family", "nginx_installation_status",
    "public_tls_listener_owner", "owned_include_slot_available",
    "node_server_name_conflict", "websocket_path_conflict",
    "origin_ca_dedicated_slot_status", "current_origin_address_digest",
    "safe_stable_certificate_reuse_eligible", "sole_exact_node_route_observed",
  ]),
  CLOUDFLARE_INVENTORY: Object.freeze([
    "record_observation_case", "ssl_mode", "websockets_enabled",
    "hostname_binding_digest", "current_record_owned_by_run", "proxy_enabled",
  ]),
  XUI_INVENTORY: Object.freeze([
    "installation_status", "admin_binding_status", "panel_fingerprint_digest",
  ]),
  CLIENT_INVENTORY: Object.freeze(["runtime_digest"]),
  BBR_INVENTORY: Object.freeze([
    "kernel_exposes_bbr", "available_congestion_controls_contains_bbr",
    "qdisc_fq_supported", "persistent_conflict_present",
    "owned_dropin_present", "current_qdisc", "current_congestion_control",
  ]),
});

// The exact observation changes a committed same-run receipt is expected to
// produce. Drift is measured against the baseline *after* these transitions,
// so the run's own effects are never mistaken for third-party interference.
const EXPECTED_TRANSITIONS = Object.freeze({
  OWNED_XUI_INSTALL: Object.freeze({
    XUI_INVENTORY: Object.freeze({
      installation_status: "owned_by_run",
      admin_binding_status: "SAME_RUN_OWNED_WITH_GENERATED_ADMIN",
      panel_fingerprint_digest: "ANY",
    }),
  }),
  OWNED_XUI_CREATE_INBOUND: Object.freeze({}),
  OWNED_XUI_PROFILE_PUBLISH: Object.freeze({}),
  OWNED_CERTIFICATE_ISSUE_ORIGIN_CA: Object.freeze({}),
  OWNED_CERTIFICATE_DEPLOY: Object.freeze({
    ORIGIN_INVENTORY: Object.freeze({
      origin_ca_dedicated_slot_status: "preexisting",
      safe_stable_certificate_reuse_eligible: "ANY",
    }),
  }),
  OWNED_NGINX_ROUTE_APPLY: Object.freeze({
    ORIGIN_INVENTORY: Object.freeze({
      owned_include_slot_available: false,
      sole_exact_node_route_observed: true,
    }),
  }),
  OWNED_CF_NODE_RECORD_APPLY: Object.freeze({
    CLOUDFLARE_INVENTORY: Object.freeze({
      record_observation_case: "SAME_RUN_CURRENT_UNPROXIED",
      current_record_owned_by_run: true,
      proxy_enabled: false,
    }),
  }),
  OWNED_CF_PROXY_ENABLE: Object.freeze({
    CLOUDFLARE_INVENTORY: Object.freeze({
      record_observation_case: "SAME_RUN_CURRENT_PROXIED",
      current_record_owned_by_run: true,
      proxy_enabled: true,
    }),
  }),
});

function evidenceExpiryMs(row) {
  if (!row || row.ttl_seconds === null) return Infinity;
  return Date.parse(row.created_at) + row.ttl_seconds * 1000;
}

function observationOf(row) {
  if (!row) return null;
  const binding = JSON.parse(row.binding || "{}");
  return binding.observation || null;
}

function consumedFamilies(leaseClass) {
  const families = CONSUMED_FAMILIES_BY_LEASE_CLASS[leaseClass];
  if (!families) {
    throw new ToolError("INTERNAL_ERROR", `no consumed finite set for lease class ${leaseClass}`);
  }
  return families;
}

// Effective approval expiry = min(nominal lease, every consumed finite
// evidence expiry). Never extends: a fresher inventory can only lower or
// preserve the ceiling that the nominal lease already sets.
function effectiveApprovalExpiryMs(ctx, run, plan, approval) {
  let expiry = Date.parse(approval.expires_at);
  const missing = [];
  for (const family of consumedFamilies(plan.lease_class)) {
    const row = ctx.ledger.freshEvidence(run.run_id, family);
    if (!row) {
      missing.push(family);
      continue;
    }
    expiry = Math.min(expiry, evidenceExpiryMs(row));
  }
  return { expiry, missing };
}

// Projects the plan's immutable baseline observation for one family forward
// through the same-run receipts committed so far, then compares the exact
// drift-sensitive fields against the current observation.
function projectExpected(baseline, family, committedKinds) {
  const expected = { ...baseline };
  for (const kind of committedKinds) {
    const transition = (EXPECTED_TRANSITIONS[kind] || {})[family];
    if (!transition) continue;
    for (const [key, value] of Object.entries(transition)) expected[key] = value;
  }
  return expected;
}

// A field is drifted when the current observation is neither what the plan
// baseline recorded nor what this run's own committed receipts would produce.
// Both are accepted because an inventory taken before a commit legitimately
// still shows the pre-commit value; anything outside that pair is a third
// party changing the resource under us.
function driftFields(ctx, run, plan, family) {
  const baseline = ctx.ledger.getScalar(run.run_id, `baseline:${plan.plan_ref}:${family}`);
  if (!baseline) return [];
  const current = observationOf(ctx.ledger.freshEvidence(run.run_id, family));
  if (!current) return [];
  const committedKinds = ctx.ledger.ownershipByRun(run.run_id).map((row) => row.object_kind);
  const expected = projectExpected(baseline, family, committedKinds);
  return (DRIFT_FIELDS[family] || []).filter((field) => {
    if (expected[field] === "ANY") return false;
    const observed = JSON.stringify(current[field]);
    return observed !== JSON.stringify(expected[field]) &&
      observed !== JSON.stringify(baseline[field]);
  });
}

// Records the exact baseline observation each family contributed to a plan,
// so later checkpoints compare against immutable plan facts and not against
// whatever the last refresh happened to see.
function recordPlanBaseline(ctx, runId, planRef, family, observation) {
  ctx.ledger.setScalar(runId, `baseline:${planRef}:${family}`, observation);
}

function baselineDriftFamilies(ctx, run, plan) {
  const drifted = [];
  for (const family of consumedFamilies(plan.lease_class)) {
    if (family === "PROTECTED_LINE_HEALTH") continue;
    const fields = driftFields(ctx, run, plan, family);
    if (fields.length > 0) drifted.push({ family, fields });
  }
  return drifted;
}

// --- active-cursor write expiry: three-way split, never a forward resume ---

function classifyCommitObservation(ctx, run) {
  const committed = ctx.ledger.committedMainChanges(run.run_id);
  if (ctx.ledger.openReconciliationObligation(run.run_id)) return { row: "UNKNOWN_OR_THIRD_DIGEST", committed };
  const unknown = ctx.ledger.getScalar(run.run_id, "unknown_commit_open");
  if (unknown) return { row: "UNKNOWN_OR_THIRD_DIGEST", committed };
  if (committed.length === 0) return { row: "ZERO_COMMITTED_CHANGES", committed };
  const foreign = committed.filter((row) => {
    const details = JSON.parse(row.details || "{}");
    return details.sameRunOwned === false;
  });
  if (foreign.length > 0) return { row: "UNKNOWN_OR_THIRD_DIGEST", committed };
  return { row: "SAME_RUN_OWNED_COMMITTED_CHANGES", committed };
}

// Revokes every forward authority listed in the frozen revocation set, then
// projects the row's destination. Runs inside one ledger transaction so the
// revocation and the projection are never separately visible.
function applyWriteExpiryResolution(ctx, run, plan, rowId, committed) {
  const row = WRITE_EXPIRY.rows[rowId];
  const graphDigest = digestOf(committed.map((c) => ({ kind: c.object_kind, after: c.after_digest })));
  ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    ctx.ledger.appendEvent(run.run_id, "ACTIVE_CURSOR_WRITE_EXPIRY", {
      row: rowId,
      revoked: WRITE_EXPIRY.revokesBeforeProjection,
      planRef: plan.plan_ref,
      priorCommittedChangeCount: committed.length,
      forwardResume: false,
    });
    if (rowId === "SAME_RUN_OWNED_COMMITTED_CHANGES") {
      ctx.ledger.insertRecoveryObligation({
        obligationRef: mintRef("runtime"),
        runId: run.run_id,
        column: "main",
        cause: "ACTIVE_CURSOR_WRITE_EXPIRY_OWNED_COMMITS",
        boundGraphDigest: graphDigest,
      });
    } else if (rowId === "UNKNOWN_OR_THIRD_DIGEST") {
      if (!ctx.ledger.openReconciliationObligation(run.run_id)) {
        ctx.ledger.insertReconciliationObligation({
          obligationRef: mintRef("runtime"),
          runId: run.run_id,
          originalTool: "active_checkpoint_refresh_tools",
          failureContext: "ACTIVE_CURSOR_WRITE_EXPIRY_UNKNOWN_OR_THIRD_DIGEST",
        });
      }
    }
    ctx.ledger.setPhases(run.run_id, { mainPhase: row.destination });
  });
  return row;
}

// Called immediately before every external mutation dispatch. Throws with the
// exact contract error for the resolved row; the caller has not dispatched
// anything, so no external effect can exist on any of these paths.
function enforceForwardDispatch(ctx, run, plan, approval, toolName) {
  const { expiry, missing } = effectiveApprovalExpiryMs(ctx, run, plan, approval);
  // A consumed finite family that is no longer current *is* an expired
  // effective approval: the minimum that defines the effective expiry has
  // already passed. Treating it as a mere "stale evidence, retry" would let a
  // caller refresh and resume forward execution, which is exactly what the
  // no-forward-resume rule forbids.
  if (missing.length > 0 || expiry <= ctx.ledger.now()) {
    const { row, committed } = classifyCommitObservation(ctx, run);
    const resolved = applyWriteExpiryResolution(ctx, run, plan, row, committed);
    const code = row === "ZERO_COMMITTED_CHANGES" ? "APPROVAL_STALE"
      : row === "SAME_RUN_OWNED_COMMITTED_CHANGES" ? "ROLLBACK_REQUIRED"
        : "MANUAL_ACTION_REQUIRED";
    const detail = missing.length > 0
      ? `consumed finite evidence expired (${missing.join(", ")})`
      : "effective approval lease expired";
    throw new ToolError(code,
      `${detail} before dispatch; forward authority revoked, now ${resolved.destination}`.slice(0, 250));
  }
  const drifted = baselineDriftFamilies(ctx, run, plan);
  if (drifted.length > 0) {
    const { row, committed } = classifyCommitObservation(ctx, run);
    applyWriteExpiryResolution(ctx, run, plan, row, committed);
    throw new ToolError("BASELINE_DRIFT",
      `plan baseline drifted on ${drifted.map((d) => d.family).join(", ")}; forward authority revoked`.slice(0, 220));
  }
  return { effectiveExpiryMs: expiry };
}

// --- HOST_P3 dedicated BBR checkpoint -------------------------------------

// Exact no-drift with both nominal and effective leases unexpired preserves
// the identical plan, cursor, approval, and both expiry values without any
// extension. Anything else invalidates the authority and returns the branch
// to BBR_PLAN_READY for a fresh compile and a new host prompt.
function hostP3RefreshCheckpoint(ctx, run) {
  const plan = ctx.ledger.currentPlan(run.run_id);
  if (!plan || plan.scope !== "host_p3" || run.bbr_phase !== HOST_P3_CHECKPOINT.origin) {
    return { applicable: false };
  }
  const approval = ctx.ledger.db
    .prepare("SELECT * FROM approvals WHERE plan_ref = ? AND status = 'active' ORDER BY rowid DESC LIMIT 1")
    .get(plan.plan_ref) || null;
  if (!approval) return { applicable: false };

  const nominalExpiry = Date.parse(approval.expires_at);
  const { expiry: effectiveExpiry, missing } = effectiveApprovalExpiryMs(ctx, run, plan, approval);
  const expired = missing.length > 0 || nominalExpiry <= ctx.ledger.now() || effectiveExpiry <= ctx.ledger.now();
  const drifted = driftFields(ctx, run, plan, "BBR_INVENTORY");

  if (!expired && drifted.length === 0) {
    ctx.ledger.appendEvent(run.run_id, "HOST_P3_CHECKPOINT_PRESERVED", {
      planRef: plan.plan_ref,
      preserved: HOST_P3_CHECKPOINT.noDrift.preserves,
      cursorAdvance: false,
      nominalLeaseExtension: false,
      effectiveLeaseExtension: false,
    });
    return {
      applicable: true, preserved: true, planRef: plan.plan_ref,
      approvalRef: approval.approval_ref,
      nominalExpiresAt: approval.expires_at,
      effectiveExpiresAt: new Date(effectiveExpiry).toISOString(),
    };
  }

  ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    ctx.ledger.appendEvent(run.run_id, "HOST_P3_CHECKPOINT_REPLAN", {
      planRef: plan.plan_ref,
      cause: expired ? "NOMINAL_OR_EFFECTIVE_LEASE_EXPIRED" : "ANY_BBR_BASELINE_DRIFT",
      invalidates: HOST_P3_CHECKPOINT.driftOrExpired.invalidates,
      externalWrite: false,
    });
    ctx.ledger.setPhases(run.run_id, { bbrPhase: HOST_P3_CHECKPOINT.driftOrExpired.destination });
  });
  return { applicable: true, preserved: false, replanned: true };
}

module.exports = {
  CONSUMED_FAMILIES_BY_LEASE_CLASS,
  DRIFT_FIELDS,
  EXPECTED_TRANSITIONS,
  evidenceExpiryMs,
  observationOf,
  consumedFamilies,
  effectiveApprovalExpiryMs,
  recordPlanBaseline,
  driftFields,
  baselineDriftFamilies,
  classifyCommitObservation,
  applyWriteExpiryResolution,
  enforceForwardDispatch,
  hostP3RefreshCheckpoint,
};
