"use strict";

// Read-only inventory and protected-line tools.
//
// Every observation flows through the closed adapter registry (fixed
// helper/broker operations) and is projected into the frozen data schema as
// masked, evidence-backed values.
//
// While a forward cursor is active these same tools are the coordinated
// pre-mutation checkpoint. A refresh replaces only its own finite evidence
// families: it never advances the cursor, never extends a lease, and never
// rewrites a plan. If it observes drift from the plan's immutable baseline,
// it takes the drift resolver's three-way split rather than continuing.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const forwardGate = require("../core/forward-gate.cjs");
const {
  requireRun, auditGate, stateGate, withIdempotency, applySuccessByOrigin,
  advanceReadProbeCursorIfPlanned,
} = require("./common.cjs");

const DRIFT_RESOLVER = contracts.ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.driftOrForeignOrStaleIdentity;
const REFRESH_TOOLS = contracts.ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.refreshTools;

const FAMILY_BY_TOOL = Object.freeze({
  origin_inventory: "ORIGIN_INVENTORY",
  cloudflare_inventory: "CLOUDFLARE_INVENTORY",
  xui_inventory: "XUI_INVENTORY",
  client_inventory: "CLIENT_INVENTORY",
});

function projectInventory(ctx, toolName, run, evidenceType, ttlKey, maskedSummary, payload, binding) {
  const evidenceRef = ctx.ledger.putEvidence({
    runId: run.run_id,
    evidenceType,
    ttl: contracts.EVIDENCE_TTLS[ttlKey],
    maskedSummary,
    payload,
    // The masked observation is retained inside the ledger binding so the
    // plan resolver can consume it without a second adapter read.
    binding: { ...binding, observation: payload },
  });
  ctx.ledger.appendEvent(run.run_id, "EVIDENCE_MINTED", { evidenceType, evidenceRef });
  applyCheckpointOrSuccess(ctx, toolName, run);
  return evidenceRef;
}

// While a forward cursor is open, an inventory call is a checkpoint refresh,
// not a state transition. Outside that window it applies the frozen
// successByOrigin matrix as usual.
function applyCheckpointOrSuccess(ctx, toolName, run) {
  const plan = ctx.ledger.currentPlan(run.run_id);
  const forwardCursor = plan &&
    ["node_p2", "node_install_p3"].includes(plan.scope) &&
    ctx.ledger.cursorNext(plan.plan_ref) !== null &&
    ["APPROVED", "APPLYING"].includes(run.main_phase);
  if (!forwardCursor || !REFRESH_TOOLS.includes(toolName)) {
    applySuccessByOrigin(ctx, toolName, run);
    return;
  }
  const family = FAMILY_BY_TOOL[toolName];
  const drifted = forwardGate.driftFields(ctx, run, plan, family);
  if (drifted.length === 0) {
    ctx.ledger.appendEvent(run.run_id, "ACTIVE_CHECKPOINT_REFRESH_NO_DRIFT", {
      tool: toolName, family, cursorAdvance: false, leaseExtension: false,
      preserves: contracts.ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.noDrift.preserves,
    });
    return;
  }
  applyCheckpointDrift(ctx, run, plan, toolName, family, drifted);
}

// Drift is resolved by what this run has actually committed, never by the
// caller and never by rewriting the plan.
function applyCheckpointDrift(ctx, run, plan, toolName, family, driftedFields) {
  const { row, committed } = forwardGate.classifyCommitObservation(ctx, run);
  const rowId = row === "ZERO_COMMITTED_CHANGES" ? "ZERO_COMMIT_SAFE_REBASE"
    : row === "SAME_RUN_OWNED_COMMITTED_CHANGES" ? "OWNED_COMMITTED_GRAPH"
      : "THIRD_DIGEST_OR_OWNERSHIP_MISMATCH";
  const resolved = DRIFT_RESOLVER.rows[rowId];
  const graphDigest = digestOf(committed.map((c) => ({ kind: c.object_kind, after: c.after_digest })));
  ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    ctx.ledger.appendEvent(run.run_id, "ACTIVE_CHECKPOINT_DRIFT", {
      tool: toolName, family, driftedFields, row: rowId,
      destination: resolved.destination, planRewrite: false, overwrite: false, cursorAdvance: false,
    });
    if (rowId === "OWNED_COMMITTED_GRAPH") {
      ctx.ledger.insertRecoveryObligation({
        obligationRef: mintRef("runtime"), runId: run.run_id, column: "main",
        cause: "ACTIVE_CHECKPOINT_DRIFT_OWNED_GRAPH", boundGraphDigest: graphDigest,
      });
    } else if (rowId === "THIRD_DIGEST_OR_OWNERSHIP_MISMATCH" &&
               !ctx.ledger.openReconciliationObligation(run.run_id)) {
      ctx.ledger.insertReconciliationObligation({
        obligationRef: mintRef("runtime"), runId: run.run_id,
        originalTool: "active_checkpoint_refresh_tools",
        failureContext: "ACTIVE_CHECKPOINT_DRIFT_THIRD_DIGEST_OR_OWNERSHIP_MISMATCH",
      });
    }
    ctx.ledger.setPhases(run.run_id, { mainPhase: resolved.destination });
  });
}

function origin_inventory(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "origin_inventory");
  stateGate("origin_inventory", run);
  const { observation } = ctx.adapters.callHelper("origin.inventory.v1", "origin_inventory", {
    runId: run.run_id,
    originTargetRef: run.binding.origin_target_ref,
    sshIdentitySecretRef: run.binding.ssh_identity_secret_ref,
    refresh: input.refresh,
  });
  const evidenceRef = projectInventory(ctx, "origin_inventory", run,
    "ORIGIN_INVENTORY", "INVENTORY", "masked origin host inventory", observation,
    { target: run.binding.origin_target_ref });
  return { data: { origin_inventory_ref: evidenceRef, ...observation } };
}

function cloudflare_inventory(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "cloudflare_inventory");
  stateGate("cloudflare_inventory", run);
  const { observation } = ctx.adapters.callBroker("cf.dns_read", "cloudflare_inventory", {
    runId: run.run_id,
    cloudflareTargetRef: run.binding.cloudflare_target_ref,
    nodeHostnameRef: run.binding.node_hostname_ref,
    cfAuditSecretRef: run.binding.cf_audit_secret_ref,
    refresh: input.refresh,
  });
  const evidenceRef = projectInventory(ctx, "cloudflare_inventory", run,
    "CLOUDFLARE_INVENTORY", "CLOUDFLARE_INVENTORY", "masked cloudflare zone/record inventory",
    observation, { zone: run.binding.cloudflare_target_ref });
  return { data: { cloudflare_inventory_ref: evidenceRef, ...observation } };
}

function xui_inventory(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "xui_inventory");
  stateGate("xui_inventory", run);
  if (!ctx.ledger.freshEvidence(run.run_id, "ORIGIN_INVENTORY")) {
    throw new ToolError("DEPENDENCY_MISSING",
      "xui_inventory requires a current origin inventory", { retryable: true });
  }
  // The immutable run provenance selects exactly one fixed broker read: a
  // same-run install receipt selects the owned read, an imported onboarding
  // administrator credential selects the existing read.
  const sameRunInstall = ctx.ledger.getScalar(run.run_id, "install_receipt_ref");
  const operationName = sameRunInstall
    ? "xui.inventory_owned_fixed.v1"
    : run.binding.existing_xui_admin_secret_ref
      ? "xui.inventory_existing_fixed.v1"
      : "xui.inventory_owned_fixed.v1";
  const { observation } = ctx.adapters.callBroker(operationName, "xui_inventory", {
    runId: run.run_id,
    originTargetRef: run.binding.origin_target_ref,
    adminSecretRef: sameRunInstall
      ? ctx.ledger.getScalar(run.run_id, "panel_admin_secret_ref")
      : run.binding.existing_xui_admin_secret_ref,
    sameRunInstallReceiptRef: sameRunInstall,
    refresh: input.refresh,
  });
  const evidenceRef = projectInventory(ctx, "xui_inventory", run,
    "XUI_INVENTORY", "INVENTORY", "masked 3x-ui installation inventory", observation,
    { target: run.binding.origin_target_ref });
  return { data: { xui_inventory_ref: evidenceRef, ...observation } };
}

function client_inventory(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "client_inventory");
  stateGate("client_inventory", run);
  const { observation } = ctx.adapters.callHelper("client.inventory_fixed.v1", "client_inventory", {
    runId: run.run_id,
    refresh: input.refresh,
  });
  const evidenceRef = projectInventory(ctx, "client_inventory", run,
    "CLIENT_INVENTORY", "INVENTORY", "masked allowlisted client runtime inventory", observation,
    {});
  return { data: { client_inventory_ref: evidenceRef, ...observation } };
}

// Resolves which binding scope this protected-line proof carries. The scope
// is server-derived from the ledger: the caller cannot ask for a stronger
// binding than the run has actually earned.
function resolveBindingScope(ctx, run) {
  const plan = ctx.ledger.currentPlan(run.run_id);
  const next = plan ? ctx.ledger.cursorNext(plan.plan_ref) : null;
  const mode = next && next.tool === "old_line_verify" ? next.mode : null;

  if (mode === "post_main_rollback_bound_to_exact_receipt" ||
      run.main_phase === "ROLLED_BACK") {
    const aggregate = ctx.ledger.aggregateReceipt(run.run_id, "MAIN_ROLLBACK_RECEIPT");
    if (!aggregate) {
      throw new ToolError("DEPENDENCY_MISSING",
        "a post-rollback protected-line proof requires the aggregate rollback receipt");
    }
    return { scope: "post_main_rollback", rollbackReceiptRef: aggregate.receipt_ref };
  }
  // Once this run owns a route, every protected-line proof is bound to that
  // exact route; before that, an install this run performed is the strongest
  // prerequisite effect the proof can be bound to.
  const routeDigest = ctx.ledger.getScalar(run.run_id, "current_route_digest");
  if (routeDigest) return { scope: "current_route", routeDigest };

  const installReceiptRef = ctx.ledger.getScalar(run.run_id, "install_receipt_ref");
  if (installReceiptRef) {
    const receipt = ctx.ledger.latestOwnership(run.run_id, "OWNED_XUI_INSTALLATION");
    if (!receipt) {
      throw new ToolError("DEPENDENCY_MISSING",
        "a post-install protected-line proof requires the exact install ownership receipt");
    }
    return { scope: "post_xui_install", prerequisiteEffectDigest: receipt.after_digest };
  }
  if (mode === "bind_exact_install_receipt") {
    throw new ToolError("DEPENDENCY_MISSING",
      "a post-install protected-line proof requires the exact install ownership receipt");
  }
  return { scope: "pre_change" };
}

function old_line_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "old_line_verify");
  stateGate("old_line_verify", run);
  const destination = ctx.ledger.getOnboardingRef(input.probe_destination_ref);
  if (!destination || destination.role !== "probe_destination") {
    throw new ToolError("DEPENDENCY_MISSING",
      "probe_destination_ref is not a registered allowlisted probe destination");
  }
  return withIdempotency(ctx, run.run_id, "old_line_verify", input, () => {
    let status = "not_applicable";
    if (run.binding.protected_line_ref !== null) {
      // Fixed composite: the broker resolves the protected-line runtime
      // secret server-side and hands ephemeral material to the fixed probe
      // helper only; no secret byte reaches this process.
      const probe = ctx.adapters.callBroker(
        "protected_line.runtime_probe_fixed.v1", "old_line_verify", {
          runId: run.run_id,
          protectedLineRef: run.binding.protected_line_ref,
          protectedLineRuntimeSecretRef: run.binding.protected_line_runtime_secret_ref,
          probeDestinationRef: input.probe_destination_ref,
        });
      if (!probe.observation.healthy || !probe.observation.authenticated ||
          !probe.observation.expectedEgress) {
        throw new ToolError("PROBE_FAILED",
          "protected line probe did not prove authenticated health", { retryable: true });
      }
      status = "healthy";
    }
    const resolved = resolveBindingScope(ctx, run);
    const evidenceRef = ctx.ledger.putEvidence({
      runId: run.run_id,
      evidenceType: "PROTECTED_LINE_HEALTH",
      ttl: contracts.EVIDENCE_TTLS.PROTECTED_LINE,
      maskedSummary: `protected line ${status} (${resolved.scope})`,
      payload: { status, bindingScope: resolved.scope },
      binding: {
        scope: resolved.scope,
        routeDigest: resolved.routeDigest ?? null,
        prerequisiteEffectDigest: resolved.prerequisiteEffectDigest ?? null,
        rollbackReceiptRef: resolved.rollbackReceiptRef ?? null,
      },
    });
    ctx.ledger.appendEvent(run.run_id, "EVIDENCE_MINTED", {
      evidenceType: "PROTECTED_LINE_HEALTH", evidenceRef, bindingScope: resolved.scope,
    });
    advanceReadProbeCursorIfPlanned(ctx, run, "old_line_verify");
    applySuccessByOrigin(ctx, "old_line_verify", run);
    return {
      data: {
        protected_line_status: status,
        health_evidence_ref: evidenceRef,
        authenticated_or_server_proven_na: true,
        expected_egress_or_server_proven_na: true,
        binding_scope: resolved.scope,
        bound_current_route_digest: resolved.routeDigest ?? null,
        bound_prerequisite_effect_digest: resolved.prerequisiteEffectDigest ?? null,
        bound_rollback_receipt_ref: resolved.rollbackReceiptRef ?? null,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

module.exports = {
  origin_inventory, cloudflare_inventory, xui_inventory, client_inventory, old_line_verify,
  applyCheckpointOrSuccess, resolveBindingScope, FAMILY_BY_TOOL,
};
