"use strict";

// Read-only inventory and protected-line tools. Every observation flows
// through the closed adapter registry (fixed helper/broker operations) and is
// projected into the frozen data schema as masked, evidence-backed values.

const { ToolError } = require("../core/errors.cjs");
const {
  requireRun, auditGate, stateGate, withIdempotency, applySuccessByOrigin,
  advanceReadProbeCursorIfPlanned,
} = require("./common.cjs");

function projectInventory(ctx, toolName, run, evidenceType, ttlKey, maskedSummary, payload, binding) {
  const evidenceRef = ctx.ledger.putEvidence({
    runId: run.run_id,
    evidenceType,
    ttl: require("../../contract/mcp/schemas/contracts.cjs").EVIDENCE_TTLS[ttlKey],
    maskedSummary,
    payload,
    // The masked observation is retained inside the ledger binding so the
    // plan resolver can consume it without a second adapter read.
    binding: { ...binding, observation: payload },
  });
  ctx.ledger.appendEvent(run.run_id, "EVIDENCE_MINTED", { evidenceType, evidenceRef });
  applySuccessByOrigin(ctx, toolName, run);
  return evidenceRef;
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
  // zone_ref is a server-minted opaque runtime handle carried inside the
  // masked observation (never the raw zone identity).
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
  // The immutable run provenance selects exactly one fixed broker read.
  const operationName = run.binding.existing_xui_admin_secret_ref
    ? "xui.inventory_existing_fixed.v1"
    : "xui.inventory_owned_fixed.v1";
  const { observation } = ctx.adapters.callBroker(operationName, "xui_inventory", {
    runId: run.run_id,
    originTargetRef: run.binding.origin_target_ref,
    adminSecretRef: run.binding.existing_xui_admin_secret_ref,
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
    // Phase 0-1 serves only the pre-change baseline binding scope; route,
    // install-receipt, and rollback-receipt bindings are Phase 3-4 scope.
    const bindingScope = "pre_change";
    const evidenceRef = ctx.ledger.putEvidence({
      runId: run.run_id,
      evidenceType: "PROTECTED_LINE_HEALTH",
      ttl: require("../../contract/mcp/schemas/contracts.cjs").EVIDENCE_TTLS.PROTECTED_LINE,
      maskedSummary: `protected line ${status} (${bindingScope})`,
      payload: { status, bindingScope },
      binding: { scope: bindingScope },
    });
    ctx.ledger.appendEvent(run.run_id, "EVIDENCE_MINTED", {
      evidenceType: "PROTECTED_LINE_HEALTH", evidenceRef,
    });
    advanceReadProbeCursorIfPlanned(ctx, run, "old_line_verify");
    applySuccessByOrigin(ctx, "old_line_verify", run);
    return {
      data: {
        protected_line_status: status,
        health_evidence_ref: evidenceRef,
        authenticated_or_server_proven_na: true,
        expected_egress_or_server_proven_na: true,
        binding_scope: bindingScope,
        bound_current_route_digest: null,
        bound_prerequisite_effect_digest: null,
        bound_rollback_receipt_ref: null,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

module.exports = {
  origin_inventory, cloudflare_inventory, xui_inventory, client_inventory, old_line_verify,
};
