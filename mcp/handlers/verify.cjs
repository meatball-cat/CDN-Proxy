"use strict";

// Bounded read/probe tools. Each one goes through the closed adapter
// registry, mints TTL-bound evidence, and applies the frozen successByOrigin
// matrix. None of them is an external mutator.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const {
  requireRun, auditGate, configureGate, stateGate, withIdempotency, applySuccessByOrigin,
  advanceReadProbeCursorIfPlanned,
} = require("./common.cjs");

function mintProbeEvidence(ctx, run, evidenceType, ttlKey, summary, payload) {
  const evidenceRef = ctx.ledger.putEvidence({
    runId: run.run_id,
    evidenceType,
    ttl: contracts.EVIDENCE_TTLS[ttlKey],
    maskedSummary: summary,
    payload,
    binding: { observation: payload },
  });
  ctx.ledger.appendEvent(run.run_id, "EVIDENCE_MINTED", { evidenceType, evidenceRef });
  return evidenceRef;
}

function requireRegisteredProbeDestination(ctx, ref) {
  const destination = ctx.ledger.getOnboardingRef(ref);
  if (!destination || destination.role !== "probe_destination") {
    throw new ToolError("DEPENDENCY_MISSING",
      "probe_destination_ref is not a registered allowlisted probe destination");
  }
}

function origin_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "origin_verify");
  configureGate(run, "origin_verify");
  stateGate("origin_verify", run);
  return withIdempotency(ctx, run.run_id, "origin_verify", input, () => {
    const { observation } = ctx.adapters.callHelper("origin.probe_fixed.v1", "origin_verify", {
      runId: run.run_id, kind: "direct_origin_tls_websocket",
    });
    const evidenceRef = mintProbeEvidence(ctx, run, "DIRECT_ORIGIN_TLS_WEBSOCKET",
      "ORIGIN_VERIFY", "direct origin TLS+WebSocket probe", observation);
    advanceReadProbeCursorIfPlanned(ctx, run, "origin_verify");
    applySuccessByOrigin(ctx, "origin_verify", run);
    return {
      data: {
        origin_verify_ref: evidenceRef,
        ...observation,
        node_binding_digest: run.node_binding_digest,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

function cdn_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "cdn_verify");
  configureGate(run, "cdn_verify");
  stateGate("cdn_verify", run);
  requireRegisteredProbeDestination(ctx, input.probe_destination_ref);
  return withIdempotency(ctx, run.run_id, "cdn_verify", input, () => {
    const { observation } = ctx.adapters.callBroker("cf.dns_read", "cdn_verify", {
      runId: run.run_id, kind: "cdn_verify_same_call_api_read",
    });
    const evidenceRef = mintProbeEvidence(ctx, run, "CLOUDFLARE_TLS_WEBSOCKET",
      "CDN_VERIFY", "cloudflare TLS+WebSocket probe", observation);
    advanceReadProbeCursorIfPlanned(ctx, run, "cdn_verify");
    applySuccessByOrigin(ctx, "cdn_verify", run);
    return {
      data: {
        cdn_verify_ref: evidenceRef,
        ...observation,
        node_binding_digest: run.node_binding_digest,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

function xui_profile_inspect(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "xui_profile_inspect");
  configureGate(run, "xui_profile_inspect");
  stateGate("xui_profile_inspect", run);
  const { observation } = ctx.adapters.callBroker(
    "xui.profile_inspect_projection.v1", "xui_profile_inspect", {
      runId: run.run_id,
      profileRef: input.profile_ref,
      expectedNodeBindingDigest: input.expected_node_binding_digest,
    });
  mintProbeEvidence(ctx, run, "CLIENT_PROFILE_VERIFY", "PROFILE_VERIFY",
    "non-secret client profile field equality projection", observation);
  advanceReadProbeCursorIfPlanned(ctx, run, "xui_profile_inspect");
  applySuccessByOrigin(ctx, "xui_profile_inspect", run);
  return {
    data: {
      profile_ref: input.profile_ref,
      ...observation,
      node_binding_digest: run.node_binding_digest,
    },
  };
}

function traffic_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "traffic_verify");
  configureGate(run, "traffic_verify");
  stateGate("traffic_verify", run);
  requireRegisteredProbeDestination(ctx, input.probe_destination_ref);
  return withIdempotency(ctx, run.run_id, "traffic_verify", input, () => {
    const { observation } = ctx.adapters.callBroker(
      "client.authenticated_egress_probe_fixed.v1", "traffic_verify", {
        runId: run.run_id,
        clientRuntimeRef: input.client_runtime_ref,
        profileRef: input.profile_ref,
        probeDestinationRef: input.probe_destination_ref,
      });
    mintProbeEvidence(ctx, run, "AUTHENTICATED_PROXY_REQUEST",
      "TRAFFIC_VERIFY", "authenticated proxy request and expected egress", observation);
    advanceReadProbeCursorIfPlanned(ctx, run, "traffic_verify");
    applySuccessByOrigin(ctx, "traffic_verify", run);
    const { mintRef } = require("../core/refs.cjs");
    return {
      data: {
        probe_ref: mintRef("probe"),
        ...observation,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

function logs_correlate(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "logs_correlate");
  configureGate(run, "logs_correlate");
  stateGate("logs_correlate", run);
  const { observation } = ctx.adapters.callHelper(
    "origin.logs_correlate_fixed.v1", "logs_correlate", {
      runId: run.run_id,
      probeRef: input.probe_ref,
      correlationWindowRef: input.correlation_window_ref,
      maxLinesPerSource: input.max_lines_per_source,
    });
  const evidenceRef = mintProbeEvidence(ctx, run, "NGINX_XRAY_LOG_CORRELATION",
    "LOG_WINDOW", "bounded nginx/xray log correlation", observation);
  advanceReadProbeCursorIfPlanned(ctx, run, "logs_correlate");
  applySuccessByOrigin(ctx, "logs_correlate", run);
  return {
    data: {
      probe_ref: input.probe_ref,
      ...observation,
      evidence_refs: [evidenceRef],
    },
  };
}

function bbr_inventory(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "bbr_inventory");
  configureGate(run, "bbr_inventory");
  if (!run.enable_bbr) {
    throw new ToolError("WRONG_STATE", "the BBR branch was not requested for this run");
  }
  stateGate("bbr_inventory", run);
  const { observation } = ctx.adapters.callHelper(
    "origin.bbr_inventory_fixed.v1", "bbr_inventory", {
      runId: run.run_id,
      originTargetRef: run.binding.origin_target_ref,
      refresh: input.refresh,
    });
  const evidenceRef = mintProbeEvidence(ctx, run, "BBR_INVENTORY", "BBR_INVENTORY",
    "masked kernel BBR capability inventory", observation);
  applySuccessByOrigin(ctx, "bbr_inventory", run);
  return { data: { bbr_inventory_ref: evidenceRef, ...observation } };
}

function bbr_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "bbr_verify");
  configureGate(run, "bbr_verify");
  stateGate("bbr_verify", run);
  requireRegisteredProbeDestination(ctx, input.probe_destination_ref);
  return withIdempotency(ctx, run.run_id, "bbr_verify", input, () => {
    const { observation } = ctx.adapters.callHelper(
      "origin.bbr_inventory_fixed.v1", "bbr_verify", {
        runId: run.run_id,
        bbrChangeRef: input.bbr_change_ref,
      });
    const evidenceRef = mintProbeEvidence(ctx, run, "BBR_VERIFY", "BBR_VERIFY",
      "live/persistent BBR readback with protected-line health", observation);
    advanceReadProbeCursorIfPlanned(ctx, run, "bbr_verify");
    applySuccessByOrigin(ctx, "bbr_verify", run);
    return {
      data: {
        bbr_verify_ref: evidenceRef,
        ...observation,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

module.exports = {
  origin_verify, cdn_verify, xui_profile_inspect, traffic_verify,
  logs_correlate, bbr_inventory, bbr_verify,
};
