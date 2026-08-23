"use strict";

// Bounded read/probe tools.
//
// None of these is an external mutator, but each is load-bearing for
// acceptance, so each one proves its own claim rather than reporting a
// hopeful summary. In particular: a TLS handshake, an HTTP 101, a low
// latency, or a well-formed static profile is never by itself evidence that
// the node works. The authenticated end-to-end predicate needs a real
// authenticated request whose observed public egress equals the origin's own
// expected egress at the same allowlisted destination, compared as opaque
// HMAC digests so no raw address ever enters MCP.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const { LowEntropyBinder } = require("../core/hmac.cjs");
const identity = require("../core/identity.cjs");
const forwardGate = require("../core/forward-gate.cjs");
const {
  requireRun, auditGate, configureGate, stateGate, withIdempotency, applySuccessByOrigin,
  advanceReadProbeCursorIfPlanned,
} = require("./common.cjs");
const { assertTrue, assertEquals } = require("./mutators.cjs");

const E2E_POLICY = contracts.AUTHENTICATED_E2E_POLICY;

function mintProbeEvidence(ctx, run, evidenceType, ttlKey, summary, payload, binding = {}) {
  const evidenceRef = ctx.ledger.putEvidence({
    runId: run.run_id,
    evidenceType,
    ttl: contracts.EVIDENCE_TTLS[ttlKey],
    maskedSummary: summary,
    payload,
    binding: { ...binding, observation: payload },
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
  return destination;
}

function requireRegisteredClientRuntime(ctx, ref) {
  const runtime = ctx.ledger.getOnboardingRef(ref);
  if (!runtime || runtime.role !== "client_runtime") {
    throw new ToolError("DEPENDENCY_MISSING",
      "client_runtime_ref is not a registered allowlisted client runtime");
  }
  return runtime;
}

// --- origin_verify --------------------------------------------------------

// Direct-origin proof. Bound to the exact current route digest, so a route
// that changes afterwards invalidates the proof rather than silently
// carrying it forward into the proxy gate.
function origin_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "origin_verify");
  configureGate(run, "origin_verify");
  stateGate("origin_verify", run);
  return withIdempotency(ctx, run.run_id, "origin_verify", input, () => {
    const routeDigest = ctx.ledger.getScalar(run.run_id, "current_route_digest");
    if (!routeDigest) {
      throw new ToolError("DEPENDENCY_MISSING",
        "direct-origin verification requires a current same-run route");
    }
    const { observation } = ctx.adapters.callHelper("origin.probe_fixed.v1", "origin_verify", {
      runId: run.run_id,
      kind: "direct_origin_tls_websocket",
      routeDigest,
      nodeHostnameRef: run.binding.node_hostname_ref,
      websocketPathRef: ctx.ledger.getScalar(run.run_id, "websocket_path_ref"),
    });
    // A TLS handshake alone proves nothing about routing; all four facts must
    // hold before this counts as a direct-origin proof.
    assertTrue(observation, "tls_valid", "PROBE_FAILED", "direct-origin TLS was not valid");
    assertTrue(observation, "san_matches", "PROBE_FAILED",
      "direct-origin certificate SAN does not match the node hostname");
    assertTrue(observation, "websocket_upgrade_valid", "PROBE_FAILED",
      "direct-origin WebSocket upgrade was not valid");
    assertTrue(observation, "expected_route_reached", "PROBE_FAILED",
      "the direct-origin probe did not reach the expected route");

    const evidenceRef = mintProbeEvidence(ctx, run, "DIRECT_ORIGIN_TLS_WEBSOCKET",
      "ORIGIN_VERIFY", "direct origin TLS+WebSocket probe bound to the current route",
      observation, { routeDigest });
    advanceReadProbeCursorIfPlanned(ctx, run, "origin_verify");
    applySuccessByOrigin(ctx, "origin_verify", run);
    return {
      data: {
        origin_verify_ref: evidenceRef,
        tls_valid: true,
        san_matches: true,
        websocket_upgrade_valid: true,
        expected_route_reached: true,
        node_binding_digest: run.node_binding_digest,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

// --- cdn_verify -----------------------------------------------------------

function cdn_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "cdn_verify");
  configureGate(run, "cdn_verify");
  stateGate("cdn_verify", run);
  requireRegisteredProbeDestination(ctx, input.probe_destination_ref);
  return withIdempotency(ctx, run.run_id, "cdn_verify", input, () => {
    const { observation } = ctx.adapters.callBroker("cf.dns_read", "cdn_verify", {
      runId: run.run_id,
      kind: "cdn_verify_same_call_api_read",
      nodeHostnameRef: run.binding.node_hostname_ref,
      recordRef: ctx.ledger.getScalar(run.run_id, "record_ref"),
      cfAuditSecretRef: run.binding.cf_audit_secret_ref,
    });
    for (const [field, message] of [
      ["tls_valid", "Cloudflare-fronted TLS was not valid"],
      ["san_matches", "Cloudflare-fronted certificate SAN does not match the node hostname"],
      ["websocket_upgrade_valid", "Cloudflare-fronted WebSocket upgrade was not valid"],
      ["strict_compatible_mode_observed", "the observed zone mode is not strict-compatible"],
      ["expected_route_reached", "the Cloudflare probe did not reach the expected route"],
      ["cf_api_owned_proxied_record_current", "the API does not show this run's own record as currently proxied"],
      ["cf_api_ssl_strict_compatible_current", "the API does not currently show a strict-compatible SSL mode"],
      ["cf_api_websockets_enabled_current", "the API does not currently show WebSockets enabled"],
      ["independent_public_resolution_cloudflare_fronted", "independent public resolution is not Cloudflare-fronted"],
      ["public_resolution_not_proxy_mediated", "the public resolution was mediated by a local proxy"],
    ]) {
      assertTrue(observation, field, "CDN_NOT_VERIFIED", message);
    }
    // The public resolution must not be the origin itself: if it were, the
    // record is not actually fronted. Compared as opaque digests in the
    // PUBLIC_VS_ORIGIN_V1 domain; no raw address enters MCP.
    LowEntropyBinder.requireSameDomain("PUBLIC_RESOLUTION", "PUBLIC_COMPARISON_ORIGIN");
    const publicDigest = ctx.binder.digest("PUBLIC_RESOLUTION", {
      targetId: run.binding.cloudflare_target_ref, runId: run.run_id,
      value: observation.public_resolution_source_value,
    });
    const originDigest = ctx.binder.digest("PUBLIC_COMPARISON_ORIGIN", {
      targetId: run.binding.cloudflare_target_ref, runId: run.run_id,
      value: observation.origin_comparison_source_value,
    });
    if (LowEntropyBinder.equal(publicDigest, originDigest)) {
      throw new ToolError("CDN_NOT_VERIFIED",
        "public resolution equals the origin address; the record is not Cloudflare-fronted");
    }
    if (observation.public_resolution_not_198_18_0_0_15 !== true) {
      throw new ToolError("CDN_NOT_VERIFIED",
        "public resolution falls inside the benchmarking range and cannot be trusted");
    }

    const evidenceRef = mintProbeEvidence(ctx, run, "CLOUDFLARE_TLS_WEBSOCKET",
      "CDN_VERIFY", "cloudflare TLS+WebSocket probe with independent public resolution",
      observation);
    advanceReadProbeCursorIfPlanned(ctx, run, "cdn_verify");
    applySuccessByOrigin(ctx, "cdn_verify", run);
    return {
      data: {
        cdn_verify_ref: evidenceRef,
        tls_valid: true,
        san_matches: true,
        websocket_upgrade_valid: true,
        strict_compatible_mode_observed: true,
        expected_route_reached: true,
        node_binding_digest: run.node_binding_digest,
        cf_api_owned_proxied_record_current: true,
        cf_api_ssl_strict_compatible_current: true,
        cf_api_websockets_enabled_current: true,
        independent_public_resolution_cloudflare_fronted: true,
        public_resolution_not_origin: true,
        public_resolution_not_198_18_0_0_15: true,
        public_resolution_not_proxy_mediated: true,
        public_resolution_digest: publicDigest,
        origin_comparison_binding_digest: originDigest,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

// --- xui_profile_inspect --------------------------------------------------

function xui_profile_inspect(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "xui_profile_inspect");
  configureGate(run, "xui_profile_inspect");
  stateGate("xui_profile_inspect", run);
  if (input.expected_node_binding_digest !== run.node_binding_digest) {
    throw new ToolError("CONFLICT_DETECTED",
      "expected_node_binding_digest does not match this run's node binding");
  }
  const currentProfile = ctx.ledger.getScalar(run.run_id, "profile_ref");
  if (currentProfile !== input.profile_ref) {
    throw new ToolError("DEPENDENCY_MISSING",
      "profile_ref does not name this run's own published profile");
  }
  // A non-secret projection only: the broker resolves the runtime secret on
  // its own side and returns field equality, never credential bytes.
  const { observation } = ctx.adapters.callBroker(
    "xui.profile_inspect_projection.v1", "xui_profile_inspect", {
      runId: run.run_id,
      profileRef: input.profile_ref,
      expectedNodeBindingDigest: input.expected_node_binding_digest,
    });
  for (const [field, message] of [
    ["address_matches_node_hostname", "profile address does not match the node hostname"],
    ["sni_matches_node_hostname", "profile SNI does not match the node hostname"],
    ["websocket_host_matches_node_hostname", "profile websocket Host does not match the node hostname"],
    ["websocket_path_digest_matches", "profile websocket path does not match the same-run generated path"],
    ["importable", "the profile is not importable by the allowlisted client runtime"],
  ]) {
    assertTrue(observation, field, "CONFLICT_DETECTED", message);
  }
  assertEquals(observation, "transport", "ws", "CONFLICT_DETECTED", "profile transport is not ws");
  assertEquals(observation, "tls_enabled", true, "CONFLICT_DETECTED", "profile TLS is not enabled");
  assertEquals(observation, "allow_insecure", false, "CONFLICT_DETECTED",
    "profile allows insecure TLS");
  assertEquals(observation, "public_port", 443, "CONFLICT_DETECTED", "profile port is not 443");
  assertTrue(observation, "flow_is_none", "CONFLICT_DETECTED", "profile flow is not none");
  assertTrue(observation, "backend_security_is_none", "CONFLICT_DETECTED",
    "profile backend security is not none");

  identity.bindProducerFields(ctx, run, "xui_profile_inspect", observation.hostname_identity_digest);
  identity.bindWebsocketPathDigest(ctx, run, "xui_profile_inspect", observation.websocket_path_digest);

  mintProbeEvidence(ctx, run, "CLIENT_FIELD_BINDING_EQUALITY", "PROFILE_VERIFY",
    "non-secret client profile field equality projection", observation);
  advanceReadProbeCursorIfPlanned(ctx, run, "xui_profile_inspect");
  applySuccessByOrigin(ctx, "xui_profile_inspect", run);
  return {
    data: {
      profile_ref: input.profile_ref,
      profile_digest: observation.profile_digest,
      address_matches_node_hostname: true,
      sni_matches_node_hostname: true,
      websocket_host_matches_node_hostname: true,
      websocket_path_digest_matches: true,
      transport: "ws",
      tls_enabled: true,
      allow_insecure: false,
      public_port: 443,
      flow_is_none: true,
      backend_security_is_none: true,
      importable: true,
      node_binding_digest: run.node_binding_digest,
    },
  };
}

// --- traffic_verify -------------------------------------------------------

// The authenticated end-to-end probe. Two independent observations of the
// same allowlisted destination - what the origin says its own egress is, and
// what the destination actually observed through the proxied client - are
// compared as opaque HMAC digests in one comparison domain. Equality is the
// only signal that certifies the path; a handshake or an upgrade is not.
function traffic_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "traffic_verify");
  configureGate(run, "traffic_verify");
  stateGate("traffic_verify", run);
  const destination = requireRegisteredProbeDestination(ctx, input.probe_destination_ref);
  requireRegisteredClientRuntime(ctx, input.client_runtime_ref);
  if (input.expected_node_binding_digest !== run.node_binding_digest) {
    throw new ToolError("CONFLICT_DETECTED",
      "expected_node_binding_digest does not match this run's node binding");
  }
  if (ctx.ledger.getScalar(run.run_id, "profile_ref") !== input.profile_ref ||
      ctx.ledger.getScalar(run.run_id, "profile_secret_ref") !== input.client_profile_secret_ref) {
    throw new ToolError("SECRET_SCOPE_MISMATCH",
      "traffic verification requires this run's own profile and its runtime SecretRef");
  }
  return withIdempotency(ctx, run.run_id, "traffic_verify", input, () => {
    // What the origin itself reports as its egress at this destination.
    const expected = ctx.adapters.callHelper("origin.expected_egress_fixed.v1", "traffic_verify", {
      runId: run.run_id,
      probeDestinationRef: input.probe_destination_ref,
      originTargetRef: run.binding.origin_target_ref,
    });
    // What the destination observed from a real authenticated request that
    // traversed the proxied client path.
    const proxied = ctx.adapters.callBroker(
      "client.authenticated_egress_probe_fixed.v1", "traffic_verify", {
        runId: run.run_id,
        clientRuntimeRef: input.client_runtime_ref,
        profileRef: input.profile_ref,
        clientProfileSecretRef: input.client_profile_secret_ref,
        probeDestinationRef: input.probe_destination_ref,
      });
    const observation = proxied.observation || {};

    assertTrue(observation, "authenticated", "PROBE_FAILED",
      "the proxy request was not authenticated; a TLS handshake or HTTP 101 alone is not end-to-end evidence");
    assertTrue(observation, "request_succeeded", "PROBE_FAILED",
      "the authenticated proxy request did not succeed");
    if (proxied.probeDestinationRef !== input.probe_destination_ref ||
        expected.probeDestinationRef !== input.probe_destination_ref) {
      throw new ToolError("PROBE_FAILED",
        "expected and proxy-observed egress were not measured at the same allowlisted destination");
    }

    // Same comparison domain, per-install key, constant-time equality.
    const domain = LowEntropyBinder.requireSameDomain(
      "DIRECT_EXPECTED_EGRESS", "PROXY_OBSERVED_EGRESS");
    const expectedDigest = ctx.binder.digest("DIRECT_EXPECTED_EGRESS", {
      targetId: destination.ref, runId: run.run_id, value: expected.egressSourceValue,
    });
    const proxyDigest = ctx.binder.digest("PROXY_OBSERVED_EGRESS", {
      targetId: destination.ref, runId: run.run_id, value: proxied.egressSourceValue,
    });
    if (!LowEntropyBinder.equal(expectedDigest, proxyDigest)) {
      throw new ToolError("PROBE_FAILED",
        "proxy-observed egress does not equal the origin's expected egress at the same destination");
    }
    // Structural guard: nothing that looks like a raw address may be present
    // on anything this tool is about to return.
    assertRawEgressAbsent(observation);

    const expectedEvidenceRef = mintProbeEvidence(ctx, run, "EXPECTED_PUBLIC_EGRESS",
      "TRAFFIC_VERIFY", "origin-reported expected egress (opaque HMAC digest)",
      { binding: "DIRECT_EXPECTED_EGRESS", domain, digest: expectedDigest });
    const proxyEvidenceRef = mintProbeEvidence(ctx, run, "PROXY_OBSERVED_EGRESS",
      "TRAFFIC_VERIFY", "proxy-observed egress (opaque HMAC digest)",
      { binding: "PROXY_OBSERVED_EGRESS", domain, digest: proxyDigest });
    const probeRef = mintRef("probe");
    const correlationWindowRef = mintRef("runtime");
    mintProbeEvidence(ctx, run, "AUTHENTICATED_PROXY_REQUEST", "TRAFFIC_VERIFY",
      "authenticated proxy request with matching same-destination egress",
      { authenticated: true, requestSucceeded: true, egressEqual: true },
      { probeRef, correlationWindowRef });

    advanceReadProbeCursorIfPlanned(ctx, run, "traffic_verify");
    applySuccessByOrigin(ctx, "traffic_verify", run);
    return {
      data: {
        probe_ref: probeRef,
        authenticated: true,
        request_succeeded: true,
        expected_public_egress: true,
        expected_egress_evidence_ref: expectedEvidenceRef,
        proxy_observed_egress_evidence_ref: proxyEvidenceRef,
        expected_egress_binding_digest: expectedDigest,
        proxy_observed_egress_binding_digest: proxyDigest,
        same_allowlisted_destination: true,
        observed_egress_equals_expected: true,
        raw_egress_value_exposed: false,
        correlation_window_ref: correlationWindowRef,
        ephemeral_artifact_removed: observation.ephemeral_artifact_removed === true,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

const RAW_ADDRESS = /(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)|(?:\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b)/;

function assertRawEgressAbsent(value) {
  const serialized = JSON.stringify(value ?? null);
  if (RAW_ADDRESS.test(serialized)) {
    throw new ToolError("INTERNAL_ERROR",
      "refused to emit a traffic result carrying a raw address value");
  }
}

// --- logs_correlate -------------------------------------------------------

function logs_correlate(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "logs_correlate");
  configureGate(run, "logs_correlate");
  stateGate("logs_correlate", run);
  const trafficEvidence = ctx.ledger.freshEvidence(run.run_id, "AUTHENTICATED_PROXY_REQUEST");
  if (!trafficEvidence) {
    throw new ToolError("EVIDENCE_STALE",
      "log correlation requires a current authenticated proxy request", { retryable: true });
  }
  const trafficBinding = JSON.parse(trafficEvidence.binding || "{}");
  if (trafficBinding.probeRef !== input.probe_ref ||
      trafficBinding.correlationWindowRef !== input.correlation_window_ref) {
    throw new ToolError("CONFLICT_DETECTED",
      "probe_ref and correlation_window_ref do not name the current authenticated probe window");
  }
  const nginxAndXray = ctx.adapters.callHelper("origin.logs_correlate_fixed.v1", "logs_correlate", {
    runId: run.run_id,
    probeRef: input.probe_ref,
    correlationWindowRef: input.correlation_window_ref,
    maxLinesPerSource: input.max_lines_per_source,
  });
  const counters = ctx.adapters.callBroker("xui.logs_counter_read_fixed.v1", "logs_correlate", {
    runId: run.run_id,
    probeRef: input.probe_ref,
    inboundRef: ctx.ledger.getScalar(run.run_id, "inbound_ref"),
  });
  const observation = { ...(nginxAndXray.observation || {}), ...(counters.observation || {}) };
  assertTrue(observation, "nginx_correlated", "PROBE_FAILED",
    "the bounded nginx window does not correlate with the probe");
  assertTrue(observation, "xray_correlated", "PROBE_FAILED",
    "the bounded Xray window does not correlate with the probe");
  assertTrue(observation, "correlation_complete", "PROBE_FAILED",
    "log correlation is incomplete");

  const evidenceRef = mintProbeEvidence(ctx, run, "LOG_CORRELATION", "LOG_WINDOW",
    "bounded nginx/Xray/3x-ui correlation for the same probe window", observation,
    { probeRef: input.probe_ref });
  advanceReadProbeCursorIfPlanned(ctx, run, "logs_correlate");
  applySuccessByOrigin(ctx, "logs_correlate", run);
  return {
    data: {
      probe_ref: input.probe_ref,
      nginx_correlated: true,
      xray_correlated: true,
      xui_counter_correlated: observation.xui_counter_correlated === true,
      correlation_complete: true,
      evidence_refs: [evidenceRef],
    },
  };
}

// --- bbr_inventory --------------------------------------------------------

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
  // An owned drop-in is itself a persistent conflict for a fresh exclusive
  // create, so eligibility can never be true while one is present.
  const ownedDropinPresent = observation.owned_dropin_present === true;
  const persistentConflict = ownedDropinPresent || observation.persistent_conflict_present === true;
  const eligible = !persistentConflict &&
    observation.kernel_exposes_bbr === true &&
    observation.available_congestion_controls_contains_bbr === true &&
    observation.qdisc_fq_supported === true;
  const projected = {
    kernel_exposes_bbr: observation.kernel_exposes_bbr === true,
    available_congestion_controls_contains_bbr:
      observation.available_congestion_controls_contains_bbr === true,
    qdisc_fq_supported: observation.qdisc_fq_supported === true,
    persistent_conflict_present: persistentConflict,
    eligible,
    current_qdisc: observation.current_qdisc,
    current_congestion_control: observation.current_congestion_control,
    owned_dropin_present: ownedDropinPresent,
    inventory_digest: digestOf(observation),
  };
  const evidenceRef = mintProbeEvidence(ctx, run, "BBR_INVENTORY", "BBR_INVENTORY",
    "masked kernel BBR capability inventory", projected);
  // From BBR_HOST_APPROVED this is the dedicated HOST_P3 checkpoint: exact
  // no-drift preserves the identical plan, cursor, approval and both expiry
  // values with no extension; drift or expiry returns to BBR_PLAN_READY.
  const checkpoint = forwardGate.hostP3RefreshCheckpoint(ctx, run);
  if (!checkpoint.applicable) {
    applySuccessByOrigin(ctx, "bbr_inventory", run);
  }
  return { data: { bbr_inventory_ref: evidenceRef, ...projected } };
}

// --- bbr_verify -----------------------------------------------------------

function bbr_verify(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "bbr_verify");
  configureGate(run, "bbr_verify");
  stateGate("bbr_verify", run);
  requireRegisteredProbeDestination(ctx, input.probe_destination_ref);
  if (ctx.ledger.getScalar(run.run_id, "bbr_change_ref") !== input.bbr_change_ref) {
    throw new ToolError("CONFLICT_DETECTED",
      "bbr_change_ref does not name this run's own BBR change");
  }
  return withIdempotency(ctx, run.run_id, "bbr_verify", input, () => {
    const { observation } = ctx.adapters.callHelper(
      "origin.bbr_inventory_fixed.v1", "bbr_verify", {
        runId: run.run_id,
        bbrChangeRef: input.bbr_change_ref,
        ownedDropinDigest: ctx.ledger.getScalar(run.run_id, "bbr_dropin_digest"),
      });
    const probe = run.binding.protected_line_ref === null
      ? { observation: { healthy: true, authenticated: true, expectedEgress: true, notApplicable: true } }
      : ctx.adapters.callBroker("protected_line.runtime_probe_fixed.v1", "bbr_verify", {
        runId: run.run_id,
        protectedLineRef: run.binding.protected_line_ref,
        protectedLineRuntimeSecretRef: run.binding.protected_line_runtime_secret_ref,
        probeDestinationRef: input.probe_destination_ref,
      });

    const verified = observation.live_qdisc_matches === true &&
      observation.live_congestion_control_matches === true &&
      observation.persistent_dropin_matches === true;
    if (!verified) {
      // A conclusive verify-false is a durable rollback authorization source
      // in its own right: record it and enter the dedicated BBR manual path.
      recordBbrVerifyFalse(ctx, run);
      throw new ToolError("PROBE_FAILED",
        "BBR verification is conclusively false; the dedicated BBR rollback is now authorized");
    }
    const protectedLineStatus = run.binding.protected_line_ref === null ? "not_applicable" : "healthy";
    if (protectedLineStatus === "healthy" && probe.observation.healthy !== true) {
      throw new ToolError("PROTECTED_LINE_UNPROVEN",
        "the protected prior line is not healthy after the BBR change");
    }
    const protectedLineEvidenceRef = mintProbeEvidence(ctx, run, "PROTECTED_LINE_HEALTH",
      "PROTECTED_LINE", `protected line ${protectedLineStatus} after the BBR change`,
      { status: protectedLineStatus, bindingScope: "current_route" },
      { scope: "current_route", boundChangeRef: input.bbr_change_ref });
    const evidenceRef = mintProbeEvidence(ctx, run, "BBR_VERIFY", "BBR_VERIFY",
      "live/persistent BBR readback with protected-line health", observation);
    advanceReadProbeCursorIfPlanned(ctx, run, "bbr_verify");
    applySuccessByOrigin(ctx, "bbr_verify", run);
    return {
      data: {
        bbr_verify_ref: evidenceRef,
        live_qdisc_matches: true,
        live_congestion_control_matches: true,
        persistent_dropin_matches: true,
        live_congestion_control: "bbr",
        persistent_congestion_control: "bbr",
        live_default_qdisc: "fq",
        persistent_default_qdisc: "fq",
        protected_line_status: protectedLineStatus,
        protected_line_evidence_ref: protectedLineEvidenceRef,
        protected_line_bound_change_ref: input.bbr_change_ref,
        completed_at: ctx.ledger.nowIso(),
      },
    };
  });
}

// Mints the CONCLUSIVE_VERIFY_FALSE source episode. Exactly one baseline
// binding is carried: the normal committed apply receipt and its change ref.
function recordBbrVerifyFalse(ctx, run) {
  const applyReceiptRef = ctx.ledger.getScalar(run.run_id, "bbr_apply_receipt_ref");
  const changeRef = ctx.ledger.getScalar(run.run_id, "bbr_change_ref");
  if (!applyReceiptRef || !changeRef) return;
  ctx.ledger.transaction(() => {
    ctx.ledger.supersedeAllBbrSourceEpisodes(run.run_id);
    ctx.ledger.insertBbrSourceEpisode({
      episodeRef: mintRef("runtime"),
      runId: run.run_id,
      sourceRowId: "CONCLUSIVE_VERIFY_FALSE",
      durableCause: "CONCLUSIVE_BBR_VERIFY_FALSE",
      baselineKind: "NORMAL_COMMITTED_APPLY",
      baselineReceiptRef: applyReceiptRef,
      baselineChangeRef: changeRef,
      baselineBindingDigest: digestOf({ applyReceiptRef, changeRef }),
    });
    ctx.ledger.appendEvent(run.run_id, "BBR_VERIFY_CONCLUSIVELY_FALSE", {
      sourceRowId: "CONCLUSIVE_VERIFY_FALSE", applyReceiptRef,
    });
    ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_MANUAL_ACTION_REQUIRED" });
  });
}

module.exports = {
  origin_verify, cdn_verify, xui_profile_inspect, traffic_verify,
  logs_correlate, bbr_inventory, bbr_verify,
  mintProbeEvidence, requireRegisteredProbeDestination, assertRawEgressAbsent,
  E2E_POLICY,
};
