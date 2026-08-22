"use strict";

// Plan compilation and host-mediated authorization. Operation lists come only
// from the frozen PLAN_OPERATION_RESOLVER templates; the caller never selects
// operations, templates, or lease classes.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const {
  requireRun, auditGate, configureGate, checkExpectedLedgerDigest, withIdempotency,
} = require("./common.cjs");

const RESOLVER = contracts.PLAN_OPERATION_RESOLVER;

const SCOPE_BY_INTENT = Object.freeze({
  configure_existing: "node_p2",
  install_then_configure: "node_install_p3",
  enable_bbr: "host_p3",
  rollback_owned_changes: "rollback",
});

const LEASE_CLASS_BY_SCOPE = Object.freeze({
  node_p2: "NODE_P2",
  node_install_p3: "NODE_INSTALL_P3",
  host_p3: "HOST_P3",
  rollback: "ROLLBACK",
});

const MAIN_COMPILE_ORIGINS = Object.freeze(["INVENTORIED", "PLAN_READY", "APPROVED"]);

function freshObservation(ctx, runId, evidenceType) {
  const row = ctx.ledger.freshEvidence(runId, evidenceType);
  if (!row) return null;
  const binding = JSON.parse(row.binding);
  return { evidence: row, observation: binding.observation || null };
}

function requireFreshFamilies(ctx, runId, families) {
  const out = {};
  for (const [key, evidenceType] of Object.entries(families)) {
    const found = freshObservation(ctx, runId, evidenceType);
    if (!found) {
      throw new ToolError("EVIDENCE_STALE",
        `plan compilation requires fresh ${evidenceType} evidence`, { retryable: true });
    }
    out[key] = found;
  }
  return out;
}

function resolveXuiCase(adminBindingStatus) {
  const row = RESOLVER.xuiCases[adminBindingStatus];
  if (!row) {
    throw new ToolError("DEPENDENCY_MISSING",
      "xui inventory observation does not resolve to a known case");
  }
  return row;
}

function resolveCertificateStrategy(run, originObservation) {
  const safeReuse = originObservation.safe_stable_certificate_reuse_eligible === true;
  const originCaEligible =
    run.binding.cf_origin_ca_secret_ref !== null &&
    originObservation.origin_ca_dedicated_slot_status === "absent_root_owned_available";
  const key = `${safeReuse ? "T" : "F"}${originCaEligible ? "T" : "F"}`;
  const row = RESOLVER.certificateCases[key];
  if (row.strategy === "not_applicable") {
    throw new ToolError("DEPENDENCY_MISSING",
      "certificate decision denies the run: no safe reuse and no Origin CA eligibility");
  }
  return row.strategy;
}

function enforceCloudflareForwardGate(cfObservation) {
  const gate = RESOLVER.cloudflareForwardGate;
  if (!gate.strictCompatibleModes.includes(cfObservation.ssl_mode) ||
      cfObservation.websockets_enabled !== true) {
    throw new ToolError("DEPENDENCY_MISSING",
      "cloudflare zone is not strict-compatible with websockets enabled; correct it externally and start a new run");
  }
}

function enforceGlobalForwardEligibility(observations) {
  const origin = observations.origin.observation;
  const cf = observations.cloudflare.observation;
  const failures = [];
  if (origin.nginx_installation_status !== "supported_existing") failures.push("SUPPORTED_EXISTING_NGINX");
  if (origin.public_tls_listener_owner !== "nginx_safe") failures.push("SAFE_PUBLIC_TLS_443_LISTENER_OWNERSHIP");
  if (origin.owned_include_slot_available !== true) failures.push("CREATE_ONLY_OWNED_INCLUDE_SLOT");
  if (origin.node_server_name_conflict !== false || origin.websocket_path_conflict !== false) {
    failures.push("NO_SERVER_NAME_OR_WEBSOCKET_PATH_CONFLICT");
  }
  if (!["ABSENT_AVAILABLE", "SAME_RUN_CURRENT_UNPROXIED", "SAME_RUN_CURRENT_PROXIED"]
    .includes(cf.record_observation_case)) {
    failures.push("CLOUDFLARE_RECORD_CASE_ABSENT_OR_SAME_RUN_CURRENT_NOT_FOREIGN_OR_AMBIGUOUS");
  }
  if (failures.length > 0) {
    throw new ToolError("DEPENDENCY_MISSING",
      `global forward eligibility failed: ${failures.join(", ")}`.slice(0, 250));
  }
}

function evidenceExpiryMs(row) {
  if (row.ttl_seconds === null) return Infinity;
  return Date.parse(row.created_at) + row.ttl_seconds * 1000;
}

function plan_compile(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "plan_compile");
  configureGate(run, "plan_compile");
  if (SCOPE_BY_INTENT[input.intent] !== input.scope) {
    throw new ToolError("INVALID_INPUT",
      "scope and intent do not match the closed scope/intent matrix");
  }
  checkExpectedLedgerDigest(run, input);
  return withIdempotency(ctx, run.run_id, "plan_compile", input, () => {
    let templateId;
    let certificateStrategy = "not_applicable";
    let consumed;

    if (input.scope === "node_p2" || input.scope === "node_install_p3") {
      if (!MAIN_COMPILE_ORIGINS.includes(run.main_phase)) {
        throw new ToolError("WRONG_STATE",
          `plan_compile(${input.scope}) is not legal from main_phase ${run.main_phase}`);
      }
      consumed = requireFreshFamilies(ctx, run.run_id, {
        origin: "ORIGIN_INVENTORY",
        cloudflare: "CLOUDFLARE_INVENTORY",
        xui: "XUI_INVENTORY",
        client: "CLIENT_INVENTORY",
        protectedLine: "PROTECTED_LINE_HEALTH",
      });
      enforceCloudflareForwardGate(consumed.cloudflare.observation);
      enforceGlobalForwardEligibility(consumed);
      const xuiCase = resolveXuiCase(consumed.xui.observation.admin_binding_status);
      if (xuiCase.resolution === "DENY") {
        throw new ToolError("DEPENDENCY_MISSING",
          `xui observation case denies the next plan (${consumed.xui.observation.admin_binding_status})`);
      }
      if (input.scope === "node_install_p3") {
        if (xuiCase.resolution !== "NODE_INSTALL_P3") {
          throw new ToolError("DEPENDENCY_MISSING",
            "install plan requires the proven absent clean-host observation case");
        }
        templateId = RESOLVER.scopes.NODE_INSTALL_P3.templateId;
      } else {
        if (xuiCase.resolution !== "NODE_P2") {
          throw new ToolError("DEPENDENCY_MISSING",
            "node plan requires a compatible existing or same-run owned 3x-ui observation case");
        }
        certificateStrategy = resolveCertificateStrategy(run, consumed.origin.observation);
        templateId = RESOLVER.scopes.NODE_P2.templateByCertificateStrategy[certificateStrategy];
      }
    } else if (input.scope === "host_p3") {
      if (run.bbr_phase !== "BBR_INVENTORIED" && run.bbr_phase !== "BBR_PLAN_READY") {
        throw new ToolError("WRONG_STATE",
          `plan_compile(host_p3) is not legal from bbr_phase ${run.bbr_phase}`);
      }
      consumed = requireFreshFamilies(ctx, run.run_id, { bbr: "BBR_INVENTORY" });
      if (consumed.bbr.observation.eligible !== true) {
        throw new ToolError("DEPENDENCY_MISSING",
          "bbr inventory does not prove supported-kernel eligibility");
      }
      templateId = RESOLVER.scopes.HOST_P3.templateId;
    } else {
      // rollback scope: only legal from an open recovery state, which no
      // Phase 0-1 run can reach (no external mutation can commit).
      if (!["ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"].includes(run.main_phase) &&
          run.bbr_phase !== "BBR_MANUAL_ACTION_REQUIRED") {
        throw new ToolError("WRONG_STATE",
          "rollback plan requires an open recovery state");
      }
      throw new ToolError("DEPENDENCY_MISSING",
        "rollback compilation requires an owned committed change graph; none exists in this build");
    }

    const template = RESOLVER.templates[templateId];
    const planRef = mintRef("plan");
    const challengeRef = mintRef("runtime");
    const leaseClass = LEASE_CLASS_BY_SCOPE[input.scope];
    const baselineDigest = digestOf(Object.fromEntries(
      Object.entries(consumed).map(([key, value]) => [key, value.evidence.payload_digest]),
    ));
    const nodeBindingDigest = run.node_binding_digest;

    const result = ctx.ledger.transaction(() => {
      ctx.ledger.invalidateCurrentPlan(run.run_id);
      const operationRefs = ctx.ledger.insertOperations(run.run_id, planRef, template.steps);
      const planDigest = digestOf({
        planRef, templateId, leaseClass, baselineDigest, operationRefs, certificateStrategy,
      });
      const impactDigest = digestOf({
        planDigest,
        steps: template.steps.map((step) => `${step.stepId}:${step.tool}:${step.mode}`),
      });
      ctx.ledger.insertPlan({
        planRef,
        runId: run.run_id,
        scope: input.scope,
        intent: input.intent,
        templateId,
        leaseClass,
        planDigest,
        baselineDigest,
        impactDigest,
        certificateStrategy,
        nodeBindingDigest,
      });
      const { parseIsoDurationSeconds } = require("../ledger/ledger.cjs");
      const challengeTtl = contracts.TOOLS_BY_NAME.plan_compile.policy.produces
        .find((produce) => produce.type === "APPROVAL_CHALLENGE").ttl;
      const challengeTtlMs = parseIsoDurationSeconds(challengeTtl) * 1000;
      ctx.ledger.insertChallenge({
        challengeRef,
        planRef,
        runId: run.run_id,
        expiresAt: new Date(ctx.ledger.now() + challengeTtlMs).toISOString(),
      });
      ctx.ledger.appendEvent(run.run_id, "PLAN_COMPILED", {
        planRef, templateId, leaseClass, planDigest, challengeRef,
      });
      if (input.scope === "host_p3") {
        ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_PLAN_READY" });
      } else {
        ctx.ledger.setPhases(run.run_id, { mainPhase: "PLAN_READY" });
      }
      return {
        data: {
          plan_ref: planRef,
          plan_digest: planDigest,
          baseline_digest: baselineDigest,
          template_id: templateId,
          approval_challenge_ref: challengeRef,
          operation_refs: operationRefs,
          rollback_atomic_stage_ids: [],
          rollback_atomic_stage_selection_digest: null,
          bbr_rollback_stage_ids: [],
          bbr_rollback_stage_selection_digest: null,
          impact_digest: impactDigest,
          lease_class: leaseClass,
          certificate_strategy: certificateStrategy,
          node_binding_digest: nodeBindingDigest,
        },
      };
    });
    return result;
  });
}

function plan_authorize(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "plan_authorize");
  configureGate(run, "plan_authorize");
  checkExpectedLedgerDigest(run, input);
  return withIdempotency(ctx, run.run_id, "plan_authorize", input, () => {
    const plan = ctx.ledger.currentPlan(run.run_id);
    if (!plan || plan.plan_ref !== input.plan_ref) {
      throw new ToolError("APPROVAL_STALE",
        "plan_ref does not name the current compiled plan");
    }
    const challenge = ctx.ledger.getChallenge(input.approval_challenge_ref);
    if (!challenge || challenge.plan_ref !== plan.plan_ref) {
      throw new ToolError("APPROVAL_STALE",
        "approval_challenge_ref does not bind the current plan");
    }
    // A consumed challenge is a replay regardless of the current phase.
    if (challenge.status === "consumed") {
      throw new ToolError("APPROVAL_REPLAYED", "approval challenge was already consumed");
    }
    if (challenge.status !== "open" || Date.parse(challenge.expires_at) <= ctx.ledger.now()) {
      throw new ToolError("APPROVAL_STALE", "approval challenge is expired or invalidated");
    }
    const originPhase = plan.scope === "host_p3" ? run.bbr_phase : run.main_phase;
    const expectedOrigin = plan.scope === "host_p3" ? "BBR_PLAN_READY" : "PLAN_READY";
    if (originPhase !== expectedOrigin) {
      throw new ToolError("WRONG_STATE",
        `plan_authorize is not legal from ${originPhase}`);
    }
    if (input.displayed_impact_digest !== plan.impact_digest) {
      throw new ToolError("APPROVAL_STALE",
        "displayed_impact_digest does not match the compiled plan impact digest");
    }

    // Effective approval expiry = min(nominal lease expiry, every currently
    // consumed finite evidence expiry).
    const { parseIsoDurationSeconds } = require("../ledger/ledger.cjs");
    const leaseTtlSeconds = parseIsoDurationSeconds(
      contracts.LEASE_POLICIES[plan.lease_class].ttl,
    );
    let expiryMs = ctx.ledger.now() + leaseTtlSeconds * 1000;
    const consumedFamilies = plan.scope === "host_p3"
      ? ["BBR_INVENTORY"]
      : ["ORIGIN_INVENTORY", "CLOUDFLARE_INVENTORY", "XUI_INVENTORY", "CLIENT_INVENTORY", "PROTECTED_LINE_HEALTH"];
    for (const family of consumedFamilies) {
      const row = ctx.ledger.freshEvidence(run.run_id, family);
      if (!row) {
        throw new ToolError("BASELINE_DRIFT",
          `consumed finite evidence family ${family} is no longer fresh`);
      }
      expiryMs = Math.min(expiryMs, evidenceExpiryMs(row));
    }

    const approvalRef = mintRef("approval");
    const expiresAt = new Date(expiryMs).toISOString();
    return ctx.ledger.transaction(() => {
      ctx.ledger.consumeChallenge(challenge.challenge_ref);
      ctx.ledger.insertApproval({
        approvalRef,
        planRef: plan.plan_ref,
        runId: run.run_id,
        leaseClass: plan.lease_class,
        expiresAt,
      });
      ctx.ledger.appendEvent(run.run_id, "PLAN_AUTHORIZED", {
        approvalRef, planRef: plan.plan_ref, leaseClass: plan.lease_class, expiresAt,
        hostPrompt: "server_host_prompt_boundary",
      });
      if (plan.scope === "host_p3") {
        ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_HOST_APPROVED" });
      } else {
        ctx.ledger.setPhases(run.run_id, { mainPhase: "APPROVED" });
      }
      return {
        data: {
          approval_ref: approvalRef,
          lease_class: plan.lease_class,
          approved_operation_refs: ctx.ledger.planOperations(plan.plan_ref)
            .map((op) => op.operation_ref),
          expires_at: expiresAt,
          plan_digest: plan.plan_digest,
        },
      };
    });
  });
}

module.exports = { plan_compile, plan_authorize };
