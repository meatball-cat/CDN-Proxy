"use strict";

// Plan compilation and host-mediated authorization.
//
// Operation lists come only from the frozen PLAN_OPERATION_RESOLVER
// templates; the caller never selects operations, templates, lease classes,
// rollback stages, or authorization sources. Rollback plans additionally
// carry a server-computed frozen stage selection derived from what this run
// actually owns.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const { parseIsoDurationSeconds } = require("../ledger/ledger.cjs");
const forwardGate = require("../core/forward-gate.cjs");
const rollbackEngine = require("../core/rollback.cjs");
const identityBinding = require("../core/identity.cjs");
const manifest = require("../adapters/manifest.cjs");
const {
  requireRun, auditGate, configureGate, checkExpectedLedgerDigest, withIdempotency,
} = require("./common.cjs");

const RESOLVER = contracts.PLAN_OPERATION_RESOLVER;
const BBR_SOURCES = contracts.BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET;
const MAIN_ROLLBACK_BBR_GATE = contracts.MAIN_ROLLBACK_BBR_GATE;
const BBR_ROLLBACK_MAIN_GATE = contracts.BBR_ROLLBACK_MAIN_GATE;
const INSTALL_CHAIN = contracts.XUI_INSTALL_POLICY.subplanChain;

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
// APPLYING is reachable only through the install subplan: once that cursor is
// complete, the gated replan in XUI_INSTALL_POLICY.subplanChain allows exactly
// one dependent NODE_P2 compile from there.
const INSTALL_GATED_REPLAN_ORIGIN = "APPLYING";
const MAIN_ROLLBACK_COMPILE_ORIGINS = Object.freeze([
  "ORIGIN_CONFIGURED", "ORIGIN_VERIFIED", "CDN_ENABLED", "CDN_VERIFIED",
  "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED",
  "OLD_LINE_REVERIFIED", "DELIVERY_REPORT_SEALED",
  "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED",
]);

function freshObservation(ctx, runId, evidenceType) {
  const row = ctx.ledger.freshEvidence(runId, evidenceType);
  if (!row) return null;
  const binding = JSON.parse(row.binding);
  return { evidence: row, observation: binding.observation || null, binding };
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

// Certificate decision. Reuse requires a currently safe, stable, root-owned
// pair with enough remaining validity on a trusted clock; otherwise Origin CA
// if eligible; otherwise the run is denied before any plan or lease.
function resolveCertificateStrategy(ctx, run, originObservation) {
  const validity = RESOLVER.certificateReuseValidity;
  let safeReuse = originObservation.safe_stable_certificate_reuse_eligible === true &&
    originObservation.node_hostname_coverage === true &&
    originObservation.certificate_key_pair_matches === true;
  if (safeReuse) {
    // Trusted server clock, minimum P30D remaining.
    const notAfter = originObservation.selected_certificate_not_after;
    const minimumMs = 30 * 24 * 3600 * 1000;
    if (!notAfter || Date.parse(notAfter) - ctx.ledger.now() < minimumMs) {
      safeReuse = false;
    }
  }
  const originCaEligible =
    run.binding.cf_origin_ca_secret_ref !== null &&
    originObservation.origin_ca_dedicated_slot_status === "absent_root_owned_available";
  const key = `${safeReuse ? "T" : "F"}${originCaEligible ? "T" : "F"}`;
  const row = RESOLVER.certificateCases[key];
  if (row.strategy === "not_applicable") {
    throw new ToolError("CERTIFICATE_NOT_READY",
      `certificate decision denies the run: no safe reuse (minimum ${validity.minimumRemainingValidity}) and no Origin CA eligibility`);
  }
  return row.strategy;
}

function enforceCloudflareForwardGate(cfObservation) {
  const gate = RESOLVER.cloudflareForwardGate;
  if (!gate.strictCompatibleModes.includes(cfObservation.ssl_mode)) {
    throw new ToolError("SSL_MODE_NOT_STRICT_COMPATIBLE",
      `zone SSL mode ${cfObservation.ssl_mode} is not strict-compatible; correct it externally and start a new run`);
  }
  if (cfObservation.websockets_enabled !== true) {
    throw new ToolError("DEPENDENCY_MISSING",
      "zone WebSockets are not enabled; correct it externally and start a new run");
  }
}

function enforceGlobalForwardEligibility(ctx, run, observations) {
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
  const outputDir = ctx.ledger.getOnboardingRef(run.binding.output_dir_ref);
  if (!outputDir || outputDir.flags.safe !== true) failures.push("SAFE_OUTPUT_DIRECTORY");
  if (ctx.ledger.openReconciliationObligation(run.run_id) ||
      ctx.ledger.currentRecoveryObligation(run.run_id, "main")) {
    failures.push("NO_UNKNOWN_COMMIT_OR_RECOVERY_OBLIGATION");
  }
  if (failures.length > 0) {
    throw new ToolError("DEPENDENCY_MISSING",
      `global forward eligibility failed: ${failures.join(", ")}`.slice(0, 250));
  }
  // The dedicated node hostname must be a registered, non-apex, non-panel,
  // unambiguous name under the registered zone.
  identityBinding.requireDedicatedNodeHostname(ctx, run);
}

// After the install subplan completes, the prior baseline and lease are gone.
// A dependent NODE_P2 plan needs a complete install cursor, known commits,
// fresh inventories, a protected-line proof bound to the exact install
// receipt, and no open recovery obligation.
function enforcePostInstallReplanGate(ctx, run, consumed) {
  const installReceiptRef = ctx.ledger.getScalar(run.run_id, "install_receipt_ref");
  if (!installReceiptRef) return;
  const failures = [];
  if (ctx.ledger.pendingOperationRefs(run.run_id).length > 0) failures.push("NO_OPEN_OPERATION");
  if (ctx.ledger.getScalar(run.run_id, "unknown_commit_open")) failures.push("ALL_COMMITS_KNOWN");
  if (ctx.ledger.currentRecoveryObligation(run.run_id, "main") ||
      ctx.ledger.openReconciliationObligation(run.run_id)) {
    failures.push("NO_ROLLBACK_OR_MANUAL_OBLIGATION");
  }
  const protectedLine = consumed.protectedLine.binding;
  if (protectedLine.scope !== "post_xui_install") {
    failures.push("FRESH_PROTECTED_LINE_BOUND_TO_COMPLETED_PREREQUISITE_RECEIPTS");
  } else {
    const receipt = ctx.ledger.latestOwnership(run.run_id, "OWNED_XUI_INSTALLATION");
    if (!receipt || protectedLine.prerequisiteEffectDigest !== receipt.after_digest) {
      failures.push("FRESH_PROTECTED_LINE_BOUND_TO_COMPLETED_PREREQUISITE_RECEIPTS");
    }
  }
  if (failures.length > 0) {
    throw new ToolError("DEPENDENCY_MISSING",
      `post-install replan gate failed: ${failures.join(", ")}`.slice(0, 250));
  }
}

// --- rollback source resolution ------------------------------------------

// Resolves exactly one current, unconsumed, unsuperseded BBR rollback source
// episode. Zero rows denies; more than one row denies and stays manual.
function resolveBbrRollbackSource(ctx, run) {
  const episodes = ctx.ledger.currentBbrSourceEpisodes(run.run_id);
  if (episodes.length === 0) {
    // An explicit request from a committed apply mints the episode itself.
    if (BBR_SOURCES.rows.EXPLICIT_COMMITTED_APPLY.compileAllowedOrigins.includes(run.bbr_phase)) {
      const applyReceiptRef = ctx.ledger.getScalar(run.run_id, "bbr_apply_receipt_ref");
      const changeRef = ctx.ledger.getScalar(run.run_id, "bbr_change_ref");
      if (!applyReceiptRef || !changeRef) {
        throw new ToolError("DEPENDENCY_MISSING",
          "an explicit BBR rollback requires exactly one committed apply baseline receipt");
      }
      return {
        mint: true,
        sourceRowId: "EXPLICIT_COMMITTED_APPLY",
        durableCause: BBR_SOURCES.rows.EXPLICIT_COMMITTED_APPLY.durableCause,
        baselineKind: "NORMAL_COMMITTED_APPLY",
        baselineReceiptRef: applyReceiptRef,
        baselineChangeRef: changeRef,
        baselineBindingDigest: digestOf({ applyReceiptRef, changeRef }),
      };
    }
    throw new ToolError("DEPENDENCY_MISSING",
      "no current BBR rollback authorization source row is visible; no plan is compiled");
  }
  if (episodes.length > 1) {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      "more than one current BBR rollback source episode is visible; no plan is compiled");
  }
  const episode = episodes[0];
  const row = BBR_SOURCES.rows[episode.source_row_id];
  if (!row) {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      "the current BBR source episode names an unknown authorization row");
  }
  if (!row.compileAllowedOrigins.includes(run.bbr_phase)) {
    throw new ToolError("WRONG_STATE",
      `BBR source row ${episode.source_row_id} may not compile from ${run.bbr_phase}`);
  }
  return { mint: false, episode, sourceRowId: episode.source_row_id };
}

// --- plan_compile ---------------------------------------------------------

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
    if (input.scope === "rollback") return compileRollback(ctx, run, input);
    return compileForward(ctx, run, input);
  });
}

function compileForward(ctx, run, input) {
  let templateId;
  let certificateStrategy = "not_applicable";
  let consumed;

  if (input.scope === "node_p2" || input.scope === "node_install_p3") {
    const gatedReplan = run.main_phase === INSTALL_GATED_REPLAN_ORIGIN &&
      input.scope === "node_p2" &&
      ctx.ledger.getScalar(run.run_id, "install_receipt_ref") !== null;
    if (!MAIN_COMPILE_ORIGINS.includes(run.main_phase) && !gatedReplan) {
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
    enforceGlobalForwardEligibility(ctx, run, consumed);
    const xuiCase = resolveXuiCase(consumed.xui.observation.admin_binding_status);
    if (xuiCase.resolution === "DENY") {
      throw new ToolError(xuiCase.errorCode || "DEPENDENCY_MISSING",
        `xui observation case denies the next plan (${consumed.xui.observation.admin_binding_status})`);
    }
    if (input.scope === "node_install_p3") {
      if (xuiCase.resolution !== "NODE_INSTALL_P3") {
        throw new ToolError("INSTALL_NOT_ELIGIBLE",
          "install plan requires the proven absent clean-host observation case");
      }
      // No pinned adapter, no install plan and no lease.
      manifest.requirePinnedAdapter(consumed.origin.observation);
      templateId = RESOLVER.scopes.NODE_INSTALL_P3.templateId;
    } else {
      if (xuiCase.resolution !== "NODE_P2") {
        throw new ToolError("DEPENDENCY_MISSING",
          "node plan requires a compatible existing or same-run owned 3x-ui observation case");
      }
      enforcePostInstallReplanGate(ctx, run, consumed);
      certificateStrategy = resolveCertificateStrategy(ctx, run, consumed.origin.observation);
      templateId = RESOLVER.scopes.NODE_P2.templateByCertificateStrategy[certificateStrategy];
    }
  } else if (input.scope === "host_p3") {
    if (run.bbr_phase !== "BBR_INVENTORIED" && run.bbr_phase !== "BBR_PLAN_READY" &&
        run.bbr_phase !== "BBR_HOST_APPROVED") {
      throw new ToolError("WRONG_STATE",
        `plan_compile(host_p3) is not legal from bbr_phase ${run.bbr_phase}`);
    }
    // The BBR branch may inventory early, but it may not compile, authorize,
    // or apply before the main line is delivered and still unsealed.
    if (run.main_phase !== BBR_ROLLBACK_MAIN_GATE.requiredMainPhase) {
      throw new ToolError("WRONG_STATE",
        `BBR compile requires main_phase ${BBR_ROLLBACK_MAIN_GATE.requiredMainPhase}, observed ${run.main_phase}`);
    }
    if (ctx.ledger.latestReport(run.run_id, "end_to_end_verified")) {
      throw new ToolError("WRONG_STATE", "BBR may not be applied after the main report is sealed");
    }
    consumed = requireFreshFamilies(ctx, run.run_id, {
      bbr: "BBR_INVENTORY", protectedLine: "PROTECTED_LINE_HEALTH",
    });
    const bbr = consumed.bbr.observation;
    // Conflicts are reported before the generic eligibility message so the
    // caller learns which specific condition blocked the exclusive create.
    if (bbr.owned_dropin_present !== false) {
      throw new ToolError("CONFLICT_DETECTED",
        "an owned drop-in already exists; the drop-in is exclusive-create only and is never adopted");
    }
    if (bbr.persistent_conflict_present === true) {
      throw new ToolError("CONFLICT_DETECTED",
        "a persistent sysctl conflict blocks the exclusive create; Core-v1 never edits a shared sysctl file");
    }
    if (bbr.eligible !== true || bbr.kernel_exposes_bbr !== true ||
        bbr.available_congestion_controls_contains_bbr !== true ||
        bbr.qdisc_fq_supported !== true) {
      throw new ToolError("DEPENDENCY_MISSING",
        "bbr inventory does not prove supported-kernel eligibility; Core-v1 never installs or upgrades a kernel");
    }
    templateId = RESOLVER.scopes.HOST_P3.templateId;
  } else {
    throw new ToolError("INVALID_INPUT", `unknown plan scope ${input.scope}`);
  }

  return commitPlan(ctx, run, input, {
    templateId, certificateStrategy, consumed,
    stageIds: [], bbrStageIds: [], column: input.scope === "host_p3" ? "bbr" : "main",
    // The install subplan leaves the run at APPLYING; the gated dependent
    // plan projects PLAN_READY so it needs its own fresh host prompt.
    forcedDestination: run.main_phase === INSTALL_GATED_REPLAN_ORIGIN && input.scope === "node_p2"
      ? "PLAN_READY" : null,
  });
}

function compileRollback(ctx, run, input) {
  const bbrRollbackRequested = ["BBR_APPLIED", "BBR_VERIFIED", "BBR_MANUAL_ACTION_REQUIRED"]
    .includes(run.bbr_phase);
  if (bbrRollbackRequested) return compileBbrRollback(ctx, run, input);
  return compileMainRollback(ctx, run, input);
}

function compileMainRollback(ctx, run, input) {
  if (!MAIN_ROLLBACK_COMPILE_ORIGINS.includes(run.main_phase)) {
    throw new ToolError("WRONG_STATE",
      `main rollback compilation is not legal from main_phase ${run.main_phase}`);
  }
  // Re-evaluated at every consumer, not just once at compile.
  const gate = MAIN_ROLLBACK_BBR_GATE;
  if (gate.deniedRawStates.includes(run.bbr_phase)) {
    throw new ToolError("WRONG_STATE",
      `main rollback is denied while the BBR branch is raw ${run.bbr_phase}`);
  }
  // A durable zero-dispatch admission receipt is what permits a fresh full
  // plan after a lease expiry with nothing dispatched.
  const admission = ctx.ledger.currentAdmissionReceipt(
    run.run_id, "MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY_ADMISSION_RECEIPT");

  const prefix = rollbackEngine.provenPrefix(
    ctx, run.run_id, rollbackEngine.MAIN_FAMILY, rollbackEngine.MAIN_STAGE_IDS);
  if (prefix.kind === "NON_CONTIGUOUS") {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      "durable stage receipts are not a contiguous prefix; reconcile before planning a suffix");
  }
  const owned = rollbackEngine.selectMainStages(ctx, run.run_id);
  // A proven prefix may only be resumed from its exact remaining suffix.
  const stageIds = prefix.length > 0
    ? rollbackEngine.remainingSuffix(rollbackEngine.MAIN_STAGE_IDS, prefix.length)
        .filter((id) => owned.includes(id))
    : owned;
  if (stageIds.length === 0) {
    throw new ToolError("ROLLBACK_UNSAFE",
      "no same-run owned resource remains to reverse; nothing to roll back");
  }
  return commitPlan(ctx, run, input, {
    templateId: RESOLVER.scopes.MAIN_ROLLBACK.templateId,
    certificateStrategy: "not_applicable",
    consumed: {},
    stageIds, bbrStageIds: [], column: "main",
    admissionReceiptRef: admission ? admission.receipt_ref : null,
    createsRecoveryObligation: true,
  });
}

function compileBbrRollback(ctx, run, input) {
  if (run.main_phase !== BBR_ROLLBACK_MAIN_GATE.requiredMainPhase) {
    throw new ToolError("WRONG_STATE",
      `BBR rollback requires main_phase ${BBR_ROLLBACK_MAIN_GATE.requiredMainPhase}, observed ${run.main_phase}`);
  }
  if (ctx.ledger.latestReport(run.run_id, "end_to_end_verified")) {
    throw new ToolError("WRONG_STATE", "BBR rollback is denied after the main report is sealed");
  }
  const source = resolveBbrRollbackSource(ctx, run);
  const prefix = rollbackEngine.provenPrefix(
    ctx, run.run_id, rollbackEngine.BBR_FAMILY, rollbackEngine.BBR_STAGE_IDS);
  if (prefix.kind === "NON_CONTIGUOUS") {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      "durable BBR stage receipts are not a contiguous prefix; reconcile before planning a suffix");
  }
  const bbrStageIds = prefix.length > 0
    ? rollbackEngine.remainingSuffix(rollbackEngine.BBR_STAGE_IDS, prefix.length)
    : [...rollbackEngine.BBR_STAGE_IDS];
  return commitPlan(ctx, run, input, {
    templateId: RESOLVER.scopes.BBR_ROLLBACK.templateId,
    certificateStrategy: "not_applicable",
    consumed: {},
    stageIds: [], bbrStageIds, column: "bbr",
    bbrSource: source,
  });
}

function destinationFor(ctx, run, column, scope) {
  const policy = contracts.TOOLS_BY_NAME.plan_compile.policy;
  const origin = column === "bbr" ? run.bbr_phase : run.main_phase;
  const destination = policy.successByOrigin[origin];
  if (!destination || destination === "UNCHANGED" || destination.startsWith("DELEGATE_")) return null;
  return destination;
}

function commitPlan(ctx, run, input, options) {
  const { templateId, certificateStrategy, consumed, stageIds, bbrStageIds, column } = options;
  const template = RESOLVER.templates[templateId];
  const planRef = mintRef("plan");
  const challengeRef = mintRef("runtime");
  const leaseClass = LEASE_CLASS_BY_SCOPE[input.scope];
  const baselineDigest = digestOf(Object.fromEntries(
    Object.entries(consumed).map(([key, value]) => [key, value.evidence.payload_digest]),
  ));
  const nodeBindingDigest = run.node_binding_digest;
  const stageSelectionDigest = stageIds.length > 0 ? rollbackEngine.selectionDigest(stageIds) : null;
  const bbrStageSelectionDigest = bbrStageIds.length > 0
    ? rollbackEngine.selectionDigest(bbrStageIds) : null;

  return ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    const operationRefs = ctx.ledger.insertOperations(run.run_id, planRef, template.steps);
    const planDigest = digestOf({
      planRef, templateId, leaseClass, baselineDigest, operationRefs, certificateStrategy,
      stageIds, bbrStageIds,
    });
    const impactDigest = digestOf({
      planDigest,
      steps: template.steps.map((step) => `${step.stepId}:${step.tool}:${step.mode}`),
      stageIds, bbrStageIds,
    });
    ctx.ledger.insertPlan({
      planRef, runId: run.run_id, scope: input.scope, intent: input.intent, templateId,
      leaseClass, planDigest, baselineDigest, impactDigest, certificateStrategy, nodeBindingDigest,
    });
    // The exact observation each family contributed is the immutable drift
    // baseline for every later checkpoint under this plan.
    for (const [key, value] of Object.entries(consumed)) {
      if (!value.observation) continue;
      const family = {
        origin: "ORIGIN_INVENTORY", cloudflare: "CLOUDFLARE_INVENTORY",
        xui: "XUI_INVENTORY", client: "CLIENT_INVENTORY", bbr: "BBR_INVENTORY",
      }[key];
      if (family) forwardGate.recordPlanBaseline(ctx, run.run_id, planRef, family, value.observation);
    }
    if (stageIds.length > 0) ctx.ledger.setScalar(run.run_id, `stages:${planRef}`, stageIds);
    if (bbrStageIds.length > 0) ctx.ledger.setScalar(run.run_id, `bbr_stages:${planRef}`, bbrStageIds);

    const challengeTtl = contracts.TOOLS_BY_NAME.plan_compile.policy.produces
      .find((produce) => produce.type === "APPROVAL_CHALLENGE").ttl;
    ctx.ledger.insertChallenge({
      challengeRef, planRef, runId: run.run_id,
      expiresAt: new Date(ctx.ledger.now() + parseIsoDurationSeconds(challengeTtl) * 1000).toISOString(),
    });

    // The main recovery obligation is created immutably in the same local
    // ledger transaction as the plan it authorizes.
    if (options.createsRecoveryObligation && !ctx.ledger.currentRecoveryObligation(run.run_id, "main")) {
      ctx.ledger.insertRecoveryObligation({
        obligationRef: mintRef("runtime"), runId: run.run_id, column: "main",
        cause: "MAIN_ROLLBACK_PLAN_COMPILED",
        boundGraphDigest: digestOf(ctx.ledger.committedMainChanges(run.run_id)
          .map((c) => ({ kind: c.object_kind, after: c.after_digest }))),
      });
    }
    if (options.admissionReceiptRef) ctx.ledger.consumeAdmissionReceipt(options.admissionReceiptRef);
    if (options.bbrSource && options.bbrSource.mint) {
      ctx.ledger.insertBbrSourceEpisode({
        episodeRef: mintRef("runtime"), runId: run.run_id,
        sourceRowId: options.bbrSource.sourceRowId,
        durableCause: options.bbrSource.durableCause,
        baselineKind: options.bbrSource.baselineKind,
        baselineReceiptRef: options.bbrSource.baselineReceiptRef,
        baselineChangeRef: options.bbrSource.baselineChangeRef,
        baselineBindingDigest: options.bbrSource.baselineBindingDigest,
      });
    }
    ctx.ledger.appendEvent(run.run_id, "PLAN_COMPILED", {
      planRef, templateId, leaseClass, planDigest, challengeRef,
      stageIds, bbrStageIds,
      bbrRollbackAuthorizationSourceRowId: options.bbrSource ? options.bbrSource.sourceRowId : null,
    });
    const destination = options.forcedDestination || destinationFor(ctx, run, column, input.scope);
    if (destination) {
      ctx.ledger.setPhases(run.run_id,
        column === "bbr" ? { bbrPhase: destination } : { mainPhase: destination });
    }
    return {
      data: {
        plan_ref: planRef,
        plan_digest: planDigest,
        baseline_digest: baselineDigest,
        template_id: templateId,
        approval_challenge_ref: challengeRef,
        operation_refs: operationRefs,
        rollback_atomic_stage_ids: stageIds,
        rollback_atomic_stage_selection_digest: stageSelectionDigest,
        bbr_rollback_stage_ids: bbrStageIds,
        bbr_rollback_stage_selection_digest: bbrStageSelectionDigest,
        impact_digest: impactDigest,
        lease_class: leaseClass,
        certificate_strategy: certificateStrategy,
        node_binding_digest: nodeBindingDigest,
      },
    };
  });
}

// --- plan_authorize -------------------------------------------------------

function plan_authorize(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "plan_authorize");
  configureGate(run, "plan_authorize");
  checkExpectedLedgerDigest(run, input);
  return withIdempotency(ctx, run.run_id, "plan_authorize", input, () => {
    const plan = ctx.ledger.currentPlan(run.run_id);
    if (!plan || plan.plan_ref !== input.plan_ref) {
      throw new ToolError("APPROVAL_STALE", "plan_ref does not name the current compiled plan");
    }
    const challenge = ctx.ledger.getChallenge(input.approval_challenge_ref);
    if (!challenge || challenge.plan_ref !== plan.plan_ref) {
      throw new ToolError("APPROVAL_STALE", "approval_challenge_ref does not bind the current plan");
    }
    if (challenge.status === "consumed") {
      throw new ToolError("APPROVAL_REPLAYED", "approval challenge was already consumed");
    }
    if (challenge.status !== "open" || Date.parse(challenge.expires_at) <= ctx.ledger.now()) {
      throw new ToolError("APPROVAL_STALE", "approval challenge is expired or invalidated");
    }
    const column = plan.scope === "host_p3" ||
      (plan.scope === "rollback" && plan.template_id === "BBR_ROLLBACK_V1") ? "bbr" : "main";
    const originPhase = column === "bbr" ? run.bbr_phase : run.main_phase;
    const policy = contracts.TOOLS_BY_NAME.plan_authorize.policy;
    if (!policy.allowedFrom.includes(originPhase)) {
      throw new ToolError("WRONG_STATE", `plan_authorize is not legal from ${originPhase}`);
    }
    if (input.displayed_impact_digest !== plan.impact_digest) {
      throw new ToolError("APPROVAL_STALE",
        "displayed_impact_digest does not match the compiled plan impact digest");
    }
    // Rollback authorization re-checks its own obligation and gate rows.
    if (plan.scope === "rollback") {
      if (column === "main") {
        if (!ctx.ledger.currentRecoveryObligation(run.run_id, "main")) {
          throw new ToolError("ROLLBACK_UNSAFE",
            "main rollback authorization requires a current main recovery obligation");
        }
        if (MAIN_ROLLBACK_BBR_GATE.deniedRawStates.includes(run.bbr_phase)) {
          throw new ToolError("WRONG_STATE",
            `main rollback authorization is denied while the BBR branch is raw ${run.bbr_phase}`);
        }
      } else if (ctx.ledger.currentBbrSourceEpisodes(run.run_id).length !== 1) {
        throw new ToolError("MANUAL_ACTION_REQUIRED",
          "BBR rollback authorization requires exactly one current source obligation episode");
      }
    }

    // Effective approval expiry = min(nominal lease, every currently consumed
    // finite evidence expiry). It never extends anything.
    const leaseTtlSeconds = parseIsoDurationSeconds(contracts.LEASE_POLICIES[plan.lease_class].ttl);
    let expiryMs = ctx.ledger.now() + leaseTtlSeconds * 1000;
    if (plan.scope !== "rollback") {
      for (const family of forwardGate.consumedFamilies(plan.lease_class)) {
        const row = ctx.ledger.freshEvidence(run.run_id, family);
        if (!row) {
          throw new ToolError("BASELINE_DRIFT",
            `consumed finite evidence family ${family} is no longer fresh`);
        }
        expiryMs = Math.min(expiryMs, forwardGate.evidenceExpiryMs(row));
      }
    }

    const approvalRef = mintRef("approval");
    const expiresAt = new Date(expiryMs).toISOString();
    return ctx.ledger.transaction(() => {
      ctx.ledger.consumeChallenge(challenge.challenge_ref);
      ctx.ledger.insertApproval({
        approvalRef, planRef: plan.plan_ref, runId: run.run_id,
        leaseClass: plan.lease_class, expiresAt,
      });
      ctx.ledger.appendEvent(run.run_id, "PLAN_AUTHORIZED", {
        approvalRef, planRef: plan.plan_ref, leaseClass: plan.lease_class, expiresAt,
        hostPrompt: "server_host_prompt_boundary",
      });
      const destination = policy.successByOrigin[originPhase];
      if (destination && destination !== "UNCHANGED") {
        ctx.ledger.setPhases(run.run_id,
          column === "bbr" ? { bbrPhase: destination } : { mainPhase: destination });
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

module.exports = { plan_compile, plan_authorize, resolveCertificateStrategy, resolveBbrRollbackSource };
