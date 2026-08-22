"use strict";

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const {
  requireRun, auditGate, stateGate, checkExpectedLedgerDigest,
  withIdempotency,
} = require("./common.cjs");

const ONBOARDING_ROLE_BY_FIELD = Object.freeze({
  origin_target_ref: { kind: "target", role: "origin" },
  cloudflare_target_ref: { kind: "target", role: "cloudflare_zone" },
  node_hostname_ref: { kind: "runtime", role: "node_hostname" },
  output_dir_ref: { kind: "runtime", role: "output_dir" },
  protected_line_ref: { kind: "runtime", role: "protected_line", nullable: true },
  ssh_identity_secret_ref: { kind: "secret", role: "ssh-origin-identity" },
  cf_audit_secret_ref: { kind: "secret", role: "cf-audit" },
  cf_node_dns_secret_ref: { kind: "secret", role: "cf-node-dns", nullable: true },
  cf_origin_ca_secret_ref: { kind: "secret", role: "cf-origin-ca", nullable: true },
  existing_xui_admin_secret_ref: { kind: "secret", role: "xui-panel-admin", nullable: true },
  protected_line_runtime_secret_ref: { kind: "secret", role: "protected-line-runtime", nullable: true },
});

// Audit completion requires exactly these five fresh evidence families, in
// the contract's declared order.
const AUDIT_REQUIREMENTS = Object.freeze([
  ["ORIGIN_INVENTORY", "ORIGIN_INVENTORY"],
  ["CLOUDFLARE_INVENTORY", "CLOUDFLARE_INVENTORY"],
  ["XUI_INVENTORY", "XUI_INVENTORY"],
  ["CLIENT_INVENTORY", "CLIENT_INVENTORY"],
  ["PROTECTED_LINE_HEALTHY_OR_PROVEN_NA", "PROTECTED_LINE_HEALTH"],
]);

function run_begin(ctx, input) {
  return withIdempotency(ctx, "onboarding", "run_begin", input, () => {
    for (const [field, spec] of Object.entries(ONBOARDING_ROLE_BY_FIELD)) {
      const value = input[field];
      if (value === null) {
        if (!spec.nullable) {
          throw new ToolError("DEPENDENCY_MISSING", `${field} must be registered`);
        }
        continue;
      }
      const registered = ctx.ledger.getOnboardingRef(value);
      if (!registered || registered.kind !== spec.kind || registered.role !== spec.role) {
        const code = spec.kind === "target" ? "UNAUTHORIZED_TARGET" : "DEPENDENCY_MISSING";
        throw new ToolError(code,
          `${field} does not name a registered onboarding ${spec.kind} with role ${spec.role}`);
      }
    }
    if (input.protected_line_ref === null) {
      const node = ctx.ledger.getOnboardingRef(input.node_hostname_ref);
      if (!node.flags.protectedLineNotApplicable) {
        throw new ToolError("DEPENDENCY_MISSING",
          "protected_line_ref may be null only when the server registered the protected line as not applicable");
      }
    }

    const runId = mintRef("run");
    const bbrPhase = input.mode === "configure" && input.enable_bbr
      ? "BBR_PENDING" : "BBR_NOT_REQUESTED";
    const binding = {
      origin_target_ref: input.origin_target_ref,
      cloudflare_target_ref: input.cloudflare_target_ref,
      node_hostname_ref: input.node_hostname_ref,
      output_dir_ref: input.output_dir_ref,
      protected_line_ref: input.protected_line_ref,
      protected_line_runtime_secret_ref: input.protected_line_runtime_secret_ref,
      ssh_identity_secret_ref: input.ssh_identity_secret_ref,
      cf_audit_secret_ref: input.cf_audit_secret_ref,
      cf_node_dns_secret_ref: input.cf_node_dns_secret_ref,
      cf_origin_ca_secret_ref: input.cf_origin_ca_secret_ref,
      existing_xui_admin_secret_ref: input.existing_xui_admin_secret_ref,
    };
    const targetSetDigest = digestOf(binding);
    const nodeBindingDigest = digestOf({ node_hostname_ref: input.node_hostname_ref });
    const run = ctx.ledger.transaction(() => {
      const created = ctx.ledger.createRun({
        runId,
        runMode: input.mode,
        mainPhase: "NEW",
        bbrPhase,
        enableBbr: input.mode === "configure" && input.enable_bbr,
        binding,
        targetSetDigest,
        nodeBindingDigest,
      });
      ctx.ledger.appendEvent(runId, "RUN_CREATED", { runMode: input.mode, bbrPhase });
      return ctx.ledger.getRun(created.run_id);
    });
    return {
      data: {
        run_ref: runId,
        run_mode: run.run_mode,
        main_phase: run.main_phase,
        bbr_phase: run.bbr_phase,
        target_set_digest: targetSetDigest,
        node_binding_digest: nodeBindingDigest,
        ledger_digest: run.ledger_digest,
      },
    };
  });
}

function run_status(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "run_status");
  stateGate("run_status", run);
  const plan = ctx.ledger.currentPlan(run.run_id);
  return {
    data: {
      main_phase: run.main_phase,
      bbr_phase: run.bbr_phase,
      ledger_digest: run.ledger_digest,
      plan_ref: plan ? plan.plan_ref : null,
      pending_operation_refs: ctx.ledger.pendingOperationRefs(run.run_id).slice(0, 64),
      stale_evidence_refs: ctx.ledger.staleEvidenceRefs(run.run_id).slice(0, 128),
      next_actions: nextActions(run).slice(0, 16),
    },
  };
}

function nextActions(run) {
  if (run.main_phase === "CLOSED") return [];
  if (run.run_mode === "audit") {
    if (run.main_phase === "NEW") return ["run inventories", "old_line_verify"];
    return ["completion_evaluate", "run_close"];
  }
  if (run.main_phase === "NEW") return ["run inventories"];
  if (run.main_phase === "INVENTORIED") return ["plan_compile"];
  if (run.main_phase === "PLAN_READY") return ["plan_authorize"];
  if (run.main_phase === "APPROVED" || run.main_phase === "APPLYING") {
    return ["execute next approved operation"];
  }
  return ["consult run_status and the contract state matrix"];
}

function evidence_list(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "evidence_list");
  stateGate("evidence_list", run);
  // The public cursor is an opaque runtime ref encoding the last emitted
  // evidence row of the same snapshot filter.
  const afterRef = input.cursor ? input.cursor.replace(/^runtime:/, "evidence:") : null;
  const page = ctx.ledger.listEvidence(run.run_id, afterRef, input.max_items);
  const snapshotDigest = digestOf({
    runId: run.run_id,
    filter: "all",
    lastRow: page.lastRef,
    total: page.total,
  });
  return {
    data: {
      rows: page.rows.map((row) => ({
        evidence_ref: row.evidence_ref,
        masked_summary: row.masked_summary,
      })),
      next_cursor: page.hasMore ? page.lastRef.replace(/^evidence:/, "runtime:") : null,
      continuation_state: page.hasMore ? "has_more" : "terminal",
      requested_max_items: input.max_items,
      returned_item_count: page.rows.length,
      returned_item_count_matches_rows_length: true,
      rows_length_lte_requested_max_items: true,
      cursor_snapshot_binding_digest: snapshotDigest,
      rows_and_next_cursor_bound_to_same_snapshot_filter_and_last_row: true,
    },
  };
}

function completion_evaluate(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "completion_evaluate");
  stateGate("completion_evaluate", run);
  checkExpectedLedgerDigest(run, input);
  return withIdempotency(ctx, run.run_id, "completion_evaluate", input, () => {
    if (run.run_mode === "audit") {
      const satisfied = [];
      for (const [requirementId, evidenceType] of AUDIT_REQUIREMENTS) {
        if (!ctx.ledger.freshEvidence(run.run_id, evidenceType)) {
          throw new ToolError("EVIDENCE_STALE",
            `audit completion requires fresh ${evidenceType} evidence`, { retryable: true });
        }
        satisfied.push(requirementId);
      }
      const reportRef = mintRef("artifact");
      const reportDigest = digestOf({ runId: run.run_id, label: "audit_complete", satisfied });
      ctx.ledger.transaction(() => {
        ctx.ledger.insertReport({
          reportRef, runId: run.run_id, label: "audit_complete", reportDigest,
        });
        ctx.ledger.appendEvent(run.run_id, "COMPLETION_REPORT_SEALED", {
          label: "audit_complete", reportRef,
        });
      });
      return {
        status: "ok",
        data: {
          report_ref: reportRef,
          report_digest: reportDigest,
          label: "audit_complete",
          satisfied_requirement_ids: satisfied,
          all_required_true: true,
          residual_disclosure_ref: null,
        },
      };
    }
    // Configure runs in the Phase 0-1 build cannot reach end_to_end_verified:
    // the verification adapters are phase-gated. The honest fresh label is
    // configured_not_verified, which the contract binds to status=pending.
    const residualRef = ctx.ledger.putEvidence({
      runId: run.run_id,
      evidenceType: "RESIDUAL_DISCLOSURE",
      ttl: "NO_TTL",
      maskedSummary: "configure run not verified: verification adapters are phase-gated in this build",
      payload: { label: "configured_not_verified" },
    });
    ctx.ledger.appendEvent(run.run_id, "COMPLETION_PENDING", { label: "configured_not_verified" });
    return {
      status: "pending",
      data: {
        report_ref: null,
        report_digest: null,
        label: "configured_not_verified",
        satisfied_requirement_ids: [],
        all_required_true: false,
        residual_disclosure_ref: residualRef,
      },
    };
  });
}

const MAIN_CLOSE_ALLOWED = Object.freeze(
  contracts.TOOLS_BY_NAME.run_close.policy.allowedFrom
    .filter((phase) => contracts.TOOLS_BY_NAME.run_status.policy.allowedFrom.includes(phase)),
);
const BBR_CLOSE_ALLOWED = Object.freeze(
  contracts.TOOLS_BY_NAME.run_close.policy.allowedFrom
    .filter((phase) => phase.startsWith("BBR_")),
);

function run_close(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "run_close");
  checkExpectedLedgerDigest(run, input);
  return withIdempotency(ctx, run.run_id, "run_close", input, () => {
    if (input.scope === "bbr") return closeBbr(ctx, run, input);
    return closeMain(ctx, run, input);
  });
}

function closeMain(ctx, run, input) {
  if (!MAIN_CLOSE_ALLOWED.includes(run.main_phase)) {
    throw new ToolError("WRONG_STATE",
      `run_close(main) is not legal from main_phase ${run.main_phase}`);
  }
  let boundLabel = null;
  let boundReportDigest = null;
  let residualRef = null;

  if (run.run_mode === "audit") {
    if (input.outcome !== "audit_complete") {
      throw new ToolError("WRONG_STATE", "an audit run closes only as audit_complete");
    }
    const report = ctx.ledger.latestReport(run.run_id, "audit_complete");
    if (!report) {
      throw new ToolError("WRONG_STATE",
        "audit close requires the sealed audit completion report");
    }
    boundLabel = "audit_complete";
    boundReportDigest = report.report_digest;
  } else {
    if (input.outcome === "accepted") {
      // Main accepted closure needs the sealed end-to-end report plus the
      // authenticated E2E gate, which no Phase 0-1 run can satisfy.
      throw new ToolError("WRONG_STATE",
        "main accepted close requires a sealed end_to_end_verified report; not reachable in this build");
    }
    if (input.outcome === "audit_complete" || input.outcome === "not_requested") {
      throw new ToolError("WRONG_STATE",
        `outcome ${input.outcome} is not legal for a configure main close`);
    }
    if (run.bbr_phase !== "BBR_CLOSED" && run.bbr_phase !== "BBR_NOT_REQUESTED") {
      // Configure-only barrier: every requested BBR branch must close first.
      if (run.enable_bbr) {
        throw new ToolError("WRONG_STATE",
          "configure main close requires the BBR branch to be closed first");
      }
    }
    if (run.bbr_phase === "BBR_NOT_REQUESTED") {
      throw new ToolError("WRONG_STATE",
        "configure main close requires an explicit BBR closed receipt (run_close scope=bbr) first");
    }
    residualRef = ctx.ledger.putEvidence({
      runId: run.run_id,
      evidenceType: "RESIDUAL_DISCLOSURE",
      ttl: "NO_TTL",
      maskedSummary: `main ${input.outcome} close residual disclosure`,
      payload: { outcome: input.outcome, ownedChanges: ctx.ledger.ownershipByRun(run.run_id).length },
    });
  }

  const closureRef = mintRef("closure");
  return ctx.ledger.transaction(() => {
    ctx.ledger.appendEvent(run.run_id, "HOST_CLOSURE_ACKNOWLEDGEMENT", {
      scope: "main",
      outcome: input.outcome,
      recordedBy: "server_host_prompt_boundary",
    });
    const closureDigest = digestOf({
      runId: run.run_id, scope: "main", outcome: input.outcome, boundLabel, boundReportDigest,
    });
    ctx.ledger.setPhases(run.run_id, { mainPhase: "CLOSED" });
    const current = ctx.ledger.getRun(run.run_id);
    ctx.ledger.insertClosure({
      closureRef,
      runId: run.run_id,
      scope: "main",
      outcome: input.outcome,
      closureDigest,
      residualDisclosureRef: residualRef,
      boundCompletionLabel: boundLabel,
      boundCompletionReportDigest: boundReportDigest,
      finalLedgerDigest: current.ledger_digest,
    });
    return {
      data: {
        closure_ref: closureRef,
        scope: "main",
        outcome: input.outcome,
        closure_digest: closureDigest,
        residual_disclosure_ref: residualRef,
        bound_completion_label: boundLabel,
        bound_completion_report_digest: boundReportDigest,
        final_ledger_digest: current.ledger_digest,
      },
    };
  });
}

function closeBbr(ctx, run, input) {
  if (run.run_mode !== "configure") {
    throw new ToolError("WRONG_STATE", "only a configure run closes a BBR branch");
  }
  if (!BBR_CLOSE_ALLOWED.includes(run.bbr_phase)) {
    throw new ToolError("WRONG_STATE",
      `run_close(bbr) is not legal from bbr_phase ${run.bbr_phase}`);
  }
  let outcomeReceipt;
  let residualRef = null;
  if (run.bbr_phase === "BBR_NOT_REQUESTED") {
    if (input.outcome !== "not_requested") {
      throw new ToolError("WRONG_STATE",
        "a not-requested BBR branch closes only as not_requested");
    }
    outcomeReceipt = "BBR_CLOSED_NOT_REQUESTED_RECEIPT";
  } else if (["BBR_PENDING", "BBR_INVENTORIED", "BBR_PLAN_READY", "BBR_HOST_APPROVED"].includes(run.bbr_phase)) {
    if (input.outcome !== "partial") {
      throw new ToolError("WRONG_STATE",
        "a no-write BBR branch closes only as partial (no BBR apply receipt)");
    }
    outcomeReceipt = "BBR_CLOSED_NO_WRITE_RECEIPT";
    residualRef = ctx.ledger.putEvidence({
      runId: run.run_id,
      evidenceType: "RESIDUAL_DISCLOSURE",
      ttl: "NO_TTL",
      maskedSummary: "BBR branch closed with no BBR apply receipt",
      payload: { bbrPhase: run.bbr_phase },
    });
  } else {
    // BBR_VERIFIED / BBR_ROLLED_BACK / BBR_MANUAL_ACTION_REQUIRED closures
    // require Phase 4 receipts that this build cannot produce.
    throw new ToolError("WRONG_STATE",
      `run_close(bbr) from ${run.bbr_phase} requires Phase 4 receipts not present in this build`);
  }
  const closureRef = mintRef("closure");
  return ctx.ledger.transaction(() => {
    ctx.ledger.appendEvent(run.run_id, "HOST_CLOSURE_ACKNOWLEDGEMENT", {
      scope: "bbr",
      outcome: input.outcome,
      receipt: outcomeReceipt,
      recordedBy: "server_host_prompt_boundary",
    });
    const closureDigest = digestOf({
      runId: run.run_id, scope: "bbr", outcome: input.outcome, receipt: outcomeReceipt,
    });
    ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_CLOSED" });
    const receiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef,
      runId: run.run_id,
      objectKind: outcomeReceipt,
      changeRef: mintRef("change"),
      beforeDigest: null,
      afterDigest: closureDigest,
      details: { immutable: true, receipt: outcomeReceipt },
    });
    const current = ctx.ledger.getRun(run.run_id);
    ctx.ledger.insertClosure({
      closureRef,
      runId: run.run_id,
      scope: "bbr",
      outcome: input.outcome,
      closureDigest,
      residualDisclosureRef: residualRef,
      boundCompletionLabel: null,
      boundCompletionReportDigest: null,
      finalLedgerDigest: current.ledger_digest,
    });
    return {
      data: {
        closure_ref: closureRef,
        scope: "bbr",
        outcome: input.outcome,
        closure_digest: closureDigest,
        residual_disclosure_ref: residualRef,
        bound_completion_label: null,
        bound_completion_report_digest: null,
        final_ledger_digest: current.ledger_digest,
      },
    };
  });
}

function reconcile_status(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "reconcile_status");
  stateGate("reconcile_status", run);
  const obligation = ctx.ledger.openReconciliationObligation(run.run_id);
  if (!obligation) {
    throw new ToolError("WRONG_STATE",
      "reconcile_status requires exactly one open reconciliation obligation");
  }
  // Phase 0-1 cannot create reconciliation obligations (no external mutation
  // commits), so resolving one is unreachable; the fixed observers are Phase
  // 2+ adapters and are phase-gated here.
  throw new ToolError("UPSTREAM_UNAVAILABLE",
    "reconciliation observers are phase-gated: no external adapter is active in this build",
    { retryable: false });
}

module.exports = {
  run_begin, run_status, evidence_list, completion_evaluate, run_close, reconcile_status,
};
