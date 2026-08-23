"use strict";

// Shared execution framework for every external mutator plus the two rollback
// executors.
//
// The gate chain, in order, is:
//   configure mode -> governing-column state -> current plan/approval/lease
//   -> exact cursor step -> idempotency -> forward dispatch control
//   (coordinated checkpoint, effective approval expiry, exact no-drift)
//   -> per-tool preflight -> durable intent -> closed adapter dispatch
//   -> readback verification -> commit + ownership receipt.
//
// Every denial before "durable intent" happens with provably zero external
// effect. After dispatch, an unverifiable readback never downgrades into
// success: it raises the resolver's error and leaves an honest state.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const {
  requireRun, auditGate, configureGate, stateGate, checkExpectedLedgerDigest,
  withIdempotency, applySuccessByOrigin,
} = require("./common.cjs");
const { MUTATORS } = require("./mutators.cjs");
const forwardGate = require("../core/forward-gate.cjs");
const rollback = require("../core/rollback.cjs");

const RESOLVER = contracts.PLAN_OPERATION_RESOLVER;
const FAILURE_RESOLVER = contracts.MUTATION_FAILURE_RESOLVER;
const MAIN_ROLLBACK_BBR_GATE = contracts.MAIN_ROLLBACK_BBR_GATE;
const BBR_ROLLBACK_MAIN_GATE = contracts.BBR_ROLLBACK_MAIN_GATE;

// Primary adapter operation per mutating tool, derived from the contract's
// closed helper/broker caller bindings.
function primaryOperationFor(toolName) {
  for (const [name, spec] of Object.entries(contracts.PRIVILEGED_HELPER_OPERATIONS)) {
    if (spec.mutating && spec.callers.includes(toolName)) return { kind: "helper", name };
  }
  for (const [name, spec] of Object.entries(contracts.BROKER_OPERATIONS)) {
    if (spec.callers[0] === toolName) return { kind: "broker", name };
  }
  throw new Error(`no adapter operation bound to mutator ${toolName}`);
}

// Resolves the current plan and its active approval. Deliberately separate
// from the cursor check: an expired lease must revoke forward authority even
// when the caller also named the wrong step, so the expiry resolver runs
// between these two halves rather than after both.
function resolvePlanAndApproval(ctx, run, input) {
  const plan = ctx.ledger.currentPlan(run.run_id);
  if (!plan || plan.plan_ref !== input.plan_ref) {
    throw new ToolError("WRONG_STATE", "plan_ref does not name the current approved plan");
  }
  const approval = ctx.ledger.getApproval(input.approval_ref);
  if (!approval || approval.plan_ref !== plan.plan_ref || approval.status !== "active") {
    throw new ToolError("APPROVAL_REQUIRED",
      "approval_ref does not name the active approval lease for this plan");
  }
  return { plan, approval };
}

function resolveCursorStep(ctx, plan, toolName, input, { requireExplicitOperationRef }) {
  const next = ctx.ledger.cursorNext(plan.plan_ref);
  if (!next || next.tool !== toolName ||
      (requireExplicitOperationRef && next.operation_ref !== input.operation_ref)) {
    throw new ToolError("WRONG_STATE",
      "operation_ref is not the exact current next approved template step");
  }
  return next;
}

function verifyExecutionBinding(ctx, run, toolName, input, options) {
  const { plan, approval } = resolvePlanAndApproval(ctx, run, input);
  const operation = resolveCursorStep(ctx, plan, toolName, input, options);
  return { plan, approval, operation };
}

// HOST_P3 is excluded from the active-cursor write-expiry resolver: an
// expired BBR lease returns the branch to BBR_PLAN_READY for a fresh compile.
function enforceBbrLeaseExpiry(ctx, run, plan, approval) {
  if (Date.parse(approval.expires_at) > ctx.ledger.now()) return;
  ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    ctx.ledger.appendEvent(run.run_id, "HOST_P3_LEASE_EXPIRED_PREDISPATCH", {
      planRef: plan.plan_ref, externalWrite: false,
    });
    ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_PLAN_READY" });
  });
  throw new ToolError("APPROVAL_STALE",
    "BBR approval lease expired before dispatch; recompile and obtain a fresh host prompt");
}

function executeExternalMutation(ctx, toolName, input) {
  const spec = MUTATORS[toolName];
  const run = requireRun(ctx, input.run_id);
  auditGate(run, toolName);
  configureGate(run, toolName);
  // Canonical replay must return the original binding even after the cursor
  // and phase advanced, so idempotency is resolved before the semantic gates.
  return withIdempotency(ctx, run.run_id, toolName, input, () => {
    stateGate(toolName, run);
    checkExpectedLedgerDigest(run, input);
    const { plan, approval } = resolvePlanAndApproval(ctx, run, input);

    // Pre-dispatch control runs before the cursor check: an expired effective
    // approval revokes forward authority regardless of which step the caller
    // named. Nothing below has dispatched yet, so every throw on this path
    // leaves the external world untouched.
    if (plan.lease_class === "HOST_P3") {
      enforceBbrLeaseExpiry(ctx, run, plan, approval);
    } else {
      forwardGate.enforceForwardDispatch(ctx, run, plan, approval, toolName);
    }
    const operation = resolveCursorStep(ctx, plan, toolName, input, {
      requireExplicitOperationRef: true,
    });
    const binding = { plan, approval, operation };
    const preflight = spec.preflight(ctx, run, binding) || {};
    const operationSpec = primaryOperationFor(toolName);

    ctx.ledger.appendEvent(run.run_id, "MUTATION_INTENT_DURABLE", {
      tool: toolName, operationRef: binding.operation.operation_ref,
      adapter: operationSpec.name,
      dispatchRequirement: contracts.PLAN_OPERATION_RESOLVER.forwardApprovalEffectiveExpiry.formula,
    });

    let result;
    try {
      const payload = {
        runId: run.run_id,
        planRef: binding.plan.plan_ref,
        operationRef: binding.operation.operation_ref,
        stepId: binding.operation.step_id,
        binding: run.binding,
        nodeBindingDigest: run.node_binding_digest,
        ...spec.payload(ctx, run, { ...binding, preflight }),
      };
      result = operationSpec.kind === "helper"
        ? ctx.adapters.callHelper(operationSpec.name, toolName, payload)
        : ctx.adapters.callBroker(operationSpec.name, toolName, payload);
    } catch (error) {
      // PRE_DISPATCH row: durable abort, no state change, no cursor advance.
      ctx.ledger.appendEvent(run.run_id, "MUTATION_INTENT_ABORTED_PRE_DISPATCH", {
        tool: toolName, operationRef: binding.operation.operation_ref,
        row: "PRE_DISPATCH", overwriteAllowed: FAILURE_RESOLVER.rows.PRE_DISPATCH.overwriteAllowed,
      });
      throw error;
    }

    // An optional second registered adapter edge (for example the broker
    // that generates and stores the panel administrator credentials after a
    // successful install). It runs outside the local commit transaction and
    // through the same closed registry.
    if (typeof spec.postDispatch === "function") {
      result = spec.postDispatch(ctx, run, result, { ...binding, preflight });
    }

    const policy = contracts.TOOLS_BY_NAME[toolName].policy;
    const changeRef = mintRef("change");
    const receiptRef = mintRef("receipt");
    const observation = result.observation || {};
    const beforeDigest = result.beforeDigest ?? null;
    const afterDigest = result.afterDigest || digestOf(observation);

    return ctx.ledger.transaction(() => {
      ctx.ledger.insertOwnership({
        receiptRef, runId: run.run_id,
        objectKind: `OWNED_${toolName.toUpperCase()}`,
        changeRef, beforeDigest, afterDigest,
        details: {
          sameRunOwned: true,
          operationRef: binding.operation.operation_ref,
          tool: toolName,
        },
      });
      const commons = {
        change_ref: changeRef,
        before_digest: beforeDigest,
        after_digest: afterDigest,
        ownership_receipt_ref: receiptRef,
        rollback_class: policy.rollbackClass,
        inverse_ref: policy.rollbackClass === "exact_inverse" ? mintRef("inverse") : null,
        compensation_ref: policy.rollbackClass === "compensating_action" ? mintRef("compensation") : null,
        committed: true,
      };
      // Readback verification runs inside the same transaction as the
      // ownership commit: a readback that fails to prove an invariant rolls
      // the local commit back and leaves an honest, recoverable state.
      const data = spec.project(ctx, run, result, commons, { ...binding, preflight });
      ctx.ledger.appendEvent(run.run_id, "MUTATION_COMMITTED", {
        tool: toolName, changeRef, receiptRef,
        operationRef: binding.operation.operation_ref,
      });
      ctx.ledger.completeOperation(binding.operation.operation_ref);
      applySuccessByOrigin(ctx, toolName, run);
      return { data };
    });
  });
}

const xui_install = (ctx, input) => executeExternalMutation(ctx, "xui_install", input);
const xui_create_inbound = (ctx, input) => executeExternalMutation(ctx, "xui_create_inbound", input);
const xui_profile_publish = (ctx, input) => executeExternalMutation(ctx, "xui_profile_publish", input);
const certificate_issue_origin_ca = (ctx, input) =>
  executeExternalMutation(ctx, "certificate_issue_origin_ca", input);
const certificate_deploy = (ctx, input) => executeExternalMutation(ctx, "certificate_deploy", input);
const nginx_route_apply = (ctx, input) => executeExternalMutation(ctx, "nginx_route_apply", input);
const cf_node_record_apply = (ctx, input) => executeExternalMutation(ctx, "cf_node_record_apply", input);
const cf_proxy_enable = (ctx, input) => executeExternalMutation(ctx, "cf_proxy_enable", input);
const bbr_apply = (ctx, input) => executeExternalMutation(ctx, "bbr_apply", input);

// --- main rollback executor ----------------------------------------------

// `rollback_run` has no caller operation selector at all: the server resolves
// the sole rb01 step from the exact plan, approval, template, lease, and
// ledger, and the stage selection is the plan's own frozen selection.
function rollback_run(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "rollback_run");
  configureGate(run, "rollback_run");
  return withIdempotency(ctx, run.run_id, "rollback_run", input, () => {
    stateGate("rollback_run", run);
    checkExpectedLedgerDigest(run, input);
    const binding = verifyExecutionBinding(ctx, run, "rollback_run", input, {
      requireExplicitOperationRef: false,
    });
    if (binding.plan.template_id !== "MAIN_ROLLBACK_V1") {
      throw new ToolError("WRONG_STATE",
        "rollback_run may only execute a MAIN_ROLLBACK_V1 template; BBR stages are never carried here");
    }
    // The BBR gate is re-evaluated at every consumer, not just at compile.
    enforceMainRollbackBbrGate(ctx, run);
    const obligation = ctx.ledger.currentRecoveryObligation(run.run_id, "main");
    if (!obligation) {
      throw new ToolError("ROLLBACK_UNSAFE",
        "rollback_run requires a current main recovery obligation");
    }
    if (Date.parse(binding.approval.expires_at) <= ctx.ledger.now()) {
      rollback.resolveMainRollbackLeaseExpiry(ctx, run, binding.plan);
    }

    const selectedStageIds = ctx.ledger.getScalar(run.run_id, `stages:${binding.plan.plan_ref}`);
    if (!Array.isArray(selectedStageIds) || selectedStageIds.length === 0) {
      throw new ToolError("ROLLBACK_UNSAFE", "the approved plan carries no atomic stage selection");
    }
    // A completed stage is never replayed: the plan's selection must be
    // exactly the remaining suffix given the durable prefix already proven.
    const prefix = rollback.provenPrefix(ctx, run.run_id, rollback.MAIN_FAMILY, rollback.MAIN_STAGE_IDS);
    if (prefix.kind === "NON_CONTIGUOUS") {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        "durable stage receipts are not a contiguous prefix of the frozen stage order");
    }
    const replayed = selectedStageIds.filter((id) =>
      ctx.ledger.stageReceiptIds(run.run_id, rollback.MAIN_FAMILY).includes(id));
    if (replayed.length > 0) {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        `refusing to replay completed stages: ${replayed.join(", ")}`.slice(0, 200));
    }

    const outcome = rollback.executeMainStages(ctx, run, binding.plan, binding.operation, selectedStageIds);
    return ctx.ledger.transaction(() => {
      ctx.ledger.completeOperation(binding.operation.operation_ref);
      ctx.ledger.consumeRecoveryObligation(obligation.obligation_ref);
      applySuccessByOrigin(ctx, "rollback_run", run);
      const residualRef = outcome.retainedPairs.length > 0 ? mintRef("evidence") : null;
      if (residualRef) {
        ctx.ledger.insertResidual({
          residualRef, runId: run.run_id, kind: "MAIN_ROLLBACK_RETAINED_COMPENSATION_SET",
          maskedSummary: `${outcome.retainedPairs.length} retained compensation pair(s) could not be erased`,
          bindingDigest: digestOf(outcome.retainedPairs),
        });
      }
      return {
        data: {
          rollback_receipt_ref: outcome.aggregateRef,
          reversed_change_refs: outcome.reversedChangeRefs,
          completed_atomic_stage_ids: selectedStageIds,
          atomic_stage_receipt_refs: outcome.stageReceiptRefs,
          atomic_stage_and_receipt_cardinality_equal: true,
          atomic_stage_set_exactly_equals_frozen_plan_selection: true,
          final_atomic_stage_id: outcome.finalStageId,
          final_atomic_stage_receipt_ref: outcome.finalStageReceiptRef,
          final_atomic_stage_is_last_selected_stage: true,
          final_atomic_stage_receipt_is_last_ordered_stage_receipt: true,
          final_stage_and_aggregate_receipt_same_local_ledger_transaction: true,
          finalization_receipts_both_visible: true,
          aggregate_receipt_binds_exact_selected_atomic_stage_receipts: true,
          finalization_transaction_commit_digest: outcome.commitDigest,
          aggregate_atomic_stage_receipts_complete: true,
          retained_compensation_pairs: outcome.retainedPairs.map((pair) => ({
            change_ref: pair.changeRef,
            compensation_receipt_ref: pair.compensationReceiptRef,
          })),
          retained_set_binding_digest: residualRef ? digestOf(outcome.retainedPairs) : null,
          residual_binds_exact_retained_set: true,
          inverse_readbacks_all_true: true,
          retained_compensation_residual_ref: residualRef,
          final_digest: outcome.finalDigest,
        },
      };
    });
  });
}

// The main rollback may not run while a committed or unknown BBR change is
// still raw: the dedicated BBR inverse comes first, or the branch closes.
function enforceMainRollbackBbrGate(ctx, run) {
  const gate = MAIN_ROLLBACK_BBR_GATE;
  if (gate.deniedRawStates.includes(run.bbr_phase)) {
    throw new ToolError("WRONG_STATE",
      `main rollback is denied while the BBR branch is raw ${run.bbr_phase}; complete the dedicated BBR rollback or close the branch first`);
  }
  if (run.bbr_phase === "BBR_MANUAL_ACTION_REQUIRED") {
    const applyReceipt = ctx.ledger.getScalar(run.run_id, "bbr_apply_receipt_ref");
    if (applyReceipt) {
      throw new ToolError("WRONG_STATE",
        "main rollback is denied: a committed BBR apply receipt exists and must be resolved by the dedicated BBR path");
    }
  }
  if (gate.allowedRawProvenNoWrite.states.includes(run.bbr_phase)) {
    if (ctx.ledger.getScalar(run.run_id, "bbr_apply_receipt_ref")) {
      throw new ToolError("WRONG_STATE",
        "a BBR apply receipt exists; the raw no-write allowance does not apply");
    }
  }
}

// --- BBR rollback executor -----------------------------------------------

function bbr_rollback(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "bbr_rollback");
  configureGate(run, "bbr_rollback");
  return withIdempotency(ctx, run.run_id, "bbr_rollback", input, () => {
    stateGate("bbr_rollback", run);
    checkExpectedLedgerDigest(run, input);
    const binding = verifyExecutionBinding(ctx, run, "bbr_rollback", input, {
      requireExplicitOperationRef: true,
    });
    if (binding.plan.template_id !== "BBR_ROLLBACK_V1") {
      throw new ToolError("WRONG_STATE",
        "bbr_rollback may only execute a BBR_ROLLBACK_V1 template; main stages are never carried here");
    }
    // The BBR inverse only runs while the main line is delivered but unsealed.
    if (run.main_phase !== BBR_ROLLBACK_MAIN_GATE.requiredMainPhase) {
      throw new ToolError("WRONG_STATE",
        `BBR rollback requires main_phase ${BBR_ROLLBACK_MAIN_GATE.requiredMainPhase}, observed ${run.main_phase}`);
    }
    if (ctx.ledger.latestReport(run.run_id, "end_to_end_verified")) {
      throw new ToolError("WRONG_STATE",
        "BBR rollback is denied after the main completion report is sealed");
    }
    if (Date.parse(binding.approval.expires_at) <= ctx.ledger.now()) {
      rollback.resolveBbrRollbackLeaseExpiry(ctx, run, binding.plan);
    }

    const selectedStageIds = ctx.ledger.getScalar(run.run_id, `bbr_stages:${binding.plan.plan_ref}`);
    if (!Array.isArray(selectedStageIds) || selectedStageIds.length === 0) {
      throw new ToolError("ROLLBACK_UNSAFE", "the approved plan carries no BBR stage selection");
    }
    const prefix = rollback.provenPrefix(ctx, run.run_id, rollback.BBR_FAMILY, rollback.BBR_STAGE_IDS);
    if (prefix.kind === "NON_CONTIGUOUS") {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        "durable BBR stage receipts are not a contiguous prefix of the frozen stage order");
    }
    const replayed = selectedStageIds.filter((id) =>
      ctx.ledger.stageReceiptIds(run.run_id, rollback.BBR_FAMILY).includes(id));
    if (replayed.length > 0) {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        `refusing to replay completed BBR stages: ${replayed.join(", ")}`.slice(0, 200));
    }

    const outcome = rollback.executeBbrStages(ctx, run, binding.plan, binding.operation, selectedStageIds);
    return ctx.ledger.transaction(() => {
      ctx.ledger.completeOperation(binding.operation.operation_ref);
      for (const episode of ctx.ledger.currentBbrSourceEpisodes(run.run_id)) {
        ctx.ledger.consumeBbrSourceEpisode(episode.episode_ref, "consumed");
      }
      // The BBR change invalidated the authenticated E2E evidence; the
      // template's remaining steps refresh it before the branch closes.
      for (const family of ["AUTHENTICATED_PROXY_REQUEST", "LOG_CORRELATION", "PROTECTED_LINE_HEALTH"]) {
        ctx.ledger.invalidateEvidenceFamily(run.run_id, family);
      }
      applySuccessByOrigin(ctx, "bbr_rollback", run);
      return {
        data: {
          rollback_receipt_ref: outcome.aggregateRef,
          bbr_change_ref: ctx.ledger.getScalar(run.run_id, "bbr_change_ref"),
          selected_bbr_stage_ids: selectedStageIds,
          bbr_stage_receipt_refs: outcome.stageReceiptRefs,
          bbr_stage_selection_digest: rollback.selectionDigest(selectedStageIds),
          selected_stage_and_receipt_cardinality_equal: true,
          selected_stages_are_full_or_exact_remaining_ordered_suffix: true,
          each_stage_receipt_committed_after_exact_readback_before_next_stage: true,
          aggregate_receipt_binds_exact_selected_stage_ids_and_receipts: true,
          final_bbr_stage_id: outcome.finalStageId,
          final_bbr_stage_receipt_ref: outcome.finalStageReceiptRef,
          final_bbr_stage_receipt_is_last_selected_receipt: true,
          final_bbr_stage_and_aggregate_receipt_same_local_ledger_transaction: true,
          finalization_receipts_both_visible: true,
          finalization_transaction_commit_digest: outcome.commitDigest,
          owned_dropin_removed: true,
          prior_live_values_restored: true,
          prior_persistent_values_restored: true,
          prior_values_digest: outcome.priorValuesDigest,
          inverse_readback_matches_recorded_prior: true,
          final_digest: outcome.finalDigest,
        },
      };
    });
  });
}

module.exports = {
  xui_install, xui_create_inbound, xui_profile_publish,
  certificate_issue_origin_ca, certificate_deploy, nginx_route_apply,
  cf_node_record_apply, cf_proxy_enable, bbr_apply,
  rollback_run, bbr_rollback,
  primaryOperationFor, verifyExecutionBinding, resolvePlanAndApproval,
  resolveCursorStep,
};
