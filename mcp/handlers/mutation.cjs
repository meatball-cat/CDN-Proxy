"use strict";

// Shared execution framework for every external mutator plus the two rollback
// executors. The gate chain is: configure mode -> governing-column state ->
// current plan/approval/lease -> exact cursor step -> idempotency -> durable
// intent -> closed adapter dispatch -> commit + ownership receipt.
//
// In the Phase 0-1 build every production adapter operation is phase-gated,
// so an external mutation can only succeed against injected test fakes; a
// missing fake fails closed before dispatch with no state change.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const {
  requireRun, auditGate, configureGate, stateGate, checkExpectedLedgerDigest,
  withIdempotency, applySuccessByOrigin,
} = require("./common.cjs");

// Primary adapter operation per mutating tool, derived from the contract's
// closed helper/broker caller bindings (no hand-written second map beyond the
// primary-operation choice, which the contract binds via callers).
function primaryOperationFor(toolName) {
  for (const [name, spec] of Object.entries(contracts.PRIVILEGED_HELPER_OPERATIONS)) {
    if (spec.mutating && spec.callers.includes(toolName)) {
      return { kind: "helper", name };
    }
  }
  for (const [name, spec] of Object.entries(contracts.BROKER_OPERATIONS)) {
    if (spec.callers[0] === toolName) {
      return { kind: "broker", name };
    }
  }
  throw new Error(`no adapter operation bound to mutator ${toolName}`);
}

function verifyExecutionBinding(ctx, run, toolName, input, { requireExplicitOperationRef }) {
  const plan = ctx.ledger.currentPlan(run.run_id);
  if (!plan || plan.plan_ref !== input.plan_ref) {
    throw new ToolError("WRONG_STATE", "plan_ref does not name the current approved plan");
  }
  const approval = ctx.ledger.getApproval(input.approval_ref);
  if (!approval || approval.plan_ref !== plan.plan_ref || approval.status !== "active") {
    throw new ToolError("APPROVAL_REQUIRED",
      "approval_ref does not name the active approval lease for this plan");
  }
  if (Date.parse(approval.expires_at) <= ctx.ledger.now()) {
    // Active-cursor write expiry with zero committed changes: revoke every
    // old plan/cursor/approval ref and return to INVENTORIED; forward
    // execution never resumes. (Owned-commit and unknown branches are Phase
    // 3-4 scope and unreachable here because no external commit can exist.)
    const committed = ctx.ledger.ownershipByRun(run.run_id)
      .filter((row) => row.object_kind.startsWith("OWNED_")).length;
    if (committed === 0) {
      ctx.ledger.transaction(() => {
        ctx.ledger.invalidateCurrentPlan(run.run_id);
        ctx.ledger.appendEvent(run.run_id, "ACTIVE_CURSOR_WRITE_EXPIRY_ZERO_COMMIT", {
          planRef: plan.plan_ref, approvalRef: approval.approval_ref,
        });
        if (plan.scope === "host_p3") {
          ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_PLAN_READY" });
        } else {
          ctx.ledger.setPhases(run.run_id, { mainPhase: "INVENTORIED" });
        }
      });
    }
    throw new ToolError("APPROVAL_STALE",
      "approval lease expired before dispatch; old authority revoked, recompile a fresh plan");
  }
  const next = ctx.ledger.cursorNext(plan.plan_ref);
  if (!next || next.tool !== toolName ||
      (requireExplicitOperationRef && next.operation_ref !== input.operation_ref)) {
    throw new ToolError("WRONG_STATE",
      "operation_ref is not the exact current next approved template step");
  }
  return { plan, approval, operation: next };
}

function executeExternalMutation(ctx, toolName, input, projectData) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, toolName);
  configureGate(run, toolName);
  // Canonical replay must return the original result binding even after the
  // cursor and phase have advanced, so the idempotency check runs before the
  // semantic gates.
  return withIdempotency(ctx, run.run_id, toolName, input, () => {
    stateGate(toolName, run);
    checkExpectedLedgerDigest(run, input);
    const binding = verifyExecutionBinding(ctx, run, toolName, input, {
      requireExplicitOperationRef: true,
    });
    const operationSpec = primaryOperationFor(toolName);
    ctx.ledger.appendEvent(run.run_id, "MUTATION_INTENT_DURABLE", {
      tool: toolName, operationRef: binding.operation.operation_ref,
      adapter: operationSpec.name,
    });
    let result;
    try {
      const payload = {
        runId: run.run_id,
        planRef: binding.plan.plan_ref,
        operationRef: binding.operation.operation_ref,
        stepId: binding.operation.step_id,
        binding: run.binding,
      };
      result = operationSpec.kind === "helper"
        ? ctx.adapters.callHelper(operationSpec.name, toolName, payload)
        : ctx.adapters.callBroker(operationSpec.name, toolName, payload);
    } catch (error) {
      // Failure before any observable dispatch: durable abort, no state
      // change, no cursor advance (MUTATION_FAILURE_RESOLVER PRE_DISPATCH).
      ctx.ledger.appendEvent(run.run_id, "MUTATION_INTENT_ABORTED_PRE_DISPATCH", {
        tool: toolName, operationRef: binding.operation.operation_ref,
      });
      throw error;
    }

    const policy = contracts.TOOLS_BY_NAME[toolName].policy;
    const changeRef = mintRef("change");
    const receiptRef = mintRef("receipt");
    const observation = result.observation || {};
    const beforeDigest = result.beforeDigest ?? null;
    const afterDigest = result.afterDigest || digestOf(observation);
    return ctx.ledger.transaction(() => {
      ctx.ledger.insertOwnership({
        receiptRef,
        runId: run.run_id,
        objectKind: `OWNED_${toolName.toUpperCase()}`,
        changeRef,
        beforeDigest,
        afterDigest,
        details: { operationRef: binding.operation.operation_ref, tool: toolName },
      });
      ctx.ledger.appendEvent(run.run_id, "MUTATION_COMMITTED", {
        tool: toolName, changeRef, receiptRef,
        operationRef: binding.operation.operation_ref,
      });
      ctx.ledger.completeOperation(binding.operation.operation_ref);
      applySuccessByOrigin(ctx, toolName, run);
      const mutationCommons = {
        change_ref: changeRef,
        before_digest: beforeDigest,
        after_digest: afterDigest,
        ownership_receipt_ref: receiptRef,
        rollback_class: policy.rollbackClass,
        inverse_ref: policy.rollbackClass === "exact_inverse" ? mintRef("inverse") : null,
        compensation_ref: policy.rollbackClass === "compensating_action" ? mintRef("compensation") : null,
        committed: true,
      };
      return { data: projectData(ctx, run, observation, mutationCommons, binding) };
    });
  });
}

const passThroughProjector = (ctx, run, observation, commons) => ({
  ...commons,
  ...observation,
});

const xui_install = (ctx, input) =>
  executeExternalMutation(ctx, "xui_install", input, passThroughProjector);
const xui_create_inbound = (ctx, input) =>
  executeExternalMutation(ctx, "xui_create_inbound", input, passThroughProjector);
const xui_profile_publish = (ctx, input) =>
  executeExternalMutation(ctx, "xui_profile_publish", input, passThroughProjector);
const certificate_issue_origin_ca = (ctx, input) =>
  executeExternalMutation(ctx, "certificate_issue_origin_ca", input, passThroughProjector);
const certificate_deploy = (ctx, input) =>
  executeExternalMutation(ctx, "certificate_deploy", input, passThroughProjector);
const nginx_route_apply = (ctx, input) =>
  executeExternalMutation(ctx, "nginx_route_apply", input, passThroughProjector);
const cf_node_record_apply = (ctx, input) =>
  executeExternalMutation(ctx, "cf_node_record_apply", input, passThroughProjector);
const cf_proxy_enable = (ctx, input) =>
  executeExternalMutation(ctx, "cf_proxy_enable", input, passThroughProjector);
const bbr_apply = (ctx, input) =>
  executeExternalMutation(ctx, "bbr_apply", input, passThroughProjector);

// Rollback executors: the full gate chain applies, but no Phase 0-1 run can
// legally reach ROLLING_BACK / BBR_ROLLING_BACK (no external commit exists),
// so the state gate fails closed first. If a future state ever reached the
// executor body, the phase-gated adapter would still fail before dispatch.
function rollback_run(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "rollback_run");
  configureGate(run, "rollback_run");
  stateGate("rollback_run", run);
  checkExpectedLedgerDigest(run, input);
  verifyExecutionBinding(ctx, run, "rollback_run", input, {
    requireExplicitOperationRef: false,
  });
  throw new ToolError("ROLLBACK_UNSAFE",
    "main rollback execution requires Phase 4 atomic-stage executors not present in this build");
}

function bbr_rollback(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "bbr_rollback");
  configureGate(run, "bbr_rollback");
  stateGate("bbr_rollback", run);
  checkExpectedLedgerDigest(run, input);
  verifyExecutionBinding(ctx, run, "bbr_rollback", input, {
    requireExplicitOperationRef: true,
  });
  throw new ToolError("ROLLBACK_UNSAFE",
    "BBR rollback execution requires Phase 4 stage executors not present in this build");
}

module.exports = {
  xui_install, xui_create_inbound, xui_profile_publish,
  certificate_issue_origin_ca, certificate_deploy, nginx_route_apply,
  cf_node_record_apply, cf_proxy_enable, bbr_apply,
  rollback_run, bbr_rollback,
};
