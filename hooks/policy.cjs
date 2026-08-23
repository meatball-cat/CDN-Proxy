"use strict";

const { activeToolFromHookName } = require("./catalog.cjs");
const { hasSensitiveInput, hasOutputLeak } = require("./redaction.cjs");
const { getValidators } = require("../mcp/core/validation.cjs");
const { digestOf } = require("../mcp/core/refs.cjs");
const { withSessionState, readSessionState, cleanupSessionState } = require("./state.cjs");
const contracts = require("../contract/mcp/schemas/contracts.cjs");

const fixed = Object.freeze({
  sessionReady: Object.freeze({ continue: true, systemMessage: "HOOK_READY_HERMETIC_SOURCE_ONLY" }),
  sessionEnd: Object.freeze({ continue: true, systemMessage: "HOOK_SESSION_ENDED_LOCAL_RECORDS_CLEANED" }),
  preChecked: Object.freeze({
    hookSpecificOutput: Object.freeze({
      hookEventName: "PreToolUse",
      additionalContext: "HOOK_POLICY_CHECKED_SERVER_REMAINS_AUTHORITY",
    }),
  }),
  permissionPrompt: Object.freeze({
    continue: true,
    systemMessage: "HOOK_PROMPT_CONSISTENT_HOST_DECISION_REQUIRED",
  }),
  postChecked: Object.freeze({ continue: true, systemMessage: "HOOK_OUTPUT_REDACTION_CHECKED" }),
  stopInsufficient: Object.freeze({ continue: true, systemMessage: "HOOK_STOP_INSUFFICIENT_EVIDENCE" }),
  stopRecursive: Object.freeze({ continue: true, systemMessage: "HOOK_STOP_RECURSION_SAFE" }),
});

function preDeny(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

function permissionDeny(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: "PermissionRequest",
      decision: { behavior: "deny", message: reason },
    },
  };
}

function postBlock(reason) {
  return { continue: false, decision: "block", reason };
}

function toolCheck(input) {
  const tool = activeToolFromHookName(input.tool_name);
  if (!tool) return { denied: "HOOK_DENY_NOT_ACTIVE_CATALOG" };
  if (hasSensitiveInput(input.tool_input)) return { denied: "HOOK_DENY_SENSITIVE_INPUT" };
  const validator = getValidators().get(tool);
  if (!validator || !validator.input(input.tool_input)) return { denied: "HOOK_DENY_MALFORMED_INPUT" };
  return { tool };
}

function eventDigest(event, input) {
  return digestOf({
    event,
    turn_id: input.turn_id || null,
    tool_use_id: input.tool_use_id || null,
    tool_name: input.tool_name || null,
    input: input.tool_input || null,
  });
}

function planProjection(response) {
  const body = response && response.structuredContent;
  const data = body && body.data;
  if (!data || typeof data !== "object") return null;
  const keys = ["plan_ref", "approval_challenge_ref", "impact_digest"];
  if (!keys.every((key) => typeof data[key] === "string")) return null;
  return {
    plan_ref: data.plan_ref,
    approval_challenge_ref: data.approval_challenge_ref,
    impact_digest: data.impact_digest,
  };
}

function projectServerFacts(tool, body, previous) {
  const data = body.data;
  const projection = previous || {
    main_phase: null,
    bbr_phase: null,
    ledger_digest: null,
    completion_label: null,
    completion_all_required_true: false,
    main_closure_outcome: null,
    bbr_closure_outcome: null,
    reconciliation_next_action: null,
  };
  if (tool === "run_status") {
    projection.main_phase = data.main_phase;
    projection.bbr_phase = data.bbr_phase;
    projection.ledger_digest = data.ledger_digest;
  } else if (tool === "completion_evaluate") {
    projection.completion_label = data.label;
    projection.completion_all_required_true = data.all_required_true;
  } else if (tool === "run_close") {
    if (data.scope === "main") projection.main_closure_outcome = data.outcome;
    if (data.scope === "bbr") projection.bbr_closure_outcome = data.outcome;
    projection.ledger_digest = data.final_ledger_digest;
  } else if (tool === "reconcile_status") {
    projection.reconciliation_next_action = data.next_action;
  }
  return projection;
}

function closePromptMatches(args, projection) {
  if (!projection || projection.ledger_digest !== args.expected_ledger_digest) return false;
  const phase = args.scope === "main" ? projection.main_phase : projection.bbr_phase;
  const closeMatrix = contracts.TOOLS.run_close.policy.controls.closeMatrix[args.scope];
  if (!phase || !closeMatrix[phase] || !closeMatrix[phase].includes(args.outcome)) return false;
  if (args.scope === "main" && args.outcome === "accepted") {
    return projection.completion_label === "end_to_end_verified" &&
      projection.completion_all_required_true === true;
  }
  if (args.scope === "main" && args.outcome === "audit_complete") {
    return projection.completion_label === "audit_complete" &&
      projection.completion_all_required_true === true;
  }
  return true;
}

function stopProjection(record) {
  const projection = record.server_projection;
  if (!projection) return fixed.stopInsufficient;
  if (projection.main_closure_outcome === "accepted") {
    return { continue: true, systemMessage: "HOOK_STOP_MAIN_ACCEPTED_SERVER_CLOSED" };
  }
  if (projection.main_closure_outcome === "audit_complete") {
    return { continue: true, systemMessage: "HOOK_STOP_AUDIT_COMPLETE_SERVER_CLOSED" };
  }
  if (projection.main_closure_outcome) {
    return { continue: true, systemMessage: "HOOK_STOP_MAIN_CLOSED_WITH_RESIDUAL" };
  }
  if (projection.reconciliation_next_action) {
    return {
      continue: true,
      systemMessage: `HOOK_STOP_RECONCILIATION_REQUIRED_${projection.reconciliation_next_action}`,
    };
  }
  if (projection.completion_label === "end_to_end_verified" &&
      projection.completion_all_required_true === true) {
    return { continue: true, systemMessage: "HOOK_STOP_E2E_VERIFIED_AWAITING_HOST_CLOSE" };
  }
  if (projection.completion_label === "audit_complete" &&
      projection.completion_all_required_true === true) {
    return { continue: true, systemMessage: "HOOK_STOP_AUDIT_COMPLETE_AWAITING_HOST_CLOSE" };
  }
  if (projection.completion_label === "configured_not_verified") {
    return { continue: true, systemMessage: "HOOK_STOP_CONFIGURED_NOT_VERIFIED" };
  }
  if (projection.main_phase && projection.bbr_phase) {
    return {
      continue: true,
      systemMessage: `HOOK_STOP_SERVER_STATE_${projection.main_phase}_${projection.bbr_phase}`,
    };
  }
  return fixed.stopInsufficient;
}

function evaluateHook(event, input, env) {
  const digest = eventDigest(event, input);
  if (event === "SessionStart") {
    withSessionState(env, input.session_id, digest, (record) => record);
    return fixed.sessionReady;
  }
  if (event === "SessionEnd") {
    cleanupSessionState(env, input.session_id);
    return fixed.sessionEnd;
  }
  if (event === "Stop") {
    if (input.stop_hook_active === true) return fixed.stopRecursive;
    return stopProjection(readSessionState(env, input.session_id));
  }

  const checked = toolCheck(input);
  if (event === "PreToolUse") {
    if (checked.denied) return preDeny(checked.denied);
    withSessionState(env, input.session_id, digest, (record) => record);
    return fixed.preChecked;
  }
  if (event === "PermissionRequest") {
    if (checked.denied) return permissionDeny(checked.denied);
    const record = readSessionState(env, input.session_id);
    if (checked.tool === "run_close") {
      if (!closePromptMatches(input.tool_input, record.server_projection)) {
        return permissionDeny("HOOK_DENY_PROMPT_MISMATCH");
      }
      withSessionState(env, input.session_id, digest, (current) => current);
      return fixed.permissionPrompt;
    }
    if (checked.tool !== "plan_authorize") return permissionDeny("HOOK_DENY_NO_APPROVAL_ROUTE");
    const projection = record.plan_projection;
    const args = input.tool_input;
    const matches = projection &&
      projection.plan_ref === args.plan_ref &&
      projection.approval_challenge_ref === args.approval_challenge_ref &&
      projection.impact_digest === args.displayed_impact_digest;
    if (!matches) return permissionDeny("HOOK_DENY_PROMPT_MISMATCH");
    withSessionState(env, input.session_id, digest, (record) => record);
    return fixed.permissionPrompt;
  }
  if (event === "PostToolUse") {
    if (checked.denied) return postBlock(checked.denied);
    if (hasOutputLeak(input.tool_response)) return postBlock("HOOK_REDACTION_TRIPWIRE");
    const body = input.tool_response.structuredContent;
    const outputValidator = getValidators().get(checked.tool).output;
    if (!body || !outputValidator(body)) return postBlock("HOOK_DENY_MALFORMED_OUTPUT");
    withSessionState(env, input.session_id, digest, (record) => {
      if (checked.tool === "plan_compile") {
        const projection = planProjection(input.tool_response);
        if (projection) record.plan_projection = projection;
      }
      if (body.data) {
        record.server_projection = projectServerFacts(
          checked.tool,
          body,
          record.server_projection,
        );
      }
      return record;
    });
    return fixed.postChecked;
  }
  return { continue: true, systemMessage: "HOOK_UNAVAILABLE" };
}

module.exports = { evaluateHook, preDeny, permissionDeny, postBlock };
