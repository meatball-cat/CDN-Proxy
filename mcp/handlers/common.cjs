"use strict";

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { digestOf } = require("../core/refs.cjs");
const { parseIsoDurationSeconds } = require("../ledger/ledger.cjs");

const AUDIT_ALLOWED_TOOLS = contracts.RUN_MODE_POLICY.audit.allowedTools;

function requireRun(ctx, runId) {
  const run = ctx.ledger.getRun(runId);
  if (!run) {
    throw new ToolError("UNAUTHORIZED_TARGET", "run_id does not name a registered run");
  }
  return run;
}

// Audit runs may only reach the contract's audit tool allowlist. This is
// derived from RUN_MODE_POLICY, never from a hand-written second list.
function auditGate(run, toolName) {
  if (run.run_mode === "audit" && !AUDIT_ALLOWED_TOOLS.includes(toolName)) {
    throw new ToolError("WRONG_STATE",
      `tool ${toolName} is not reachable from an audit run`);
  }
}

function configureGate(run, toolName) {
  if (run.run_mode !== "configure") {
    throw new ToolError("WRONG_STATE",
      `tool ${toolName} requires run_mode=configure from the immutable ledger`);
  }
}

// Governing-column state gate derived from the frozen tool policy.
function stateGate(toolName, run) {
  const policy = contracts.TOOLS_BY_NAME[toolName].policy;
  const column = policy.governingColumn;
  if (column === "none") return;
  if (column === "main") {
    if (!policy.allowedFrom.includes(run.main_phase)) {
      throw new ToolError("WRONG_STATE",
        `${toolName} is not legal from main_phase ${run.main_phase}`);
    }
    return;
  }
  if (column === "bbr") {
    if (!policy.allowedFrom.includes(run.bbr_phase)) {
      throw new ToolError("WRONG_STATE",
        `${toolName} is not legal from bbr_phase ${run.bbr_phase}`);
    }
    return;
  }
  if (column === "server_resolved_manual_column") {
    if (!policy.allowedFrom.includes(run.main_phase) &&
        !policy.allowedFrom.includes(run.bbr_phase)) {
      throw new ToolError("WRONG_STATE",
        `${toolName} requires an open manual-action state`);
    }
    return;
  }
  // scope_resolver columns resolve state inside the handler using the
  // caller-declared scope; nothing to do here.
}

function checkExpectedLedgerDigest(run, input) {
  if (Object.prototype.hasOwnProperty.call(input, "expected_ledger_digest") &&
      input.expected_ledger_digest !== run.ledger_digest) {
    throw new ToolError("BASELINE_DRIFT",
      "expected_ledger_digest does not match the current run ledger digest");
  }
}

// Canonical replay: the exact same idempotency key with the byte-equivalent
// input returns the original result binding as no_op; a different input under
// the same key is IDEMPOTENCY_CONFLICT.
function withIdempotency(ctx, runScope, toolName, input, execute) {
  const key = input.idempotency_key;
  const inputDigest = digestOf(input);
  const cached = ctx.ledger.findIdempotent(runScope, toolName, key);
  if (cached) {
    if (cached.inputDigest !== inputDigest) {
      throw new ToolError("IDEMPOTENCY_CONFLICT",
        "idempotency_key was already used with a different input");
    }
    return { status: "no_op", data: cached.result.data };
  }
  const result = execute();
  ctx.ledger.saveIdempotent(runScope, toolName, key, inputDigest, {
    status: result.status || "ok",
    data: result.data,
  });
  return result;
}

// Applies the frozen successByOrigin matrix for a governing column.
function applySuccessByOrigin(ctx, toolName, run) {
  const policy = contracts.TOOLS_BY_NAME[toolName].policy;
  const column = policy.governingColumn;
  const origin = column === "bbr" ? run.bbr_phase : run.main_phase;
  const destination = policy.successByOrigin[origin];
  if (!destination || destination === "UNCHANGED" || destination.startsWith("DELEGATE_")) {
    return;
  }
  if (column === "bbr") {
    ctx.ledger.setPhases(run.run_id, { bbrPhase: destination });
  } else {
    ctx.ledger.setPhases(run.run_id, { mainPhase: destination });
  }
}

function evidenceTtlSeconds(ttlKey) {
  return parseIsoDurationSeconds(contracts.EVIDENCE_TTLS[ttlKey]);
}

const PLANNED_READ_PROBE_TOOLS =
  contracts.PLAN_OPERATION_RESOLVER.cursorEnforcement.plannedReadProbeTools;

// Planned read probes advance the cursor only when the tool matches the exact
// current next approved template step; an off-cursor call is a refresh and
// never advances anything.
function advanceReadProbeCursorIfPlanned(ctx, run, toolName) {
  if (!PLANNED_READ_PROBE_TOOLS.includes(toolName)) return;
  if (run.run_mode !== "configure") return;
  const plan = ctx.ledger.currentPlan(run.run_id);
  if (!plan) return;
  const next = ctx.ledger.cursorNext(plan.plan_ref);
  if (next && next.tool === toolName) {
    ctx.ledger.completeOperation(next.operation_ref);
    ctx.ledger.appendEvent(run.run_id, "READ_PROBE_CURSOR_ADVANCE", {
      operationRef: next.operation_ref, tool: toolName,
    });
  }
}

module.exports = {
  AUDIT_ALLOWED_TOOLS,
  requireRun,
  auditGate,
  configureGate,
  stateGate,
  checkExpectedLedgerDigest,
  withIdempotency,
  applySuccessByOrigin,
  evidenceTtlSeconds,
  advanceReadProbeCursorIfPlanned,
};
