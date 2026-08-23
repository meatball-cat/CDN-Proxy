"use strict";

// Closed adapter registry. The only legal helper/broker operation names are
// the ones frozen in the contract (PRIVILEGED_HELPER_OPERATIONS and
// BROKER_OPERATIONS). There is no dynamic module loading, no shell surface,
// no caller-supplied path/URL/script, and no runtime download anywhere in
// this registry. Production operations in the Phase 0-1 build are
// phase-gated stubs: they perform no I/O and fail closed before dispatch.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");

const HELPER_OPERATION_NAMES = Object.freeze(Object.keys(contracts.PRIVILEGED_HELPER_OPERATIONS));
const BROKER_OPERATION_NAMES = Object.freeze(Object.keys(contracts.BROKER_OPERATIONS));

const MUTATING_HELPER_NAMES = Object.freeze(
  HELPER_OPERATION_NAMES.filter((name) => contracts.PRIVILEGED_HELPER_OPERATIONS[name].mutating),
);

function phaseGatedStub(kind, name) {
  return () => {
    throw new ToolError(
      "UPSTREAM_UNAVAILABLE",
      `${kind} operation ${name} is phase-gated: no external adapter is active in the Phase 0-1 build`,
      { retryable: false },
    );
  };
}

function buildProductionAdapters() {
  const helpers = {};
  for (const name of HELPER_OPERATION_NAMES) helpers[name] = phaseGatedStub("helper", name);
  const broker = {};
  for (const name of BROKER_OPERATION_NAMES) broker[name] = phaseGatedStub("broker", name);
  return Object.freeze({ helpers: Object.freeze(helpers), broker: Object.freeze(broker) });
}

// Wraps an injected adapter set (production stubs or test fakes) into the
// closed registry surface. Unknown operation names are rejected at
// construction; callers are checked against the contract's caller binding at
// every invocation; mutating helper invocations are counted.
class AdapterRegistry {
  constructor(adapters = buildProductionAdapters()) {
    for (const name of Object.keys(adapters.helpers || {})) {
      if (!HELPER_OPERATION_NAMES.includes(name)) {
        throw new Error(`unknown helper operation injected: ${name}`);
      }
    }
    for (const name of Object.keys(adapters.broker || {})) {
      if (!BROKER_OPERATION_NAMES.includes(name)) {
        throw new Error(`unknown broker operation injected: ${name}`);
      }
    }
    this.adapters = adapters;
    this.mutationCalls = [];
    // Every external invocation, mutating or not, so a test can prove no
    // adapter was reached outside a durable, plan-bound intent.
    this.externalCalls = [];
  }

  callHelper(operationName, callerTool, payload) {
    const spec = contracts.PRIVILEGED_HELPER_OPERATIONS[operationName];
    if (!spec) {
      throw new ToolError("INTERNAL_ERROR", `no such helper operation: ${operationName}`);
    }
    if (!spec.callers.includes(callerTool)) {
      throw new ToolError("INTERNAL_ERROR",
        `tool ${callerTool} is not a registered caller of ${operationName}`);
    }
    this.externalCalls.push({ kind: "helper", operationName, callerTool, mutating: spec.mutating });
    if (spec.mutating) {
      this.mutationCalls.push({ kind: "helper", operationName, callerTool });
    }
    const impl = this.adapters.helpers[operationName];
    if (!impl) return phaseGatedStub("helper", operationName)();
    return impl(payload);
  }

  callBroker(operationName, callerTool, payload) {
    const spec = contracts.BROKER_OPERATIONS[operationName];
    if (!spec) {
      throw new ToolError("INTERNAL_ERROR", `no such broker operation: ${operationName}`);
    }
    if (!spec.callers.includes(callerTool)) {
      throw new ToolError("INTERNAL_ERROR",
        `tool ${callerTool} is not a registered caller of ${operationName}`);
    }
    this.externalCalls.push({ kind: "broker", operationName, callerTool, mutating: false });
    const impl = this.adapters.broker[operationName];
    if (!impl) return phaseGatedStub("broker", operationName)();
    return impl(payload);
  }

  externalMutationCallCount() {
    return this.mutationCalls.length;
  }
}

module.exports = {
  AdapterRegistry,
  buildProductionAdapters,
  HELPER_OPERATION_NAMES,
  BROKER_OPERATION_NAMES,
  MUTATING_HELPER_NAMES,
};
