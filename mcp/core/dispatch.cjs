"use strict";

// Tool dispatch. Input validation runs strictly before any handler work:
// unknown fields, nulls, out-of-enum values, and unmet conditionals are
// rejected with INVALID_INPUT while the handler is provably not invoked.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { getValidators, formatAjvErrors } = require("./validation.cjs");
const { ToolError } = require("./errors.cjs");
const { HANDLERS } = require("../handlers/index.cjs");

function envelope(toolName, status, data, error, warnings = []) {
  return { tool: toolName, status, data, error, warnings };
}

class Dispatcher {
  constructor(ctx) {
    this.ctx = ctx;
    this.validators = getValidators();
    // Test observability: proves rejection happened before handler entry.
    this.handlerInvocations = [];
  }

  callTool(toolName, args) {
    if (!contracts.TOOLS_BY_NAME[toolName]) {
      throw new Error(`unknown tool: ${toolName}`);
    }
    const validators = this.validators.get(toolName);
    if (!validators.input(args)) {
      return envelope(toolName, "error", null, {
        code: "INVALID_INPUT",
        message: `input rejected before handler: ${formatAjvErrors(validators.input.errors)}`.slice(0, 256),
        retryable: false,
        evidence_refs: [],
      });
    }
    this.handlerInvocations.push(toolName);
    let result;
    try {
      result = HANDLERS[toolName](this.ctx, args);
    } catch (error) {
      if (error instanceof ToolError) {
        return envelope(toolName, "error", null, error.toErrorBody());
      }
      return envelope(toolName, "error", null, {
        code: "INTERNAL_ERROR",
        message: "internal error (details withheld from the MCP surface)",
        retryable: false,
        evidence_refs: [],
      });
    }
    const out = envelope(toolName, result.status || "ok", result.data, null);
    if (!validators.output(out)) {
      // A result that does not satisfy the frozen output schema must never
      // leave the server.
      return envelope(toolName, "error", null, {
        code: "INTERNAL_ERROR",
        message: `result failed the frozen output schema: ${formatAjvErrors(validators.output.errors)}`.slice(0, 256),
        retryable: false,
        evidence_refs: [],
      });
    }
    return out;
  }
}

module.exports = { Dispatcher };
