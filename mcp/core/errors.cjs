"use strict";

const contracts = require("../../contract/mcp/schemas/contracts.cjs");

// ToolError carries a closed contract error code. The dispatch layer converts
// it into the output envelope's error branch; nothing else may synthesize an
// error body.
class ToolError extends Error {
  constructor(code, message, { retryable = false, evidenceRefs = [] } = {}) {
    if (!contracts.ERROR_CODES.includes(code)) {
      throw new Error(`unknown contract error code: ${code}`);
    }
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.retryable = retryable;
    this.evidenceRefs = evidenceRefs;
  }

  toErrorBody() {
    return {
      code: this.code,
      message: this.message.slice(0, 256),
      retryable: this.retryable,
      evidence_refs: this.evidenceRefs.slice(0, 8),
    };
  }
}

module.exports = { ToolError };
