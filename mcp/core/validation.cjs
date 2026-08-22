"use strict";

// Strict Ajv 2020-12 compilation of every frozen public schema. The frozen
// contract module is the only schema source; nothing here defines or widens a
// schema. Validation happens before any handler code runs.

const Ajv2020 = require("ajv/dist/2020");
const contracts = require("../../contract/mcp/schemas/contracts.cjs");

function buildValidators() {
  const ajv = new Ajv2020({
    strict: true,
    strictTypes: true,
    strictTuples: true,
    allowUnionTypes: true,
    allErrors: false,
    validateFormats: true,
  });
  const validators = new Map();
  for (const tool of contracts.TOOL_LIST) {
    validators.set(tool.name, {
      input: ajv.compile(tool.inputSchema),
      data: ajv.compile(tool.dataSchema),
      output: ajv.compile(tool.outputSchema),
    });
  }
  return validators;
}

let cached = null;
function getValidators() {
  if (!cached) cached = buildValidators();
  return cached;
}

function formatAjvErrors(errors) {
  return (errors || [])
    .slice(0, 4)
    .map((e) => `${e.instancePath || "$"} ${e.message}`)
    .join("; ")
    .slice(0, 200);
}

module.exports = { buildValidators, getValidators, formatAjvErrors };
