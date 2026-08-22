"use strict";

// Handler table for the frozen 31-Tool catalog. Completeness against
// FROZEN_TOOL_NAMES is asserted at load time; the contract array stays the
// only catalog authority.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const lifecycle = require("./lifecycle.cjs");
const inventory = require("./inventory.cjs");
const plan = require("./plan.cjs");
const mutation = require("./mutation.cjs");
const verify = require("./verify.cjs");

const HANDLERS = Object.freeze({
  ...lifecycle,
  ...inventory,
  ...plan,
  ...mutation,
  ...verify,
});

for (const name of contracts.FROZEN_TOOL_NAMES) {
  if (typeof HANDLERS[name] !== "function") {
    throw new Error(`missing handler for frozen tool ${name}`);
  }
}
for (const name of Object.keys(HANDLERS)) {
  if (!contracts.FROZEN_TOOL_NAMES.includes(name)) {
    throw new Error(`handler ${name} is not in the frozen tool catalog`);
  }
}

module.exports = { HANDLERS };
