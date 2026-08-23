"use strict";

// Handler table for the frozen 31-Tool catalog.
//
// The table is built by picking exactly the frozen tool names out of the
// handler modules, so a module helper can never accidentally become a served
// tool and a served tool can never exist outside the catalog. Completeness
// and cardinality are asserted at load time; the contract array stays the
// only catalog authority.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const lifecycle = require("./lifecycle.cjs");
const inventory = require("./inventory.cjs");
const plan = require("./plan.cjs");
const mutation = require("./mutation.cjs");
const verify = require("./verify.cjs");
const reconcile = require("./reconcile.cjs");

const MODULES = Object.freeze([lifecycle, inventory, plan, mutation, verify, reconcile]);

const table = {};
for (const name of contracts.FROZEN_TOOL_NAMES) {
  const providers = MODULES.filter((mod) => typeof mod[name] === "function");
  if (providers.length === 0) {
    throw new Error(`missing handler for frozen tool ${name}`);
  }
  if (providers.length > 1) {
    throw new Error(`frozen tool ${name} is served by more than one handler module`);
  }
  table[name] = providers[0][name];
}
if (Object.keys(table).length !== contracts.FROZEN_TOOL_NAMES.length) {
  throw new Error("handler table cardinality does not equal the frozen catalog");
}

const HANDLERS = Object.freeze(table);

module.exports = { HANDLERS };
