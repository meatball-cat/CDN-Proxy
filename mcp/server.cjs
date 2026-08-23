#!/usr/bin/env node
"use strict";

// Production entry point for the single local stdio MCP server `cdn-node`.
// Dependencies are fixed at build time: the vendored frozen contract, the
// local SQLite WAL ledger under the controlled runtime root, the closed
// adapter registry (phase-gated stubs in this build), and the phase-gated
// Keychain seam. There is no dynamic module loading and no network import.

const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { Ledger } = require("./ledger/ledger.cjs");
const { AdapterRegistry, buildProductionAdapters } = require("./adapters/registry.cjs");
const { PhaseGatedKeychain } = require("./secrets/keychain.cjs");
const { LowEntropyBinder } = require("./core/hmac.cjs");
const { ServerCore } = require("./core/server-core.cjs");
const { startStdioTransport } = require("./core/jsonrpc.cjs");

function buildContext({ dataDir, adapters, keychain, binder, now } = {}) {
  const resolvedDataDir = dataDir || resolveRuntimeRoot().dataDir;
  return {
    ledger: new Ledger({
      dataDir: resolvedDataDir,
      now: now || (() => Date.now()),
    }),
    adapters: adapters || new AdapterRegistry(buildProductionAdapters()),
    keychain: keychain || new PhaseGatedKeychain(),
    // Per-install random HMAC key for the low-entropy comparison domains.
    // Lives only under the controlled runtime root and never enters MCP.
    binder: binder || new LowEntropyBinder({ dataDir: resolvedDataDir }),
  };
}

function createServer(options = {}) {
  return new ServerCore(buildContext(options));
}

if (require.main === module) {
  startStdioTransport(createServer());
}

module.exports = { createServer, buildContext };
