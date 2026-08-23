#!/usr/bin/env node
"use strict";

// Doctor: read-only health checks over the fixed Node identity, controlled
// runtime root, vendored frozen contract, ledger, and the served catalog.
// Exit code 0 means every check passed; it never claims INSTALLABLE,
// RUNNABLE, or ACCEPTED.

const fs = require("node:fs");
const path = require("node:path");
const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { readActiveSet } = require("./activeset.cjs");
const { sha256Digest } = require("../mcp/core/refs.cjs");

function runDoctor({ env = process.env } = {}) {
  const checks = [];
  const ok = (name, detail) => checks.push({ name, ok: true, detail });
  const fail = (name, detail) => checks.push({ name, ok: false, detail });

  const nodeMajor = Number(process.versions.node.split(".")[0]);
  if (nodeMajor >= 24) ok("node-identity", `node ${process.versions.node}`);
  else fail("node-identity", `node >=24 required, found ${process.versions.node}`);

  const installRoot = path.resolve(__dirname, "..");
  try {
    const provenance = JSON.parse(
      fs.readFileSync(path.join(installRoot, "contract", "PROVENANCE.json"), "utf8"));
    let contractOk = true;
    for (const file of provenance.files) {
      const digest = sha256Digest(fs.readFileSync(path.join(installRoot, "contract", file.file)));
      if (digest !== `sha256:${file.sha256}` && digest.slice(7) !== file.sha256) {
        contractOk = false;
        fail("contract-bytes", `${file.file} digest drifted`);
      }
    }
    if (contractOk) ok("contract-bytes", `${provenance.files.length} vendored contract files match provenance`);
  } catch (error) {
    fail("contract-bytes", `cannot verify vendored contract: ${error.message}`);
  }

  try {
    const contracts = require("../contract/mcp/schemas/contracts.cjs");
    const { toolCatalog } = require("../mcp/core/server-core.cjs");
    const served = toolCatalog().map((tool) => tool.name);
    if (served.length === 31 &&
        JSON.stringify(served) === JSON.stringify([...contracts.FROZEN_TOOL_NAMES])) {
      ok("catalog-parity", "served catalog equals the frozen 31-tool contract order");
    } else {
      fail("catalog-parity", "served catalog differs from the frozen contract");
    }
  } catch (error) {
    fail("catalog-parity", error.message);
  }

  try {
    const { getValidators } = require("../mcp/core/validation.cjs");
    ok("schema-compile", `${getValidators().size * 3} schemas compile under strict Ajv 2020-12`);
  } catch (error) {
    fail("schema-compile", error.message);
  }

  const explicitRuntime = Boolean(env.CDN_NODE_OPERATOR_HOME || env.PLUGIN_DATA);
  if (!explicitRuntime) {
    ok("active-set", "source-only doctor: no explicit runtime root was inspected");
    return { ok: checks.every((check) => check.ok), checks };
  }

  const paths = resolveRuntimeRoot(env);
  const activeSet = readActiveSet(paths);
  if (activeSet) {
    const receiptPath = path.join(paths.versionsDir, activeSet.version, "receipt.json");
    if (fs.existsSync(receiptPath)) {
      ok("active-set", `version ${activeSet.version} with layout receipt`);
    } else {
      fail("active-set", `active version ${activeSet.version} has no layout receipt`);
    }
    try {
      const { Ledger } = require("../mcp/ledger/ledger.cjs");
      const ledger = new Ledger({ dataDir: paths.dataDir });
      const mode = ledger.journalMode();
      ledger.close();
      if (mode === "wal") ok("ledger-wal", "ledger opens in WAL journal mode");
      else fail("ledger-wal", `unexpected journal mode ${mode}`);
    } catch (error) {
      fail("ledger-wal", error.message);
    }
  } else {
    ok("active-set", "no ActiveSet installed in this runtime root (nothing to check)");
  }

  const allOk = checks.every((check) => check.ok);
  return { ok: allOk, checks };
}

if (require.main === module) {
  const report = runDoctor();
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exit(report.ok ? 0 : 1);
}

module.exports = { runDoctor };
