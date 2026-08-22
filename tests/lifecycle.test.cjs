"use strict";

// Acceptance: controlled runtime root with ActiveSet receipts; atomic
// bootstrap, update, explicit rollback, uninstall; no-clobber and crash
// recovery; doctor passes; the stdio server loads with the single cdn-node
// configuration.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const {
  install, update, rollback, uninstall, readActiveSet, cleanStagingResidue,
} = require("../lifecycle/activeset.cjs");
const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { runDoctor } = require("../lifecycle/doctor.cjs");

function tempEnv() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-lifecycle-test-"));
  return { env: { CDN_NODE_OPERATOR_HOME: home }, home };
}

test("install -> update -> explicit rollback -> uninstall lifecycle", (t) => {
  const { env, home } = tempEnv();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const paths = resolveRuntimeRoot(env);

  const installed = install({ env, version: "0.1.0-test" });
  assert.equal(readActiveSet(paths).version, "0.1.0-test");
  assert.ok(installed.receipt.files.length >= 4);

  // No-clobber: a second install over an owned ActiveSet must refuse.
  assert.throws(() => install({ env, version: "0.1.0-test2" }), /no-clobber/);

  // Simulate user data that every lifecycle step must preserve.
  const userFile = path.join(paths.dataDir, "ledger.sqlite3");
  fs.writeFileSync(userFile, "user-data");

  update({ env, version: "0.2.0-test" });
  const updated = readActiveSet(paths);
  assert.equal(updated.version, "0.2.0-test");
  assert.equal(updated.previous, "0.1.0-test");
  assert.equal(fs.readFileSync(userFile, "utf8"), "user-data");

  // Duplicate version update refuses (no-clobber on the versions dir).
  assert.throws(() => update({ env, version: "0.2.0-test" }));

  rollback({ env });
  const rolledBack = readActiveSet(paths);
  assert.equal(rolledBack.version, "0.1.0-test");
  assert.equal(rolledBack.rolledBackFrom, "0.2.0-test");
  // A second explicit rollback has no recorded previous and refuses.
  assert.throws(() => rollback({ env }), /no recorded previous/);

  const removed = uninstall({ env });
  assert.equal(removed.dataPreserved, true);
  assert.equal(readActiveSet(paths), null);
  assert.equal(fs.readFileSync(userFile, "utf8"), "user-data");
});

test("interrupted update staging residue is recovered", (t) => {
  const { env, home } = tempEnv();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const paths = resolveRuntimeRoot(env);
  install({ env, version: "0.1.0-test" });
  // Simulate a crash mid-update: an abandoned staging dir and temp file.
  fs.mkdirSync(path.join(paths.versionsDir, "0.9.9-test.staging"), { recursive: true });
  fs.writeFileSync(path.join(paths.root, "active.json.tmp-99999"), "{}");
  const removed = cleanStagingResidue(paths);
  assert.equal(removed.length, 2);
  assert.equal(readActiveSet(paths).version, "0.1.0-test");
  // The lifecycle continues normally after recovery.
  update({ env, version: "0.9.9-test" });
  assert.equal(readActiveSet(paths).version, "0.9.9-test");
});

test("doctor passes on a fresh install in a temp runtime root", (t) => {
  const { env, home } = tempEnv();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  install({ env, version: "0.1.0-test" });
  const report = runDoctor({ env });
  assert.equal(report.ok, true, JSON.stringify(report.checks, null, 2));
  const names = report.checks.map((check) => check.name);
  for (const expected of ["node-identity", "contract-bytes", "catalog-parity", "schema-compile", "active-set", "ledger-wal"]) {
    assert.ok(names.includes(expected), expected);
  }
});

test("stdio server loads the single cdn-node config and serves the frozen catalog", async (t) => {
  const { env, home } = tempEnv();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const root = path.resolve(__dirname, "..");
  const mcpConfig = JSON.parse(fs.readFileSync(path.join(root, ".mcp.json"), "utf8"));
  const serverConfig = mcpConfig.mcpServers["cdn-node"];

  const child = spawn(serverConfig.command, serverConfig.args, {
    cwd: root,
    env: { ...process.env, CDN_NODE_OPERATOR_HOME: home },
    stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(() => child.kill());

  const responses = [];
  let buffer = "";
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let idx;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) responses.push(JSON.parse(line));
    }
  });

  child.stdin.write(JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } },
  }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");

  await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error("stdio server timeout")), 10000);
    const poll = setInterval(() => {
      if (responses.length >= 2) { clearTimeout(deadline); clearInterval(poll); resolve(); }
    }, 25);
  });

  const initialize = responses.find((r) => r.id === 1);
  assert.equal(initialize.result.serverInfo.name, "cdn-node");
  const list = responses.find((r) => r.id === 2);
  const contracts = require("../contract/mcp/schemas/contracts.cjs");
  assert.equal(list.result.tools.length, 31);
  assert.deepEqual(list.result.tools.map((tool) => tool.name), [...contracts.FROZEN_TOOL_NAMES]);
});
