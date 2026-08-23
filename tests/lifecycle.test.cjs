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
const { spawn, spawnSync } = require("node:child_process");
const {
  install, update, rollback, uninstall, readActiveSet, cleanStagingResidue,
} = require("../lifecycle/activeset.cjs");
const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { runDoctor } = require("../lifecycle/doctor.cjs");
const packageVersion = require("../package.json").version;

function tempEnv() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-lifecycle-test-"));
  return { env: { CDN_NODE_OPERATOR_HOME: home }, home };
}

function runLifecycleCli(script, args, env) {
  return spawnSync(process.execPath, [path.resolve(__dirname, "..", "lifecycle", script), ...args], {
    cwd: path.resolve(__dirname, ".."),
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 30000,
  });
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

test("lifecycle CLIs complete install, doctor, update, explicit rollback, and uninstall in a temp root", (t) => {
  const { env, home } = tempEnv();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const paths = resolveRuntimeRoot(env);

  const installed = runLifecycleCli("install.cjs", [], env);
  assert.equal(installed.status, 0, installed.stdout + installed.stderr);
  assert.equal(JSON.parse(installed.stdout).version, packageVersion);
  const productData = path.join(paths.dataDir, "artifact.keep");
  fs.writeFileSync(productData, "preserve");

  const doctor = runLifecycleCli("doctor.cjs", [], env);
  assert.equal(doctor.status, 0, doctor.stdout + doctor.stderr);
  assert.equal(JSON.parse(doctor.stdout).ok, true);

  const updated = runLifecycleCli("update.cjs", ["0.3.1-phase6"], env);
  assert.equal(updated.status, 0, updated.stdout + updated.stderr);
  assert.equal(JSON.parse(updated.stdout).version, "0.3.1-phase6");
  const rolledBack = runLifecycleCli("rollback.cjs", [], env);
  assert.equal(rolledBack.status, 0, rolledBack.stdout + rolledBack.stderr);
  assert.equal(JSON.parse(rolledBack.stdout).version, packageVersion);

  const removed = runLifecycleCli("uninstall.cjs", [], env);
  assert.equal(removed.status, 0, removed.stdout + removed.stderr);
  assert.equal(JSON.parse(removed.stdout).dataPreserved, true);
  assert.equal(fs.readFileSync(productData, "utf8"), "preserve");
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
  assert.equal(initialize.result.serverInfo.version, packageVersion,
    "initialize version guard: stdio response must match package version");
  assert.equal(initialize.result.protocolVersion, "2025-06-18");
  const list = responses.find((r) => r.id === 2);
  const contracts = require("../contract/mcp/schemas/contracts.cjs");
  assert.equal(list.result.tools.length, 31, "MCP catalog guard: exactly 31 Tools");
  assert.deepEqual(list.result.tools.map((tool) => tool.name), [...contracts.FROZEN_TOOL_NAMES],
    "MCP catalog guard: exact frozen Tool order");
});

test("restart/recovery reopens the same explicit temp ledger and ActiveSet", (t) => {
  const { env, home } = tempEnv();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const paths = resolveRuntimeRoot(env);
  install({ env, version: packageVersion });
  const { Ledger } = require("../mcp/ledger/ledger.cjs");
  const first = new Ledger({ dataDir: paths.dataDir });
  first.db.exec("CREATE TABLE IF NOT EXISTS restart_marker(value TEXT NOT NULL)");
  first.db.prepare("INSERT INTO restart_marker(value) VALUES (?)").run("preserved");
  first.close();

  delete require.cache[require.resolve("../mcp/ledger/ledger.cjs")];
  const { Ledger: RestartedLedger } = require("../mcp/ledger/ledger.cjs");
  const restarted = new RestartedLedger({ dataDir: paths.dataDir });
  const row = restarted.db.prepare("SELECT value FROM restart_marker").get();
  restarted.close();
  assert.equal(row.value, "preserved");
  assert.equal(readActiveSet(paths).version, packageVersion);
  assert.equal(runDoctor({ env }).ok, true);
});
