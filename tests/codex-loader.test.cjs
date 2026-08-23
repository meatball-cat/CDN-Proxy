"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const VERSION = require("../package.json").version;
const MARKETPLACE = "cdn-proxy-hermetic";
const PLUGIN_ID = `cdn-proxy@${MARKETPLACE}`;

function command(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: options.cwd || ROOT,
    env: options.env || process.env,
    input: options.input,
    encoding: "utf8",
    timeout: 30000,
  });
}

function requireSuccess(result, label) {
  assert.equal(result.status, 0, `${label}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  return result.stdout ? JSON.parse(result.stdout) : null;
}

function stdioRoundTrip(installRoot, runtimeRoot) {
  const config = JSON.parse(fs.readFileSync(path.join(installRoot, ".mcp.json"), "utf8"));
  assert.deepEqual(Object.keys(config.mcpServers), ["cdn-node"]);
  const server = config.mcpServers["cdn-node"];
  const input = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "isolated-loader-test", version: "0" },
      },
    },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ].map(JSON.stringify).join("\n") + "\n";
  const result = command(server.command, server.args, {
    cwd: path.resolve(installRoot, server.cwd),
    env: {
      ...process.env,
      CDN_PROXY_HOME: runtimeRoot,
      PLUGIN_DATA: runtimeRoot,
      PLUGIN_ROOT: installRoot,
      NODE_NO_WARNINGS: "1",
    },
    input,
  });
  assert.equal(result.status, 0, result.stderr);
  const responses = result.stdout.trim().split("\n").map(JSON.parse);
  const initialize = responses.find((row) => row.id === 1).result;
  const list = responses.find((row) => row.id === 2).result;
  assert.deepEqual(initialize.serverInfo, { name: "cdn-node", version: VERSION });
  assert.equal(list.tools.length, 31, "MCP catalog guard: loader package must serve 31 Tools");
  const frozen = require("../contract/mcp/schemas/contracts.cjs").FROZEN_TOOL_NAMES;
  assert.deepEqual(list.tools.map((tool) => tool.name), [...frozen],
    "MCP catalog guard: loader package Tool order drifted");
}

test("Codex loader validation: generated package installs and discovers one MCP, one Skill, and Core Hooks", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-codex-loader-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const marketplaceRoot = path.join(temporary, "marketplace");
  const pluginRoot = path.join(marketplaceRoot, "plugins", "cdn-proxy");
  const codexRoot = path.join(temporary, "codex-root");
  const runtimeRoot = path.join(temporary, "runtime-root");
  fs.mkdirSync(path.join(marketplaceRoot, ".agents", "plugins"), { recursive: true });
  fs.mkdirSync(path.dirname(pluginRoot), { recursive: true });
  fs.mkdirSync(codexRoot, { recursive: true });

  const version = command("codex", ["--version"]);
  assert.equal(version.status, 0, "official Codex CLI is required for loader validation");
  const packed = requireSuccess(command("npm", [
    "pack", "--json", "--ignore-scripts", "--pack-destination", temporary,
  ]), "create generated package");
  const tarball = path.join(temporary, packed[0].filename);
  const extracted = path.join(temporary, "extracted");
  fs.mkdirSync(extracted);
  requireSuccess(command("tar", ["-xzf", tarball, "-C", extracted]), "extract generated package");
  fs.renameSync(path.join(extracted, "package"), pluginRoot);

  const marketplace = {
    name: MARKETPLACE,
    interface: { displayName: "CDN-Proxy Hermetic" },
    plugins: [{
      name: "cdn-proxy",
      source: { source: "local", path: "./plugins/cdn-proxy" },
      policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
      category: "Developer Tools",
    }],
  };
  fs.writeFileSync(
    path.join(marketplaceRoot, ".agents", "plugins", "marketplace.json"),
    JSON.stringify(marketplace, null, 2) + "\n",
  );
  const isolatedEnv = { ...process.env, CODEX_HOME: codexRoot };

  const addedMarketplace = requireSuccess(command("codex", [
    "plugin", "marketplace", "add", marketplaceRoot, "--json",
  ], { env: isolatedEnv }), "add isolated marketplace");
  assert.equal(addedMarketplace.marketplaceName, MARKETPLACE);

  const available = requireSuccess(command("codex", [
    "plugin", "list", "--available", "--json",
  ], { env: isolatedEnv }), "list available isolated plugin");
  assert.equal(available.available.length, 1);
  assert.equal(available.available[0].pluginId, PLUGIN_ID);
  assert.equal(available.available[0].version, VERSION);

  const installed = requireSuccess(command("codex", [
    "plugin", "add", PLUGIN_ID, "--json",
  ], { env: isolatedEnv }), "install isolated plugin");
  assert.equal(installed.version, VERSION);
  assert.ok(fs.realpathSync(installed.installedPath).startsWith(fs.realpathSync(codexRoot) + path.sep));
  const installRoot = fs.realpathSync(installed.installedPath);
  assert.ok(fs.existsSync(path.join(installRoot, "skills", "cdn-proxy", "SKILL.md")));
  assert.deepEqual(Object.keys(JSON.parse(
    fs.readFileSync(path.join(installRoot, "hooks", "hooks.json"), "utf8"),
  ).hooks), ["SessionStart", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop", "SessionEnd"]);

  const lifecycleEnv = {
    ...isolatedEnv,
    CDN_PROXY_HOME: runtimeRoot,
    PLUGIN_DATA: runtimeRoot,
    PLUGIN_ROOT: installRoot,
  };
  requireSuccess(command(process.execPath, [path.join(installRoot, "lifecycle", "install.cjs")], {
    cwd: installRoot,
    env: lifecycleEnv,
  }), "install isolated runtime root");
  stdioRoundTrip(installRoot, runtimeRoot);
  const activeBeforeRestart = fs.readFileSync(path.join(runtimeRoot, "active.json"));
  stdioRoundTrip(installRoot, runtimeRoot);
  assert.deepEqual(fs.readFileSync(path.join(runtimeRoot, "active.json")), activeBeforeRestart);

  const hookInput = {
    session_id: "isolated_loader_session",
    transcript_path: null,
    cwd: ".",
    hook_event_name: "SessionStart",
    model: "synthetic-model",
    permission_mode: "default",
    source: "startup",
  };
  const hook = command(process.execPath, [path.join(installRoot, "hooks", "handler.cjs"), "SessionStart"], {
    cwd: temporary,
    env: lifecycleEnv,
    input: JSON.stringify(hookInput),
  });
  assert.equal(hook.status, 0, hook.stderr);
  assert.equal(JSON.parse(hook.stdout).systemMessage, "HOOK_READY_HERMETIC_SOURCE_ONLY");

  const listed = requireSuccess(command("codex", ["plugin", "list", "--json"], {
    env: isolatedEnv,
  }), "list installed isolated plugin");
  assert.equal(listed.installed.length, 1);
  assert.equal(listed.installed[0].enabled, true);

  requireSuccess(command(process.execPath, [path.join(installRoot, "lifecycle", "uninstall.cjs")], {
    cwd: installRoot,
    env: lifecycleEnv,
  }), "uninstall isolated runtime owner files");
  requireSuccess(command("codex", ["plugin", "remove", PLUGIN_ID, "--json"], {
    env: isolatedEnv,
  }), "remove isolated plugin");
  requireSuccess(command("codex", [
    "plugin", "marketplace", "remove", MARKETPLACE, "--json",
  ], { env: isolatedEnv }), "remove isolated marketplace");
});
