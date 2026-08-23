"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");

test("MCP catalog guard: actual stdio initialize and tools/list match the frozen contract", (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-mcp-protocol-"));
  t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
  const config = JSON.parse(fs.readFileSync(path.join(ROOT, ".mcp.json"), "utf8"));
  assert.deepEqual(Object.keys(config.mcpServers), ["cdn-node"]);
  const server = config.mcpServers["cdn-node"];
  const requests = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "protocol-test", version: "0" },
      },
    },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ].map(JSON.stringify).join("\n") + "\n";
  const result = spawnSync(server.command, server.args, {
    cwd: path.resolve(ROOT, server.cwd),
    env: { ...process.env, CDN_PROXY_HOME: runtime, NODE_NO_WARNINGS: "1" },
    input: requests,
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(result.status, 0, result.stderr);
  const responses = result.stdout.trim().split("\n").map(JSON.parse);
  const initialized = responses.find((row) => row.id === 1).result;
  const listed = responses.find((row) => row.id === 2).result.tools;
  const pkg = require("../package.json");
  const contracts = require("../contract/mcp/schemas/contracts.cjs");
  assert.deepEqual(initialized, {
    protocolVersion: "2025-06-18",
    capabilities: { tools: {} },
    serverInfo: { name: "cdn-node", version: pkg.version },
  });
  assert.equal(listed.length, 31, "MCP catalog guard: expected exactly 31 Tools");
  assert.deepEqual(listed.map((tool) => tool.name), [...contracts.FROZEN_TOOL_NAMES],
    "MCP catalog guard: Tool order drifted");
});
