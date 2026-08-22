"use strict";

// Acceptance: the served tools/list is set- and order-equal to the frozen
// contract, and the vendored contract is byte-equal to a fresh re-extraction
// from the read-only handoff document. No hand-written second catalog exists.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const EXPECTED_SPEC_SHA256 =
  "a4bf469b9f5ccd61a03b73b7b61cfb8a962de280e107afe56442a43a0c542ea0";

function frozenSpecPath() {
  if (process.env.CDN_OPERATOR_SPEC_PATH) return process.env.CDN_OPERATOR_SPEC_PATH;
  // Sibling handoff package next to this project checkout (relative only; no
  // absolute deployment path lives in durable bytes).
  return path.resolve(__dirname, "..", "..",
    "3x-ui-cdn-operator-development-handoff", "02-mcp-tool-plan.md");
}

test("frozen spec digest matches the external lock record", () => {
  const raw = fs.readFileSync(frozenSpecPath());
  const digest = crypto.createHash("sha256").update(raw).digest("hex");
  assert.equal(digest, EXPECTED_SPEC_SHA256);
});

test("vendored contract modules are byte-equal to a fresh re-extraction", () => {
  const text = fs.readFileSync(frozenSpecPath(), "utf8");
  const fence = /^```(?:js|javascript)\n([\s\S]*?)^```$/gm;
  const modules = new Map();
  let match;
  while ((match = fence.exec(text)) !== null) {
    const body = match[1];
    const first = body.slice(0, body.indexOf("\n"));
    const declaration = /^\/\/\s*FILE:\s*(\S+)\s*$/.exec(first);
    if (declaration) modules.set(declaration[1], body);
  }
  assert.deepEqual([...modules.keys()].sort(), [
    "mcp/schemas/contracts.cjs",
    "shared/schema-primitives.cjs",
  ]);
  for (const [file, body] of modules) {
    const vendored = fs.readFileSync(
      path.resolve(__dirname, "..", "contract", file), "utf8");
    assert.equal(vendored, body, `${file} drifted from the frozen contract`);
  }
});

test("tools/list equals the frozen ordered 31-tool catalog", () => {
  const contracts = require("../contract/mcp/schemas/contracts.cjs");
  const { toolCatalog } = require("../mcp/core/server-core.cjs");
  const served = toolCatalog();
  assert.equal(served.length, 31);
  assert.deepEqual(served.map((tool) => tool.name), [...contracts.FROZEN_TOOL_NAMES]);
  // Order-exact, not just set-equal.
  for (let i = 0; i < served.length; i += 1) {
    assert.equal(served[i].name, contracts.FROZEN_TOOL_NAMES[i]);
  }
  // Served schemas are the identical frozen objects, not copies.
  for (const tool of served) {
    assert.equal(tool.inputSchema, contracts.TOOLS_BY_NAME[tool.name].inputSchema);
    assert.equal(tool.outputSchema, contracts.TOOLS_BY_NAME[tool.name].outputSchema);
  }
});

test("plugin manifest and single-server .mcp.json load and agree", () => {
  const root = path.resolve(__dirname, "..");
  const mcpConfig = JSON.parse(fs.readFileSync(path.join(root, ".mcp.json"), "utf8"));
  const servers = Object.keys(mcpConfig.mcpServers);
  assert.deepEqual(servers, ["cdn-node"]);
  assert.equal(mcpConfig.mcpServers["cdn-node"].type, "stdio");
  const manifest = JSON.parse(
    fs.readFileSync(path.join(root, ".codex-plugin", "plugin.json"), "utf8"));
  assert.equal(manifest.name, "cdn-node-operator");
  assert.equal(manifest.status.installable, "NOT_CLAIMED");
  assert.equal(manifest.status.runnable, "NOT_CLAIMED");
  assert.equal(manifest.status.accepted, "NOT_CLAIMED");
});
