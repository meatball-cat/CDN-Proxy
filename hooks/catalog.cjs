"use strict";

const { FROZEN_TOOL_NAMES } = require("../contract/mcp/schemas/contracts.cjs");

const CORE_HOOK_EVENTS = Object.freeze([
  "SessionStart",
  "PreToolUse",
  "PermissionRequest",
  "PostToolUse",
  "Stop",
  "SessionEnd",
]);

const CORE_HOOK_POLICY_VERSION = "core-v1-hook-policy-1";
const CORE_SERVER_PREFIX = "mcp__cdn-node__";
const ACTIVE_TOOL_NAMES = Object.freeze([...FROZEN_TOOL_NAMES]);
const ACTIVE_TOOL_SET = new Set(ACTIVE_TOOL_NAMES);
const HOOK_TRUST_FILES = Object.freeze([
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "contract/PROVENANCE.json",
  "contract/shared/schema-primitives.cjs",
  "contract/mcp/schemas/contracts.cjs",
  "hooks/hooks.json",
  "hooks/catalog.cjs",
  "hooks/redaction.cjs",
  "hooks/trust.cjs",
  "hooks/state.cjs",
  "hooks/policy.cjs",
  "hooks/runner.cjs",
  "hooks/handler.cjs",
]);

function activeToolFromHookName(name) {
  if (typeof name !== "string" || !name.startsWith(CORE_SERVER_PREFIX)) return null;
  const tool = name.slice(CORE_SERVER_PREFIX.length);
  return ACTIVE_TOOL_SET.has(tool) ? tool : null;
}

module.exports = {
  CORE_HOOK_EVENTS,
  CORE_HOOK_POLICY_VERSION,
  CORE_SERVER_PREFIX,
  ACTIVE_TOOL_NAMES,
  ACTIVE_TOOL_SET,
  HOOK_TRUST_FILES,
  activeToolFromHookName,
};
