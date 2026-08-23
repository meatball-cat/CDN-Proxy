"use strict";

const { CORE_HOOK_EVENTS } = require("./catalog.cjs");
const { isPlainObject } = require("./redaction.cjs");
const { verifyHookTrust } = require("./trust.cjs");
const { evaluateHook, preDeny, permissionDeny, postBlock } = require("./policy.cjs");

const EVENT_SET = new Set(CORE_HOOK_EVENTS);

function unavailable(event, malformed = false) {
  const reason = malformed ? "HOOK_DENY_MALFORMED_INPUT" : "HOOK_UNAVAILABLE";
  if (event === "PreToolUse") return preDeny(reason);
  if (event === "PermissionRequest") return permissionDeny(reason);
  if (event === "PostToolUse") return postBlock(reason);
  return { continue: true, systemMessage: "HOOK_UNAVAILABLE" };
}

function boundedString(value, maximum = 512) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function validEnvelope(event, input) {
  if (!isPlainObject(input) || input.hook_event_name !== event) return false;
  if (!boundedString(input.session_id, 256)) return false;
  if (["PreToolUse", "PermissionRequest", "PostToolUse"].includes(event)) {
    if (!boundedString(input.turn_id, 256) || !boundedString(input.tool_name, 256) ||
        !boundedString(input.tool_use_id, 256) || !isPlainObject(input.tool_input)) return false;
  }
  if (event === "PostToolUse" && !isPlainObject(input.tool_response)) return false;
  if (event === "Stop" && typeof input.stop_hook_active !== "boolean") return false;
  return true;
}

function runHook(event, input, { env = process.env } = {}) {
  if (!EVENT_SET.has(event)) return unavailable(event);
  if (!validEnvelope(event, input)) return unavailable(event, true);
  if (!verifyHookTrust(env)) return unavailable(event);
  try {
    return evaluateHook(event, input, env);
  } catch {
    return unavailable(event);
  }
}

module.exports = { runHook, validEnvelope };
