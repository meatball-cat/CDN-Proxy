"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const EXPECTED_EVENTS = Object.freeze([
  "SessionStart",
  "PreToolUse",
  "PermissionRequest",
  "PostToolUse",
  "Stop",
  "SessionEnd",
]);

test("Hook catalog guard: exact frozen event order and command-only handlers", () => {
  const config = JSON.parse(
    fs.readFileSync(path.join(ROOT, "hooks", "hooks.json"), "utf8"),
  );
  assert.deepEqual(Object.keys(config.hooks), EXPECTED_EVENTS,
    "Hook catalog guard: Core-v1 requires the exact six-event order");

  for (const event of EXPECTED_EVENTS) {
    const groups = config.hooks[event];
    assert.equal(groups.length, 1, `${event} must have exactly one matcher group`);
    assert.equal(groups[0].hooks.length, 1, `${event} must have exactly one handler`);
    const handler = groups[0].hooks[0];
    assert.deepEqual(Object.keys(handler).sort(), ["command", "timeout", "type"],
      `${event} handler surface must stay closed`);
    assert.equal(handler.type, "command", `${event} must use a command handler`);
    assert.equal(handler.async, undefined, `${event} must be synchronous`);
    assert.match(handler.command,
      new RegExp(`^node \\\"\\$PLUGIN_ROOT/hooks/handler\\.cjs\\\" ${event}$`),
      `${event} must resolve the fixed installed handler through PLUGIN_ROOT`);
    assert.ok(handler.timeout > 0 && handler.timeout <= (event === "SessionEnd" ? 3 : 5));
  }
});

test("Hook catalog guard: every MCP call reaches the tool policy handlers", () => {
  const config = JSON.parse(
    fs.readFileSync(path.join(ROOT, "hooks", "hooks.json"), "utf8"),
  );
  for (const event of ["PreToolUse", "PermissionRequest", "PostToolUse"]) {
    assert.equal(config.hooks[event][0].matcher, "^mcp__",
      `${event} must observe every MCP namespace so a second server cannot bypass policy`);
  }
});

test("Hook catalog guard: exported catalog equals the JSON discovery order", () => {
  const { CORE_HOOK_EVENTS } = require("../hooks/catalog.cjs");
  const config = JSON.parse(
    fs.readFileSync(path.join(ROOT, "hooks", "hooks.json"), "utf8"),
  );
  assert.deepEqual([...CORE_HOOK_EVENTS], EXPECTED_EVENTS);
  assert.deepEqual(Object.keys(config.hooks), [...CORE_HOOK_EVENTS]);
});
