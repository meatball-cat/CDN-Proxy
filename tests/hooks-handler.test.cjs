"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const HANDLER = path.join(ROOT, "hooks", "handler.cjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-hook-cli-"));
  const unrelatedCwd = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-hook-cwd-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  t.after(() => fs.rmSync(unrelatedCwd, { recursive: true, force: true }));
  const env = {
    ...process.env,
    CDN_NODE_OPERATOR_HOME: root,
    PLUGIN_ROOT: ROOT,
    PLUGIN_DATA: root,
  };
  require("../lifecycle/activeset.cjs").install({
    env,
    version: require("../package.json").version,
  });
  return { root, unrelatedCwd, env };
}

function envelope(event, overrides = {}) {
  return {
    session_id: "session_cli_synthetic",
    transcript_path: null,
    cwd: ".",
    hook_event_name: event,
    model: "synthetic-model",
    permission_mode: "default",
    ...overrides,
  };
}

function invoke(event, input, options) {
  return spawnSync(process.execPath, [HANDLER, event], {
    cwd: options.cwd,
    env: options.env,
    input: typeof input === "string" ? input : JSON.stringify(input),
    encoding: "utf8",
    timeout: 3000,
  });
}

function invokeAsync(event, input, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HANDLER, event], {
      cwd: options.cwd,
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(input));
  });
}

test("command handler uses installed identity and ignores the session cwd", (t) => {
  const fx = fixture(t);
  const result = invoke("SessionStart", envelope("SessionStart", { source: "startup" }), fx);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    continue: true,
    systemMessage: "HOOK_READY_HERMETIC_SOURCE_ONLY",
  });
  assert.ok(!result.stdout.includes(fx.root));
  assert.ok(!result.stdout.includes(fx.unrelatedCwd));
});

test("unknown, malformed, and oversized stdin return one fixed closed JSON object", (t) => {
  const fx = fixture(t);
  const cases = [
    invoke("UnknownEvent", JSON.stringify({ payload: "must-not-echo" }), fx),
    invoke("PreToolUse", "{", fx),
    invoke("PreToolUse", "x".repeat(70 * 1024), fx),
  ];
  for (const result of cases) {
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout);
    assert.ok(output.systemMessage === "HOOK_UNAVAILABLE" ||
      output.hookSpecificOutput.permissionDecision === "deny");
    assert.ok(!result.stdout.includes("must-not-echo"));
    assert.ok(result.stdout.length < 512);
  }
});

test("canonical duplicate is a no-op and a reordered approval request is denied", (t) => {
  const fx = fixture(t);
  const start = envelope("SessionStart", { source: "startup" });
  assert.equal(invoke("SessionStart", start, fx).status, 0);
  assert.equal(invoke("SessionStart", start, fx).status, 0);
  const stateDir = path.join(fx.root, "hook-state");
  const stateFile = fs.readdirSync(stateDir).find((name) => name.endsWith(".json"));
  const state = JSON.parse(fs.readFileSync(path.join(stateDir, stateFile), "utf8"));
  assert.equal(state.event_digests.length, 1);

  const denied = invoke("PermissionRequest", envelope("PermissionRequest", {
    turn_id: "turn_cli",
    tool_name: "mcp__cdn-node__plan_authorize",
    tool_use_id: "tool_cli",
    tool_input: {
      run_id: `run:${"a".repeat(16)}`,
      plan_ref: `plan:${"b".repeat(16)}`,
      approval_challenge_ref: `runtime:${"c".repeat(16)}`,
      displayed_impact_digest: `sha256:${"d".repeat(64)}`,
      expected_ledger_digest: `sha256:${"e".repeat(64)}`,
      idempotency_key: "idempotency.cli.synthetic",
    },
  }), fx);
  assert.equal(JSON.parse(denied.stdout).hookSpecificOutput.decision.behavior, "deny");
});

test("concurrent Stop invocations are recursion-safe, bounded, and side-effect free", async (t) => {
  const fx = fixture(t);
  const stop = envelope("Stop", {
    turn_id: "turn_cli",
    stop_hook_active: true,
    last_assistant_message: null,
  });
  const before = fs.readFileSync(path.join(fx.root, "active.json"));
  const results = await Promise.all(Array.from({ length: 4 }, () => invokeAsync("Stop", stop, fx)));
  for (const result of results) {
    assert.equal(result.code, 0);
    assert.equal(result.stderr, "");
    assert.equal(JSON.parse(result.stdout).systemMessage, "HOOK_STOP_RECURSION_SAFE");
  }
  assert.deepEqual(fs.readFileSync(path.join(fx.root, "active.json")), before);
  assert.equal(fs.existsSync(path.join(fx.root, "hook-state")), false);
});
