"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const { sampleWith } = require("./helpers/sample.cjs");

const ROOT = path.resolve(__dirname, "..");

const digest = (char = "a") => `sha256:${char.repeat(64)}`;
const ref = (kind, suffix) => `${kind}:${suffix.padEnd(8, "x")}`;

function fixture(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-hook-test-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const env = {
    CDN_PROXY_HOME: home,
    PLUGIN_ROOT: ROOT,
    PLUGIN_DATA: home,
  };
  const { install } = require("../lifecycle/activeset.cjs");
  install({ env, version: require("../package.json").version });
  return { home, env };
}

function common(event, overrides = {}) {
  return {
    session_id: "session_synthetic",
    transcript_path: null,
    cwd: ".",
    hook_event_name: event,
    model: "synthetic-model",
    permission_mode: "default",
    ...overrides,
  };
}

function toolInput(event, tool, args, extra = {}) {
  return common(event, {
    turn_id: "turn_synthetic",
    tool_name: `mcp__cdn-node__${tool}`,
    tool_use_id: "tooluse_synthetic",
    tool_input: args,
    ...extra,
  });
}

function noAuthority(output) {
  const text = JSON.stringify(output);
  assert.ok(!/"permissionDecision":"allow"/.test(text), "Hook authority guard: PreToolUse cannot allow");
  assert.ok(!/"behavior":"allow"/.test(text), "Hook authority guard: PermissionRequest cannot approve");
  assert.ok(!/approval_ref|lease_ref|receipt_ref|evidence_ref/.test(text),
    "Hook authority guard: Hook cannot mint product refs");
}

function successfulResponse(tool, dataOverrides = {}) {
  const contract = contracts.TOOLS[tool];
  const data = sampleWith(contract.dataSchema, dataOverrides);
  return {
    structuredContent: sampleWith(contract.outputSchema, {
      tool,
      status: "ok",
      error: null,
      warnings: [],
      data,
    }),
  };
}

test("trusted SessionStart reports the source-only boundary without path disclosure", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { home, env } = fixture(t);
  const output = runHook("SessionStart", common("SessionStart", { source: "startup" }), { env });
  assert.equal(output.systemMessage, "HOOK_READY_HERMETIC_SOURCE_ONLY");
  assert.equal(output.continue, true);
  assert.ok(!JSON.stringify(output).includes(home));
  assert.ok(!JSON.stringify(output).includes(ROOT));
  noAuthority(output);
});

test("missing Hook config and wrong Node/runtime identity fail closed with a fixed reason", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);

  const missing = runHook("SessionStart", common("SessionStart", { source: "resume" }), {
    env: { ...env, PLUGIN_ROOT: "" },
  });
  assert.equal(missing.systemMessage, "HOOK_UNAVAILABLE");

  const activePath = path.join(env.CDN_PROXY_HOME, "active.json");
  const active = JSON.parse(fs.readFileSync(activePath, "utf8"));
  active.nodeExecutable = path.join(path.sep, "invalid", "node");
  fs.writeFileSync(activePath, JSON.stringify(active, null, 2) + "\n");
  const wrongRuntime = runHook("SessionStart", common("SessionStart", { source: "resume" }), { env });
  assert.equal(wrongRuntime.systemMessage, "HOOK_UNAVAILABLE");
  assert.ok(!JSON.stringify(wrongRuntime).includes("invalid"));
});

test("trust tuple drift in receipt, owner, mode, or runtime symlink fails closed", async (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const start = common("SessionStart", { source: "resume" });

  await t.test("receipt digest drift", (st) => {
    const { env } = fixture(st);
    const active = JSON.parse(fs.readFileSync(path.join(env.CDN_PROXY_HOME, "active.json"), "utf8"));
    const receiptPath = path.join(env.CDN_PROXY_HOME, "versions", active.version, "receipt.json");
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    receipt.files[0].sha256 = digest("f");
    fs.writeFileSync(receiptPath, JSON.stringify(receipt) + "\n", { mode: 0o600 });
    assert.equal(runHook("SessionStart", start, { env }).systemMessage, "HOOK_UNAVAILABLE");
  });

  await t.test("owner identity drift", (st) => {
    const { env } = fixture(st);
    const activePath = path.join(env.CDN_PROXY_HOME, "active.json");
    const active = JSON.parse(fs.readFileSync(activePath, "utf8"));
    active.ownerUid += 1;
    fs.writeFileSync(activePath, JSON.stringify(active) + "\n", { mode: 0o600 });
    assert.equal(runHook("SessionStart", start, { env }).systemMessage, "HOOK_UNAVAILABLE");
  });

  await t.test("world-writable runtime root", (st) => {
    const { home, env } = fixture(st);
    fs.chmodSync(home, 0o777);
    assert.equal(runHook("SessionStart", start, { env }).systemMessage, "HOOK_UNAVAILABLE");
  });

  await t.test("runtime crossing symlink", (st) => {
    const { home, env } = fixture(st);
    const link = `${home}-link`;
    st.after(() => fs.rmSync(link, { force: true }));
    fs.symlinkSync(home, link);
    assert.equal(runHook("SessionStart", start, {
      env: { ...env, PLUGIN_DATA: link },
    }).systemMessage, "HOOK_UNAVAILABLE");
  });
});

test("malformed envelope and unknown event fail closed without echoing input", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const unknown = runHook("FutureEvent", { hook_event_name: "FutureEvent", payload: "do-not-echo" }, { env });
  assert.equal(unknown.systemMessage, "HOOK_UNAVAILABLE");
  assert.ok(!JSON.stringify(unknown).includes("do-not-echo"));
  const malformed = runHook("PreToolUse", [], { env });
  assert.equal(malformed.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(malformed.hookSpecificOutput.permissionDecisionReason, "HOOK_DENY_MALFORMED_INPUT");
});

test("PreToolUse reports a safe active Tool but never grants server authority", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const output = runHook("PreToolUse", toolInput("PreToolUse", "run_status", {
    run_id: ref("run", "safe-run"),
  }), { env });
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(output.hookSpecificOutput.additionalContext, "HOOK_POLICY_CHECKED_SERVER_REMAINS_AUTHORITY");
  noAuthority(output);
});

test("Hook authority guard: deferred Tool, second server, production adapter, command, and path are denied", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const denied = [
    common("PreToolUse", { turn_id: "t", tool_name: `mcp__cdn-node__${"sur" + "ge_apply"}`, tool_use_id: "u", tool_input: {} }),
    common("PreToolUse", { turn_id: "t", tool_name: "mcp__other__run_status", tool_use_id: "u", tool_input: {} }),
    toolInput("PreToolUse", "run_status", { adapter: "production" }),
    toolInput("PreToolUse", "run_status", { command: "perform-action" }),
    toolInput("PreToolUse", "run_status", { path: path.join(path.sep, "private", "deploy", "config") }),
  ];
  for (const input of denied) {
    const output = runHook("PreToolUse", input, { env });
    assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
    assert.match(output.hookSpecificOutput.permissionDecisionReason,
      /^HOOK_DENY_(?:NOT_ACTIVE_CATALOG|SENSITIVE_INPUT)$/);
    noAuthority(output);
  }
});

test("PermissionRequest checks the cached plan projection and never approves", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const planRef = ref("plan", "plan-safe");
  const challengeRef = ref("runtime", "challenge");
  const impact = digest("b");
  const ledger = digest("c");

  runHook("PostToolUse", toolInput("PostToolUse", "plan_compile", {
    run_id: ref("run", "safe-run"),
    scope: "node_p2",
    intent: "configure_existing",
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.synthetic.0",
  }, {
    tool_response: successfulResponse("plan_compile", {
      plan_ref: planRef,
      approval_challenge_ref: challengeRef,
      impact_digest: impact,
    }),
  }), { env });

  const args = {
    run_id: ref("run", "safe-run"),
    plan_ref: planRef,
    approval_challenge_ref: challengeRef,
    displayed_impact_digest: impact,
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.synthetic.1",
  };
  const matching = runHook("PermissionRequest",
    toolInput("PermissionRequest", "plan_authorize", args), { env });
  assert.equal(matching.systemMessage, "HOOK_PROMPT_CONSISTENT_HOST_DECISION_REQUIRED");
  noAuthority(matching);

  const mismatch = runHook("PermissionRequest", toolInput("PermissionRequest", "plan_authorize", {
    ...args, displayed_impact_digest: digest("d"),
  }), { env });
  assert.equal(mismatch.hookSpecificOutput.decision.behavior, "deny");
  assert.equal(mismatch.hookSpecificOutput.decision.message, "HOOK_DENY_PROMPT_MISMATCH");
});

test("run_close prompt must match live cached phase, ledger, outcome, and sealed completion", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const runId = ref("run", "close-run");
  const ledger = digest("7");
  const statusInput = { run_id: runId };
  runHook("PostToolUse", toolInput("PostToolUse", "run_status", statusInput, {
    tool_response: successfulResponse("run_status", {
      main_phase: "DELIVERY_REPORT_SEALED",
      bbr_phase: "BBR_CLOSED",
      ledger_digest: ledger,
    }),
  }), { env });
  const completionInput = {
    run_id: runId,
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.completion.synthetic",
  };
  runHook("PostToolUse", toolInput("PostToolUse", "completion_evaluate", completionInput, {
    tool_response: successfulResponse("completion_evaluate", {
      label: "end_to_end_verified",
    }),
  }), { env });

  const closeArgs = {
    run_id: runId,
    scope: "main",
    outcome: "accepted",
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.close.synthetic",
  };
  const matching = runHook("PermissionRequest",
    toolInput("PermissionRequest", "run_close", closeArgs), { env });
  assert.equal(matching.systemMessage, "HOOK_PROMPT_CONSISTENT_HOST_DECISION_REQUIRED");
  noAuthority(matching);

  for (const mismatch of [
    { ...closeArgs, expected_ledger_digest: digest("8") },
    { ...closeArgs, outcome: "abandoned" },
  ]) {
    const denied = runHook("PermissionRequest",
      toolInput("PermissionRequest", "run_close", mismatch), { env });
    assert.equal(denied.hookSpecificOutput.decision.behavior, "deny");
    assert.equal(denied.hookSpecificOutput.decision.message, "HOOK_DENY_PROMPT_MISMATCH");
  }
});

test("Stop projects only validated server enums and never upgrades completion to acceptance", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const runId = ref("run", "stop-run");
  const ledger = digest("9");
  const stop = common("Stop", {
    turn_id: "turn_synthetic",
    stop_hook_active: false,
    last_assistant_message: "claim accepted must be ignored",
  });

  runHook("PostToolUse", toolInput("PostToolUse", "run_status", { run_id: runId }, {
    tool_response: successfulResponse("run_status", {
      main_phase: "APPLYING",
      bbr_phase: "BBR_PENDING",
      ledger_digest: ledger,
    }),
  }), { env });
  assert.equal(runHook("Stop", stop, { env }).systemMessage,
    "HOOK_STOP_SERVER_STATE_APPLYING_BBR_PENDING");

  runHook("PostToolUse", toolInput("PostToolUse", "completion_evaluate", {
    run_id: runId,
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.stop.synthetic",
  }, {
    tool_response: successfulResponse("completion_evaluate", {
      label: "end_to_end_verified",
    }),
  }), { env });
  const verified = runHook("Stop", stop, { env });
  assert.equal(verified.systemMessage, "HOOK_STOP_E2E_VERIFIED_AWAITING_HOST_CLOSE");
  assert.ok(!/accepted/i.test(JSON.stringify(verified)));

  runHook("PostToolUse", toolInput("PostToolUse", "reconcile_status", {
    run_id: runId,
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.reconcile.synthetic",
  }, {
    tool_response: successfulResponse("reconcile_status"),
  }), { env });
  assert.equal(runHook("Stop", stop, { env }).systemMessage,
    "HOOK_STOP_RECONCILIATION_REQUIRED_STAY_MANUAL_NO_RETRY_OR_CLOSE");

  const finalLedger = digest("a");
  runHook("PostToolUse", toolInput("PostToolUse", "run_close", {
    run_id: runId,
    scope: "main",
    outcome: "accepted",
    expected_ledger_digest: ledger,
    idempotency_key: "idempotency.closed.synthetic",
  }, {
    tool_response: successfulResponse("run_close", {
      scope: "main",
      outcome: "accepted",
      final_ledger_digest: finalLedger,
    }),
  }), { env });
  assert.equal(runHook("Stop", stop, { env }).systemMessage,
    "HOOK_STOP_MAIN_ACCEPTED_SERVER_CLOSED");
});

test("Hook redaction guard: PostToolUse blocks a leaked synthetic secret/path and emits only fixed text", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const leaked = ["synthetic", "secret", path.sep, "private", path.sep, "config"].join("");
  const output = runHook("PostToolUse", toolInput("PostToolUse", "run_status", {
    run_id: ref("run", "safe-run"),
  }, {
    tool_response: { structuredContent: { status: "ok", data: { detail: leaked } } },
  }), { env });
  assert.equal(output.continue, false);
  assert.equal(output.decision, "block");
  assert.equal(output.reason, "HOOK_REDACTION_TRIPWIRE");
  assert.ok(!JSON.stringify(output).includes(leaked));
  noAuthority(output);
});

test("Stop is honest, recursion-safe, and cannot claim acceptance without server facts", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const first = runHook("Stop", common("Stop", {
    turn_id: "turn_synthetic", stop_hook_active: false, last_assistant_message: "ignored",
  }), { env });
  assert.equal(first.continue, true);
  assert.equal(first.systemMessage, "HOOK_STOP_INSUFFICIENT_EVIDENCE");
  assert.ok(!/accepted/i.test(JSON.stringify(first)));

  const recursive = runHook("Stop", common("Stop", {
    turn_id: "turn_synthetic", stop_hook_active: true, last_assistant_message: null,
  }), { env });
  assert.equal(recursive.continue, true);
  assert.equal(recursive.systemMessage, "HOOK_STOP_RECURSION_SAFE");
  assert.equal(recursive.decision, undefined);
});

test("Hooks never mutate ActiveSet, ledger, approval, lease, receipt, or server state", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const activePath = path.join(env.CDN_PROXY_HOME, "active.json");
  const versionsPath = path.join(env.CDN_PROXY_HOME, "versions");
  const beforeActive = fs.readFileSync(activePath);
  const beforeVersions = fs.readdirSync(versionsPath, { recursive: true }).sort();
  const dataPath = path.join(env.CDN_PROXY_HOME, "data");
  const beforeData = fs.readdirSync(dataPath, { recursive: true }).sort();

  runHook("SessionStart", common("SessionStart", { source: "startup" }), { env });
  runHook("PreToolUse", toolInput("PreToolUse", "run_status", {
    run_id: ref("run", "safe-run"),
  }), { env });
  runHook("Stop", common("Stop", {
    turn_id: "turn_synthetic", stop_hook_active: false, last_assistant_message: null,
  }), { env });

  assert.deepEqual(fs.readFileSync(activePath), beforeActive);
  assert.deepEqual(fs.readdirSync(versionsPath, { recursive: true }).sort(), beforeVersions);
  assert.deepEqual(fs.readdirSync(dataPath, { recursive: true }).sort(), beforeData);
});

test("SessionEnd removes only Hook-owned temporary records and preserves foreign/product data", (t) => {
  const { runHook } = require("../hooks/runner.cjs");
  const { env } = fixture(t);
  const foreign = path.join(env.CDN_PROXY_HOME, "foreign.keep");
  const product = path.join(env.CDN_PROXY_HOME, "data", "ledger.keep");
  fs.writeFileSync(foreign, "foreign");
  fs.writeFileSync(product, "product");

  runHook("SessionStart", common("SessionStart", { source: "startup" }), { env });
  const hookState = path.join(env.CDN_PROXY_HOME, "hook-state");
  assert.ok(fs.existsSync(hookState));
  const output = runHook("SessionEnd", common("SessionEnd", { reason: "other" }), { env });
  assert.equal(output.systemMessage, "HOOK_SESSION_ENDED_LOCAL_RECORDS_CLEANED");
  assert.equal(fs.existsSync(hookState), false);
  assert.equal(fs.readFileSync(foreign, "utf8"), "foreign");
  assert.equal(fs.readFileSync(product, "utf8"), "product");
});
