"use strict";

// Acceptance: schema rejection happens strictly before handler entry. The
// dispatcher records handler invocations, so a rejected call is provably
// never dispatched and the ledger stays untouched.

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeFixture } = require("./helpers/fixture.cjs");

test("unknown field, null, bad enum, and broken conditional are rejected pre-handler", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const dispatcher = fx.core.dispatcher;

  const cases = [
    ["unknown field", "run_status", { run_id: "run:aaaaaaaaaaaa", hostile: true }],
    ["null non-nullable", "run_status", { run_id: null }],
    ["out-of-enum", "run_begin", { ...fx.runBeginInput("audit"), mode: "destroy" }],
    ["conditional violation", "run_begin", { ...fx.runBeginInput("audit"), enable_bbr: true }],
    ["missing required", "evidence_list", { run_id: "run:aaaaaaaaaaaa" }],
  ];

  for (const [label, tool, args] of cases) {
    const before = dispatcher.handlerInvocations.length;
    const result = fx.callTool(tool, args);
    assert.equal(result.status, "error", label);
    assert.equal(result.error.code, "INVALID_INPUT", label);
    assert.equal(result.data, null, label);
    assert.equal(dispatcher.handlerInvocations.length, before,
      `${label}: handler must not run`);
  }

  // No run was created by any rejected run_begin.
  const runs = fx.ctx.ledger.db.prepare("SELECT COUNT(*) AS n FROM runs").get();
  assert.equal(runs.n, 0);
});

test("valid input reaches the handler exactly once", (t) => {
  const fx = makeFixture();
  t.after(() => fx.cleanup());
  const dispatcher = fx.core.dispatcher;
  const result = fx.callTool("run_begin", fx.runBeginInput("audit"));
  assert.equal(result.status, "ok");
  assert.deepEqual(dispatcher.handlerInvocations, ["run_begin"]);
});
