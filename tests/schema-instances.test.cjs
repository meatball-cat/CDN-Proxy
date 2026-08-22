"use strict";

// Acceptance: all 93 public schemas (31 input + 31 data + 31 output
// envelopes) compile under strict Ajv 2020-12, positive synthesized instances
// validate, and unknown-field / null / out-of-enum / conditional-violating
// negatives are rejected.

const test = require("node:test");
const assert = require("node:assert/strict");
const contracts = require("../contract/mcp/schemas/contracts.cjs");
const { buildValidators } = require("../mcp/core/validation.cjs");
const { sample, sampleWith } = require("./helpers/sample.cjs");

const validators = buildValidators();

test("all 93 schemas compile under strict Ajv 2020-12", () => {
  assert.equal(validators.size, 31);
  for (const tool of contracts.TOOL_LIST) {
    const v = validators.get(tool.name);
    assert.equal(typeof v.input, "function");
    assert.equal(typeof v.data, "function");
    assert.equal(typeof v.output, "function");
  }
  assert.equal(validators.size * 3, 93);
});

function isNullable(schema) {
  return Boolean(schema && Array.isArray(schema.anyOf) &&
    schema.anyOf.some((branch) => branch.type === "null"));
}

for (const tool of contracts.TOOL_LIST) {
  const v = validators.get(tool.name);

  test(`${tool.name}: positive input/data/output instances validate`, () => {
    const input = sample(tool.inputSchema, 0);
    assert.ok(v.input(input),
      `input sample invalid: ${JSON.stringify(v.input.errors)}`);
    const data = sampleWith(tool.dataSchema, {}, 0);
    assert.ok(v.data(data),
      `data sample invalid: ${JSON.stringify(v.data.errors)}`);
    const successStatus = tool.outputSchema.properties.status.enum[0];
    const okEnvelope = {
      tool: tool.name, status: successStatus, data, error: null, warnings: [],
    };
    assert.ok(v.output(okEnvelope),
      `ok envelope invalid: ${JSON.stringify(v.output.errors)}`);
    const errorEnvelope = {
      tool: tool.name,
      status: "error",
      data: null,
      error: {
        code: tool.policy.errors[0],
        message: "synthetic error",
        retryable: false,
        evidence_refs: [],
      },
      warnings: [],
    };
    assert.ok(v.output(errorEnvelope),
      `error envelope invalid: ${JSON.stringify(v.output.errors)}`);
  });

  test(`${tool.name}: unknown fields are rejected on every closed object`, () => {
    const input = sample(tool.inputSchema, 0);
    assert.equal(v.input({ ...input, __hostile: 1 }), false);
    const data = sampleWith(tool.dataSchema, {}, 0);
    assert.equal(v.data({ ...data, __hostile: 1 }), false);
    const envelope = {
      tool: tool.name, status: tool.outputSchema.properties.status.enum[0],
      data, error: null, warnings: [], __hostile: 1,
    };
    assert.equal(v.output(envelope), false);
  });

  test(`${tool.name}: null in a non-nullable required field is rejected`, () => {
    const input = sample(tool.inputSchema, 0);
    let checkedNull = false;
    for (const key of tool.inputSchema.required) {
      const property = tool.inputSchema.properties[key];
      if (isNullable(property) || property.type === "null") continue;
      assert.equal(v.input({ ...input, [key]: null }), false,
        `input.${key}=null must be rejected`);
      checkedNull = true;
      break;
    }
    assert.ok(checkedNull, "every tool input has at least one non-nullable field");
  });

  test(`${tool.name}: out-of-enum values are rejected`, () => {
    const input = sample(tool.inputSchema, 0);
    const enumField = tool.inputSchema.required.find(
      (key) => Array.isArray(tool.inputSchema.properties[key].enum));
    if (enumField) {
      assert.equal(v.input({ ...input, [enumField]: "__not_in_enum__" }), false);
    }
    // Envelope status is itself a closed enum on all 31 output schemas.
    const data = sampleWith(tool.dataSchema, {}, 0);
    assert.equal(v.output({
      tool: tool.name, status: "__not_a_status__", data, error: null, warnings: [],
    }), false);
  });

  test(`${tool.name}: output error conditional (error implies null data)`, () => {
    const data = sampleWith(tool.dataSchema, {}, 0);
    assert.equal(v.output({
      tool: tool.name,
      status: "error",
      data,
      error: {
        code: tool.policy.errors[0], message: "x", retryable: false, evidence_refs: [],
      },
      warnings: [],
    }), false, "status=error with non-null data must be rejected");
    assert.equal(v.output({
      tool: tool.name,
      status: tool.outputSchema.properties.status.enum[0],
      data,
      error: {
        code: tool.policy.errors[0], message: "x", retryable: false, evidence_refs: [],
      },
      warnings: [],
    }), false, "success status with non-null error must be rejected");
  });
}

test("run_begin conditional: audit mode cannot request BBR", () => {
  const v = validators.get("run_begin");
  const input = sample(contracts.TOOLS_BY_NAME.run_begin.inputSchema, 0);
  input.mode = "audit";
  input.enable_bbr = true;
  assert.equal(v.input(input), false);
});

test("run_begin conditional: protected-line pair must be both-null or both-set", () => {
  const v = validators.get("run_begin");
  const base = sample(contracts.TOOLS_BY_NAME.run_begin.inputSchema, 0);
  base.mode = "audit";
  base.enable_bbr = false;
  assert.equal(v.input({
    ...base, protected_line_ref: null,
    protected_line_runtime_secret_ref: "secret:aaaaaaaaaaaaaaaa",
  }), false);
  assert.equal(v.input({
    ...base, protected_line_ref: "runtime:aaaaaaaaaaaaaaaa",
    protected_line_runtime_secret_ref: null,
  }), false);
});

test("run_close data conditional: audit_complete close binds the report", () => {
  const v = validators.get("run_close");
  const good = sampleWith(contracts.TOOLS_BY_NAME.run_close.dataSchema, {
    scope: "main", outcome: "audit_complete",
  }, 0);
  assert.ok(v.data(good), JSON.stringify(v.data.errors));
  assert.equal(v.data({ ...good, bound_completion_label: null }), false);
  assert.equal(v.data({ ...good, bound_completion_report_digest: null }), false);
});

test("completion_evaluate data conditional: labels bind status and report shape", () => {
  const v = validators.get("completion_evaluate");
  const audit = sampleWith(contracts.TOOLS_BY_NAME.completion_evaluate.dataSchema, {
    label: "audit_complete",
  }, 0);
  assert.ok(v.data(audit), JSON.stringify(v.data.errors));
  assert.equal(v.data({ ...audit, all_required_true: false }), false);
  assert.equal(v.data({ ...audit, report_ref: null }), false);
  // pending label with a sealed report ref must fail
  const pending = sampleWith(contracts.TOOLS_BY_NAME.completion_evaluate.dataSchema, {
    label: "configured_not_verified",
  }, 0);
  assert.ok(v.data(pending), JSON.stringify(v.data.errors));
  assert.equal(v.data({ ...pending, report_ref: "artifact:aaaaaaaaaaaaaaaa" }), false);
  // output-envelope coupling: ok cannot carry configured_not_verified
  assert.equal(v.output({
    tool: "completion_evaluate", status: "ok", data: pending, error: null, warnings: [],
  }), false);
  assert.ok(v.output({
    tool: "completion_evaluate", status: "pending", data: pending, error: null, warnings: [],
  }), JSON.stringify(v.output.errors));
});

test("old_line_verify data conditional: pre_change forbids route/receipt bindings", () => {
  const v = validators.get("old_line_verify");
  const good = sampleWith(contracts.TOOLS_BY_NAME.old_line_verify.dataSchema, {
    binding_scope: "pre_change",
  }, 0);
  assert.ok(v.data(good), JSON.stringify(v.data.errors));
  assert.equal(v.data({
    ...good, bound_current_route_digest: `sha256:${"a".repeat(64)}`,
  }), false);
});

test("xui_inventory data conditional: case projection is enforced", () => {
  const v = validators.get("xui_inventory");
  const good = sampleWith(contracts.TOOLS_BY_NAME.xui_inventory.dataSchema, {
    admin_binding_status: "ABSENT_CLEAN_ELIGIBLE",
  }, 0);
  assert.ok(v.data(good), JSON.stringify(v.data.errors));
  assert.equal(v.data({ ...good, installation_status: "compatible_existing" }), false);
  assert.equal(v.data({ ...good, clean_host_install_eligible: false }), false);
});
