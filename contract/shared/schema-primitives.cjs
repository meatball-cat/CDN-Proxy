// FILE: shared/schema-primitives.cjs
"use strict";

const closed = (properties, required = Object.keys(properties)) => Object.freeze({
  type: "object",
  additionalProperties: false,
  properties: Object.freeze({ ...properties }),
  required: Object.freeze([...required]),
});
const str = (minLength = 1, maxLength = 256, extra = {}) =>
  Object.freeze({ type: "string", minLength, maxLength, ...extra });
const bool = Object.freeze({ type: "boolean" });
const int = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER) =>
  Object.freeze({ type: "integer", minimum, maximum });
const enumOf = (...values) => Object.freeze({ type: "string", enum: Object.freeze(values) });
const constOf = (value) => Object.freeze({ type: typeof value, const: value });
const nullable = (schema) => Object.freeze({ anyOf: Object.freeze([schema, { type: "null" }]) });
const arr = (items, minItems = 0, maxItems = 64) => Object.freeze({
  type: "array", items, minItems, maxItems,
});
const ref = (kind) => str(12, 160, { pattern: `^${kind}:[A-Za-z0-9_-]{8,128}$` });
const A = (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) => Object.freeze({
  readOnlyHint, destructiveHint, idempotentHint, openWorldHint,
});
const E = (type, ttl) => Object.freeze({ type, ttl });
const errorBodyOf = (codes, EvidenceRef) => closed({
  code: enumOf(...codes),
  message: str(1, 256),
  retryable: bool,
  evidence_refs: arr(EvidenceRef, 0, 8),
});
const outputSchema = ({ toolName, dataSchema, errorBody, successStatuses = ["ok", "no_op"], statusDataRules = [] }) => Object.freeze({
  ...closed({
    tool: constOf(toolName),
    status: enumOf(...successStatuses, "error"),
    data: nullable(dataSchema),
    // Null-first makes the canonical non-error instance satisfy the conditional
    // without weakening the error branch.
    error: Object.freeze({ anyOf: Object.freeze([{ type: "null" }, errorBody]) }),
    warnings: arr(str(1, 256), 0, 16),
  }),
  allOf: Object.freeze([
    {
      if: { properties: { status: { const: "error" } }, required: ["status"] },
      then: { properties: { data: { type: "null" }, error: errorBody } },
      else: { properties: { data: dataSchema, error: { type: "null" } } },
    },
    ...statusDataRules,
  ]),
});
const contract = ({ name, title, description, input, data, annotations, policy, errorBody, successStatuses, statusDataRules }) =>
  Object.freeze({
    name, title, description,
    inputSchema: input,
    dataSchema: data,
    outputSchema: outputSchema({ toolName: name, dataSchema: data, errorBody, successStatuses, statusDataRules }),
    annotations,
    policy,
  });

module.exports = Object.freeze({
  closed, str, bool, int, enumOf, constOf, nullable, arr, ref,
  A, E, errorBodyOf, outputSchema, contract,
});
