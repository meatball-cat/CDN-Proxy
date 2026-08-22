"use strict";

// Seeded schema instance synthesizer used by the tests. It derives positive
// instances directly from the frozen schemas (the same closed-schema shape
// the validator instance-tests), so the tests never maintain a hand-written
// instance list per tool.

function check(schema, value, at = "$", errors = []) {
  if (!schema || typeof schema !== "object") return errors;
  if (Array.isArray(schema.allOf)) {
    for (const branch of schema.allOf) check(branch, value, at, errors);
  }
  if (schema.if) {
    const branch = check(schema.if, value, at, []).length === 0 ? schema.then : schema.else;
    if (branch) check(branch, value, at, errors);
  }
  if (Array.isArray(schema.anyOf)) {
    if (!schema.anyOf.some((branch) => check(branch, value, at, []).length === 0)) {
      errors.push(`${at}: matches no anyOf branch`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(schema, "const") && value !== schema.const) {
    errors.push(`${at}: const mismatch`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    errors.push(`${at}: not in enum`);
  }
  if (schema.type) {
    const actual = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
    const expected = schema.type === "integer" ? "number" : schema.type;
    if (actual !== expected) {
      errors.push(`${at}: type mismatch`);
      return errors;
    }
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) errors.push(`${at}: minLength`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errors.push(`${at}: maxLength`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${at}: pattern`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${at}: minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${at}: maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${at}: minItems`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${at}: maxItems`);
    if (schema.uniqueItems && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) {
      errors.push(`${at}: uniqueItems`);
    }
    if (schema.items) value.forEach((item, i) => check(schema.items, item, `${at}[${i}]`, errors));
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of schema.required || []) {
      if (!(key in value)) errors.push(`${at}.${key}: required`);
    }
    for (const [key, subschema] of Object.entries(schema.properties || {})) {
      if (key in value) check(subschema, value[key], `${at}.${key}`, errors);
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const key of Object.keys(value)) {
        if (!(key in schema.properties)) errors.push(`${at}.${key}: additional`);
      }
    }
  }
  return errors;
}

function sample(schema, seed = 0) {
  if (!schema || typeof schema !== "object") return null;
  if (Object.prototype.hasOwnProperty.call(schema, "const")) return schema.const;
  if (Array.isArray(schema.enum)) return schema.enum[seed % schema.enum.length];
  if (Array.isArray(schema.anyOf) && !(schema.type === "object" || schema.properties)) {
    return sample(schema.anyOf[0], seed);
  }
  if (Array.isArray(schema.oneOf) && !(schema.type === "object" || schema.properties)) {
    return sample(schema.oneOf[0], seed);
  }
  if (schema.type === "null") return null;
  if (schema.type === "boolean") return true;
  if (schema.type === "integer" || schema.type === "number") return schema.minimum ?? 0;
  if (schema.type === "array") {
    const length = schema.minItems || 0;
    if (schema.uniqueItems && schema.items && Array.isArray(schema.items.enum)) {
      return schema.items.enum.slice(0, length);
    }
    return Array.from({ length }, (_, index) => sample(schema.items, Number(seed) + index));
  }
  if (schema.type === "string") {
    if (schema.pattern) {
      const refLike = /^\^([a-z]+):\[A-Za-z0-9_-\]\{(\d+),/.exec(schema.pattern);
      if (refLike) {
        const length = Number(refLike[2]);
        const tail = "abcdefghijklmnopqrstuvwxyz0123456789"[Number(seed) % 36];
        return `${refLike[1]}:${"a".repeat(Math.max(0, length - 1))}${tail}`;
      }
      if (schema.pattern.startsWith("^sha256:")) return `sha256:${"a".repeat(64)}`;
      if (schema.pattern.startsWith("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) return "2026-08-09T00:00:00Z";
      if (schema.pattern === "^[A-Za-z0-9._:-]+$") return "k".repeat(16);
      if (schema.pattern.startsWith("^PT")) return "PT5M";
      if (schema.pattern === "^/[A-Za-z0-9_-]{32}$") return `/${"a".repeat(32)}`;
    }
    const length = Math.max(1, schema.minLength || 1);
    const tail = "abcdefghijklmnopqrstuvwxyz0123456789"[Number(seed) % 36];
    return `${"x".repeat(Math.max(0, length - 1))}${tail}`;
  }
  if (schema.type === "object" || schema.properties) {
    const value = {};
    for (const key of schema.required || Object.keys(schema.properties || {})) {
      if (schema.properties && schema.properties[key]) {
        value[key] = sample(schema.properties[key], seed);
      }
    }
    applyConditionals(schema, value, seed);
    return value;
  }
  return null;
}

function applyConditionals(schema, value, seed) {
  for (const clause of schema.allOf || []) {
    if (!clause.if || (!clause.then && !clause.else)) continue;
    const branch = check(clause.if, value, "$", []).length === 0 ? clause.then : clause.else;
    if (!branch) continue;
    projectBranch(branch, value, seed);
  }
}

function projectBranch(branch, value, seed) {
  if (branch.if) {
    const inner = check(branch.if, value, "$", []).length === 0 ? branch.then : branch.else;
    if (inner) projectBranch(inner, value, seed);
  }
  for (const [key, subschema] of Object.entries(branch.properties || {})) {
    value[key] = sample(subschema, seed);
  }
}

// sample + targeted overrides + conditional re-projection. Overrides applied
// before re-projection steer discriminator fields; overrides applied after
// win for plain fields.
function sampleWith(schema, overrides = {}, seed = 0) {
  const value = sample(schema, seed);
  Object.assign(value, overrides);
  applyConditionals(schema, value, seed);
  Object.assign(value, overrides);
  return value;
}

module.exports = { sample, sampleWith, check };
