"use strict";

// Hooks never return a value copied from the event. These checks are an
// additional tripwire for deployment-shaped input and output. Opaque refs,
// digests, and idempotency keys are the only identifier-like strings a Hook
// may inspect or retain.

const SAFE_OPAQUE_KEY = /(?:^|_)(?:ref|refs|digest|digests|id|key)$/;
const SENSITIVE_KEY = /(?:^|_)(?:adapter|command|argv|credential|credentials|secret|token|password|private_key|host|hostname|ip|port|url|uri|path|socket|ssh|dns|nginx|keychain)(?:$|_)/i;
const OPAQUE_VALUE = /^(?:sha256:[a-f0-9]{64}|[a-z]+:[A-Za-z0-9_-]{8,}|[A-Za-z0-9._:-]{8,})$/;
const DEPLOYMENT_SHAPE = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:secret|password|credential|bearer)(?:\s*[:=]|\/)|\/(?:Users|home|private|etc|var)\/|(?:^|[\s"'])~\/|\b(?:\d{1,3}\.){3}\d{1,3}\b|\bwss?:\/\/|\bhttps?:\/\/)/i;

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function hasSensitiveInput(value, key = "", depth = 0) {
  if (depth > 16) return true;
  if (value === null || typeof value === "boolean" || typeof value === "number") return false;
  if (typeof value === "string") {
    if (SAFE_OPAQUE_KEY.test(key) && OPAQUE_VALUE.test(value)) return false;
    return DEPLOYMENT_SHAPE.test(value);
  }
  if (Array.isArray(value)) return value.some((entry) => hasSensitiveInput(entry, key, depth + 1));
  if (!isPlainObject(value)) return true;
  return Object.entries(value).some(([childKey, child]) => {
    if (!SAFE_OPAQUE_KEY.test(childKey) && SENSITIVE_KEY.test(childKey)) return true;
    return hasSensitiveInput(child, childKey, depth + 1);
  });
}

function hasOutputLeak(value, key = "", depth = 0) {
  if (depth > 16) return true;
  if (value === null || typeof value === "boolean" || typeof value === "number") return false;
  if (typeof value === "string") {
    if (SAFE_OPAQUE_KEY.test(key) && OPAQUE_VALUE.test(value)) return false;
    return DEPLOYMENT_SHAPE.test(value);
  }
  if (Array.isArray(value)) return value.some((entry) => hasOutputLeak(entry, key, depth + 1));
  if (!isPlainObject(value)) return true;
  return Object.entries(value).some(([childKey, child]) => {
    if (!SAFE_OPAQUE_KEY.test(childKey) && SENSITIVE_KEY.test(childKey)) return true;
    return hasOutputLeak(child, childKey, depth + 1);
  });
}

module.exports = { isPlainObject, hasSensitiveInput, hasOutputLeak };
