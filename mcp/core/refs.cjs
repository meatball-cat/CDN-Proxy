"use strict";

const crypto = require("node:crypto");

// Server-minted opaque refs. The suffix is CSPRNG-random base64url and is
// never parsed as a path, command, URL, hostname, port, UUID, or credential.
const REF_KINDS = Object.freeze([
  "run", "target", "plan", "approval", "operation", "evidence", "closure",
  "change", "inverse", "compensation", "artifact", "secret", "runtime",
  "certificate", "record", "inbound", "profile", "probe", "receipt",
]);

function mintRef(kind) {
  if (!REF_KINDS.includes(kind)) throw new Error(`unknown ref kind: ${kind}`);
  return `${kind}:${crypto.randomBytes(24).toString("base64url")}`;
}

function isRef(kind, value) {
  return typeof value === "string" &&
    new RegExp(`^${kind}:[A-Za-z0-9_-]{8,128}$`).test(value);
}

function sha256Digest(input) {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

function digestOf(value) {
  return sha256Digest(canonicalJson(value));
}

module.exports = { REF_KINDS, mintRef, isRef, sha256Digest, canonicalJson, digestOf };
