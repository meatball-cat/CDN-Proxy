"use strict";

// Low-entropy binding (LOW_ENTROPY_BINDING_POLICY).
//
// Values such as public IP addresses have too little entropy for a bare
// SHA-256 digest to be opaque: an observer could enumerate the space and
// recover the address. Core-v1 therefore compares them as HMAC-SHA-256
// digests under a per-install random key that never leaves this process, and
// binds each digest to a comparison domain, the registered target, and the
// run so digests from different domains or runs can never be equated.
//
// The raw value never enters MCP, a Hook payload, a log line, or a report;
// neither does the key. Equality is a constant-time comparison of digests.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("./errors.cjs");

const POLICY = contracts.LOW_ENTROPY_BINDING_POLICY;
const DOMAIN_BY_BINDING = POLICY.comparisonDomainByBinding;
const BINDINGS = POLICY.bindings;

class LowEntropyBinder {
  constructor({ dataDir }) {
    if (!dataDir) throw new Error("low-entropy binder requires an explicit dataDir");
    const keyPath = path.join(dataDir, "binding.key");
    let key;
    try {
      key = fs.readFileSync(keyPath);
      if (key.length !== 32) throw new Error("short key");
    } catch {
      key = crypto.randomBytes(32);
      // Descriptor-relative exclusive create with an owner-only mode; a
      // concurrent creator wins and we adopt its key rather than clobbering.
      try {
        const fd = fs.openSync(keyPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
        fs.writeSync(fd, key);
        fs.fsyncSync(fd);
        fs.closeSync(fd);
      } catch {
        key = fs.readFileSync(keyPath);
      }
    }
    // Kept only as a private closure variable: no property on `this` holds
    // the key, so no accidental serialization can carry it out.
    this.digest = (binding, { targetId, runId, value }) => {
      if (!BINDINGS.includes(binding)) {
        throw new Error(`unknown low-entropy binding: ${binding}`);
      }
      const domain = DOMAIN_BY_BINDING[binding];
      const mac = crypto.createHmac("sha256", key);
      // Context is length-prefixed so no two different contexts can collide
      // by concatenation.
      for (const part of [domain, String(targetId), String(runId), String(value)]) {
        mac.update(Buffer.from(`${Buffer.byteLength(part)}:`, "utf8"));
        mac.update(Buffer.from(part, "utf8"));
      }
      return `sha256:${mac.digest("hex")}`;
    };
  }

  toJSON() {
    return { lowEntropyBinder: "opaque" };
  }

  // Constant-time equality over two digests produced by this binder.
  static equal(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  }

  // Two digests may only be compared when their bindings share a comparison
  // domain. Cross-domain comparison is a contract violation, not a mismatch.
  static requireSameDomain(bindingA, bindingB) {
    const a = DOMAIN_BY_BINDING[bindingA];
    const b = DOMAIN_BY_BINDING[bindingB];
    if (!a || !b || a !== b) {
      throw new ToolError("INTERNAL_ERROR",
        "refused to compare low-entropy digests across different comparison domains");
    }
    return a;
  }
}

module.exports = { LowEntropyBinder, DOMAIN_BY_BINDING, BINDINGS };
