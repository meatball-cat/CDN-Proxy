#!/usr/bin/env node
"use strict";

// Verify: re-extracts the frozen contract from the read-only handoff document
// (path supplied via CDN_OPERATOR_SPEC_PATH) and byte-compares it with the
// vendored copy, proving no hand-written second catalog can drift.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function verifyContractParity() {
  const specPath = process.env.CDN_OPERATOR_SPEC_PATH;
  if (!specPath) {
    return { ok: false, error: "CDN_OPERATOR_SPEC_PATH is required for contract parity verification" };
  }
  const text = fs.readFileSync(specPath, "utf8");
  const fence = /^```(?:js|javascript)\n([\s\S]*?)^```$/gm;
  const modules = new Map();
  let match;
  while ((match = fence.exec(text)) !== null) {
    const body = match[1];
    const first = body.slice(0, body.indexOf("\n"));
    const declaration = /^\/\/\s*FILE:\s*(\S+)\s*$/.exec(first);
    if (declaration) modules.set(declaration[1], body);
  }
  const contractRoot = path.resolve(__dirname, "..", "contract");
  const results = [];
  for (const [file, body] of modules) {
    const vendored = fs.readFileSync(path.join(contractRoot, file), "utf8");
    results.push({
      file,
      byteEqual: vendored === body,
      sha256: crypto.createHash("sha256").update(body).digest("hex"),
    });
  }
  return { ok: results.length === 2 && results.every((r) => r.byteEqual), results };
}

if (require.main === module) {
  const report = verifyContractParity();
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exit(report.ok ? 0 : 1);
}

module.exports = { verifyContractParity };
