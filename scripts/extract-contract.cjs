#!/usr/bin/env node
"use strict";

// Extracts the executable frozen contract modules from the read-only handoff
// document 02-mcp-tool-plan.md into contract/. The frozen document is the sole
// contract authority; this script never edits it and never synthesizes contract
// content. Re-running is idempotent. Tests re-extract and byte-compare so no
// second hand-written catalog can drift.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const EXPECTED_SPEC_SHA256 =
  "a4bf469b9f5ccd61a03b73b7b61cfb8a962de280e107afe56442a43a0c542ea0";
const SPEC_BASENAME = "02-mcp-tool-plan.md";
const EXPECTED_FILES = Object.freeze([
  "shared/schema-primitives.cjs",
  "mcp/schemas/contracts.cjs",
]);

function resolveSpecPath() {
  const explicit = process.env.CDN_OPERATOR_SPEC_PATH || process.argv[2];
  if (explicit) return explicit;
  throw new Error(
    `frozen spec path required: set CDN_OPERATOR_SPEC_PATH or pass the path to ${SPEC_BASENAME} as argv[2]`,
  );
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function extractModules(text) {
  const fence = /^```(?:js|javascript)\n([\s\S]*?)^```$/gm;
  const modules = new Map();
  let match;
  while ((match = fence.exec(text)) !== null) {
    const body = match[1];
    const first = body.slice(0, body.indexOf("\n"));
    const declaration = /^\/\/\s*FILE:\s*(\S+)\s*$/.exec(first);
    if (!declaration) continue;
    const file = declaration[1];
    if (modules.has(file)) {
      throw new Error(`duplicate // FILE: block for ${file}`);
    }
    modules.set(file, body);
  }
  return modules;
}

function main() {
  const specPath = resolveSpecPath();
  if (path.basename(specPath) !== SPEC_BASENAME) {
    throw new Error(`spec path must point at ${SPEC_BASENAME}`);
  }
  const raw = fs.readFileSync(specPath);
  const digest = sha256(raw);
  if (digest !== EXPECTED_SPEC_SHA256) {
    throw new Error(
      `frozen spec digest mismatch: expected ${EXPECTED_SPEC_SHA256} got ${digest}; refusing to extract`,
    );
  }
  const modules = extractModules(raw.toString("utf8"));
  for (const file of EXPECTED_FILES) {
    if (!modules.has(file)) throw new Error(`missing // FILE: block for ${file}`);
  }
  for (const file of modules.keys()) {
    if (!EXPECTED_FILES.includes(file)) {
      throw new Error(`unexpected // FILE: block ${file}`);
    }
  }
  const outRoot = path.join(__dirname, "..", "contract");
  const written = [];
  for (const file of EXPECTED_FILES) {
    const target = path.join(outRoot, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const body = modules.get(file);
    fs.writeFileSync(target, body, { mode: 0o444, flag: "w" });
    written.push({ file, sha256: sha256(Buffer.from(body, "utf8")) });
  }
  const provenance = {
    source: SPEC_BASENAME,
    source_sha256: EXPECTED_SPEC_SHA256,
    extraction: "fenced js blocks declared with // FILE:, byte-exact",
    files: written,
  };
  fs.writeFileSync(
    path.join(outRoot, "PROVENANCE.json"),
    JSON.stringify(provenance, null, 2) + "\n",
  );
  process.stdout.write(
    written.map((w) => `${w.sha256}  contract/${w.file}`).join("\n") + "\n",
  );
}

main();
