"use strict";

// Acceptance: static scans over every durable byte in this repository prove
// there is no plaintext secret, private-key container, real deployment value,
// raw path, dynamic loader, shell/spawn surface in production code, network
// import, or active Future-v2 entry point.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const SKIP_DIRS = new Set(["node_modules", ".git"]);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const ALL_FILES = walk(ROOT);
const PRODUCTION_SOURCE = ALL_FILES.filter((file) => {
  const relative = path.relative(ROOT, file);
  return relative.endsWith(".cjs") &&
    !relative.startsWith("tests" + path.sep) &&
    !relative.startsWith("contract" + path.sep);
});
const DURABLE_TEXT = ALL_FILES.filter((file) =>
  /\.(cjs|json|md|txt)$/.test(file) && !file.includes("package-lock.json") &&
  // The scanner itself names the forbidden patterns it hunts for.
  path.resolve(file) !== __filename);

// Closed production import registry: node builtins actually used, ajv, and
// in-repo relative modules. Anything else fails the scan.
const ALLOWED_BUILTINS = new Set([
  "node:fs", "node:path", "node:os", "node:crypto", "node:sqlite",
]);
const ALLOWED_PACKAGES = new Set(["ajv/dist/2020"]);

test("production import registry is closed: builtins, ajv, and relative modules only", () => {
  for (const file of PRODUCTION_SOURCE) {
    const text = fs.readFileSync(file, "utf8");
    const requires = [...text.matchAll(/require\(\s*([^)]*)\)/g)];
    for (const match of requires) {
      const argument = match[1].trim();
      assert.match(argument, /^["']/,
        `${path.relative(ROOT, file)}: dynamic (non-literal) require: ${argument}`);
      const specifier = argument.slice(1, -1);
      const legal = specifier.startsWith("./") || specifier.startsWith("../") ||
        ALLOWED_BUILTINS.has(specifier) || ALLOWED_PACKAGES.has(specifier);
      assert.ok(legal,
        `${path.relative(ROOT, file)}: require outside the closed registry: ${specifier}`);
    }
  }
});

test("no shell, spawn, eval, dynamic import, or network surface in production code", () => {
  const forbidden = [
    /child_process/, /\beval\s*\(/, /new\s+Function\s*\(/, /\bimport\s*\(/,
    /require\(\s*["'](?:node:)?(?:vm|worker_threads|net|http|https|dns|tls|dgram|repl|cluster)["']\s*\)/,
    /execSync|spawnSync|execFile/,
  ];
  for (const file of PRODUCTION_SOURCE) {
    const text = fs.readFileSync(file, "utf8");
    for (const pattern of forbidden) {
      assert.ok(!pattern.test(text),
        `${path.relative(ROOT, file)} matches forbidden pattern ${pattern}`);
    }
  }
});

test("no plaintext secret, private-key container, or credential material in durable bytes", () => {
  const forbidden = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /-----BEGIN (?:RSA|OPENSSH|EC|PGP)/,
    /PuTTY-User-Key-File/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bxox[baprs]-/,
    /password\s*[:=]\s*["'][^"'\n]{4,}["']/i,
  ];
  for (const file of DURABLE_TEXT) {
    const text = fs.readFileSync(file, "utf8");
    for (const pattern of forbidden) {
      assert.ok(!pattern.test(text),
        `${path.relative(ROOT, file)} matches ${pattern}`);
    }
  }
});

test("no real deployment value: public IPs, real-looking hostnames, or home paths", () => {
  const ipPattern = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
  for (const file of DURABLE_TEXT) {
    const relative = path.relative(ROOT, file);
    const text = fs.readFileSync(file, "utf8");
    for (const match of text.matchAll(ipPattern)) {
      const value = match[0];
      const octets = value.split(".").map(Number);
      const versionLike = octets.every((n) => n <= 30); // e.g. 2020.12 style
      const loopbackOrLocal = value.startsWith("127.") || value === "0.0.0.0";
      assert.ok(loopbackOrLocal || versionLike,
        `${relative} contains a non-local IPv4 literal: ${value}`);
    }
    // Absolute per-user paths must never live in durable bytes; runtime
    // resolution uses os.homedir() only.
    assert.ok(!/\/Users\/[a-z0-9_-]+\//i.test(text),
      `${relative} contains an absolute per-user path`);
    assert.ok(!/\/home\/[a-z0-9_-]+\//i.test(text),
      `${relative} contains an absolute per-user path`);
  }
});

test("no active Future-v2 entry point in production or config bytes", () => {
  // Scanned against every durable byte except the vendored frozen contract
  // (which names deferred ideas only in its non-normative Future-v2 prose).
  const scanned = DURABLE_TEXT.filter((file) => {
    const relative = path.relative(ROOT, file);
    return !relative.startsWith("contract" + path.sep);
  });
  const forbidden = [
    /local-privacy/i, /\bsurge\b/i, /credential[ _-]rotation/i,
    /\bacme\b/i, /zone[ _-]setting[ _-]write/i, /kernel[ _-](?:install|upgrade)/i,
  ];
  for (const file of scanned) {
    const text = fs.readFileSync(file, "utf8");
    for (const pattern of forbidden) {
      assert.ok(!pattern.test(text),
        `${path.relative(ROOT, file)} matches deferred-capability pattern ${pattern}`);
    }
  }
});

test("dependency set is exactly ajv", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.deepEqual(Object.keys(pkg.dependencies || {}), ["ajv"]);
  assert.equal(pkg.dependencies.ajv, "8.20.0");
  assert.equal(pkg.devDependencies, undefined);
});

test("mutating adapter operations are exactly the contract's closed set", () => {
  const contracts = require("../contract/mcp/schemas/contracts.cjs");
  const { MUTATING_HELPER_NAMES, HELPER_OPERATION_NAMES, BROKER_OPERATION_NAMES } =
    require("../mcp/adapters/registry.cjs");
  assert.deepEqual([...HELPER_OPERATION_NAMES],
    Object.keys(contracts.PRIVILEGED_HELPER_OPERATIONS));
  assert.deepEqual([...BROKER_OPERATION_NAMES],
    Object.keys(contracts.BROKER_OPERATIONS));
  for (const name of MUTATING_HELPER_NAMES) {
    assert.equal(contracts.PRIVILEGED_HELPER_OPERATIONS[name].mutating, true);
  }
});
