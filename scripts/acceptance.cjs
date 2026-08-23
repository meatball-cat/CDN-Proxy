"use strict";

// Independent acceptance runner.
//
// Re-verifies the frozen handoff package (read-only), re-runs its invariant
// validator, runs the full test suite, re-extracts and byte-compares the
// vendored contract, and runs doctor against a throwaway runtime root. Every
// step's real output is written to acceptance/RESULTS.log; nothing here can
// report a pass it did not observe.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SPEC_DIR = process.env.CDN_OPERATOR_HANDOFF_DIR ||
  path.resolve(ROOT, "..", "3x-ui-cdn-operator-development-handoff");
const OUT = path.join(ROOT, "acceptance", "RESULTS.log");

const lines = [];
function section(title) {
  lines.push("", `--- ${title} ---`);
  process.stdout.write(`\n--- ${title} ---\n`);
}
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trimEnd();
  lines.push(output);
  process.stdout.write(`${output}\n`);
  return { status: result.status, output };
}

const failures = [];
function expectZero(label, result) {
  if (result.status !== 0) failures.push(`${label} exited ${result.status}`);
}

lines.push("=== Core-v1 Phase 0-6 source acceptance run ===");
lines.push(`date: ${new Date().toISOString()}`);
lines.push(`node: ${process.version}`);
lines.push(`handoff: ${SPEC_DIR}`);

section("[1] frozen handoff checksum re-verification (must stay 8/8, untouched)");
expectZero("checksums", run("shasum", ["-a", "256", "-c", "SHA256SUMS.txt"], { cwd: SPEC_DIR }));

section("[2] frozen spec-invariants re-run (read-only)");
expectZero("spec-invariants",
  run(process.execPath, ["validation/spec-invariants.cjs", "--all"], { cwd: SPEC_DIR }));

section("[3] full test suite");
const suite = run(process.execPath,
  ["--test", ...fs.readdirSync(path.join(ROOT, "tests"))
    .filter((name) => name.endsWith(".test.cjs"))
    .sort()
    .map((name) => path.join("tests", name))],
  { cwd: ROOT });
expectZero("tests", suite);

section("[4] contract parity verify (re-extraction byte-compare)");
expectZero("contract-parity", run(process.execPath, ["lifecycle/verify.cjs"], {
  cwd: ROOT,
  env: { ...process.env, CDN_OPERATOR_SPEC_PATH: path.join(SPEC_DIR, "02-mcp-tool-plan.md") },
}));

section("[5] doctor on a fresh temp runtime root");
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-operator-acceptance-"));
expectZero("doctor", run(process.execPath, ["lifecycle/doctor.cjs"], {
  cwd: ROOT,
  env: { ...process.env, CDN_NODE_OPERATOR_HOME: tempRoot },
}));
fs.rmSync(tempRoot, { recursive: true, force: true });

section("[6] frozen package unchanged after the run");
expectZero("checksums-after", run("shasum", ["-a", "256", "-c", "SHA256SUMS.txt"], { cwd: SPEC_DIR }));

section("summary");
const verdict = failures.length === 0
  ? "all acceptance steps exited 0"
  : `FAILURES: ${failures.join("; ")}`;
lines.push(verdict);
process.stdout.write(`${verdict}\n`);

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${lines.join("\n")}\n`);
process.exit(failures.length === 0 ? 0 : 1);
