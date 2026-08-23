#!/usr/bin/env node
"use strict";

// Red/green mutation harness. Every control copies the candidate without its
// VCS metadata, applies one named guard mutation, requires the smallest mapped
// test to fail with a guard-specific message, removes the copy, then proves the
// unmodified candidate passes the same test.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");

const CONTROLS = Object.freeze({
  "hook-catalog-event": {
    test: "tests/hooks-catalog.test.cjs",
    failure: "Hook catalog guard",
    mutate(copy) {
      const target = path.join(copy, "hooks", "hooks.json");
      const config = JSON.parse(fs.readFileSync(target, "utf8"));
      delete config.hooks.PostToolUse;
      fs.writeFileSync(target, JSON.stringify(config, null, 2) + "\n");
    },
  },
  "hook-authority-widening": {
    test: "tests/hooks-security.test.cjs",
    failure: "Hook authority guard",
    mutate(copy) {
      replaceOnce(
        path.join(copy, "hooks", "policy.cjs"),
        'if (!tool) return { denied: "HOOK_DENY_NOT_ACTIVE_CATALOG" };',
        'if (!tool) return { tool: "run_status" }; if (tool === "run_status") return { tool };',
      );
    },
  },
  "hook-output-leak": {
    test: "tests/hooks-security.test.cjs",
    failure: "Hook redaction guard",
    mutate(copy) {
      replaceOnce(
        path.join(copy, "hooks", "policy.cjs"),
        'if (hasOutputLeak(input.tool_response)) return postBlock("HOOK_REDACTION_TRIPWIRE");',
        'if (false && hasOutputLeak(input.tool_response)) return postBlock("HOOK_REDACTION_TRIPWIRE");',
      );
    },
  },
});

function replaceOnce(target, before, after) {
  const source = fs.readFileSync(target, "utf8");
  const first = source.indexOf(before);
  if (first < 0 || source.indexOf(before, first + before.length) >= 0) {
    throw new Error("mutation anchor guard: expected exactly one source match");
  }
  fs.writeFileSync(target, source.slice(0, first) + after + source.slice(first + before.length));
}

function runTest(cwd, testFile) {
  return spawnSync(process.execPath, ["--test", testFile], {
    cwd,
    encoding: "utf8",
    env: { ...process.env },
    timeout: 30000,
  });
}

function makeCopy() {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-negative-control-"));
  const copy = path.join(temporary, "candidate");
  fs.cpSync(ROOT, copy, {
    recursive: true,
    filter(source) {
      const relative = path.relative(ROOT, source);
      return relative !== ".git" && relative !== "node_modules" &&
        !relative.startsWith(`.git${path.sep}`) &&
        !relative.startsWith(`node_modules${path.sep}`);
    },
  });
  fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(copy, "node_modules"), "dir");
  return { temporary, copy };
}

function main() {
  const name = process.argv[2];
  const control = CONTROLS[name];
  if (!control) {
    process.stderr.write(`unknown control; expected one of: ${Object.keys(CONTROLS).join(", ")}\n`);
    process.exitCode = 2;
    return;
  }

  const { temporary, copy } = makeCopy();
  try {
    control.mutate(copy);
    const broken = runTest(copy, control.test);
    const brokenText = `${broken.stdout || ""}\n${broken.stderr || ""}`;
    if (broken.status === 0 || !brokenText.includes(control.failure)) {
      process.stderr.write("negative control guard: broken copy did not fail as required\n");
      process.exitCode = 1;
      return;
    }
    process.stdout.write(`${name}: BROKEN_COPY_FAIL exit=${broken.status} guard=${control.failure}\n`);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }

  const restored = runTest(ROOT, control.test);
  if (restored.status !== 0) {
    process.stderr.write(restored.stdout || "");
    process.stderr.write(restored.stderr || "");
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`${name}: RESTORED_CANDIDATE_PASS exit=0\n`);
}

main();
