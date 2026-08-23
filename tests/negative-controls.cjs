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
  "manifest-phase": {
    test: "tests/phase-metadata.test.cjs",
    failure: "phase metadata guard",
    mutate(copy) {
      const target = path.join(copy, ".codex-plugin", "plugin.json");
      const manifest = JSON.parse(fs.readFileSync(target, "utf8"));
      manifest.version = "0.1.0-phase1";
      fs.writeFileSync(target, JSON.stringify(manifest, null, 2) + "\n");
    },
  },
  "lock-or-server-version": {
    test: "tests/phase-metadata.test.cjs",
    failure: "phase metadata guard",
    variants: [
      {
        label: "package-lock",
        failure: "phase metadata guard",
        mutate(copy) {
          const target = path.join(copy, "package-lock.json");
          const lock = JSON.parse(fs.readFileSync(target, "utf8"));
          lock.version = "0.1.0-phase1";
          lock.packages[""].version = "0.1.0-phase1";
          fs.writeFileSync(target, JSON.stringify(lock, null, 2) + "\n");
        },
      },
      {
        label: "server-info",
        failure: "initialize version guard",
        mutate(copy) {
          replaceOnce(
            path.join(copy, "mcp", "core", "server-core.cjs"),
            'const SERVER_VERSION = require("../../package.json").version;',
            'const SERVER_VERSION = "0.1.0-phase1";',
          );
        },
      },
    ],
  },
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
  "package-security": {
    test: "tests/package-release.test.cjs",
    failure: "package security guard",
    mutate(copy) {
      const marker = ["-----BEGIN", "PRIVATE", "KEY-----"].join(" ");
      const userPath = ["", "Users", "synthetic-user", "deploy", "config"].join(path.sep);
      fs.writeFileSync(
        path.join(copy, "hooks", "unsafe-package-fixture.cjs"),
        `"use strict";\n// ${marker}\n// ${userPath}\n`,
      );
    },
  },
  "mcp-catalog-parity": {
    test: "tests/mcp-protocol.test.cjs",
    failure: "MCP catalog guard",
    mutate(copy) {
      replaceOnce(
        path.join(copy, "mcp", "core", "server-core.cjs"),
        "return contracts.TOOL_LIST.map((tool) => ({",
        "return contracts.TOOL_LIST.slice(1).map((tool) => ({",
      );
    },
  },
  "lifecycle-isolation": {
    test: "tests/lifecycle-isolation.test.cjs",
    failure: "lifecycle isolation guard",
    mutate(copy) {
      replaceOnce(
        path.join(copy, "runtime", "root.cjs"),
        "dataDir: path.join(root, \"data\"),",
        "dataDir: path.join(path.dirname(root), \"escaped-data\"),",
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

  const variants = control.variants || [control];
  for (const variant of variants) {
    const { temporary, copy } = makeCopy();
    try {
      variant.mutate(copy);
      const broken = runTest(copy, control.test);
      const brokenText = `${broken.stdout || ""}\n${broken.stderr || ""}`;
      const requiredFailure = variant.failure || control.failure;
      if (broken.status === 0 || !brokenText.includes(requiredFailure)) {
        process.stderr.write("negative control guard: broken copy did not fail as required\n");
        process.exitCode = 1;
        return;
      }
      const variantLabel = variant.label ? ` variant=${variant.label}` : "";
      process.stdout.write(
        `${name}:${variantLabel} BROKEN_COPY_FAIL exit=${broken.status} guard=${requiredFailure}\n`,
      );
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
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
