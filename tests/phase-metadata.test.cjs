"use strict";

// Acceptance: the user-visible phase labels cannot diverge again. The
// package version suffix is the single declaration of the implemented phase
// range; the plugin manifest, the Skill, and the README must all name that
// same range, and none of them may upgrade a source-only build into a claim
// about real infrastructure.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

const readText = (...parts) => fs.readFileSync(path.join(ROOT, ...parts), "utf8");

const PACKAGE_TEXT = readText("package.json");
const MANIFEST_TEXT = readText(".codex-plugin", "plugin.json");
const SKILL_TEXT = readText("skills", "cdn-node-operator", "SKILL.md");
const README_TEXT = readText("README.md");

const pkg = JSON.parse(PACKAGE_TEXT);
const manifest = JSON.parse(MANIFEST_TEXT);

// "Phase 0-4" / "Phases 0-4", hyphen or en dash, case-insensitive.
const PHASE_RANGE = /\bPhases?\s*0\s*[-\u2013]\s*(\d+)/gi;

function declaredRanges(text) {
  return [...text.matchAll(PHASE_RANGE)].map((match) => Number(match[1]));
}

test("the package version suffix declares the implemented phase range", () => {
  const parsed = /^\d+\.\d+\.\d+-phase(\d+)$/.exec(pkg.version);
  assert.ok(parsed, `package version must end in -phase<N>, found ${pkg.version}`);
  assert.equal(manifest.version, pkg.version);
  assert.equal(manifest.status.phase, `PHASE_0_${parsed[1]}_ONLY`);
});

test("manifest, Skill, README, and package all name the same phase range", () => {
  const highest = Number(/-phase(\d+)$/.exec(pkg.version)[1]);
  const documents = {
    "package.json": PACKAGE_TEXT,
    ".codex-plugin/plugin.json": MANIFEST_TEXT,
    "skills/cdn-node-operator/SKILL.md": SKILL_TEXT,
    "README.md": README_TEXT,
  };
  for (const [name, text] of Object.entries(documents)) {
    const ranges = declaredRanges(text);
    assert.ok(ranges.length > 0, `${name} states no Phase 0-N range`);
    for (const range of ranges) {
      assert.equal(range, highest,
        `${name} states Phase 0-${range} but the build implements Phase 0-${highest}`);
    }
  }
});

test("the three honest-scope claims stay unclaimed everywhere they appear", () => {
  assert.equal(manifest.status.installable, "NOT_CLAIMED");
  assert.equal(manifest.status.runnable, "NOT_CLAIMED");
  assert.equal(manifest.status.accepted, "NOT_CLAIMED");
  for (const [name, text] of Object.entries({
    "skills/cdn-node-operator/SKILL.md": SKILL_TEXT,
    "README.md": README_TEXT,
  })) {
    for (const token of ["INSTALLABLE", "RUNNABLE", "ACCEPTED"]) {
      assert.match(text, new RegExp(`\\b${token}\\b`), `${name} drops the ${token} claim`);
    }
    assert.equal((text.match(/NOT_CLAIMED/g) || []).length, 3,
      `${name} must mark exactly the three claims NOT_CLAIMED`);
  }
});

test("the Skill scopes Phase 0-4 to source and hermetic fake adapters", () => {
  // Markdown wraps these phrases across lines, so match across whitespace.
  assert.match(SKILL_TEXT, /hermetic\s+fake\s+adapters/i);
  assert.match(SKILL_TEXT, /not\s+a\s+real\s+run/i);
  assert.match(SKILL_TEXT, /phase-gated/i);
  assert.match(SKILL_TEXT, /fails\s+closed/i);
});
