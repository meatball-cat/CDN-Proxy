"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, name), "utf8"));

test("package security guard: plugin manifest uses the accepted distributable shape", () => {
  const pkg = readJson("package.json");
  const manifest = readJson(".codex-plugin/plugin.json");
  assert.deepEqual(Object.keys(manifest), [
    "name", "version", "description", "author", "license", "keywords", "mcpServers", "interface",
  ]);
  assert.equal(pkg.name, "cdn-proxy");
  assert.equal(manifest.name, "cdn-proxy");
  assert.equal(manifest.mcpServers, "./.mcp.json");
  assert.equal(manifest.author.name, "CDN-Proxy Contributors");
  for (const field of ["displayName", "shortDescription", "longDescription", "developerName", "category", "capabilities", "defaultPrompt"]) {
    assert.ok(manifest.interface[field], `manifest interface missing ${field}`);
  }
  assert.match(manifest.description, /Phase 0-6 source candidate/);
  for (const token of ["INSTALLABLE", "RUNNABLE", "ACCEPTED"]) {
    assert.match(manifest.description, new RegExp(`${token}: NOT_CLAIMED`));
  }
});

test("package security guard: npm dry-run contains only the audited release surface", () => {
  const packed = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(packed.status, 0, packed.stderr);
  const report = JSON.parse(packed.stdout)[0];
  const files = report.files.map((file) => file.path).sort();
  const required = [
    ".codex-plugin/plugin.json", ".mcp.json", "DEPENDENCIES.json", "README.md",
    "hooks/hooks.json", "lifecycle/install.cjs", "mcp/server.cjs",
    "node_modules/ajv/package.json", "package.json", "runtime/root.cjs",
    "skills/cdn-proxy/SKILL.md",
  ];
  for (const name of required) assert.ok(files.includes(name), `package missing ${name}`);
  for (const name of files) {
    assert.ok(!path.isAbsolute(name), `absolute package entry: ${name}`);
    assert.ok(!name.startsWith("tests/") && !name.startsWith("acceptance/") &&
      !name.startsWith("scripts/"), `non-release entry: ${name}`);
  }
  assert.equal(files.length, new Set(files).size);
});

test("package security guard: generated tarball has safe entries, modes, and source bytes", (t) => {
  const temporary = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "cdn-package-audit-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const packed = spawnSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", temporary], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(packed.status, 0, packed.stderr);
  const tarball = path.join(temporary, JSON.parse(packed.stdout)[0].filename);
  const names = spawnSync("tar", ["-tzf", tarball], { encoding: "utf8", timeout: 30000 });
  assert.equal(names.status, 0, names.stderr);
  for (const name of names.stdout.trim().split("\n")) {
    assert.match(name, /^package\//, `package security guard: entry escaped prefix: ${name}`);
    assert.ok(!name.includes("../") && !path.isAbsolute(name));
  }
  const verbose = spawnSync("tar", ["-tvzf", tarball], { encoding: "utf8", timeout: 30000 });
  assert.equal(verbose.status, 0, verbose.stderr);
  for (const line of verbose.stdout.trim().split("\n")) {
    const mode = line.split(/\s+/, 1)[0];
    assert.match(mode, /^[d-][rwx-]{9}[+@.]?$/, `package security guard: nonregular entry: ${line}`);
    assert.notEqual(mode[5], "w", `package security guard: group-writable entry: ${line}`);
    assert.notEqual(mode[8], "w", `package security guard: world-writable entry: ${line}`);
  }
  const extract = path.join(temporary, "extract");
  fs.mkdirSync(extract);
  const unpacked = spawnSync("tar", ["-xzf", tarball, "-C", extract], {
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(unpacked.status, 0, unpacked.stderr);
  const ownFiles = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      assert.ok(!entry.isSymbolicLink(), `package security guard: symlink entry ${entry.name}`);
      if (entry.isDirectory()) walk(target);
      else if (!target.includes(`${path.sep}node_modules${path.sep}`)) ownFiles.push(target);
    }
  };
  walk(path.join(extract, "package"));
  const privateContainer = new RegExp(["-----BEGIN", "PRIVATE", "KEY-----"].join(" "));
  for (const file of ownFiles.filter((name) => /\.(?:cjs|json|md)$/.test(name))) {
    const source = fs.readFileSync(file, "utf8");
    assert.ok(!privateContainer.test(source), `package security guard: private container in ${file}`);
    assert.ok(!/\/Users\/[a-z0-9_-]+\//i.test(source), `package security guard: user path in ${file}`);
    assert.ok(!/\/home\/[a-z0-9_-]+\//i.test(source), `package security guard: home path in ${file}`);
  }
});

test("package security guard: dependency audit manifest equals the lock closure", () => {
  const pkg = readJson("package.json");
  const lock = readJson("package-lock.json");
  const audit = readJson("DEPENDENCIES.json");
  const locked = Object.entries(lock.packages)
    .filter(([name]) => name.startsWith("node_modules/"))
    .map(([name, value]) => ({
      name: name.slice("node_modules/".length),
      version: value.version,
      license: value.license,
      integrity: value.integrity,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  assert.deepEqual(audit.dependencies, locked);
  assert.deepEqual(audit.directDependencies, pkg.dependencies);
  assert.deepEqual(pkg.bundleDependencies, ["ajv"]);
  assert.equal(audit.generatedFrom, "package-lock.json");
});
