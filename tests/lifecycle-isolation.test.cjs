"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { install, update, rollback, uninstall } = require("../lifecycle/activeset.cjs");
const { PRODUCT_DIR_NAME, resolveRuntimeRoot } = require("../runtime/root.cjs");

test("runtime identity guard: cdn-proxy uses its own explicit runtime root", () => {
  const root = path.join(os.tmpdir(), "cdn-proxy-runtime-identity");
  const resolved = resolveRuntimeRoot({ CDN_PROXY_HOME: root });
  assert.equal(PRODUCT_DIR_NAME, "cdn-proxy");
  assert.equal(resolved.root, path.resolve(root));
});

test("lifecycle isolation guard: every owned write stays under the explicit runtime root", (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-lifecycle-boundary-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const root = path.join(parent, "runtime");
  const sentinel = path.join(parent, "foreign.keep");
  fs.writeFileSync(sentinel, "foreign");
  const env = { CDN_PROXY_HOME: root };
  install({ env, version: "0.1.0-boundary" });
  update({ env, version: "0.2.0-boundary" });
  rollback({ env });
  uninstall({ env });
  assert.deepEqual(fs.readdirSync(parent).sort(), ["foreign.keep", "runtime"]);
  assert.equal(fs.readFileSync(sentinel, "utf8"), "foreign");
  assert.deepEqual(fs.readdirSync(root), ["data"]);
});
