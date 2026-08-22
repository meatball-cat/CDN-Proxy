"use strict";

// Per-user controlled runtime root. Product code self-locates from its
// installed directory and resolves the data root from the OS user profile at
// runtime; the session working directory is never state authority and no
// absolute deployment path is hard-coded into durable bytes.

const os = require("node:os");
const path = require("node:path");

const PRODUCT_DIR_NAME = "cdn-node-operator";

function resolveRuntimeRoot(env = process.env) {
  const override = env.CDN_NODE_OPERATOR_HOME;
  const root = override
    ? path.resolve(override)
    : path.join(os.homedir(), "Library", "Application Support", PRODUCT_DIR_NAME);
  return {
    root,
    dataDir: path.join(root, "data"),
    versionsDir: path.join(root, "versions"),
    activeSetPath: path.join(root, "active.json"),
  };
}

module.exports = { resolveRuntimeRoot, PRODUCT_DIR_NAME };
