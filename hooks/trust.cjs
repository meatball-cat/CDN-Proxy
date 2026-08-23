"use strict";

// Trust is installation evidence, not policy authority. Any ambiguity returns
// false; callers emit a fixed fail-closed message and never expose which path,
// digest, owner, mode, or runtime identity was rejected.

const fs = require("node:fs");
const path = require("node:path");
const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { sha256Digest } = require("../mcp/core/refs.cjs");
const {
  CORE_HOOK_POLICY_VERSION,
  HOOK_TRUST_FILES,
} = require("./catalog.cjs");

const INSTALL_ROOT = path.resolve(__dirname, "..");

function safeRealpath(target) {
  try {
    return fs.realpathSync(target);
  } catch {
    return null;
  }
}

function isOwnedAndNotWritableByOthers(target, expectedUid) {
  try {
    const link = fs.lstatSync(target);
    const stat = fs.statSync(target);
    if (link.isSymbolicLink()) return false;
    if (typeof expectedUid === "number" && stat.uid !== expectedUid) return false;
    return (stat.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

function readJson(target, maximumBytes = 1024 * 1024) {
  const stat = fs.statSync(target);
  if (!stat.isFile() || stat.size > maximumBytes) return null;
  const parsed = JSON.parse(fs.readFileSync(target, "utf8"));
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
}

function verifyHookTrust(env = process.env) {
  try {
    if (!env.PLUGIN_ROOT || !env.PLUGIN_DATA) return false;
    if (fs.lstatSync(env.PLUGIN_ROOT).isSymbolicLink() ||
        fs.lstatSync(env.PLUGIN_DATA).isSymbolicLink()) return false;
    const pluginRoot = safeRealpath(env.PLUGIN_ROOT);
    const installedRoot = safeRealpath(INSTALL_ROOT);
    if (!pluginRoot || pluginRoot !== installedRoot) return false;

    const paths = resolveRuntimeRoot(env);
    const runtimeRoot = safeRealpath(paths.root);
    const pluginData = safeRealpath(env.PLUGIN_DATA);
    if (!runtimeRoot || runtimeRoot !== pluginData) return false;

    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    if (!isOwnedAndNotWritableByOthers(pluginRoot, uid)) return false;
    if (!isOwnedAndNotWritableByOthers(runtimeRoot, uid)) return false;
    if (!isOwnedAndNotWritableByOthers(paths.activeSetPath, uid)) return false;

    const active = readJson(paths.activeSetPath);
    if (!active || active.installRoot !== installedRoot) return false;
    if (active.runtimeRoot !== runtimeRoot) return false;
    if (active.ownerUid !== uid) return false;
    if (active.policyVersion !== CORE_HOOK_POLICY_VERSION) return false;
    if (active.nodeExecutable !== safeRealpath(process.execPath)) return false;

    const receiptPath = path.join(paths.versionsDir, active.version, "receipt.json");
    if (!isOwnedAndNotWritableByOthers(receiptPath, uid)) return false;
    const receipt = readJson(receiptPath);
    if (!receipt || receipt.version !== active.version) return false;
    if (receipt.nodeMajor !== Number(process.versions.node.split(".")[0])) return false;
    if (sha256Digest(JSON.stringify(receipt)) !== active.receiptDigest) return false;
    if (!Array.isArray(receipt.files) || receipt.files.length !== HOOK_TRUST_FILES.length) return false;

    for (let index = 0; index < HOOK_TRUST_FILES.length; index += 1) {
      const relative = HOOK_TRUST_FILES[index];
      const item = receipt.files[index];
      if (!item || item.path !== relative) return false;
      const target = path.join(installedRoot, relative);
      if (!isOwnedAndNotWritableByOthers(target, uid)) return false;
      if (safeRealpath(target) !== target) return false;
      if (sha256Digest(fs.readFileSync(target)) !== item.sha256) return false;
    }
    return true;
  } catch {
    return false;
  }
}

module.exports = { verifyHookTrust };
