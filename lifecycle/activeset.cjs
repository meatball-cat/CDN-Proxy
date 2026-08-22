"use strict";

// ActiveSet lifecycle state machine: atomic bootstrap, update, explicit
// rollback, and uninstall over the controlled runtime root. Guarantees:
// no-clobber (install never overwrites an existing owned ActiveSet or any
// foreign file), atomic promotion via write-temp-then-rename, explicit
// rollback only to the recorded previous version, and uninstall that removes
// only owned files while preserving user data (ledger, artifacts) unless the
// caller explicitly requests a purge.

const fs = require("node:fs");
const path = require("node:path");
const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { sha256Digest } = require("../mcp/core/refs.cjs");

const PRODUCT_VERSION = require("../package.json").version;

function installRootOfThisBuild() {
  return path.resolve(__dirname, "..");
}

function layoutReceipt(version) {
  const installRoot = installRootOfThisBuild();
  const covered = [
    "contract/PROVENANCE.json",
    "contract/shared/schema-primitives.cjs",
    "contract/mcp/schemas/contracts.cjs",
    ".mcp.json",
  ];
  return {
    version,
    nodeMajor: Number(process.versions.node.split(".")[0]),
    createdAt: new Date().toISOString(),
    files: covered.map((relative) => ({
      path: relative,
      sha256: sha256Digest(fs.readFileSync(path.join(installRoot, relative))),
    })),
  };
}

function readActiveSet(paths) {
  if (!fs.existsSync(paths.activeSetPath)) return null;
  return JSON.parse(fs.readFileSync(paths.activeSetPath, "utf8"));
}

function writeActiveSetAtomic(paths, activeSet) {
  const temp = `${paths.activeSetPath}.tmp-${process.pid}`;
  fs.writeFileSync(temp, JSON.stringify(activeSet, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(temp, paths.activeSetPath);
}

function cleanStagingResidue(paths) {
  if (!fs.existsSync(paths.versionsDir)) return [];
  const removed = [];
  for (const entry of fs.readdirSync(paths.versionsDir)) {
    if (entry.endsWith(".staging")) {
      fs.rmSync(path.join(paths.versionsDir, entry), { recursive: true, force: true });
      removed.push(entry);
    }
  }
  for (const entry of fs.readdirSync(paths.root)) {
    if (entry.startsWith("active.json.tmp-")) {
      fs.rmSync(path.join(paths.root, entry), { force: true });
      removed.push(entry);
    }
  }
  return removed;
}

function stageVersion(paths, version) {
  const finalDir = path.join(paths.versionsDir, version);
  if (fs.existsSync(finalDir)) {
    throw new Error(`no-clobber: version ${version} already exists in the runtime root`);
  }
  const stagingDir = `${finalDir}.staging`;
  fs.rmSync(stagingDir, { recursive: true, force: true });
  fs.mkdirSync(stagingDir, { recursive: true, mode: 0o700 });
  const receipt = layoutReceipt(version);
  fs.writeFileSync(path.join(stagingDir, "receipt.json"),
    JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(stagingDir, finalDir);
  return receipt;
}

function install({ env = process.env, version = PRODUCT_VERSION } = {}) {
  const paths = resolveRuntimeRoot(env);
  fs.mkdirSync(paths.root, { recursive: true, mode: 0o700 });
  fs.mkdirSync(paths.versionsDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(paths.dataDir, { recursive: true, mode: 0o700 });
  cleanStagingResidue(paths);
  const existing = readActiveSet(paths);
  if (existing) {
    throw new Error(
      `no-clobber: an ActiveSet (version ${existing.version}) already owns this runtime root; use update`,
    );
  }
  const receipt = stageVersion(paths, version);
  writeActiveSetAtomic(paths, {
    version,
    previous: null,
    installRoot: installRootOfThisBuild(),
    receiptDigest: sha256Digest(JSON.stringify(receipt)),
    promotedAt: new Date().toISOString(),
  });
  return { paths, receipt };
}

function update({ env = process.env, version } = {}) {
  const paths = resolveRuntimeRoot(env);
  cleanStagingResidue(paths);
  const existing = readActiveSet(paths);
  if (!existing) throw new Error("update requires an installed ActiveSet");
  if (!version || version === existing.version) {
    throw new Error("update requires a new distinct version identifier");
  }
  const receipt = stageVersion(paths, version);
  writeActiveSetAtomic(paths, {
    version,
    previous: existing.version,
    installRoot: installRootOfThisBuild(),
    receiptDigest: sha256Digest(JSON.stringify(receipt)),
    promotedAt: new Date().toISOString(),
  });
  return { paths, receipt };
}

// Rollback is explicit-only: it promotes exactly the recorded previous
// version and never guesses or deletes user data.
function rollback({ env = process.env } = {}) {
  const paths = resolveRuntimeRoot(env);
  const existing = readActiveSet(paths);
  if (!existing) throw new Error("rollback requires an installed ActiveSet");
  if (!existing.previous) throw new Error("no recorded previous version to roll back to");
  const previousReceiptPath = path.join(paths.versionsDir, existing.previous, "receipt.json");
  if (!fs.existsSync(previousReceiptPath)) {
    throw new Error(`previous version ${existing.previous} receipt is missing; manual recovery required`);
  }
  const receipt = JSON.parse(fs.readFileSync(previousReceiptPath, "utf8"));
  writeActiveSetAtomic(paths, {
    version: existing.previous,
    previous: null,
    installRoot: installRootOfThisBuild(),
    receiptDigest: sha256Digest(JSON.stringify(receipt)),
    promotedAt: new Date().toISOString(),
    rolledBackFrom: existing.version,
  });
  return { paths, receipt };
}

function uninstall({ env = process.env, purgeData = false } = {}) {
  const paths = resolveRuntimeRoot(env);
  const existing = readActiveSet(paths);
  if (!existing) throw new Error("uninstall requires an installed ActiveSet");
  fs.rmSync(paths.versionsDir, { recursive: true, force: true });
  fs.rmSync(paths.activeSetPath, { force: true });
  if (purgeData) {
    fs.rmSync(paths.dataDir, { recursive: true, force: true });
  }
  // Remove the root only if nothing foreign remains inside it.
  const remaining = fs.existsSync(paths.root) ? fs.readdirSync(paths.root) : [];
  if (remaining.length === 0) fs.rmSync(paths.root, { recursive: true, force: true });
  return { paths, dataPreserved: !purgeData };
}

module.exports = {
  PRODUCT_VERSION, install, update, rollback, uninstall,
  readActiveSet, cleanStagingResidue, layoutReceipt,
};
