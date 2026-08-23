"use strict";

// Hook state is a disposable, per-session replay cache. It contains only
// event digests and opaque plan projections. It is never server truth and it
// is intentionally outside the ledger/data directory.

const fs = require("node:fs");
const path = require("node:path");
const { resolveRuntimeRoot } = require("../runtime/root.cjs");
const { digestOf } = require("../mcp/core/refs.cjs");

function statePaths(env, sessionId) {
  const root = resolveRuntimeRoot(env).root;
  const stateRoot = path.join(root, "hook-state");
  const sessionDigest = digestOf({ sessionId }).slice("sha256:".length);
  return {
    root,
    stateRoot,
    lockPath: path.join(stateRoot, ".lock"),
    sessionPath: path.join(stateRoot, `${sessionDigest}.json`),
    sessionDigest: `sha256:${sessionDigest}`,
  };
}

function defaultRecord(sessionDigest) {
  return {
    version: 1,
    session_digest: sessionDigest,
    event_digests: [],
    recorded_at: null,
    plan_projection: null,
    server_projection: null,
  };
}

function safeOwnedFile(target, expectedMode) {
  const link = fs.lstatSync(target);
  const stat = fs.statSync(target);
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  return !link.isSymbolicLink() && (uid === null || stat.uid === uid) &&
    (stat.mode & 0o777) === expectedMode;
}

function ensureRoot(paths) {
  fs.mkdirSync(paths.stateRoot, { recursive: true, mode: 0o700 });
  if (!safeOwnedFile(paths.stateRoot, 0o700)) throw new Error("hook-state-owner-mode");
  const realRoot = fs.realpathSync(paths.root);
  const realState = fs.realpathSync(paths.stateRoot);
  if (path.dirname(realState) !== realRoot) throw new Error("hook-state-boundary");
}

function readRecord(paths) {
  if (!fs.existsSync(paths.sessionPath)) return defaultRecord(paths.sessionDigest);
  if (!safeOwnedFile(paths.sessionPath, 0o600)) throw new Error("hook-state-owner-mode");
  const record = JSON.parse(fs.readFileSync(paths.sessionPath, "utf8"));
  if (!record || record.version !== 1 || record.session_digest !== paths.sessionDigest) {
    throw new Error("hook-state-invalid");
  }
  return record;
}

function writeRecord(paths, record) {
  const temporary = `${paths.sessionPath}.tmp-${process.pid}`;
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, JSON.stringify(record) + "\n");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, paths.sessionPath);
  const directory = fs.openSync(paths.stateRoot, "r");
  try {
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(directory);
  }
}

function withSessionState(env, sessionId, eventDigest, update) {
  const paths = statePaths(env, sessionId);
  ensureRoot(paths);
  const lock = fs.openSync(paths.lockPath, "wx", 0o600);
  try {
    const record = readRecord(paths);
    if (!record.event_digests.includes(eventDigest)) {
      const next = update(record) || record;
      next.event_digests = [...next.event_digests, eventDigest].slice(-64);
      next.recorded_at = new Date().toISOString();
      writeRecord(paths, next);
      return { record: next, replayed: false };
    }
    return { record, replayed: true };
  } finally {
    fs.closeSync(lock);
    fs.rmSync(paths.lockPath, { force: true });
  }
}

function readSessionState(env, sessionId) {
  const paths = statePaths(env, sessionId);
  if (!fs.existsSync(paths.sessionPath)) return defaultRecord(paths.sessionDigest);
  return readRecord(paths);
}

function cleanupSessionState(env, sessionId) {
  const paths = statePaths(env, sessionId);
  if (!fs.existsSync(paths.stateRoot)) return;
  const lock = fs.openSync(paths.lockPath, "wx", 0o600);
  try {
    fs.rmSync(paths.sessionPath, { force: true });
  } finally {
    fs.closeSync(lock);
    fs.rmSync(paths.lockPath, { force: true });
  }
  if (fs.readdirSync(paths.stateRoot).length === 0) fs.rmdirSync(paths.stateRoot);
}

module.exports = { withSessionState, readSessionState, cleanupSessionState };
