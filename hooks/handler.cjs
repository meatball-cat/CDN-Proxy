#!/usr/bin/env node
"use strict";

// A bounded stdio adapter around the pure runner. It emits one closed JSON
// object and intentionally suppresses raw parser/runtime errors.

const { runHook } = require("./runner.cjs");

const MAX_INPUT_BYTES = 64 * 1024;
const event = process.argv[2] || "";
let bytes = 0;
let body = "";
let rejected = false;

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  bytes += Buffer.byteLength(chunk);
  if (bytes > MAX_INPUT_BYTES) {
    rejected = true;
    body = "";
    return;
  }
  if (!rejected) body += chunk;
});
process.stdin.on("end", () => {
  let input = null;
  if (!rejected) {
    try {
      input = JSON.parse(body);
    } catch {
      input = null;
    }
  }
  process.stdout.write(`${JSON.stringify(runHook(event, input))}\n`);
});
process.stdin.resume();
