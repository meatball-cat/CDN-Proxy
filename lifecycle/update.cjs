#!/usr/bin/env node
"use strict";

const { update } = require("./activeset.cjs");

if (require.main === module) {
  try {
    const version = process.argv[2];
    const { paths, receipt } = update({ version });
    process.stdout.write(JSON.stringify({
      ok: true, root: paths.root, version: receipt.version,
    }, null, 2) + "\n");
  } catch (error) {
    process.stdout.write(JSON.stringify({ ok: false, error: error.message }) + "\n");
    process.exit(1);
  }
}
