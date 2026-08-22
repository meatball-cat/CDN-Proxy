#!/usr/bin/env node
"use strict";

// Explicit rollback only: promotes exactly the recorded previous ActiveSet.

const { rollback } = require("./activeset.cjs");

if (require.main === module) {
  try {
    const { paths, receipt } = rollback();
    process.stdout.write(JSON.stringify({
      ok: true, root: paths.root, version: receipt.version,
    }, null, 2) + "\n");
  } catch (error) {
    process.stdout.write(JSON.stringify({ ok: false, error: error.message }) + "\n");
    process.exit(1);
  }
}
