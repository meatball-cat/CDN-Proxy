#!/usr/bin/env node
"use strict";

// Uninstall removes only owned lifecycle files. User data (ledger, evidence,
// artifacts) is preserved unless --purge-data is passed explicitly.

const { uninstall } = require("./activeset.cjs");

if (require.main === module) {
  try {
    const purgeData = process.argv.includes("--purge-data");
    const { dataPreserved } = uninstall({ purgeData });
    process.stdout.write(JSON.stringify({ ok: true, dataPreserved }) + "\n");
  } catch (error) {
    process.stdout.write(JSON.stringify({ ok: false, error: error.message }) + "\n");
    process.exit(1);
  }
}
