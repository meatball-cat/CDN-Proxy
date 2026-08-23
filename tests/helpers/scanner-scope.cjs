"use strict";

// Shared scanner scope.
//
// A static scanner necessarily spells out the patterns it hunts for, so the
// scanner files are the only files excluded from the package-byte scans.
// Keeping the list in one place means neither scanner can quietly exempt
// anything else, and both scanners cover each other's non-pattern bytes.

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..", "..");

const SCANNER_FILES = Object.freeze([
  path.join(ROOT, "tests", "security-scan.test.cjs"),
  path.join(ROOT, "tests", "negative-security.test.cjs"),
]);

for (const file of SCANNER_FILES) {
  if (!fs.existsSync(file)) throw new Error(`declared scanner file is missing: ${file}`);
}

// Developer tooling that drives the product from outside. It is scoped out
// of the product-code bans (it must spawn processes to run the suite) but is
// pinned to one known file so nothing can hide there.
const TOOLING_SOURCE = Object.freeze(["scripts/acceptance.cjs"]);

function isScannerFile(file) {
  return SCANNER_FILES.includes(path.resolve(file));
}

function isToolingFile(file) {
  const relative = path.relative(ROOT, path.resolve(file)).split(path.sep).join("/");
  return TOOLING_SOURCE.includes(relative);
}

module.exports = { ROOT, SCANNER_FILES, TOOLING_SOURCE, isScannerFile, isToolingFile };
