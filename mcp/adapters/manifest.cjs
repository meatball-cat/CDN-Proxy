"use strict";

// Supported-host and installer-adapter manifest.
//
// Core-v1 installs 3x-ui on a clean host through exactly one build-time
// allowlisted, digest-pinned, versioned adapter. The manifest below is the
// sole authority for which adapter may run: it is frozen at build time,
// resolved server-side from immutable inventory facts, and is never
// influenced by caller input. There is no command, argv, script, URL, path,
// username, password, port, payload, or source field anywhere in this file,
// and nothing here can be extended at runtime.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");

// Caller-supplied keys that may never appear on an installer input. Derived
// from the frozen XUI_INSTALL_POLICY so no second list exists.
const CALLER_FORBIDDEN_FIELDS = contracts.XUI_INSTALL_POLICY.callerForbiddenFields;

// Host families this build is willing to install on at all. An unsupported
// or unknown family denies before any plan, lease, or write.
const SUPPORTED_OS_FAMILIES = Object.freeze(["debian", "ubuntu"]);

// The build-time allowlist. `digest` pins the exact adapter bytes; the
// helper must report this digest back on every install readback. Adding a
// row is a build-time source change, never a runtime or caller action.
const PINNED_INSTALL_ADAPTERS = Object.freeze([
  Object.freeze({
    adapter_id: "xui-install-adapter",
    version: "2.6.2",
    os_families: Object.freeze(["debian", "ubuntu"]),
    digest: "sha256:3b2f4a6c8d1e0f7a5b9c3d2e4f6a8b0c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f01",
    helper_operation: "origin.xui_install_owned.v1",
    readback_operation: "origin.xui_install_readback.v1",
    uninstall_operation: "origin.xui_uninstall_owned.v1",
    broker_operation: "xui.install_generate_store_admin_secret",
  }),
]);

const PINNED_DIGESTS = Object.freeze(PINNED_INSTALL_ADAPTERS.map((row) => row.digest));

// Structural guard: prove at load time that the manifest cannot smuggle a
// caller-controllable execution field into the installer path.
for (const row of PINNED_INSTALL_ADAPTERS) {
  for (const key of Object.keys(row)) {
    if (CALLER_FORBIDDEN_FIELDS.includes(key)) {
      throw new Error(`install manifest row exposes forbidden execution field ${key}`);
    }
  }
  if (row.helper_operation !== contracts.XUI_INSTALL_POLICY.helperOperation ||
      row.broker_operation !== contracts.XUI_INSTALL_POLICY.brokerOperation) {
    throw new Error("install manifest row is not bound to the frozen contract operations");
  }
}

function isSupportedOsFamily(osFamily) {
  return SUPPORTED_OS_FAMILIES.includes(osFamily);
}

// Resolves the sole eligible pinned adapter from server-held inventory facts.
// Returns null when the host is not installable; callers turn that into the
// contract's INSTALL_NOT_ELIGIBLE / INSTALL_ADAPTER_UNTRUSTED denial before
// any plan, lease, or side effect.
function resolvePinnedAdapter(originObservation) {
  if (!originObservation || !isSupportedOsFamily(originObservation.os_family)) return null;
  const eligible = PINNED_INSTALL_ADAPTERS.filter((row) =>
    row.os_families.includes(originObservation.os_family));
  // Ambiguity is a denial, not a choice: exactly one row may match.
  return eligible.length === 1 ? eligible[0] : null;
}

function requirePinnedAdapter(originObservation) {
  const adapter = resolvePinnedAdapter(originObservation);
  if (!adapter) {
    throw new ToolError("INSTALL_ADAPTER_UNTRUSTED",
      "no single build-time allowlisted digest-pinned installer adapter is eligible for this host");
  }
  return adapter;
}

// Post-write trust check. A digest outside the frozen allowlist means bytes
// of unknown provenance are on the host: never adopted, never overwritten,
// always surfaced as an untrusted-adapter failure that requires recovery.
function isPinnedDigest(digest) {
  return typeof digest === "string" && PINNED_DIGESTS.includes(digest);
}

// Guards any installer-bound input object against caller-supplied execution
// selectors. Runs before the eligibility resolver so a hostile input is
// rejected before the manifest is even consulted.
function assertNoCallerExecutionSelector(input) {
  for (const key of Object.keys(input || {})) {
    if (CALLER_FORBIDDEN_FIELDS.includes(key)) {
      throw new ToolError("INVALID_INPUT",
        `installer input may not carry the caller-controlled field ${key}`);
    }
  }
}

module.exports = {
  SUPPORTED_OS_FAMILIES,
  PINNED_INSTALL_ADAPTERS,
  PINNED_DIGESTS,
  CALLER_FORBIDDEN_FIELDS,
  isSupportedOsFamily,
  resolvePinnedAdapter,
  requirePinnedAdapter,
  isPinnedDigest,
  assertNoCallerExecutionSelector,
};
