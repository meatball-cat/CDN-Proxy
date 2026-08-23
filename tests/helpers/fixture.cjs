"use strict";

// Test fixture: temporary data dir, fake adapters over an in-memory staging
// host, a real credential broker behind an in-memory Keychain seam, and a
// controllable clock.
//
// No fake ever touches a real server, Cloudflare zone, DNS record,
// certificate, kernel, or the real macOS Keychain, and no test writes outside
// its own temp directory.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { AdapterRegistry } = require("../../mcp/adapters/registry.cjs");
const { buildContext } = require("../../mcp/server.cjs");
const { ServerCore } = require("../../mcp/core/server-core.cjs");
const { mintRef, sha256Digest } = require("../../mcp/core/refs.cjs");
const { InMemoryKeychain } = require("../../mcp/secrets/keychain.cjs");
const { CredentialBroker } = require("../../mcp/secrets/broker.cjs");
const { FakeHost } = require("./fake-host.cjs");
const { buildFakeAdapters, dataObservation } = require("./fake-adapters.cjs");

let keyCounter = 0;
function idemKey(prefix = "k") {
  keyCounter += 1;
  return `${prefix}-${String(keyCounter).padStart(6, "0")}-abcdefgh`;
}

function makeFixture(options = {}) {
  const {
    xuiCase,
    protectedLineApplicable = true,
    now,
    enableBbr = false,
    hostOverrides = {},
    hostnameFlags = {},
    removeHelperOperations = [],
    removeBrokerOperations = [],
  } = options;

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-operator-test-"));
  let clock = now ?? Date.parse("2026-08-22T00:00:00Z");

  const host = new FakeHost(hostOverrides);
  if (xuiCase) {
    // The observed case is projected from the frozen observation-case table,
    // so the harness cannot invent a combination the contract forbids.
    const row = contracts.XUI_INVENTORY_OBSERVATION_CASES[xuiCase];
    if (!row) throw new Error("unknown xui observation case " + xuiCase);
    host.xuiAdminBindingStatus = xuiCase;
    host.xuiInstallationStatus = row.installationStatus;
    host.xuiCleanHostEligible = row.cleanHostInstallEligible;
    host.xuiAdminProvenance = row.adminProvenance;
    host.panelFingerprintDigest = row.panelFingerprint === "NULL"
      ? null : sha256Digest("panel-fingerprint:" + xuiCase);
    host.xuiVersionMasked = row.versionMasked === "NULL" ? null : "x.y.z";
    host.installOwnershipReceiptRef = row.ownershipReceipt === "NON_NULL"
      ? mintRef("receipt") : null;
  }

  const keychain = new InMemoryKeychain();
  const credentialBroker = new CredentialBroker(keychain);

  const refs = {
    origin_target_ref: mintRef("target"),
    cloudflare_target_ref: mintRef("target"),
    node_hostname_ref: mintRef("runtime"),
    output_dir_ref: mintRef("runtime"),
    protected_line_ref: protectedLineApplicable ? mintRef("runtime") : null,
    probe_destination_ref: mintRef("runtime"),
    client_runtime_ref: mintRef("runtime"),
    ssh_identity_secret_ref: mintRef("secret"),
    cf_audit_secret_ref: mintRef("secret"),
    cf_node_dns_secret_ref: mintRef("secret"),
    cf_origin_ca_secret_ref: mintRef("secret"),
    existing_xui_admin_secret_ref: mintRef("secret"),
    protected_line_runtime_secret_ref: protectedLineApplicable ? mintRef("secret") : null,
  };
  host.clientRuntimeRef = refs.client_runtime_ref;
  host.probeDestinationRef = refs.probe_destination_ref;

  // The server-computed identity digest of the one dedicated node hostname.
  // The raw hostname itself never appears anywhere in the harness.
  const identityDigest = sha256Digest(`node-hostname-identity:${refs.node_hostname_ref}`);

  const fake = buildFakeAdapters({ host, credentialBroker, keychain, identityDigest });
  // Removing an operation models a downstream path that is simply not
  // available; the registry then fails closed before any dispatch.
  for (const name of removeHelperOperations) delete fake.helpers[name];
  for (const name of removeBrokerOperations) delete fake.broker[name];
  const adapters = new AdapterRegistry({ helpers: fake.helpers, broker: fake.broker });
  const ctx = buildContext({ dataDir: tmpDir, adapters, keychain, now: () => clock });
  const core = new ServerCore(ctx);

  const seed = [
    ["origin_target_ref", "target", "origin", {}],
    ["cloudflare_target_ref", "target", "cloudflare_zone", {}],
    ["node_hostname_ref", "runtime", "node_hostname", {
      dedicated_node_hostname: true,
      apex: false,
      management_hostname: false,
      ambiguous: false,
      zone_target_ref: refs.cloudflare_target_ref,
      hostname_identity_digest: identityDigest,
      ...(protectedLineApplicable ? {} : { protectedLineNotApplicable: true }),
      ...hostnameFlags,
    }],
    ["output_dir_ref", "runtime", "output_dir", { safe: true }],
    ["probe_destination_ref", "runtime", "probe_destination", {}],
    ["client_runtime_ref", "runtime", "client_runtime", {}],
    ["ssh_identity_secret_ref", "secret", "ssh-origin-identity", {}],
    ["cf_audit_secret_ref", "secret", "cf-audit", {}],
    ["cf_node_dns_secret_ref", "secret", "cf-node-dns", {}],
    ["cf_origin_ca_secret_ref", "secret", "cf-origin-ca", {}],
    ["existing_xui_admin_secret_ref", "secret", "xui-panel-admin", {}],
  ];
  if (protectedLineApplicable) {
    seed.push(["protected_line_ref", "runtime", "protected_line", {}]);
    seed.push(["protected_line_runtime_secret_ref", "secret", "protected-line-runtime", {}]);
  }
  for (const [field, kind, role, flags] of seed) {
    ctx.ledger.registerOnboardingRef({
      ref: refs[field], kind, role, maskedLabel: `masked-${role}`, flags,
    });
    if (kind === "secret") {
      keychain.registerImported(refs[field], role);
      ctx.ledger.registerSecretRef({
        secretRef: refs[field], runId: null, role, provenance: "imported",
      });
    }
  }

  const callTool = (name, args) =>
    core.handle("tools/call", { name, arguments: args }).structuredContent;

  // Throws with the tool's contract error if the call did not succeed, so a
  // journey step that silently fails cannot be mistaken for a pass.
  const ok = (name, args) => {
    const response = callTool(name, args);
    if (response.status === "error") {
      throw new Error(`${name} failed: ${response.error.code}: ${response.error.message}`);
    }
    return response;
  };

  const runBeginInput = (mode, extra = {}) => ({
    mode,
    origin_target_ref: refs.origin_target_ref,
    cloudflare_target_ref: refs.cloudflare_target_ref,
    node_hostname_ref: refs.node_hostname_ref,
    ssh_identity_secret_ref: refs.ssh_identity_secret_ref,
    cf_audit_secret_ref: refs.cf_audit_secret_ref,
    cf_node_dns_secret_ref: refs.cf_node_dns_secret_ref,
    cf_origin_ca_secret_ref: refs.cf_origin_ca_secret_ref,
    existing_xui_admin_secret_ref: refs.existing_xui_admin_secret_ref,
    protected_line_ref: refs.protected_line_ref,
    protected_line_runtime_secret_ref: refs.protected_line_runtime_secret_ref,
    output_dir_ref: refs.output_dir_ref,
    enable_bbr: enableBbr,
    idempotency_key: idemKey("begin"),
    ...extra,
  });

  return {
    ctx, core, adapters, host, keychain, credentialBroker, identityDigest,
    fakeCalls: fake.calls, refs, tmpDir, callTool, ok, runBeginInput, idemKey,
    advanceClock: (ms) => { clock += ms; },
    clockNow: () => clock,
    cleanup: () => {
      ctx.ledger.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

// --- journey drivers ------------------------------------------------------

function runInventories(fx, runId) {
  fx.ok("origin_inventory", { run_id: runId, refresh: true });
  fx.ok("cloudflare_inventory", { run_id: runId, refresh: true });
  fx.ok("xui_inventory", { run_id: runId, refresh: true });
  fx.ok("client_inventory", { run_id: runId, refresh: true });
  fx.ok("old_line_verify", {
    run_id: runId,
    probe_destination_ref: fx.refs.probe_destination_ref,
    idempotency_key: fx.idemKey("old-line"),
  });
}

function ledgerDigest(fx, runId) {
  return fx.ctx.ledger.getRun(runId).ledger_digest;
}

function compileAndAuthorize(fx, runId, scope, intent) {
  const compiled = fx.ok("plan_compile", {
    run_id: runId, scope, intent,
    expected_ledger_digest: fx.ctx.ledger.getRun(runId).ledger_digest,
    idempotency_key: fx.idemKey("compile"),
  }).data;
  const approved = fx.ok("plan_authorize", {
    run_id: runId,
    plan_ref: compiled.plan_ref,
    approval_challenge_ref: compiled.approval_challenge_ref,
    displayed_impact_digest: compiled.impact_digest,
    expected_ledger_digest: fx.ctx.ledger.getRun(runId).ledger_digest,
    idempotency_key: fx.idemKey("authorize"),
  }).data;
  return { compiled, approved };
}

// The coordinated pre-mutation checkpoint: refresh every finite inventory
// family the remaining plan consumes. A refresh never advances the cursor and
// never extends a lease, so it is safe to run before any step.
function refreshCheckpoint(fx, runId) {
  fx.ok("origin_inventory", { run_id: runId, refresh: true });
  fx.ok("cloudflare_inventory", { run_id: runId, refresh: true });
  fx.ok("xui_inventory", { run_id: runId, refresh: true });
  fx.ok("client_inventory", { run_id: runId, refresh: true });
}

const CHECKPOINT_CONSUMERS = Object.freeze([
  "xui_install", "xui_create_inbound", "xui_profile_publish",
  "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply",
  "cf_node_record_apply", "cf_proxy_enable", "origin_verify", "cdn_verify", "traffic_verify",
]);

// Executes the approved template step by step, driving whichever tool the
// server's cursor says is next. Never chooses an operation itself.
function driveTemplate(fx, runId, planRef, approvalRef, { stopAfter = null, skipRefresh = false } = {}) {
  const results = [];
  for (let guard = 0; guard < 32; guard += 1) {
    const next = fx.ctx.ledger.cursorNext(planRef);
    if (!next) break;
    if (!skipRefresh && CHECKPOINT_CONSUMERS.includes(next.tool)) refreshCheckpoint(fx, runId);
    const base = {
      run_id: runId, plan_ref: planRef, operation_ref: next.operation_ref,
      approval_ref: approvalRef, expected_ledger_digest: fx.ctx.ledger.getRun(runId).ledger_digest,
      idempotency_key: fx.idemKey(next.step_id),
    };
    let response;
    switch (next.tool) {
      case "old_line_verify":
        response = fx.ok("old_line_verify", {
          run_id: runId, probe_destination_ref: fx.refs.probe_destination_ref,
          idempotency_key: fx.idemKey("old-line"),
        });
        break;
      case "origin_verify":
        response = fx.ok("origin_verify", { run_id: runId, idempotency_key: fx.idemKey("origin-verify") });
        break;
      case "cdn_verify":
        response = fx.ok("cdn_verify", {
          run_id: runId, probe_destination_ref: fx.refs.probe_destination_ref,
          idempotency_key: fx.idemKey("cdn-verify"),
        });
        break;
      case "xui_profile_inspect":
        response = fx.ok("xui_profile_inspect", {
          run_id: runId,
          profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
          expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
        });
        break;
      case "traffic_verify":
        response = fx.ok("traffic_verify", {
          run_id: runId,
          client_runtime_ref: fx.refs.client_runtime_ref,
          profile_ref: fx.ctx.ledger.getScalar(runId, "profile_ref"),
          client_profile_secret_ref: fx.ctx.ledger.getScalar(runId, "profile_secret_ref"),
          probe_destination_ref: fx.refs.probe_destination_ref,
          expected_node_binding_digest: fx.ctx.ledger.getRun(runId).node_binding_digest,
          idempotency_key: fx.idemKey("traffic"),
        });
        break;
      case "logs_correlate": {
        const traffic = fx.ctx.ledger.freshEvidence(runId, "AUTHENTICATED_PROXY_REQUEST");
        const binding = JSON.parse(traffic.binding);
        response = fx.ok("logs_correlate", {
          run_id: runId, probe_ref: binding.probeRef,
          correlation_window_ref: binding.correlationWindowRef,
          max_lines_per_source: 50,
        });
        break;
      }
      case "bbr_verify":
        response = fx.ok("bbr_verify", {
          run_id: runId,
          bbr_change_ref: fx.ctx.ledger.getScalar(runId, "bbr_change_ref"),
          probe_destination_ref: fx.refs.probe_destination_ref,
          idempotency_key: fx.idemKey("bbr-verify"),
        });
        break;
      case "rollback_run":
        response = fx.ok("rollback_run", {
          run_id: runId, plan_ref: planRef, approval_ref: approvalRef,
          expected_ledger_digest: fx.ctx.ledger.getRun(runId).ledger_digest, idempotency_key: fx.idemKey("rollback"),
        });
        break;
      default:
        response = fx.ok(next.tool, base);
    }
    results.push({ step: next.step_id, tool: next.tool, response });
    if (stopAfter && (next.step_id === stopAfter || next.step_id.endsWith(":" + stopAfter))) break;
  }
  return results;
}

module.exports = {
  makeFixture, runInventories, compileAndAuthorize, driveTemplate, ledgerDigest, refreshCheckpoint,
  dataObservation, FakeHost, idemKey,
};
