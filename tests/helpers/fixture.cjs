"use strict";

// Test fixture: temporary data dir, fake adapters, fake Keychain seam, and a
// controllable clock. Fake observations are synthesized from the frozen data
// schemas plus targeted overrides, so no hand-written per-tool instance list
// exists. No fake ever touches a real server, Cloudflare, DNS, 3x-ui, Nginx,
// or the real macOS Keychain.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { AdapterRegistry } = require("../../mcp/adapters/registry.cjs");
const { buildContext } = require("../../mcp/server.cjs");
const { ServerCore } = require("../../mcp/core/server-core.cjs");
const { mintRef } = require("../../mcp/core/refs.cjs");
const { sampleWith } = require("./sample.cjs");

function dataObservation(toolName, dropKeys, overrides, seed = 0) {
  const schema = contracts.TOOLS_BY_NAME[toolName].dataSchema;
  const instance = sampleWith(schema, overrides, seed);
  for (const key of dropKeys) delete instance[key];
  return instance;
}

class FakeKeychain {
  constructor() {
    this.roles = new Map();
  }

  register(secretRef, role) {
    this.roles.set(secretRef, role);
  }

  hasSecret(secretRef) {
    return this.roles.has(secretRef);
  }

  roleOf(secretRef) {
    return this.roles.get(secretRef) || null;
  }
}

function buildFakeAdapters({ xuiCase = "COMPATIBLE_EXISTING_WITH_IMPORTED_ADMIN" } = {}) {
  const calls = [];
  const record = (kind, name) => calls.push({ kind, name });

  const helpers = {
    "origin.inventory.v1": (payload) => {
      record("helper", "origin.inventory.v1");
      return {
        observation: dataObservation("origin_inventory", ["origin_inventory_ref"], {
          os_family: "debian",
          nginx_installation_status: "supported_existing",
          public_tls_listener_owner: "nginx_safe",
          node_server_name_conflict: false,
          websocket_path_conflict: false,
          owned_include_slot_available: true,
          safe_stable_certificate_reuse_eligible: true,
          node_hostname_coverage: true,
          sufficient_certificate_validity: true,
          certificate_key_pair_matches: true,
          origin_ca_dedicated_slot_status: "absent_root_owned_available",
          registered_origin_address_type: "A",
        }, 1),
      };
    },
    "client.inventory_fixed.v1": (payload) => {
      record("helper", "client.inventory_fixed.v1");
      return {
        observation: dataObservation("client_inventory", ["client_inventory_ref"], {
          client_runtime_refs: [payload.clientRuntimeRef || mintRef("runtime")],
          probe_destination_refs: [payload.probeDestinationRef || mintRef("runtime")],
        }, 2),
      };
    },
    "origin.bbr_inventory_fixed.v1": () => {
      record("helper", "origin.bbr_inventory_fixed.v1");
      return {
        observation: dataObservation("bbr_inventory", ["bbr_inventory_ref"], {
          kernel_exposes_bbr: true,
          available_congestion_controls_contains_bbr: true,
          qdisc_fq_supported: true,
          persistent_conflict_present: false,
          eligible: true,
          owned_dropin_present: false,
        }, 3),
      };
    },
    "origin.probe_fixed.v1": () => {
      record("helper", "origin.probe_fixed.v1");
      return { observation: { probed: true } };
    },
    "origin.xui_inbound_apply_owned.v1": (payload) => {
      record("helper-mutating", "origin.xui_inbound_apply_owned.v1");
      return {
        observation: dataObservation("xui_create_inbound", [
          "change_ref", "before_digest", "after_digest", "ownership_receipt_ref",
          "rollback_class", "inverse_ref", "compensation_ref", "committed",
        ], {
          listen_loopback_only: true,
          inbound_absent_before_create: true,
          created_same_run: true,
          proxy_protocol_enabled: false,
        }, 4),
        beforeDigest: null,
      };
    },
  };

  const broker = {
    "cf.dns_read": () => {
      record("broker", "cf.dns_read");
      return {
        observation: dataObservation("cloudflare_inventory",
          ["cloudflare_inventory_ref"], {
            record_observation_case: "ABSENT_AVAILABLE",
            ssl_mode: "strict",
            websockets_enabled: true,
          }, 5),
      };
    },
    "xui.inventory_existing_fixed.v1": () => {
      record("broker", "xui.inventory_existing_fixed.v1");
      return {
        observation: dataObservation("xui_inventory", ["xui_inventory_ref"], {
          admin_binding_status: xuiCase,
        }, 6),
      };
    },
    "xui.inventory_owned_fixed.v1": () => {
      record("broker", "xui.inventory_owned_fixed.v1");
      return {
        observation: dataObservation("xui_inventory", ["xui_inventory_ref"], {
          admin_binding_status: "ABSENT_NOT_INSTALL_ELIGIBLE",
        }, 6),
      };
    },
    "protected_line.runtime_probe_fixed.v1": () => {
      record("broker", "protected_line.runtime_probe_fixed.v1");
      return { observation: { healthy: true, authenticated: true, expectedEgress: true } };
    },
  };

  return { helpers, broker, calls };
}

function makeFixture({ xuiCase, protectedLineApplicable = true, now } = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cdn-operator-test-"));
  let clock = now ?? Date.parse("2026-08-22T00:00:00Z");
  const fake = buildFakeAdapters({ xuiCase });
  const adapters = new AdapterRegistry({ helpers: fake.helpers, broker: fake.broker });
  const keychain = new FakeKeychain();
  const ctx = buildContext({
    dataDir: tmpDir,
    adapters,
    keychain,
    now: () => clock,
  });
  const core = new ServerCore(ctx);

  // Seed the onboarding registry with masked synthetic entries only.
  const refs = {
    origin_target_ref: mintRef("target"),
    cloudflare_target_ref: mintRef("target"),
    node_hostname_ref: mintRef("runtime"),
    output_dir_ref: mintRef("runtime"),
    protected_line_ref: protectedLineApplicable ? mintRef("runtime") : null,
    probe_destination_ref: mintRef("runtime"),
    ssh_identity_secret_ref: mintRef("secret"),
    cf_audit_secret_ref: mintRef("secret"),
    cf_node_dns_secret_ref: mintRef("secret"),
    cf_origin_ca_secret_ref: mintRef("secret"),
    existing_xui_admin_secret_ref: mintRef("secret"),
    protected_line_runtime_secret_ref: protectedLineApplicable ? mintRef("secret") : null,
  };
  const seed = [
    ["origin_target_ref", "target", "origin"],
    ["cloudflare_target_ref", "target", "cloudflare_zone"],
    ["node_hostname_ref", "runtime", "node_hostname"],
    ["output_dir_ref", "runtime", "output_dir"],
    ["probe_destination_ref", "runtime", "probe_destination"],
    ["ssh_identity_secret_ref", "secret", "ssh-origin-identity"],
    ["cf_audit_secret_ref", "secret", "cf-audit"],
    ["cf_node_dns_secret_ref", "secret", "cf-node-dns"],
    ["cf_origin_ca_secret_ref", "secret", "cf-origin-ca"],
    ["existing_xui_admin_secret_ref", "secret", "xui-panel-admin"],
  ];
  if (protectedLineApplicable) {
    seed.push(["protected_line_ref", "runtime", "protected_line"]);
    seed.push(["protected_line_runtime_secret_ref", "secret", "protected-line-runtime"]);
  }
  for (const [field, kind, role] of seed) {
    const flags = field === "node_hostname_ref" && !protectedLineApplicable
      ? { protectedLineNotApplicable: true } : {};
    ctx.ledger.registerOnboardingRef({
      ref: refs[field], kind, role, maskedLabel: `masked-${role}`, flags,
    });
    if (kind === "secret") keychain.register(refs[field], role);
  }

  const callTool = (name, args) => {
    const response = core.handle("tools/call", { name, arguments: args });
    return response.structuredContent;
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
    enable_bbr: false,
    idempotency_key: `key-${Math.random().toString(36).slice(2, 14)}.0000`,
    ...extra,
  });

  return {
    ctx, core, adapters, fakeCalls: fake.calls, keychain, refs, tmpDir,
    callTool, runBeginInput,
    advanceClock: (ms) => { clock += ms; },
    cleanup: () => {
      ctx.ledger.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

module.exports = { makeFixture, buildFakeAdapters, FakeKeychain, dataObservation };
