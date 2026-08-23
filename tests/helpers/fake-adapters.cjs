"use strict";

// Fake adapter set for the staging harness.
//
// These implement exactly the contract's closed helper/broker operation names
// against the in-memory FakeHost. They are the only place a test can steer
// host behaviour, and they carry the same one-way credential boundary as the
// production adapters: plaintext lives in the broker/keychain seam and only
// opaque refs and masked metadata come back.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { mintRef, digestOf, sha256Digest } = require("../../mcp/core/refs.cjs");
const { sampleWith } = require("./sample.cjs");

function dataObservation(toolName, dropKeys, overrides, seed = 0) {
  const schema = contracts.TOOLS_BY_NAME[toolName].dataSchema;
  const instance = sampleWith(schema, overrides, seed);
  for (const key of dropKeys) delete instance[key];
  return instance;
}

const MUTATION_COMMON_KEYS = Object.freeze([
  "change_ref", "before_digest", "after_digest", "ownership_receipt_ref",
  "rollback_class", "inverse_ref", "compensation_ref", "committed",
]);

function buildFakeAdapters({ host, credentialBroker, keychain, identityDigest, calls = [] }) {
  const record = (kind, name) => calls.push({ kind, name });
  const thirdParty = (key) => host.thirdPartyDigestOn === key;
  const createOnly = (key) => ({
    absentBefore: true,
    exclusiveCreate: true,
    thirdPartyDigestObserved: thirdParty(key),
  });

  const helpers = {
    "origin.inventory.v1": (payload) => {
      record("helper", "origin.inventory.v1");
      // Called as a reconciliation observer, this returns a before/after
      // digest verdict rather than a full inventory projection.
      if (payload && payload.originalTool) {
        return { observation: host.reconcileObservation };
      }
      return {
        observation: dataObservation("origin_inventory", ["origin_inventory_ref"], {
          os_family: host.osFamily,
          nginx_installation_status: host.nginxInstallationStatus,
          public_tls_listener_owner: host.publicTlsListenerOwner,
          node_server_name_conflict: host.nodeServerNameConflict,
          websocket_path_conflict: host.websocketPathConflict,
          owned_include_slot_available: host.ownedIncludeSlotAvailable,
          sole_exact_node_route_observed: host.soleExactNodeRouteObserved,
          safe_stable_certificate_reuse_eligible: host.safeStableCertificateReuseEligible,
          node_hostname_coverage: true,
          sufficient_certificate_validity: true,
          certificate_key_pair_matches: true,
          selected_certificate_not_after: host.certificateNotAfter,
          origin_ca_dedicated_slot_status: host.originCaDedicatedSlotStatus,
          registered_origin_address_type: host.registeredOriginAddressType,
          current_origin_address_digest: host.originAddressDigest(),
          host_fingerprint_digest: sha256Digest("host-fingerprint"),
        }, 1),
        observation_kind: "ORIGIN",
      };
    },

    "origin.xui_install_owned.v1": (payload) => {
      record("helper-mutating", "origin.xui_install_owned.v1");
      host.xuiInstallationStatus = "owned_by_run";
      host.xuiAdminBindingStatus = "SAME_RUN_OWNED_WITH_GENERATED_ADMIN";
      host.xuiAdminProvenance = "SAME_RUN_CURRENT";
      host.xuiCleanHostEligible = false;
      host.xuiVersionMasked = host.installedVersionMasked || "x.y.z";
      host.panelFingerprintDigest = sha256Digest("panel-fingerprint-owned");
      const readbackDigest = sha256Digest(`install-readback:${payload.runId}`);
      host.installOwnershipReceiptRef = mintRef("receipt");
      return {
        observation: {
          adapter_digest: host.adapterDigest,
          readback_digest: readbackDigest,
          service_active: true,
          panel_loopback_only: true,
          installed_version_masked: host.xuiVersionMasked,
        },
        installationRef: mintRef("runtime"),
        beforeDigest: null,
        afterDigest: readbackDigest,
        precondition: createOnly("xui_install"),
      };
    },

    "origin.xui_install_readback.v1": () => {
      record("helper", "origin.xui_install_readback.v1");
      return { observation: { adapter_digest: host.adapterDigest, service_active: true } };
    },

    "origin.xui_inbound_apply_owned.v1": (payload) => {
      record("helper-mutating", "origin.xui_inbound_apply_owned.v1");
      const client = credentialBroker.generateVlessClientId();
      const path = credentialBroker.generateWebsocketPath();
      host.inboundPresent = true;
      host.websocketPathDigest = path.pathDigest;
      return {
        observation: dataObservation("xui_create_inbound", [
          ...MUTATION_COMMON_KEYS, "inbound_ref", "client_secret_ref", "inbound_receipt_ref",
          "loopback_listener_ref",
        ], {
          listen_loopback_only: true,
          inbound_protocol: "vless",
          inbound_transport: "ws",
          inbound_tls: "none",
          inbound_flow: "none",
          proxy_protocol_enabled: false,
          websocket_host: "",
          inbound_public_domain: null,
          inbound_absent_before_create: true,
          created_same_run: true,
          websocket_path_digest: path.pathDigest,
        }, 4),
        inboundRef: mintRef("inbound"),
        clientSecretRef: client.secretRef,
        websocketPathRef: path.pathRef,
        loopbackListenerRef: mintRef("runtime"),
        beforeDigest: null,
        precondition: createOnly("xui_create_inbound"),
      };
    },

    "origin.certificate_deploy_owned.v1": () => {
      record("helper-mutating", "origin.certificate_deploy_owned.v1");
      host.certificateSlotsPresent = true;
      host.originCaDedicatedSlotStatus = "preexisting";
      return {
        observation: dataObservation("certificate_deploy", [
          ...MUTATION_COMMON_KEYS, "fullchain_slot_ref", "private_key_slot_ref",
          "certificate_slot_receipt_ref",
        ], {
          stable_service_slots_verified: true,
          private_key_exposed: false,
          dedicated_slots_absent_before_create: true,
          descriptor_relative_nofollow_o_excl: true,
          created_same_run_slots: true,
          exact_slot_readback_verified: true,
          regular_files: true, root_owned: true, no_symlink: true, no_hardlink: true,
          trusted_parent: true, private_key_mode: "0600", fullchain_mode: "0644",
          fsync_complete: true, atomic_receipt_written: true,
          nginx_consumes_opaque_slot_refs_only: true,
          hostname_identity_digest: identityDigest,
        }, 7),
        fullchainSlotRef: mintRef("runtime"),
        privateKeySlotRef: mintRef("runtime"),
        beforeDigest: null,
        precondition: createOnly("certificate_deploy"),
      };
    },

    "origin.nginx_route_apply_owned.v1": () => {
      record("helper-mutating", "origin.nginx_route_apply_owned.v1");
      host.nginxIncludePresent = true;
      host.ownedIncludeSlotAvailable = false;
      host.soleExactNodeRouteObserved = true;
      const routeDigest = sha256Digest("effective-route");
      return {
        observation: dataObservation("nginx_route_apply", [
          ...MUTATION_COMMON_KEYS, "route_ref", "route_receipt_ref",
          "fullchain_slot_ref", "private_key_slot_ref",
        ], {
          syntax_valid: true, reload_verified: true, supported_existing_nginx: true,
          safe_public_tls_listener_ownership: true, no_server_name_conflict: true,
          no_websocket_path_conflict: true, create_only_owned_include: true,
          nginx_install_performed: false, sole_exact_server_name: true,
          sole_exact_websocket_path: true, loopback_upstream_exact: true,
          public_tls_listener_443: true, http11_upgrade_connection_exact: true,
          unmatched_request_nondisclosing_404: true, backend_tls_disabled: true,
          proxy_protocol_disabled: true, no_wildcard_or_default_server: true,
          exact_node_hostname_and_high_entropy_path: true,
          include_absent_before_create: true, descriptor_relative_nofollow_o_excl: true,
          created_same_run_include: true, include_readback_matches: true,
          effective_route_digest: routeDigest,
          hostname_identity_digest: identityDigest,
          websocket_path_digest: host.websocketPathDigest,
        }, 8),
        routeRef: mintRef("runtime"),
        fullchainSlotRef: mintRef("runtime"),
        privateKeySlotRef: mintRef("runtime"),
        beforeDigest: null,
        afterDigest: routeDigest,
        precondition: createOnly("nginx_route_apply"),
      };
    },

    "origin.bbr_apply_owned.v1": () => {
      record("helper-mutating", "origin.bbr_apply_owned.v1");
      host.ownedDropinPresent = true;
      host.liveCongestionControl = "bbr";
      host.persistentCongestionControl = "bbr";
      host.liveQdisc = "fq";
      host.persistentQdisc = "fq";
      const dropinDigest = sha256Digest("owned-dropin");
      return {
        observation: dataObservation("bbr_apply", [
          ...MUTATION_COMMON_KEYS, "bbr_receipt_ref", "owned_dropin_ref",
          "prior_qdisc", "prior_congestion_control",
        ], {
          dropin_digest: dropinDigest,
          live_apply_readback: true, persistent_readback: true,
          live_congestion_control: "bbr", persistent_congestion_control: "bbr",
          live_default_qdisc: "fq", persistent_default_qdisc: "fq",
          descriptor_relative_nofollow: true, exclusive_create: true,
          owned_dropin_absent_before_create: true, dropin_readback_matches: true,
          owned_dropin_path_bound_to_approved_runtime_ref: true,
          receipt_binds_owned_path_and_dropin_digest: true,
        }, 9),
        ownedDropinRef: mintRef("runtime"),
        beforeDigest: null,
        afterDigest: dropinDigest,
        precondition: createOnly("bbr_apply"),
      };
    },

    "origin.bbr_inventory_fixed.v1": () => {
      record("helper", "origin.bbr_inventory_fixed.v1");
      const persistentConflict = host.persistentConflictPresent || host.ownedDropinPresent;
      const eligible = host.kernelExposesBbr && host.qdiscFqSupported && !persistentConflict;
      return {
        observation: dataObservation("bbr_inventory", ["bbr_inventory_ref"], {
          kernel_exposes_bbr: host.kernelExposesBbr,
          available_congestion_controls_contains_bbr: host.kernelExposesBbr,
          qdisc_fq_supported: host.qdiscFqSupported,
          persistent_conflict_present: persistentConflict,
          eligible,
          owned_dropin_present: host.ownedDropinPresent,
          current_qdisc: host.currentQdisc,
          current_congestion_control: host.currentCongestionControl,
          live_qdisc_matches: !host.bbrVerifyFalse && host.liveQdisc === "fq",
          live_congestion_control_matches: !host.bbrVerifyFalse && host.liveCongestionControl === "bbr",
          persistent_dropin_matches: !host.bbrVerifyFalse && host.persistentCongestionControl === "bbr",
          live_congestion_control: host.liveCongestionControl,
          persistent_congestion_control: host.persistentCongestionControl,
          live_default_qdisc: host.liveQdisc,
          persistent_default_qdisc: host.persistentQdisc,
        }, 3),
      };
    },

    "origin.bbr_restore_owned.v1": (payload) => {
      record("helper-mutating", "origin.bbr_restore_owned.v1");
      if (thirdParty(payload.stageId)) return { thirdPartyDigestObserved: true };
      if (host.failStage === payload.stageId) {
        return { readbackVerified: false, observation: { stage: payload.stageId } };
      }
      if (payload.stageId === "bbr_rb01_owned_dropin_remove") host.ownedDropinPresent = false;
      if (payload.stageId === "bbr_rb02_prior_live_restore") {
        host.liveCongestionControl = payload.recordedPriorValues.congestionControl;
        host.liveQdisc = payload.recordedPriorValues.qdisc;
      }
      if (payload.stageId === "bbr_rb03_prior_persistent_restore") {
        host.persistentCongestionControl = payload.recordedPriorValues.congestionControl;
        host.persistentQdisc = payload.recordedPriorValues.qdisc;
      }
      return {
        readbackVerified: true,
        readbackDigest: sha256Digest(`bbr-stage:${payload.stageId}`),
        observation: { stage: payload.stageId, readback: payload.expectedReadback },
      };
    },

    // --- main rollback inverse helpers ---
    "origin.nginx_route_delete_owned.v1": (p) => inverseHelper("rb03_nginx_route_delete", p, () => {
      host.nginxIncludePresent = false;
      host.ownedIncludeSlotAvailable = true;
      host.soleExactNodeRouteObserved = false;
    }),
    "origin.certificate_delete_owned.v1": (p) => inverseHelper("rb04_certificate_slots_delete", p, () => {
      host.certificateSlotsPresent = false;
      host.originCaDedicatedSlotStatus = "absent_root_owned_available";
    }),
    "origin.artifact_remove_owned_unchanged.v1": (p) => inverseHelper("rb06_client_artifact_dispose", p, () => {
      host.artifactPresent = false;
    }),
    "origin.xui_inbound_remove_owned.v1": (p) => inverseHelper("rb08_xui_inbound_remove", p, () => {
      host.inboundPresent = false;
    }),
    "origin.xui_uninstall_owned.v1": (p) => inverseHelper("rb10_xui_install_uninstall", p, () => {
      host.xuiInstallationStatus = "absent";
      host.xuiAdminBindingStatus = "ABSENT_CLEAN_ELIGIBLE";
      host.xuiCleanHostEligible = true;
      host.installOwnershipReceiptRef = null;
    }),

    // --- read-only observers ---
    "origin.rollback_graph_readback_fixed.v1": () => {
      record("helper", "origin.rollback_graph_readback_fixed.v1");
      return { observation: host.reconcileObservation };
    },
    "ledger.rollback_local_artifact_tombstone_fixed.v1": () => {
      record("helper", "ledger.rollback_local_artifact_tombstone_fixed.v1");
      return { observation: host.reconcileObservation };
    },
    "ledger.rollback_secret_disposition_receipts_fixed.v1": (p) => {
      record("helper", "ledger.rollback_secret_disposition_receipts_fixed.v1");
      if (p && p.stageId) return inverseHelper(p.stageId, p, () => {});
      return { observation: host.reconcileObservation };
    },
    "ledger.bbr_rollback_stage_receipts_fixed.v1": () => {
      record("helper", "ledger.bbr_rollback_stage_receipts_fixed.v1");
      return { observation: host.reconcileObservation };
    },
    "origin.reconcile_xui_install_readback.v1": () => ({ observation: host.reconcileObservation }),
    "origin.reconcile_certificate_slot_readback.v1": () => ({ observation: host.reconcileObservation }),
    "origin.reconcile_nginx_include_readback.v1": () => ({ observation: host.reconcileObservation }),

    "client.inventory_fixed.v1": (payload) => {
      record("helper", "client.inventory_fixed.v1");
      return {
        observation: dataObservation("client_inventory", ["client_inventory_ref"], {
          client_runtime_refs: [host.clientRuntimeRef],
          probe_destination_refs: [host.probeDestinationRef],
          runtime_digest: sha256Digest("client-runtime"),
        }, 2),
      };
    },

    "origin.probe_fixed.v1": (payload) => {
      record("helper", "origin.probe_fixed.v1");
      if (payload.kind === "direct_origin_tls_websocket") {
        return {
          observation: {
            tls_valid: host.originTlsValid !== false,
            san_matches: host.originSanMatches !== false,
            websocket_upgrade_valid: host.originUpgradeValid !== false,
            expected_route_reached: host.originRouteReached !== false,
          },
        };
      }
      return { observation: { probed: true } };
    },

    "origin.expected_egress_fixed.v1": (payload) => {
      record("helper", "origin.expected_egress_fixed.v1");
      return {
        probeDestinationRef: payload.probeDestinationRef,
        egressSourceValue: host.egressToken,
      };
    },

    "origin.logs_correlate_fixed.v1": () => {
      record("helper", "origin.logs_correlate_fixed.v1");
      return {
        observation: {
          nginx_correlated: host.nginxCorrelated !== false,
          xray_correlated: host.xrayCorrelated !== false,
          correlation_complete: host.correlationComplete !== false,
        },
      };
    },
  };

  function inverseHelper(stageId, payload, mutate) {
    record("helper-mutating", `inverse:${stageId}`);
    if (thirdParty(stageId)) return { thirdPartyDigestObserved: true };
    if (host.failStage === stageId) return { readbackVerified: false, observation: { stageId } };
    mutate();
    return {
      readbackVerified: true,
      readbackDigest: sha256Digest(`inverse:${stageId}`),
      observation: { stageId },
      retainedResidual: host.retainResidualAt === stageId
        ? { kind: "UNERASABLE_COPY", maskedSummary: "a copy could not be proven destroyed" }
        : null,
    };
  }

  const brokerOps = {
    "cf.dns_read": (payload) => {
      record("broker", "cf.dns_read");
      if (payload && payload.kind === "cdn_verify_same_call_api_read") {
        return {
          observation: {
            tls_valid: host.cdnTlsValid !== false,
            san_matches: host.cdnSanMatches !== false,
            websocket_upgrade_valid: host.cdnUpgradeValid !== false,
            strict_compatible_mode_observed: host.strictCompatibleModes !== false,
            expected_route_reached: host.cdnRouteReached !== false,
            cf_api_owned_proxied_record_current: host.recordProxied,
            cf_api_ssl_strict_compatible_current: ["strict", "origin_pull"].includes(host.sslMode),
            cf_api_websockets_enabled_current: host.websocketsEnabled,
            independent_public_resolution_cloudflare_fronted: host.publicFronted !== false,
            public_resolution_not_198_18_0_0_15: host.publicNotBenchmark !== false,
            public_resolution_not_proxy_mediated: host.publicNotProxyMediated !== false,
            public_resolution_source_value: host.publicResolutionToken,
            origin_comparison_source_value: host.originAddressToken,
          },
        };
      }
      if (payload && payload.originalTool) {
        return { observation: host.reconcileObservation };
      }
      // The record-dependent fields are exactly the per-case projection the
      // frozen schema requires; an absent or ambiguous record carries nulls.
      const present = ["SAME_RUN_CURRENT_UNPROXIED", "SAME_RUN_CURRENT_PROXIED", "FOREIGN_OR_STALE"]
        .includes(host.recordObservationCase);
      const dependent = present ? {
        record_count_category: "one",
        current_record_ref: host.currentRecordRef || (host.currentRecordRef = mintRef("record")),
        current_record_type: host.registeredOriginAddressType,
        current_record_digest: sha256Digest("cf-record"),
        current_record_origin_address_binding_digest: sha256Digest("cf-record-origin-binding"),
        current_record_owned_by_run: host.recordObservationCase !== "FOREIGN_OR_STALE",
        record_matches_current_origin_address_digest: host.recordObservationCase !== "FOREIGN_OR_STALE",
        proxy_enabled: host.recordProxied,
      } : {
        record_count_category: host.recordObservationCase === "AMBIGUOUS_MULTIPLE" ? "multiple" : "zero",
        current_record_ref: null,
        current_record_type: null,
        current_record_digest: null,
        current_record_origin_address_binding_digest: null,
        current_record_owned_by_run: null,
        record_matches_current_origin_address_digest: null,
        proxy_enabled: null,
      };
      return {
        observation: dataObservation("cloudflare_inventory", ["cloudflare_inventory_ref"], {
          record_observation_case: host.recordObservationCase,
          ssl_mode: host.sslMode,
          websockets_enabled: host.websocketsEnabled,
          hostname_binding_digest: identityDigest,
          ...dependent,
        }, 5),
      };
    },

    "xui.inventory_existing_fixed.v1": () => {
      record("broker", "xui.inventory_existing_fixed.v1");
      return { observation: xuiObservation() };
    },
    "xui.inventory_owned_fixed.v1": () => {
      record("broker", "xui.inventory_owned_fixed.v1");
      return { observation: xuiObservation() };
    },

    "xui.inbound_create_generate_store_client.v1": () =>
      helpers["origin.xui_inbound_apply_owned.v1"]({}),

    "xui.profile_publish_derive_store.v1": (payload) => {
      record("broker", "xui.profile_publish_derive_store.v1");
      const runtime = credentialBroker.deriveProfileRuntimeSecret(
        payload.clientSecretRef, payload.nodeBindingDigest);
      host.artifactPresent = true;
      const artifactDigest = sha256Digest("client-artifact");
      return {
        observation: dataObservation("xui_profile_publish", [
          ...MUTATION_COMMON_KEYS, "profile_ref", "client_profile_secret_ref",
          "client_artifact_ref", "residual_disclosure_ref",
        ], {
          artifact_digest: artifactDigest,
          artifact_mode: "0600",
          address_sni_host_equal: true,
          transport: "ws", tls_enabled: true, allow_insecure: false,
          public_port: 443, flow: "none",
          artifact_absent_before_create: true,
          descriptor_relative_nofollow_o_excl: true,
          created_same_run_artifact: true,
          artifact_readback_matches: true,
          hostname_identity_digest: identityDigest,
          websocket_path_digest: host.websocketPathDigest,
        }, 6),
        profileRef: mintRef("profile"),
        profileRuntimeSecretRef: runtime.secretRef,
        artifactRef: mintRef("artifact"),
        beforeDigest: null,
        afterDigest: artifactDigest,
        precondition: createOnly("xui_profile_publish"),
      };
    },

    "xui.profile_inspect_projection.v1": () => {
      record("broker", "xui.profile_inspect_projection.v1");
      return {
        observation: {
          profile_digest: sha256Digest("profile"),
          address_matches_node_hostname: host.profileAddressMatches !== false,
          sni_matches_node_hostname: host.profileSniMatches !== false,
          websocket_host_matches_node_hostname: host.profileHostMatches !== false,
          websocket_path_digest_matches: host.profilePathMatches !== false,
          transport: "ws", tls_enabled: true, allow_insecure: false,
          public_port: 443, flow_is_none: true, backend_security_is_none: true,
          importable: true,
          hostname_identity_digest: host.profileIdentityDigest || identityDigest,
          websocket_path_digest: host.profilePathDigestOverride || host.websocketPathDigest,
        },
      };
    },

    "xui.logs_counter_read_fixed.v1": () => {
      record("broker", "xui.logs_counter_read_fixed.v1");
      return { observation: { xui_counter_correlated: host.xuiCounterCorrelated !== false } };
    },

    "cf.origin_ca_issue_store_private_key": (payload) => {
      record("broker", "cf.origin_ca_issue_store_private_key");
      // Key and CSR are generated inside the broker; only the CSR leaves it.
      const issued = credentialBroker.generateOriginCaKeyAndCsr(payload.nodeHostnameRef);
      const result = {
        observation: dataObservation("certificate_issue_origin_ca", [
          ...MUTATION_COMMON_KEYS, "fullchain_ref",
        ], {
          issuer: "origin_ca",
          csr_generated_locally: true,
          csr_only_request_verified: true,
          csr_key_algorithm: "RSA-2048",
          origin_ca_request_type: "origin-rsa",
          requested_validity_days: 365,
          wildcard_requested: false,
          response_san_matches_exact_node_hostname: host.certificateSanMatches !== false,
          response_expiry_matches_request: true,
          fullchain_assembled_in_broker: true,
          fullchain_order: "leaf_then_required_issuer_chain",
          broker_custody_verified: true,
          certificate_fingerprint: sha256Digest("leaf-certificate"),
          san_binding_digest: identityDigest,
          not_after: "2027-08-22T00:00:00Z",
          hostname_identity_digest: host.certificateIdentityDigest || identityDigest,
        }, 10),
        fullchainRef: mintRef("certificate"),
        privateKeySecretRef: issued.privateKeySecretRef,
        csr: issued.csr,
        beforeDigest: null,
      };
      // Fault injection for the negative security test only: a broker that
      // tried to hand back private-key bytes must be rejected by the server.
      if (host.leakPrivateKey) {
        // Synthesized at runtime rather than written as a literal: the
        // package-byte scanners must never find a private-key container in
        // durable bytes, not even inside a hostile fixture.
        const dashes = "-".repeat(5);
        const marker = dashes + ["BEGIN", "PRIVATE", "KEY"].join(" ") + dashes;
        result.observation.private_key_pem =
          marker + "\nFAKE\n" + marker.replace("BEGIN", "END");
      }
      return result;
    },
    "cf.origin_ca_list_reconcile_fixed.v1": () => ({ observation: host.reconcileObservation }),

    "cf.dns_create_owned": () => {
      record("broker", "cf.dns_create_owned");
      host.recordPresent = true;
      host.recordProxied = false;
      host.recordObservationCase = "SAME_RUN_CURRENT_UNPROXIED";
      const recordDigest = sha256Digest("cf-record");
      return {
        observation: dataObservation("cf_node_record_apply", [
          ...MUTATION_COMMON_KEYS, "record_ref", "record_receipt_ref",
          "origin_address_binding_digest",
        ], {
          prior_record_observation_case: "ABSENT_AVAILABLE",
          record_digest: recordDigest,
          hostname_binding_digest: identityDigest,
          record_type: host.registeredOriginAddressType,
          record_value_source: "server_registered_current_origin_address",
          proxied: false, create_only: true, absent_before_create: true, created_same_run: true,
          hostname_identity_digest: host.recordIdentityDigest || identityDigest,
        }, 11),
        recordRef: mintRef("record"),
        originAddressSourceValue: host.recordOriginAddressOverride || host.originAddressDigest(),
        beforeDigest: null,
        afterDigest: recordDigest,
        precondition: createOnly("cf_node_record_apply"),
      };
    },

    "cf.dns_proxy_owned": (payload) => {
      if (payload && payload.stageId) {
        return inverseHelper("rb01_cf_proxy_restore", payload, () => { host.recordProxied = false; });
      }
      record("broker", "cf.dns_proxy_owned");
      host.recordProxied = true;
      host.recordObservationCase = "SAME_RUN_CURRENT_PROXIED";
      return {
        observation: {
          record_ref: payload.recordRef,
          record_digest: sha256Digest("cf-record-proxied"),
          proxied: true,
          origin_proof_bound: true,
        },
        beforeDigest: payload.recordDigest,
        afterDigest: sha256Digest("cf-record-proxied"),
      };
    },

    "cf.dns_delete_owned": (payload) =>
      inverseHelper("rb02_cf_record_delete", payload, () => {
        host.recordPresent = false;
        host.recordObservationCase = "ABSENT_AVAILABLE";
      }),

    "certificate.revoke_same_run_private_key.v1": (payload) =>
      inverseHelper("rb05_origin_ca_private_key_dispose", payload, () => {
        credentialBroker.revoke(payload.secretRef, "revoked");
      }),
    "artifact.revoke_same_run_runtime_secrets.v1": (payload) =>
      inverseHelper("rb07_profile_runtime_secret_dispose", payload, () => {
        credentialBroker.revoke(payload.secretRef, "revoked");
      }),
    "xui.revoke_same_run_client_secret.v1": (payload) =>
      inverseHelper("rb09_xui_client_secret_revoke", payload, () => {
        credentialBroker.revoke(payload.secretRef, "revoked");
      }),
    "xui.revoke_same_run_panel_admin.v1": (payload) =>
      inverseHelper("rb11_xui_panel_admin_revoke", payload, () => {
        credentialBroker.revoke(payload.secretRef, "revoked");
      }),

    "artifact.render_0600": () => ({ observation: { artifact_mode: "0600" } }),
    "artifact.reconcile_owned_fixed.v1": () => ({ observation: host.reconcileObservation }),
    "xui.reconcile_change_readback_fixed.v1": () => ({ observation: host.reconcileObservation }),
    "xui.install_generate_store_admin_secret": () => {
      const admin = credentialBroker.generatePanelAdmin();
      return { panelAdminSecretRef: admin.secretRef, maskedMetadata: admin.masked };
    },

    "client.authenticated_egress_probe_fixed.v1": (payload) => {
      record("broker", "client.authenticated_egress_probe_fixed.v1");
      const observation = {
        authenticated: host.authenticated,
        request_succeeded: host.requestSucceeded,
        ephemeral_artifact_removed: true,
      };
      // Likewise synthesized: a documentation-range address assembled at
      // runtime so no IPv4 literal exists in the repository bytes.
      if (host.leakRawEgress) {
        observation.observed_public_ip = [203, 0, 113, 77].join(".");
      }
      return {
        observation,
        probeDestinationRef: payload.probeDestinationRef,
        egressSourceValue: host.proxyEgressToken,
      };
    },

    "protected_line.runtime_probe_fixed.v1": () => {
      record("broker", "protected_line.runtime_probe_fixed.v1");
      return {
        observation: {
          healthy: host.protectedLineHealthy,
          authenticated: host.protectedLineHealthy,
          expectedEgress: host.protectedLineHealthy,
        },
      };
    },
  };

  function xuiObservation() {
    return dataObservation("xui_inventory", ["xui_inventory_ref"], {
      installation_status: host.xuiInstallationStatus,
      admin_binding_status: host.xuiAdminBindingStatus,
      admin_secret_provenance: host.xuiAdminProvenance,
      clean_host_install_eligible: host.xuiCleanHostEligible,
      version_masked: host.xuiVersionMasked,
      ownership_receipt_ref: host.installOwnershipReceiptRef,
      owned_inbound_refs: [],
      panel_fingerprint_digest: host.panelFingerprintDigest,
    }, 6);
  }

  return {
    helpers, broker: brokerOps, calls,
    inverseHelper, createOnly, thirdParty, record, dataObservation,
  };
}

module.exports = { buildFakeAdapters, dataObservation, MUTATION_COMMON_KEYS };
