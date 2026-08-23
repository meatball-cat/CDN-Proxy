"use strict";

// Per-tool mutator specifications.
//
// Each spec has three server-owned parts and no caller-owned part:
//   preflight  - proves the exact precondition before anything is dispatched;
//                every denial here happens with zero external effect.
//   payload    - the operation payload, derived only from immutable ledger
//                facts, registered onboarding refs, and prior receipts.
//   project    - verifies the adapter's readback against the frozen data
//                contract and mints the result. A readback that does not
//                prove an invariant is a failure, never a downgrade.
//
// The frozen data schemas pin many of these invariants as `const: true`.
// Rather than let a false readback surface as an opaque schema failure, each
// projector asserts it explicitly with the right contract error code, so the
// caller learns which safety property was not proven.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const manifest = require("../adapters/manifest.cjs");
const identity = require("../core/identity.cjs");
const { observationOf } = require("../core/forward-gate.cjs");

const RESOLVER = contracts.PLAN_OPERATION_RESOLVER;
const NO_CLOBBER = contracts.NO_CLOBBER_POLICY;

// --- shared assertions ----------------------------------------------------

function assertTrue(observation, field, code, message) {
  if (observation[field] !== true) {
    throw new ToolError(code, message);
  }
}

function assertEquals(observation, field, expected, code, message) {
  if (observation[field] !== expected) {
    throw new ToolError(code, message);
  }
}

// Create-only, no-clobber precondition. A resource this run creates must have
// been observed absent and unambiguous, the before-digest must be null, and
// the adapter must confirm it took an exclusive create. Anything else means
// something already occupies the slot: fail to manual without writing, never
// adopt and never overwrite.
function assertCreateOnly(result, resourceName) {
  const precondition = result.precondition || {};
  if (precondition.absentBefore !== true || precondition.exclusiveCreate !== true) {
    throw new ToolError("CONFLICT_DETECTED",
      `${resourceName} was not proven absent for an exclusive create; refusing to adopt or overwrite`);
  }
  if (precondition.thirdPartyDigestObserved === true) {
    throw new ToolError("CONFLICT_DETECTED",
      `${resourceName} changed concurrently under a third-party digest; no write was performed`);
  }
  if ((result.beforeDigest ?? null) !== null) {
    throw new ToolError("CONFLICT_DETECTED",
      `${resourceName} reported a pre-existing digest; ${NO_CLOBBER.successBeforeDigest} is required`);
  }
}

// A same-run receipt that a later step depends on must exist and be current.
function requireReceipt(ctx, run, objectKind, message) {
  const receipt = ctx.ledger.latestOwnership(run.run_id, objectKind);
  if (!receipt) throw new ToolError("DEPENDENCY_MISSING", message);
  return receipt;
}

function freshObservationOrThrow(ctx, run, family, message) {
  const observation = observationOf(ctx.ledger.freshEvidence(run.run_id, family));
  if (!observation) throw new ToolError("EVIDENCE_STALE", message, { retryable: true });
  return observation;
}

// Private-key containers must never cross the broker boundary at all. The
// closed data schema already has no field that could carry one, but a broker
// that offers key bytes has violated its own custody contract: surface that
// as a failure rather than silently dropping the field.
// Assembled from parts so this detector is not itself a literal container
// that the package-byte scanners would have to special-case.
const KEY_DASHES = "-".repeat(5);
const PRIVATE_KEY_CONTAINER = new RegExp([
  KEY_DASHES + "BEGIN [A-Z ]*PRIVATE KEY" + KEY_DASHES,
  ["PuTTY", "User", "Key", "File"].join("-"),
  ["BEGIN", "PGP", "PRIVATE"].join(" "),
  "^" + ["SSH", "PRIVATE", "KEY"].join(" "),
].join("|"), "m");

function assertNoPrivateKeyMaterial(result, operationName) {
  let serialized;
  try {
    serialized = JSON.stringify(result ?? null);
  } catch {
    throw new ToolError("SECRET_SCOPE_MISMATCH",
      `${operationName} returned a result that cannot be safely inspected`);
  }
  if (PRIVATE_KEY_CONTAINER.test(serialized)) {
    throw new ToolError("SECRET_SCOPE_MISMATCH",
      `${operationName} returned private-key material across the broker boundary`);
  }
}

// --- xui_install ----------------------------------------------------------

// Clean-host first install. Every non-clean observation denies before effect:
// an existing, partial, drifted, ambiguous, or unsupported installation is
// never upgraded, reinstalled, or removed.
const xui_install = {
  preflight(ctx, run, { plan }) {
    if (plan.lease_class !== "NODE_INSTALL_P3") {
      throw new ToolError("WRONG_STATE", "xui_install requires the NODE_INSTALL_P3 lease");
    }
    const xui = freshObservationOrThrow(ctx, run, "XUI_INVENTORY",
      "xui_install requires a current 3x-ui inventory");
    const observedCase = xui.admin_binding_status;
    if (observedCase !== "ABSENT_CLEAN_ELIGIBLE") {
      const row = contracts.XUI_INVENTORY_OBSERVATION_CASES[observedCase];
      const code = row && contracts.PLAN_OPERATION_RESOLVER.xuiCases[observedCase]
        ? contracts.PLAN_OPERATION_RESOLVER.xuiCases[observedCase].errorCode || "INSTALL_NOT_ELIGIBLE"
        : "INSTALL_NOT_ELIGIBLE";
      throw new ToolError(code,
        `clean-host install denied: observed 3x-ui case ${observedCase} is not a proven clean host`);
    }
    if (xui.installation_status !== "absent" || xui.clean_host_install_eligible !== true) {
      throw new ToolError("INSTALL_NOT_ELIGIBLE",
        "clean-host install requires a proven absent installation on an eligible clean host");
    }
    const origin = freshObservationOrThrow(ctx, run, "ORIGIN_INVENTORY",
      "xui_install requires a current origin inventory");
    const adapter = manifest.requirePinnedAdapter(origin);
    return { adapter };
  },

  payload(ctx, run, { preflight }) {
    // Only opaque, server-resolved handles cross this boundary. There is no
    // command, script, URL, path, username, password, or port anywhere here.
    return {
      adapterId: preflight.adapter.adapter_id,
      adapterVersion: preflight.adapter.version,
      adapterDigest: preflight.adapter.digest,
    };
  },

  // The panel administrator credentials are generated and stored by the
  // broker in its own registered operation, bound to the install this run
  // just performed. Routing it through the closed registry means the
  // caller-binding check applies to it like any other adapter edge.
  postDispatch(ctx, run, result, { preflight }) {
    const stored = ctx.adapters.callBroker(
      preflight.adapter.broker_operation, "xui_install", {
        runId: run.run_id,
        originTargetRef: run.binding.origin_target_ref,
        ownedInstallReadbackDigest: (result.observation || {}).readback_digest,
        generatedSecretPolicy: contracts.GENERATED_SECRET_POLICY,
      });
    return {
      ...result,
      panelAdminSecretRef: stored.panelAdminSecretRef,
      maskedMetadata: stored.maskedMetadata,
    };
  },

  project(ctx, run, result, commons, { preflight }) {
    const observation = result.observation || {};
    if (!manifest.isPinnedDigest(observation.adapter_digest)) {
      throw new ToolError("INSTALL_ADAPTER_UNTRUSTED",
        "install readback reported an adapter digest outside the build-time allowlist");
    }
    if (observation.adapter_digest !== preflight.adapter.digest) {
      throw new ToolError("INSTALL_ADAPTER_UNTRUSTED",
        "install readback digest does not equal the pinned adapter selected before dispatch");
    }
    assertTrue(observation, "service_active", "PROBE_FAILED",
      "install readback did not prove the service is active");
    assertTrue(observation, "panel_loopback_only", "PROBE_FAILED",
      "install readback did not prove the panel binds loopback only");
    if (typeof observation.readback_digest !== "string") {
      throw new ToolError("PROBE_FAILED", "install readback digest is missing");
    }
    const panelAdminSecretRef = result.panelAdminSecretRef;
    if (typeof panelAdminSecretRef !== "string" || !panelAdminSecretRef.startsWith("secret:")) {
      throw new ToolError("SECRET_REF_MISSING",
        "install did not return an opaque panel administrator SecretRef");
    }
    if (ctx.keychain.roleOf(panelAdminSecretRef) !== "xui-panel-admin") {
      throw new ToolError("SECRET_SCOPE_MISMATCH",
        "panel administrator SecretRef is not bound to the xui-panel-admin role");
    }
    ctx.ledger.registerSecretRef({
      secretRef: panelAdminSecretRef, runId: run.run_id,
      role: "xui-panel-admin", provenance: "same-run-generated",
    });

    // Install ownership is committed before any dependent mutation, and the
    // prior protected-line proof is invalidated: the next proof must be bound
    // to this exact install receipt before the install cursor may complete.
    const installationReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: installationReceiptRef,
      runId: run.run_id,
      objectKind: "OWNED_XUI_INSTALLATION",
      changeRef: commons.change_ref,
      beforeDigest: null,
      afterDigest: observation.readback_digest,
      details: {
        sameRunOwned: true,
        adapterDigest: observation.adapter_digest,
        panelAdminSecretRef,
        installationRef: result.installationRef,
      },
    });
    ctx.ledger.invalidateEvidenceFamily(run.run_id, "PROTECTED_LINE_HEALTH");
    ctx.ledger.setScalar(run.run_id, "install_receipt_ref", installationReceiptRef);
    ctx.ledger.setScalar(run.run_id, "panel_admin_secret_ref", panelAdminSecretRef);
    ctx.ledger.appendEvent(run.run_id, "INSTALL_OWNERSHIP_COMMITTED", {
      installationReceiptRef, adapterDigest: observation.adapter_digest,
      priorProtectedLineEvidenceInvalidated: true,
    });

    return {
      ...commons,
      installation_ref: result.installationRef,
      installation_ownership_receipt_ref: installationReceiptRef,
      panel_admin_secret_ref: panelAdminSecretRef,
      installed_version_masked: observation.installed_version_masked,
      adapter_digest: observation.adapter_digest,
      readback_digest: observation.readback_digest,
      service_active: true,
      panel_loopback_only: true,
    };
  },
};

// --- xui_create_inbound ---------------------------------------------------

const xui_create_inbound = {
  preflight(ctx, run) {
    const xui = freshObservationOrThrow(ctx, run, "XUI_INVENTORY",
      "xui_create_inbound requires a current 3x-ui inventory");
    if (!["COMPATIBLE_EXISTING_WITH_IMPORTED_ADMIN", "SAME_RUN_OWNED_WITH_GENERATED_ADMIN"]
      .includes(xui.admin_binding_status)) {
      throw new ToolError("DEPENDENCY_MISSING",
        `inbound creation requires a current administrator binding, observed ${xui.admin_binding_status}`);
    }
    return { panelFingerprintDigest: xui.panel_fingerprint_digest };
  },

  payload(ctx, run, { preflight }) {
    return {
      panelFingerprintDigest: preflight.panelFingerprintDigest,
      adminSecretRef: ctx.ledger.getScalar(run.run_id, "panel_admin_secret_ref")
        || run.binding.existing_xui_admin_secret_ref,
      inboundPolicy: contracts.XUI_INBOUND_POLICY,
    };
  },

  project(ctx, run, result, commons) {
    const observation = result.observation || {};
    assertCreateOnly(result, "xui inbound");
    // Loopback-only, plain WebSocket, no TLS at the Xray layer: TLS belongs to
    // the Nginx service slot, and a non-loopback listener would expose the
    // inbound directly to the public internet.
    assertTrue(observation, "listen_loopback_only", "CONFLICT_DETECTED",
      "inbound readback did not prove a loopback-only listener");
    assertEquals(observation, "inbound_protocol", "vless", "CONFLICT_DETECTED",
      "inbound protocol is not the frozen vless protocol");
    assertEquals(observation, "inbound_transport", "ws", "CONFLICT_DETECTED",
      "inbound transport is not the frozen websocket transport");
    assertEquals(observation, "inbound_tls", "none", "CONFLICT_DETECTED",
      "inbound must terminate no TLS of its own");
    assertEquals(observation, "inbound_flow", "none", "CONFLICT_DETECTED",
      "inbound flow must be none");
    assertEquals(observation, "proxy_protocol_enabled", false, "CONFLICT_DETECTED",
      "inbound must not enable the PROXY protocol");
    assertEquals(observation, "websocket_host", "", "CONFLICT_DETECTED",
      "inbound websocket host must stay server-unconstrained");
    assertTrue(observation, "inbound_absent_before_create", "CONFLICT_DETECTED",
      "inbound was not observed absent before create");
    assertTrue(observation, "created_same_run", "CONFLICT_DETECTED",
      "inbound is not a same-run created resource");

    const clientSecretRef = result.clientSecretRef;
    if (typeof clientSecretRef !== "string" || ctx.keychain.roleOf(clientSecretRef) !== "xui-client-credential") {
      throw new ToolError("SECRET_SCOPE_MISMATCH",
        "inbound did not return a client credential SecretRef bound to the xui-client-credential role");
    }
    ctx.ledger.registerSecretRef({
      secretRef: clientSecretRef, runId: run.run_id,
      role: "xui-client-credential", provenance: "same-run-generated",
    });
    const websocketPathDigest = identity.bindWebsocketPathDigest(
      ctx, run, "xui_create_inbound", observation.websocket_path_digest);
    ctx.ledger.setScalar(run.run_id, "websocket_path_ref", result.websocketPathRef);
    ctx.ledger.setScalar(run.run_id, "client_secret_ref", clientSecretRef);

    const inboundReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: inboundReceiptRef, runId: run.run_id, objectKind: "OWNED_XUI_INBOUND_RESOURCE",
      changeRef: commons.change_ref, beforeDigest: null, afterDigest: commons.after_digest,
      details: { sameRunOwned: true, inboundRef: result.inboundRef, clientSecretRef },
    });
    ctx.ledger.setScalar(run.run_id, "inbound_ref", result.inboundRef);

    return {
      ...commons,
      inbound_ref: result.inboundRef,
      client_secret_ref: clientSecretRef,
      inbound_receipt_ref: inboundReceiptRef,
      loopback_listener_ref: result.loopbackListenerRef,
      websocket_path_digest: websocketPathDigest,
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
    };
  },
};

// --- xui_profile_publish --------------------------------------------------

const xui_profile_publish = {
  preflight(ctx, run) {
    requireReceipt(ctx, run, "OWNED_XUI_INBOUND_RESOURCE",
      "profile publication requires the same-run owned inbound receipt");
    const outputDir = ctx.ledger.getOnboardingRef(run.binding.output_dir_ref);
    if (!outputDir || outputDir.role !== "output_dir" || outputDir.flags.safe !== true) {
      throw new ToolError("OUTPUT_DIR_UNSAFE",
        "profile publication requires a registered safe output directory");
    }
    return { outputDirRef: run.binding.output_dir_ref };
  },

  payload(ctx, run, { preflight }) {
    return {
      outputDirRef: preflight.outputDirRef,
      clientSecretRef: ctx.ledger.getScalar(run.run_id, "client_secret_ref"),
      websocketPathRef: ctx.ledger.getScalar(run.run_id, "websocket_path_ref"),
      nodeHostnameRef: run.binding.node_hostname_ref,
      profilePolicy: contracts.CLIENT_PROFILE_POLICY,
    };
  },

  project(ctx, run, result, commons) {
    const observation = result.observation || {};
    assertCreateOnly(result, "client profile artifact");
    assertEquals(observation, "artifact_mode", "0600", "OUTPUT_DIR_UNSAFE",
      "client profile artifact was not created with owner-only mode 0600");
    assertTrue(observation, "descriptor_relative_nofollow_o_excl", "OUTPUT_DIR_UNSAFE",
      "client profile artifact was not created descriptor-relative, nofollow, exclusive");
    assertTrue(observation, "artifact_absent_before_create", "CONFLICT_DETECTED",
      "client profile artifact was not observed absent before create");
    assertTrue(observation, "created_same_run_artifact", "CONFLICT_DETECTED",
      "client profile artifact is not a same-run created resource");
    assertTrue(observation, "artifact_readback_matches", "PROBE_FAILED",
      "client profile artifact readback does not match what was written");
    assertTrue(observation, "address_sni_host_equal", "CONFLICT_DETECTED",
      "client profile address, SNI, and websocket Host are not identical");
    assertEquals(observation, "transport", "ws", "CONFLICT_DETECTED", "profile transport must be ws");
    assertEquals(observation, "tls_enabled", true, "CONFLICT_DETECTED", "profile TLS must be enabled");
    assertEquals(observation, "allow_insecure", false, "CONFLICT_DETECTED",
      "profile must never allow insecure TLS");
    assertEquals(observation, "public_port", 443, "CONFLICT_DETECTED", "profile public port must be 443");
    assertEquals(observation, "flow", "none", "CONFLICT_DETECTED", "profile flow must be none");

    // The profile's address, SNI, and websocket Host all bind to the one
    // registered dedicated node hostname; the path binds to the same-run
    // generated websocket path.
    identity.bindProducerFields(ctx, run, "xui_profile_publish", observation.hostname_identity_digest);
    identity.bindWebsocketPathDigest(ctx, run, "xui_profile_publish", observation.websocket_path_digest);

    const profileSecretRef = result.profileRuntimeSecretRef;
    if (typeof profileSecretRef !== "string" || ctx.keychain.roleOf(profileSecretRef) !== "client-profile-runtime") {
      throw new ToolError("SECRET_SCOPE_MISMATCH",
        "profile publication did not return a client-profile-runtime SecretRef");
    }
    ctx.ledger.registerSecretRef({
      secretRef: profileSecretRef, runId: run.run_id,
      role: "client-profile-runtime", provenance: "same-run-generated",
    });
    const artifactReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: artifactReceiptRef, runId: run.run_id, objectKind: "OWNED_CLIENT_ARTIFACT",
      changeRef: commons.change_ref, beforeDigest: null, afterDigest: observation.artifact_digest,
      details: {
        sameRunOwned: true, artifactRef: result.artifactRef,
        profileRef: result.profileRef, profileSecretRef,
      },
    });
    ctx.ledger.setScalar(run.run_id, "profile_ref", result.profileRef);
    ctx.ledger.setScalar(run.run_id, "profile_secret_ref", profileSecretRef);
    ctx.ledger.setScalar(run.run_id, "client_artifact_ref", result.artifactRef);
    // A published client profile carries credential material off this host.
    // Deleting the artifact later cannot prove that no copy survives, so the
    // residual is disclosed at publication time rather than pretended away.
    const residualRef = mintRef("evidence");
    ctx.ledger.insertResidual({
      residualRef, runId: run.run_id,
      kind: "CLIENT_PROFILE_COPY_NOT_PROVABLY_DESTROYABLE",
      maskedSummary: "a published client profile copy cannot be proven destroyed by any later local deletion",
      bindingDigest: observation.artifact_digest,
    });

    return {
      ...commons,
      profile_ref: result.profileRef,
      client_profile_secret_ref: profileSecretRef,
      client_artifact_ref: result.artifactRef,
      artifact_digest: observation.artifact_digest,
      artifact_mode: "0600",
      node_binding_digest: run.node_binding_digest,
      address_sni_host_equal: true,
      transport: "ws",
      tls_enabled: true,
      allow_insecure: false,
      public_port: 443,
      flow: "none",
      artifact_absent_before_create: true,
      descriptor_relative_nofollow_o_excl: true,
      created_same_run_artifact: true,
      artifact_readback_matches: true,
      residual_disclosure_ref: residualRef,
    };
  },
};

// --- certificate_issue_origin_ca -----------------------------------------

const certificate_issue_origin_ca = {
  preflight(ctx, run, { plan }) {
    if (plan.certificate_strategy !== "origin_ca") {
      throw new ToolError("WRONG_STATE",
        "Origin CA issuance is only legal under the origin_ca certificate strategy");
    }
    if (run.binding.cf_origin_ca_secret_ref === null) {
      throw new ToolError("SECRET_REF_MISSING",
        "Origin CA issuance requires a registered cf-origin-ca credential");
    }
    return {};
  },

  payload(ctx, run) {
    return {
      nodeHostnameRef: run.binding.node_hostname_ref,
      cfOriginCaSecretRef: run.binding.cf_origin_ca_secret_ref,
    };
  },

  project(ctx, run, result, commons) {
    const observation = result.observation || {};
    // The private key is generated locally and stays in broker custody. Only
    // the CSR is transmitted. Any private-key-shaped field on this result is
    // a contract violation, not a value to redact.
    assertNoPrivateKeyMaterial(result, "cf.origin_ca_issue_store_private_key");
    assertTrue(observation, "csr_generated_locally", "CONFLICT_DETECTED",
      "Origin CA issuance did not prove the key and CSR were generated locally");
    assertTrue(observation, "csr_only_request_verified", "CONFLICT_DETECTED",
      "Origin CA issuance did not prove that only the CSR was transmitted");
    assertEquals(observation, "csr_key_algorithm", "RSA-2048", "CONFLICT_DETECTED",
      "Origin CA CSR key algorithm is not the frozen RSA-2048");
    assertEquals(observation, "origin_ca_request_type", "origin-rsa", "CONFLICT_DETECTED",
      "Origin CA request type is not the frozen origin-rsa");
    assertEquals(observation, "requested_validity_days", 365, "CONFLICT_DETECTED",
      "Origin CA validity is not the frozen 365 days");
    assertEquals(observation, "wildcard_requested", false, "CONFLICT_DETECTED",
      "Origin CA requests must never be wildcards");
    assertTrue(observation, "response_san_matches_exact_node_hostname", "CONFLICT_DETECTED",
      "issued certificate SAN does not match the exact registered node hostname");
    assertTrue(observation, "response_expiry_matches_request", "CONFLICT_DETECTED",
      "issued certificate expiry does not match the request");
    assertTrue(observation, "fullchain_assembled_in_broker", "CONFLICT_DETECTED",
      "fullchain was not assembled inside the broker");
    assertEquals(observation, "fullchain_order", "leaf_then_required_issuer_chain", "CONFLICT_DETECTED",
      "fullchain order is not leaf followed by the required issuer chain");
    assertTrue(observation, "broker_custody_verified", "SECRET_SCOPE_MISMATCH",
      "Origin CA private key is not provably in broker custody");

    const privateKeySecretRef = result.privateKeySecretRef;
    if (typeof privateKeySecretRef !== "string" ||
        ctx.keychain.roleOf(privateKeySecretRef) !== "origin-ca-private-key") {
      throw new ToolError("SECRET_SCOPE_MISMATCH",
        "Origin CA issuance did not return an origin-ca-private-key SecretRef");
    }
    ctx.ledger.registerSecretRef({
      secretRef: privateKeySecretRef, runId: run.run_id,
      role: "origin-ca-private-key", provenance: "same-run-generated",
    });
    identity.bindProducerFields(ctx, run, "certificate_issue_origin_ca",
      observation.hostname_identity_digest);

    ctx.ledger.setScalar(run.run_id, "fullchain_ref", result.fullchainRef);
    ctx.ledger.setScalar(run.run_id, "origin_ca_private_key_secret_ref", privateKeySecretRef);
    // Remote public issuance metadata cannot be erased by a local rollback;
    // record it now so the residual disclosure is honest later.
    ctx.ledger.insertResidual({
      residualRef: mintRef("evidence"),
      runId: run.run_id,
      kind: "REMOTE_ORIGIN_CA_PUBLIC_ISSUANCE_METADATA",
      maskedSummary: "Origin CA public issuance metadata is retained remotely and is not locally erasable",
      bindingDigest: observation.certificate_fingerprint,
    });

    return {
      ...commons,
      fullchain_ref: result.fullchainRef,
      certificate_fingerprint: observation.certificate_fingerprint,
      san_binding_digest: observation.san_binding_digest,
      issuer: "origin_ca",
      csr_generated_locally: true,
      csr_only_request_verified: true,
      csr_key_algorithm: "RSA-2048",
      origin_ca_request_type: "origin-rsa",
      requested_validity_days: 365,
      wildcard_requested: false,
      response_san_matches_exact_node_hostname: true,
      response_expiry_matches_request: true,
      fullchain_assembled_in_broker: true,
      fullchain_order: "leaf_then_required_issuer_chain",
      not_after: observation.not_after,
      broker_custody_verified: true,
    };
  },
};

// --- certificate_deploy ---------------------------------------------------

const certificate_deploy = {
  preflight(ctx, run) {
    const origin = freshObservationOrThrow(ctx, run, "ORIGIN_INVENTORY",
      "certificate deploy requires a current origin inventory");
    if (origin.origin_ca_dedicated_slot_status !== "absent_root_owned_available") {
      throw new ToolError("CONFLICT_DETECTED",
        `certificate slots are not absent and root-owned (observed ${origin.origin_ca_dedicated_slot_status}); refusing to back up, replace, or adopt`);
    }
    const fullchainRef = ctx.ledger.getScalar(run.run_id, "fullchain_ref");
    const privateKeySecretRef = ctx.ledger.getScalar(run.run_id, "origin_ca_private_key_secret_ref");
    if (!fullchainRef || !privateKeySecretRef) {
      throw new ToolError("CERTIFICATE_NOT_READY",
        "certificate deploy requires the same-run Origin CA custody pair");
    }
    return { fullchainRef, privateKeySecretRef };
  },

  payload(ctx, run, { preflight }) {
    return {
      fullchainRef: preflight.fullchainRef,
      privateKeySecretRef: preflight.privateKeySecretRef,
    };
  },

  project(ctx, run, result, commons) {
    const observation = result.observation || {};
    assertNoPrivateKeyMaterial(result, "origin.certificate_deploy_owned.v1");
    assertCreateOnly(result, "certificate service slots");
    for (const [field, message] of [
      ["stable_service_slots_verified", "certificate slots are not the verified stable service slots"],
      ["dedicated_slots_absent_before_create", "certificate slots were not observed absent before create"],
      ["descriptor_relative_nofollow_o_excl", "certificate slots were not created descriptor-relative, nofollow, exclusive"],
      ["created_same_run_slots", "certificate slots are not same-run created"],
      ["exact_slot_readback_verified", "certificate slot readback was not verified"],
      ["regular_files", "certificate slots are not regular files"],
      ["root_owned", "certificate slots are not root-owned"],
      ["no_symlink", "certificate slot path contains a symlink"],
      ["no_hardlink", "certificate slot path contains a hardlink"],
      ["trusted_parent", "certificate slot parent directory is not trusted"],
      ["fsync_complete", "certificate slot write was not fsynced"],
      ["atomic_receipt_written", "certificate slot receipt was not written atomically"],
      ["nginx_consumes_opaque_slot_refs_only", "nginx would receive a raw path instead of an opaque slot ref"],
    ]) {
      assertTrue(observation, field, "CONFLICT_DETECTED", message);
    }
    assertEquals(observation, "private_key_exposed", false, "SECRET_SCOPE_MISMATCH",
      "certificate deploy reported the private key as exposed");
    assertEquals(observation, "private_key_mode", "0600", "OUTPUT_DIR_UNSAFE",
      "private key slot mode is not 0600");
    assertEquals(observation, "fullchain_mode", "0644", "OUTPUT_DIR_UNSAFE",
      "fullchain slot mode is not 0644");
    identity.bindProducerFields(ctx, run, "certificate_deploy", observation.hostname_identity_digest);

    const slotReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: slotReceiptRef, runId: run.run_id, objectKind: "OWNED_CERTIFICATE_SLOTS",
      changeRef: commons.change_ref, beforeDigest: null, afterDigest: commons.after_digest,
      details: {
        sameRunOwned: true,
        fullchainSlotRef: result.fullchainSlotRef,
        privateKeySlotRef: result.privateKeySlotRef,
      },
    });
    ctx.ledger.setScalar(run.run_id, "fullchain_slot_ref", result.fullchainSlotRef);
    ctx.ledger.setScalar(run.run_id, "private_key_slot_ref", result.privateKeySlotRef);

    return {
      ...commons,
      fullchain_slot_ref: result.fullchainSlotRef,
      private_key_slot_ref: result.privateKeySlotRef,
      certificate_slot_receipt_ref: slotReceiptRef,
      certificate_fingerprint: observation.certificate_fingerprint,
      san_binding_digest: observation.san_binding_digest,
      stable_service_slots_verified: true,
      private_key_exposed: false,
      dedicated_slots_absent_before_create: true,
      descriptor_relative_nofollow_o_excl: true,
      created_same_run_slots: true,
      exact_slot_readback_verified: true,
      regular_files: true,
      root_owned: true,
      no_symlink: true,
      no_hardlink: true,
      trusted_parent: true,
      private_key_mode: "0600",
      fullchain_mode: "0644",
      fsync_complete: true,
      atomic_receipt_written: true,
      nginx_consumes_opaque_slot_refs_only: true,
    };
  },
};

// --- nginx_route_apply ----------------------------------------------------

const nginx_route_apply = {
  preflight(ctx, run, { plan }) {
    const origin = freshObservationOrThrow(ctx, run, "ORIGIN_INVENTORY",
      "nginx route apply requires a current origin inventory");
    if (origin.nginx_installation_status !== "supported_existing") {
      throw new ToolError("DEPENDENCY_MISSING",
        `nginx route apply requires a supported existing nginx (observed ${origin.nginx_installation_status}); Core-v1 never installs nginx`);
    }
    if (origin.public_tls_listener_owner !== "nginx_safe") {
      throw new ToolError("CONFLICT_DETECTED",
        `the public TLS listener is not safely owned by nginx (observed ${origin.public_tls_listener_owner})`);
    }
    if (origin.owned_include_slot_available !== true) {
      throw new ToolError("CONFLICT_DETECTED",
        "the create-only owned include slot is not available");
    }
    if (origin.node_server_name_conflict === true || origin.websocket_path_conflict === true) {
      throw new ToolError("CONFLICT_DETECTED",
        "an existing server_name or websocket path conflicts with the planned route");
    }
    requireReceipt(ctx, run, "OWNED_XUI_INBOUND_RESOURCE",
      "nginx route apply requires the same-run owned inbound receipt");

    // Certificate slots come from the plan's own strategy: a reuse plan binds
    // the observed safe stable slots and writes no certificate byte; an
    // origin_ca plan binds this run's own deploy receipt.
    if (plan.certificate_strategy === "reuse") {
      if (origin.safe_stable_certificate_reuse_eligible !== true) {
        throw new ToolError("CERTIFICATE_NOT_READY",
          "reuse plan requires a currently safe, stable, root-owned certificate pair");
      }
      if (origin.node_hostname_coverage !== true) {
        throw new ToolError("CERTIFICATE_NOT_READY",
          "the reused certificate does not cover the exact registered node hostname");
      }
      return {
        certificateSource: "reuse",
        slotRefs: origin.stable_service_slot_refs,
        // The reused certificate's SAN coverage is proven by the origin
        // inventory, so the route binds the certificate_san identity field
        // that an origin_ca run would bind at issuance.
        bindsCertificateSan: true,
      };
    }
    const deployReceipt = requireReceipt(ctx, run, "OWNED_CERTIFICATE_SLOTS",
      "origin_ca plan requires the same-run certificate deploy receipt");
    return { certificateSource: "origin_ca", deployReceipt };
  },

  payload(ctx, run, { preflight }) {
    return {
      certificateSource: preflight.certificateSource,
      fullchainSlotRef: ctx.ledger.getScalar(run.run_id, "fullchain_slot_ref"),
      privateKeySlotRef: ctx.ledger.getScalar(run.run_id, "private_key_slot_ref"),
      websocketPathRef: ctx.ledger.getScalar(run.run_id, "websocket_path_ref"),
      inboundRef: ctx.ledger.getScalar(run.run_id, "inbound_ref"),
      routePolicy: contracts.NGINX_ROUTE_POLICY,
    };
  },

  project(ctx, run, result, commons, { preflight }) {
    const observation = result.observation || {};
    assertCreateOnly(result, "nginx include");
    for (const [field, message] of [
      ["syntax_valid", "nginx configuration did not pass a syntax check"],
      ["reload_verified", "nginx reload was not verified"],
      ["supported_existing_nginx", "route was not applied to a supported existing nginx"],
      ["safe_public_tls_listener_ownership", "public TLS listener ownership is not safe"],
      ["no_server_name_conflict", "a server_name conflict was present"],
      ["no_websocket_path_conflict", "a websocket path conflict was present"],
      ["create_only_owned_include", "the include was not created create-only"],
      ["sole_exact_server_name", "the route does not serve the sole exact node server_name"],
      ["sole_exact_websocket_path", "the route does not serve the sole exact websocket path"],
      ["loopback_upstream_exact", "the upstream is not the exact loopback inbound"],
      ["public_tls_listener_443", "the route does not bind the public TLS port 443"],
      ["http11_upgrade_connection_exact", "the route does not set the exact HTTP/1.1 upgrade headers"],
      ["unmatched_request_nondisclosing_404", "unmatched requests are not answered with a nondisclosing 404"],
      ["backend_tls_disabled", "backend TLS is enabled; the backend must be plain loopback"],
      ["proxy_protocol_disabled", "the PROXY protocol is enabled"],
      ["no_wildcard_or_default_server", "the route registers a wildcard or default server"],
      ["exact_node_hostname_and_high_entropy_path", "the route does not bind the exact hostname and high-entropy path"],
      ["include_absent_before_create", "the include was not observed absent before create"],
      ["descriptor_relative_nofollow_o_excl", "the include was not created descriptor-relative, nofollow, exclusive"],
      ["created_same_run_include", "the include is not same-run created"],
      ["include_readback_matches", "include readback does not match what was written"],
    ]) {
      assertTrue(observation, field, "CONFLICT_DETECTED", message);
    }
    assertEquals(observation, "nginx_install_performed", false, "CONFLICT_DETECTED",
      "Core-v1 must never install nginx");

    identity.bindProducerFields(ctx, run, "nginx_route_apply", observation.hostname_identity_digest);
    identity.bindWebsocketPathDigest(ctx, run, "nginx_route_apply", observation.websocket_path_digest);
    if (preflight.bindsCertificateSan) {
      identity.bindEqualityField(ctx, run, "certificate_san", observation.hostname_identity_digest);
    }

    const routeReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: routeReceiptRef, runId: run.run_id, objectKind: "OWNED_NGINX_ROUTE",
      changeRef: commons.change_ref, beforeDigest: null,
      afterDigest: observation.effective_route_digest,
      details: { sameRunOwned: true, routeRef: result.routeRef },
    });
    ctx.ledger.setScalar(run.run_id, "route_ref", result.routeRef);
    ctx.ledger.setScalar(run.run_id, "current_route_digest", observation.effective_route_digest);

    return {
      ...commons,
      route_ref: result.routeRef,
      route_receipt_ref: routeReceiptRef,
      fullchain_slot_ref: result.fullchainSlotRef,
      private_key_slot_ref: result.privateKeySlotRef,
      nginx_config_digest: observation.nginx_config_digest,
      node_binding_digest: run.node_binding_digest,
      syntax_valid: true,
      reload_verified: true,
      supported_existing_nginx: true,
      safe_public_tls_listener_ownership: true,
      no_server_name_conflict: true,
      no_websocket_path_conflict: true,
      create_only_owned_include: true,
      nginx_install_performed: false,
      sole_exact_server_name: true,
      sole_exact_websocket_path: true,
      loopback_upstream_exact: true,
      public_tls_listener_443: true,
      http11_upgrade_connection_exact: true,
      unmatched_request_nondisclosing_404: true,
      backend_tls_disabled: true,
      proxy_protocol_disabled: true,
      no_wildcard_or_default_server: true,
      exact_node_hostname_and_high_entropy_path: true,
      include_absent_before_create: true,
      descriptor_relative_nofollow_o_excl: true,
      created_same_run_include: true,
      include_readback_matches: true,
      effective_route_digest: observation.effective_route_digest,
    };
  },
};

// --- cf_node_record_apply -------------------------------------------------

const cf_node_record_apply = {
  preflight(ctx, run) {
    const cf = freshObservationOrThrow(ctx, run, "CLOUDFLARE_INVENTORY",
      "record creation requires a current Cloudflare inventory");
    // Strict-compatible mode and WebSockets are read-only prerequisites.
    // Core-v1 performs no zone-wide setting write of any kind.
    const gate = RESOLVER.cloudflareForwardGate;
    if (!gate.strictCompatibleModes.includes(cf.ssl_mode)) {
      throw new ToolError("SSL_MODE_NOT_STRICT_COMPATIBLE",
        `zone SSL mode ${cf.ssl_mode} is not strict-compatible; correct it externally and start a new run`);
    }
    if (cf.websockets_enabled !== true) {
      throw new ToolError("DEPENDENCY_MISSING",
        "zone WebSockets are not enabled; correct it externally and start a new run");
    }
    if (cf.record_observation_case !== "ABSENT_AVAILABLE") {
      throw new ToolError("CONFLICT_DETECTED",
        `record case ${cf.record_observation_case} is not an absent, unambiguous slot; refusing to overwrite or adopt`);
    }
    const origin = freshObservationOrThrow(ctx, run, "ORIGIN_INVENTORY",
      "record creation requires a current origin inventory");
    return {
      recordType: origin.registered_origin_address_type,
      currentOriginAddressDigest: origin.current_origin_address_digest,
    };
  },

  payload(ctx, run, { preflight }) {
    // The record value is never caller data: the server binds it to the
    // registered current origin address digest.
    return {
      recordType: preflight.recordType,
      currentOriginAddressDigest: preflight.currentOriginAddressDigest,
      nodeHostnameRef: run.binding.node_hostname_ref,
      cfNodeDnsSecretRef: run.binding.cf_node_dns_secret_ref,
    };
  },

  project(ctx, run, result, commons, { preflight }) {
    const observation = result.observation || {};
    assertCreateOnly(result, "cloudflare node record");
    assertEquals(observation, "prior_record_observation_case", "ABSENT_AVAILABLE", "CONFLICT_DETECTED",
      "record was not created against a proven absent slot");
    assertEquals(observation, "proxied", false, "CONFLICT_DETECTED",
      "the node record must be created unproxied so the origin can be proven directly first");
    assertEquals(observation, "record_value_source", "server_registered_current_origin_address",
      "CONFLICT_DETECTED", "record value did not come from the server-registered current origin address");
    assertTrue(observation, "create_only", "CONFLICT_DETECTED", "record was not created create-only");
    assertTrue(observation, "absent_before_create", "CONFLICT_DETECTED",
      "record was not observed absent before create");
    assertTrue(observation, "created_same_run", "CONFLICT_DETECTED",
      "record is not a same-run created resource");
    if (observation.record_type !== preflight.recordType) {
      throw new ToolError("CONFLICT_DETECTED",
        "created record type does not match the registered origin address type");
    }
    // The record's origin binding is compared as an opaque HMAC digest in the
    // RECORD_ORIGIN_EQUALITY_V1 domain; no raw address enters MCP.
    const expected = ctx.binder.digest("CURRENT_ORIGIN_ADDRESS", {
      targetId: run.binding.origin_target_ref, runId: run.run_id,
      value: preflight.currentOriginAddressDigest,
    });
    const observed = ctx.binder.digest("RECORD_ORIGIN_ADDRESS", {
      targetId: run.binding.origin_target_ref, runId: run.run_id,
      value: result.originAddressSourceValue,
    });
    const { LowEntropyBinder } = require("../core/hmac.cjs");
    LowEntropyBinder.requireSameDomain("CURRENT_ORIGIN_ADDRESS", "RECORD_ORIGIN_ADDRESS");
    if (!LowEntropyBinder.equal(expected, observed)) {
      throw new ToolError("CONFLICT_DETECTED",
        "created record does not bind the current registered origin address");
    }
    identity.bindProducerFields(ctx, run, "cf_node_record_apply", observation.hostname_identity_digest);

    const recordReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: recordReceiptRef, runId: run.run_id, objectKind: "OWNED_CF_RECORD",
      changeRef: commons.change_ref, beforeDigest: null, afterDigest: observation.record_digest,
      details: { sameRunOwned: true, recordRef: result.recordRef },
    });
    ctx.ledger.setScalar(run.run_id, "record_ref", result.recordRef);
    ctx.ledger.setScalar(run.run_id, "record_digest", observation.record_digest);

    return {
      ...commons,
      record_ref: result.recordRef,
      record_receipt_ref: recordReceiptRef,
      prior_record_observation_case: "ABSENT_AVAILABLE",
      record_digest: observation.record_digest,
      hostname_binding_digest: observation.hostname_binding_digest,
      record_type: observation.record_type,
      origin_address_binding_digest: observed,
      record_value_source: "server_registered_current_origin_address",
      proxied: false,
      create_only: true,
      absent_before_create: true,
      created_same_run: true,
    };
  },
};

// --- cf_proxy_enable ------------------------------------------------------

const cf_proxy_enable = {
  preflight(ctx, run) {
    // The proxy gate: a record may only be fronted after the origin itself
    // has been proven directly. Without that proof, enabling the proxy would
    // hide an unverified origin behind Cloudflare.
    const originProof = ctx.ledger.freshEvidence(run.run_id, "DIRECT_ORIGIN_TLS_WEBSOCKET");
    if (!originProof) {
      throw new ToolError("ORIGIN_NOT_VERIFIED",
        "proxy may not be enabled before a current direct-origin TLS+WebSocket proof exists");
    }
    const proofBinding = JSON.parse(originProof.binding || "{}");
    const currentRouteDigest = ctx.ledger.getScalar(run.run_id, "current_route_digest");
    if (proofBinding.routeDigest !== currentRouteDigest) {
      throw new ToolError("ORIGIN_NOT_VERIFIED",
        "the direct-origin proof is not bound to the current route");
    }
    const cf = freshObservationOrThrow(ctx, run, "CLOUDFLARE_INVENTORY",
      "proxy enable requires a current Cloudflare inventory");
    const gate = RESOLVER.cloudflareForwardGate;
    if (!gate.strictCompatibleModes.includes(cf.ssl_mode)) {
      throw new ToolError("SSL_MODE_NOT_STRICT_COMPATIBLE",
        `zone SSL mode ${cf.ssl_mode} is not strict-compatible`);
    }
    if (cf.websockets_enabled !== true) {
      throw new ToolError("DEPENDENCY_MISSING", "zone WebSockets are not enabled");
    }
    if (cf.current_record_owned_by_run !== true) {
      throw new ToolError("CONFLICT_DETECTED",
        "the observed record is not this run's own created record; refusing to proxy an unowned record");
    }
    const receipt = requireReceipt(ctx, run, "OWNED_CF_RECORD",
      "proxy enable requires this run's own record receipt");
    return { receipt, originProofRef: originProof.evidence_ref };
  },

  payload(ctx, run, { preflight }) {
    return {
      recordRef: ctx.ledger.getScalar(run.run_id, "record_ref"),
      recordDigest: ctx.ledger.getScalar(run.run_id, "record_digest"),
      ownedRecordReceiptRef: preflight.receipt.receipt_ref,
      originProofRef: preflight.originProofRef,
      cfNodeDnsSecretRef: run.binding.cf_node_dns_secret_ref,
    };
  },

  project(ctx, run, result, commons) {
    const observation = result.observation || {};
    assertEquals(observation, "proxied", true, "PROBE_FAILED",
      "proxy enable readback did not prove the record is proxied");
    assertTrue(observation, "origin_proof_bound", "ORIGIN_NOT_VERIFIED",
      "proxy receipt is not bound to the direct-origin proof");

    const proxyReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: proxyReceiptRef, runId: run.run_id, objectKind: "OWNED_CF_PROXY",
      changeRef: commons.change_ref,
      beforeDigest: ctx.ledger.getScalar(run.run_id, "record_digest"),
      afterDigest: observation.record_digest,
      details: { sameRunOwned: true, priorProxied: false, recordRef: observation.record_ref },
    });
    ctx.ledger.setScalar(run.run_id, "proxy_receipt_ref", proxyReceiptRef);

    return {
      ...commons,
      record_ref: observation.record_ref,
      proxy_receipt_ref: proxyReceiptRef,
      record_digest: observation.record_digest,
      proxied: true,
      origin_proof_bound: true,
    };
  },
};

// --- bbr_apply ------------------------------------------------------------

const bbr_apply = {
  preflight(ctx, run, { plan }) {
    if (plan.lease_class !== "HOST_P3") {
      throw new ToolError("WRONG_STATE", "bbr_apply requires the dedicated HOST_P3 lease");
    }
    const bbr = freshObservationOrThrow(ctx, run, "BBR_INVENTORY",
      "bbr_apply requires a current BBR inventory");
    // Supported-kernel only. Core-v1 never installs or upgrades a kernel,
    // edits a bootloader or a shared sysctl file, or reboots.
    if (bbr.kernel_exposes_bbr !== true ||
        bbr.available_congestion_controls_contains_bbr !== true ||
        bbr.qdisc_fq_supported !== true) {
      throw new ToolError("DEPENDENCY_MISSING",
        "the current kernel does not already expose BBR and fq; Core-v1 never installs or upgrades a kernel");
    }
    if (bbr.persistent_conflict_present === true) {
      throw new ToolError("CONFLICT_DETECTED",
        "a persistent sysctl conflict is present; Core-v1 never edits a shared sysctl file");
    }
    if (bbr.owned_dropin_present !== false) {
      throw new ToolError("CONFLICT_DETECTED",
        "an owned drop-in already exists; the drop-in is exclusive-create only");
    }
    if (bbr.eligible !== true) {
      throw new ToolError("DEPENDENCY_MISSING", "BBR inventory does not prove eligibility");
    }
    return { priorQdisc: bbr.current_qdisc, priorCongestionControl: bbr.current_congestion_control };
  },

  payload(ctx, run, { preflight }) {
    return {
      targetValues: contracts.BBR_TARGET_POLICY.targetValues,
      allowedKeys: contracts.BBR_SAFETY_POLICY.allowedKeys,
      priorQdisc: preflight.priorQdisc,
      priorCongestionControl: preflight.priorCongestionControl,
    };
  },

  project(ctx, run, result, commons, { preflight }) {
    const observation = result.observation || {};
    assertCreateOnly(result, "bbr sysctl drop-in");
    for (const [field, message] of [
      ["live_apply_readback", "live sysctl readback was not verified"],
      ["persistent_readback", "persistent sysctl readback was not verified"],
      ["descriptor_relative_nofollow", "the drop-in was not created descriptor-relative and nofollow"],
      ["exclusive_create", "the drop-in was not exclusive-created"],
      ["owned_dropin_absent_before_create", "the drop-in was not observed absent before create"],
      ["dropin_readback_matches", "drop-in readback does not match what was written"],
      ["owned_dropin_path_bound_to_approved_runtime_ref", "the drop-in path is not bound to the approved runtime ref"],
      ["receipt_binds_owned_path_and_dropin_digest", "the receipt does not bind the owned path and drop-in digest"],
    ]) {
      assertTrue(observation, field, "CONFLICT_DETECTED", message);
    }
    const targets = contracts.BBR_TARGET_POLICY.applyReadback;
    for (const [field, expected] of [
      ["live_congestion_control", targets.liveCongestionControl],
      ["persistent_congestion_control", targets.persistentCongestionControl],
      ["live_default_qdisc", targets.liveQdisc],
      ["persistent_default_qdisc", targets.persistentQdisc],
    ]) {
      assertEquals(observation, field, expected, "PROBE_FAILED",
        `bbr readback ${field} is not the frozen target value ${expected}`);
    }

    // The exact prior values are recorded now: the inverse restores these and
    // nothing else, and it never adopts an older drop-in.
    const priorValuesDigest = digestOf({
      qdisc: preflight.priorQdisc,
      congestionControl: preflight.priorCongestionControl,
    });
    const bbrReceiptRef = mintRef("receipt");
    ctx.ledger.insertOwnership({
      receiptRef: bbrReceiptRef, runId: run.run_id, objectKind: "OWNED_BBR_APPLY",
      changeRef: commons.change_ref, beforeDigest: priorValuesDigest,
      afterDigest: observation.dropin_digest,
      details: {
        sameRunOwned: true,
        ownedDropinRef: result.ownedDropinRef,
        priorQdisc: preflight.priorQdisc,
        priorCongestionControl: preflight.priorCongestionControl,
        priorValuesDigest,
        receiptType: "BBR_APPLY_RECEIPT",
      },
    });
    ctx.ledger.setScalar(run.run_id, "bbr_apply_receipt_ref", bbrReceiptRef);
    ctx.ledger.setScalar(run.run_id, "bbr_change_ref", commons.change_ref);
    ctx.ledger.setScalar(run.run_id, "bbr_prior_values", {
      qdisc: preflight.priorQdisc,
      congestionControl: preflight.priorCongestionControl,
      digest: priorValuesDigest,
    });
    ctx.ledger.setScalar(run.run_id, "bbr_dropin_digest", observation.dropin_digest);
    // Applying BBR changes the transport path: every authenticated E2E
    // evidence family it invalidates must be refreshed before acceptance.
    for (const family of ["AUTHENTICATED_PROXY_REQUEST", "LOG_CORRELATION", "PROTECTED_LINE_HEALTH"]) {
      ctx.ledger.invalidateEvidenceFamily(run.run_id, family);
    }

    return {
      ...commons,
      bbr_receipt_ref: bbrReceiptRef,
      owned_dropin_ref: result.ownedDropinRef,
      dropin_digest: observation.dropin_digest,
      prior_qdisc: preflight.priorQdisc,
      prior_congestion_control: preflight.priorCongestionControl,
      live_apply_readback: true,
      persistent_readback: true,
      live_congestion_control: "bbr",
      persistent_congestion_control: "bbr",
      live_default_qdisc: "fq",
      persistent_default_qdisc: "fq",
      descriptor_relative_nofollow: true,
      exclusive_create: true,
      owned_dropin_absent_before_create: true,
      dropin_readback_matches: true,
      owned_dropin_path_bound_to_approved_runtime_ref: true,
      receipt_binds_owned_path_and_dropin_digest: true,
    };
  },
};

const MUTATORS = Object.freeze({
  xui_install,
  xui_create_inbound,
  xui_profile_publish,
  certificate_issue_origin_ca,
  certificate_deploy,
  nginx_route_apply,
  cf_node_record_apply,
  cf_proxy_enable,
  bbr_apply,
});

module.exports = {
  MUTATORS, assertCreateOnly, assertTrue, assertEquals, requireReceipt,
  freshObservationOrThrow, assertNoPrivateKeyMaterial, PRIVATE_KEY_CONTAINER,
};
