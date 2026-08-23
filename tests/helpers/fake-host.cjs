"use strict";

// Fake staging host.
//
// A single mutable object standing in for the origin, the Cloudflare zone,
// the 3x-ui panel, nginx, the kernel sysctl state, and the local artifact
// directory. Nothing in here touches a real server, zone, DNS record,
// certificate, kernel, filesystem path outside the temp data dir, or the real
// macOS Keychain. Every adapter is a pure function of this state plus the
// server-supplied payload, so tests can steer any branch by setting a field.

const { mintRef, digestOf, sha256Digest } = require("../../mcp/core/refs.cjs");

const DEFAULT_ORIGIN_ADDRESS = "origin-address-token-a";
const DEFAULT_EGRESS = "egress-token-a";
const DEFAULT_PUBLIC_RESOLUTION = "public-edge-token-a";

class FakeHost {
  constructor(overrides = {}) {
    this.osFamily = "debian";
    // Adapter digest must match the build-time pinned allowlist to be trusted.
    this.adapterDigest =
      "sha256:3b2f4a6c8d1e0f7a5b9c3d2e4f6a8b0c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f01";

    // --- 3x-ui ---
    this.xuiInstallationStatus = "compatible_existing";
    this.xuiAdminBindingStatus = "COMPATIBLE_EXISTING_WITH_IMPORTED_ADMIN";
    this.xuiAdminProvenance = "IMPORTED_CURRENT";
    this.xuiCleanHostEligible = false;
    this.panelFingerprintDigest = sha256Digest("panel-fingerprint");
    this.xuiVersionMasked = "x.y.z";
    this.installOwnershipReceiptRef = null;
    this.inboundPresent = false;

    // --- nginx / origin ---
    this.nginxInstallationStatus = "supported_existing";
    this.publicTlsListenerOwner = "nginx_safe";
    this.ownedIncludeSlotAvailable = true;
    this.nodeServerNameConflict = false;
    this.websocketPathConflict = false;
    this.soleExactNodeRouteObserved = false;
    this.safeStableCertificateReuseEligible = true;
    this.certificateNotAfter = "2027-08-22T00:00:00Z";
    this.originCaDedicatedSlotStatus = "absent_root_owned_available";
    this.registeredOriginAddressType = "A";
    this.originAddressToken = DEFAULT_ORIGIN_ADDRESS;
    this.certificateSlotsPresent = false;
    this.nginxIncludePresent = false;

    // --- cloudflare ---
    this.recordObservationCase = "ABSENT_AVAILABLE";
    this.recordPresent = false;
    this.recordProxied = false;
    this.sslMode = "strict";
    this.websocketsEnabled = true;

    // --- kernel / bbr ---
    this.kernelExposesBbr = true;
    this.qdiscFqSupported = true;
    this.persistentConflictPresent = false;
    this.ownedDropinPresent = false;
    this.currentQdisc = "pfifo_fast";
    this.currentCongestionControl = "cubic";
    this.liveCongestionControl = "cubic";
    this.persistentCongestionControl = "cubic";
    this.liveQdisc = "pfifo_fast";
    this.persistentQdisc = "pfifo_fast";

    // --- probes ---
    this.protectedLineHealthy = true;
    this.egressToken = DEFAULT_EGRESS;
    this.proxyEgressToken = DEFAULT_EGRESS;
    this.publicResolutionToken = DEFAULT_PUBLIC_RESOLUTION;
    this.authenticated = true;
    this.requestSucceeded = true;
    this.artifactPresent = false;

    // What a reconciliation observer can prove. Setting this to null models
    // an observer that cannot resolve the question at all.
    this.reconcileObservation = "PROVEN_NOT_COMMITTED";

    // --- fault injection (all default off) ---
    this.thirdPartyDigestOn = null;      // stage id or adapter name
    this.failStage = null;               // stage id that refuses readback
    this.bbrVerifyFalse = false;
    this.leakPrivateKey = false;
    this.leakRawEgress = false;

    Object.assign(this, overrides);
  }

  originAddressDigest() {
    return sha256Digest(this.originAddressToken);
  }
}

module.exports = { FakeHost, DEFAULT_ORIGIN_ADDRESS, DEFAULT_EGRESS, DEFAULT_PUBLIC_RESOLUTION };
