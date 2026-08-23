"use strict";

// Credential broker.
//
// The broker is the only component that generates, holds, or uses plaintext
// credential material. Every public method returns an opaque SecretRef plus
// masked, non-reversible metadata; there is no method that returns plaintext
// to the server, and the Keychain custody token never leaves this module.
//
// Generation parameters come exclusively from the frozen
// GENERATED_SECRET_POLICY. The caller cannot choose a value, a length, an
// alphabet, a username, a password, or a path.

const crypto = require("node:crypto");
const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { mintRef, sha256Digest } = require("../core/refs.cjs");

const POLICY = contracts.GENERATED_SECRET_POLICY;

// A base64url string of exactly `outputCharacters` characters, drawn from
// `randomBytes` bytes of OS CSPRNG entropy. Nothing weaker is representable.
function csprngBase64Url(randomBytes, outputCharacters) {
  const raw = crypto.randomBytes(randomBytes).toString("base64url");
  if (raw.length < outputCharacters) {
    throw new Error("csprng encoding produced fewer characters than the frozen policy requires");
  }
  return raw.slice(0, outputCharacters);
}

// Masked metadata is derived from the shape of a value, never from the value
// itself: length and a keyed fingerprint that cannot be reversed or matched
// against a candidate without the per-broker key.
function maskedShape(kind, value, fingerprintKey) {
  return {
    kind,
    length: value.length,
    entropy_class: "csprng",
    fingerprint: sha256Digest(
      crypto.createHmac("sha256", fingerprintKey).update(value).digest(),
    ),
  };
}

class CredentialBroker {
  constructor(keychain) {
    if (!keychain || typeof keychain.put !== "function") {
      throw new Error("credential broker requires a keychain custody seam");
    }
    // Held privately; the token is never exported, logged, or returned.
    const token = keychain.custodyToken;
    const fingerprintKey = crypto.randomBytes(32);
    // Scope uniqueness registry for the frozen uniqueness rule.
    const issuedFingerprints = new Set();

    const store = (role, provenance, kind, value) => {
      const masked = maskedShape(kind, value, fingerprintKey);
      // SERVER_SIDE_SCOPE_UNIQUENESS_CHECK_BOUNDED_COLLISION_RETRY_THEN_FAIL
      if (issuedFingerprints.has(masked.fingerprint)) return null;
      issuedFingerprints.add(masked.fingerprint);
      const secretRef = mintRef("secret");
      keychain.put(token, {
        secretRef, role, provenance, bytes: value, maskedMetadata: masked,
      });
      return { secretRef, masked };
    };

    // Bounded collision retry then fail, per the frozen uniqueness policy.
    const storeUnique = (role, provenance, kind, generate) => {
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const stored = store(role, provenance, kind, generate());
        if (stored) return stored;
      }
      throw new Error(`scope uniqueness could not be established for ${kind}`);
    };

    this.storeUnique = storeUnique;
    this.useForAdapter = (secretRef) => keychain.use(token, secretRef);
    this.disposeSecret = (secretRef, disposition) => keychain.dispose(token, secretRef, disposition);
    this.keychain = keychain;
  }

  // --- clean-host install: panel administrator credentials ------------------

  // Generates and stores the panel administrator username and password.
  // Returns one opaque SecretRef for the credential pair plus masked
  // metadata; neither the username nor the password ever crosses this
  // boundary, so no MCP result, log line, Hook payload, fixture, or report
  // can carry them.
  generatePanelAdmin() {
    const usernamePolicy = POLICY.panelAdminUsername;
    const passwordPolicy = POLICY.panelAdminPassword;
    const pair = this.storeUnique("xui-panel-admin", "same-run-generated", "panel-admin-pair", () => {
      const username = csprngBase64Url(usernamePolicy.randomBytes, usernamePolicy.outputCharacters);
      const password = csprngBase64Url(passwordPolicy.randomBytes, passwordPolicy.outputCharacters);
      return JSON.stringify({ username, password });
    });
    return {
      secretRef: pair.secretRef,
      masked: {
        kind: "panel-admin-pair",
        username_length: usernamePolicy.outputCharacters,
        username_entropy_bits: usernamePolicy.entropyBits,
        password_length: passwordPolicy.outputCharacters,
        password_entropy_bits: passwordPolicy.entropyBits,
        encoding: usernamePolicy.encoding,
        fingerprint: pair.masked.fingerprint,
      },
    };
  }

  // --- node journey: inbound client credential and websocket path ----------

  generateVlessClientId() {
    const clientPolicy = POLICY.vlessClientId;
    const stored = this.storeUnique("xui-client-credential", "same-run-generated", "vless-client-id",
      () => crypto.randomUUID());
    return {
      secretRef: stored.secretRef,
      masked: {
        kind: "vless-client-id",
        format: clientPolicy.format,
        version: clientPolicy.version,
        random_bits: clientPolicy.randomBits,
        fingerprint: stored.masked.fingerprint,
      },
    };
  }

  // The WebSocket path is high-entropy routing material. It is generated from
  // the frozen CSPRNG policy, held in custody, and projected to the server as
  // an opaque ref plus a digest. The raw path never enters MCP.
  generateWebsocketPath() {
    const pathPolicy = POLICY.websocketPath;
    const exact = new RegExp(pathPolicy.exactPattern);
    const stored = this.storeUnique("websocket-path", "same-run-generated", "websocket-path", () => {
      const value = `/${csprngBase64Url(pathPolicy.randomBytes, 32)}`;
      if (!exact.test(value)) {
        throw new Error("generated websocket path does not match the frozen exact pattern");
      }
      return value;
    });
    return {
      pathRef: stored.secretRef,
      pathDigest: stored.masked.fingerprint,
      masked: {
        kind: "websocket-path",
        entropy_bits: pathPolicy.entropyBits,
        query_allowed: pathPolicy.queryAllowed,
        fragment_allowed: pathPolicy.fragmentAllowed,
      },
    };
  }

  // --- client profile runtime secret ---------------------------------------

  deriveProfileRuntimeSecret(clientSecretRef, bindingDigest) {
    const source = this.useForAdapter(clientSecretRef);
    if (source === null) {
      throw new Error("profile derivation requires a current client credential in custody");
    }
    const stored = this.storeUnique("client-profile-runtime", "same-run-generated", "profile-runtime",
      () => JSON.stringify({ client: source, binding: bindingDigest }));
    return { secretRef: stored.secretRef, masked: { kind: "profile-runtime", fingerprint: stored.masked.fingerprint } };
  }

  // --- Origin CA private key and CSR ---------------------------------------

  // Generates the RSA-2048 key locally and keeps it in custody. Only the CSR
  // (public material) is returned for transmission to the issuer; the private
  // key is never returned, never transmitted, and never rendered.
  generateOriginCaKeyAndCsr(nodeHostnameRef) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
    const publicDer = publicKey.export({ type: "spki", format: "der" });
    const stored = this.storeUnique("origin-ca-private-key", "same-run-generated", "origin-ca-key",
      () => privatePem);
    // The CSR is modelled as public request metadata bound to the exact
    // hostname and the public-key fingerprint. No private material is in it.
    const csrPublicKeyFingerprint = sha256Digest(publicDer);
    return {
      privateKeySecretRef: stored.secretRef,
      csr: Object.freeze({
        node_hostname_ref: nodeHostnameRef,
        key_algorithm: "RSA-2048",
        request_type: "origin-rsa",
        requested_validity_days: 365,
        wildcard: false,
        public_key_fingerprint: csrPublicKeyFingerprint,
      }),
      masked: { kind: "origin-ca-key", key_algorithm: "RSA-2048" },
    };
  }

  // --- disposition ---------------------------------------------------------

  revoke(secretRef, disposition = "revoked") {
    return this.disposeSecret(secretRef, disposition);
  }
}

module.exports = { CredentialBroker, csprngBase64Url };
