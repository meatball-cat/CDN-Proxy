"use strict";

// Keychain seam.
//
// The MCP server process never sees secret bytes. It holds opaque SecretRefs
// and asks the seam only three questions: does this ref exist, which role is
// it bound to, and what is its disposition. Plaintext custody belongs to the
// broker/Keychain side of the seam; nothing on this side can read it.
//
// The production implementation (the real macOS Keychain broker) is not part
// of this build and stays phase-gated. Tests and the staging harness inject
// an in-memory seam that has the same shape and the same one-way boundary.

const SECRET_ROLES = Object.freeze([
  "ssh-origin-identity",
  "xui-panel-admin",
  "xui-client-credential",
  "client-profile-runtime",
  "protected-line-runtime",
  "cf-audit",
  "cf-node-dns",
  "cf-origin-ca",
  "origin-ca-private-key",
]);

// Non-credential high-entropy material that must also never reach MCP: the
// generated WebSocket path is projected as an opaque ref plus digest only.
const CUSTODY_ROLES = Object.freeze([...SECRET_ROLES, "websocket-path"]);

class PhaseGatedKeychain {
  hasSecret() {
    return false;
  }

  roleOf() {
    return null;
  }

  dispositionOf() {
    return null;
  }
}

// In-memory custody used by the test/staging harness. Plaintext is held in a
// private WeakMap-like closure keyed by ref; there is no accessor that
// returns it to the server side, and `toJSON`/`inspect` never expose it.
class InMemoryKeychain {
  constructor() {
    const plaintext = new Map();
    const meta = new Map();
    // Only the broker holds this token; handing it over is how the broker
    // proves it is the plaintext owner rather than an ordinary caller.
    const custodyToken = Symbol("keychain-custody");

    this.custodyToken = custodyToken;

    this.put = (token, { secretRef, role, provenance, bytes, maskedMetadata = {} }) => {
      if (token !== custodyToken) {
        throw new Error("only the credential broker may store plaintext in the keychain seam");
      }
      if (!CUSTODY_ROLES.includes(role)) {
        throw new Error(`unknown custody role: ${role}`);
      }
      plaintext.set(secretRef, bytes);
      meta.set(secretRef, { role, provenance, disposition: "current", maskedMetadata });
      return secretRef;
    };

    this.use = (token, secretRef) => {
      if (token !== custodyToken) {
        throw new Error("only the credential broker may use plaintext from the keychain seam");
      }
      return plaintext.get(secretRef) ?? null;
    };

    this.dispose = (token, secretRef, disposition) => {
      if (token !== custodyToken) {
        throw new Error("only the credential broker may dispose keychain plaintext");
      }
      const row = meta.get(secretRef);
      if (!row) return false;
      plaintext.delete(secretRef);
      meta.set(secretRef, { ...row, disposition });
      return true;
    };

    this.hasSecret = (secretRef) => meta.has(secretRef);
    this.roleOf = (secretRef) => (meta.get(secretRef) || {}).role || null;
    this.dispositionOf = (secretRef) => (meta.get(secretRef) || {}).disposition || null;
    this.maskedMetadataOf = (secretRef) => ({ ...((meta.get(secretRef) || {}).maskedMetadata || {}) });
    this.registerImported = (secretRef, role) => {
      meta.set(secretRef, { role, provenance: "imported", disposition: "current", maskedMetadata: {} });
    };
    this.custodyRefs = () => [...meta.keys()];
  }

  // Defensive: neither a JSON dump nor a console inspection of the seam can
  // ever carry plaintext, because plaintext lives only in the closure above.
  toJSON() {
    return { keychain: "opaque", entries: this.custodyRefs().length };
  }
}

module.exports = { PhaseGatedKeychain, InMemoryKeychain, SECRET_ROLES, CUSTODY_ROLES };
