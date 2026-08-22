"use strict";

// Keychain seam. The server process never sees secret bytes; it only asks
// whether an opaque SecretRef exists and which role it is bound to. The
// production implementation is phase-gated in the Phase 0-1 build (the real
// macOS Keychain broker is Phase 2 scope). Tests inject a fake seam.

class PhaseGatedKeychain {
  hasSecret() {
    return false;
  }

  roleOf() {
    return null;
  }
}

module.exports = { PhaseGatedKeychain };
