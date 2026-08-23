"use strict";

// Domain identity binding (DOMAIN_IDENTITY_BINDING_POLICY).
//
// Exactly one dedicated node hostname governs the whole node journey. It
// comes from the onboarding registry, never from caller input, and the same
// identity must appear in the Cloudflare record, the certificate SAN, the
// Nginx server_name, and the client profile's address, SNI, and WebSocket
// Host. The WebSocket path is a separate high-entropy binding that must be
// byte-identical across the inbound, the Nginx route, and the profile.
//
// Any disagreement between these fields is a denial, not a warning: a client
// pointed at one name while the certificate covers another is exactly the
// failure this binding exists to prevent.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("./errors.cjs");
const { digestOf } = require("./refs.cjs");

const POLICY = contracts.DOMAIN_IDENTITY_BINDING_POLICY;
const EQUALITY_FIELDS = POLICY.equalityFields;

// Which mutator/probe result contributes which equality field. Derived from
// the frozen field list so no second mapping can drift from it.
const FIELD_BY_PRODUCER = Object.freeze({
  cf_node_record_apply: "cloudflare_record",
  certificate_issue_origin_ca: "certificate_san",
  certificate_deploy: "certificate_san",
  nginx_route_apply: "nginx_server_name",
  xui_profile_publish: Object.freeze(["profile_address", "profile_sni", "profile_websocket_host"]),
  xui_profile_inspect: Object.freeze(["profile_address", "profile_sni", "profile_websocket_host"]),
});

// Validates the onboarding registration of the dedicated node hostname.
// A hostname that is the zone apex, is the panel/management hostname, is
// ambiguous, or does not sit under the registered zone can never be used.
function requireDedicatedNodeHostname(ctx, run) {
  const registered = ctx.ledger.getOnboardingRef(run.binding.node_hostname_ref);
  if (!registered || registered.role !== "node_hostname") {
    throw new ToolError("UNAUTHORIZED_TARGET",
      "node_hostname_ref does not name a registered node hostname");
  }
  const flags = registered.flags || {};
  if (flags.dedicated_node_hostname !== true) {
    throw new ToolError("UNAUTHORIZED_TARGET",
      "node hostname registration does not prove a dedicated node hostname");
  }
  if (flags.apex === true) {
    throw new ToolError("UNAUTHORIZED_TARGET",
      "the zone apex may never be registered as a node hostname");
  }
  if (flags.management_hostname === true) {
    throw new ToolError("UNAUTHORIZED_TARGET",
      "the panel/management hostname may never be reused as a node hostname");
  }
  if (flags.ambiguous === true) {
    throw new ToolError("CONFLICT_DETECTED",
      "node hostname registration is ambiguous; resolve it externally and start a new run");
  }
  if (flags.zone_target_ref !== run.binding.cloudflare_target_ref) {
    throw new ToolError("UNAUTHORIZED_TARGET",
      "node hostname does not sit under the registered Cloudflare zone");
  }
  if (typeof flags.hostname_identity_digest !== "string") {
    throw new ToolError("UNAUTHORIZED_TARGET",
      "node hostname registration carries no server-computed identity digest");
  }
  return { registered, flags, identityDigest: flags.hostname_identity_digest };
}

// The immutable per-run identity every dependent field must match. The raw
// hostname is not part of it: only the server-computed identity digest.
function nodeIdentity(ctx, run) {
  const { identityDigest } = requireDedicatedNodeHostname(ctx, run);
  return {
    hostnameRef: run.binding.node_hostname_ref,
    identityDigest,
    bindingDigest: digestOf({ node_hostname_ref: run.binding.node_hostname_ref }),
  };
}

// Records one field's observed identity and rejects the first disagreement.
// Fields are recorded as the journey proceeds, so a mismatch is caught at the
// mutation that introduces it rather than at the end.
function bindEqualityField(ctx, run, field, observedIdentityDigest) {
  if (!EQUALITY_FIELDS.includes(field)) {
    throw new ToolError("INTERNAL_ERROR", `unknown domain equality field ${field}`);
  }
  const identity = nodeIdentity(ctx, run);
  if (observedIdentityDigest !== identity.identityDigest) {
    throw new ToolError("CONFLICT_DETECTED",
      `${field} does not match the registered dedicated node hostname identity`);
  }
  ctx.ledger.recordIdentityBinding(run.run_id, field, observedIdentityDigest);
  return identity;
}

function bindProducerFields(ctx, run, producerTool, observedIdentityDigest) {
  const fields = FIELD_BY_PRODUCER[producerTool];
  if (!fields) return nodeIdentity(ctx, run);
  const list = Array.isArray(fields) ? fields : [fields];
  let identity = null;
  for (const field of list) {
    identity = bindEqualityField(ctx, run, field, observedIdentityDigest);
  }
  return identity;
}

// Final gate: every equality field must be present and identical. Used by the
// authenticated-E2E completion predicate.
function assertSetEquality(ctx, run) {
  const identity = nodeIdentity(ctx, run);
  const bound = ctx.ledger.identityBindings(run.run_id);
  const missing = EQUALITY_FIELDS.filter((field) => !(field in bound));
  if (missing.length > 0) {
    throw new ToolError("DEPENDENCY_MISSING",
      `domain identity set-equality is incomplete: ${missing.join(", ")}`.slice(0, 200));
  }
  const disagreeing = EQUALITY_FIELDS.filter((field) => bound[field] !== identity.identityDigest);
  if (disagreeing.length > 0) {
    throw new ToolError("CONFLICT_DETECTED",
      `domain identity mismatch on ${disagreeing.join(", ")}`.slice(0, 200));
  }
  return identity;
}

// The WebSocket path binding is separate: high-entropy, opaque, and required
// to be byte-identical across the inbound, the route, and the profile.
function bindWebsocketPathDigest(ctx, run, consumer, observedPathDigest) {
  const current = ctx.ledger.websocketPathDigest(run.run_id);
  if (current === null) {
    ctx.ledger.recordWebsocketPathDigest(run.run_id, observedPathDigest);
    return observedPathDigest;
  }
  if (current !== observedPathDigest) {
    throw new ToolError("CONFLICT_DETECTED",
      `${consumer} websocket path does not match the exact same-run generated path`);
  }
  return current;
}

module.exports = {
  EQUALITY_FIELDS,
  FIELD_BY_PRODUCER,
  requireDedicatedNodeHostname,
  nodeIdentity,
  bindEqualityField,
  bindProducerFields,
  assertSetEquality,
  bindWebsocketPathDigest,
};
