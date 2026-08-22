// FILE: mcp/schemas/contracts.cjs
"use strict";

const {
  closed, str, bool, int, enumOf, constOf, nullable, arr, ref,
  A, E, errorBodyOf, contract,
} = require("../../shared/schema-primitives.cjs");

const FROZEN_TOOL_NAMES = Object.freeze([
  "run_begin", "run_status", "reconcile_status", "plan_compile", "plan_authorize",
  "evidence_list", "completion_evaluate", "run_close", "rollback_run",
  "origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory",
  "old_line_verify", "xui_install", "xui_create_inbound", "xui_profile_publish",
  "xui_profile_inspect", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply",
  "origin_verify", "cf_node_record_apply", "cf_proxy_enable", "cdn_verify", "traffic_verify",
  "logs_correlate", "bbr_inventory", "bbr_apply", "bbr_verify", "bbr_rollback",
]);
const CORE_V1_TOOL_NAMES = FROZEN_TOOL_NAMES;

const MAIN_PHASES = Object.freeze([
  "NEW", "INVENTORIED", "PLAN_READY", "APPROVED", "APPLYING",
  "ORIGIN_CONFIGURED", "ORIGIN_VERIFIED", "CDN_ENABLED", "CDN_VERIFIED",
  "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED",
  "OLD_LINE_REVERIFIED", "DELIVERY_REPORT_SEALED",
  "ROLLBACK_REQUIRED", "ROLLING_BACK", "ROLLED_BACK",
  "MANUAL_ACTION_REQUIRED", "CLOSED",
]);
const BBR_PHASES = Object.freeze([
  "BBR_NOT_REQUESTED", "BBR_PENDING", "BBR_INVENTORIED", "BBR_PLAN_READY",
  "BBR_HOST_APPROVED", "BBR_APPLIED", "BBR_VERIFIED", "BBR_ROLLING_BACK",
  "BBR_ROLLED_BACK", "BBR_MANUAL_ACTION_REQUIRED", "BBR_CLOSED",
]);

const S = Object.freeze({
  MainPhase: enumOf(...MAIN_PHASES),
  BbrPhase: enumOf(...BBR_PHASES),
  RunRef: ref("run"), TargetRef: ref("target"), PlanRef: ref("plan"),
  ApprovalRef: ref("approval"), OperationRef: ref("operation"),
  EvidenceRef: ref("evidence"), ClosureRef: ref("closure"),
  ChangeRef: ref("change"), InverseRef: ref("inverse"),
  CompensationRef: ref("compensation"), ArtifactRef: ref("artifact"),
  SecretRef: ref("secret"), RuntimeRef: ref("runtime"),
  CertificateRef: ref("certificate"), RecordRef: ref("record"),
  InboundRef: ref("inbound"), ProfileRef: ref("profile"),
  ProbeRef: ref("probe"), ReceiptRef: ref("receipt"),
  NullableRuntimeRef: nullable(ref("runtime")),
  NullableSecretRef: nullable(ref("secret")),
  Digest: str(71, 71, { pattern: "^sha256:[a-f0-9]{64}$" }),
  Timestamp: str(20, 40, { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+Z$" }),
  IdempotencyKey: str(16, 128, { pattern: "^[A-Za-z0-9._:-]+$" }),
  MaskedText: str(1, 128),
});

const ERROR_CODES = Object.freeze([
  "INVALID_INPUT", "UNAUTHORIZED_TARGET", "WRONG_STATE", "DEPENDENCY_MISSING",
  "APPROVAL_REQUIRED", "APPROVAL_STALE", "APPROVAL_REPLAYED", "BASELINE_DRIFT",
  "IDEMPOTENCY_CONFLICT", "SECRET_REF_MISSING", "SECRET_SCOPE_MISMATCH",
  "UPSTREAM_AUTH_FAILED", "UPSTREAM_FORBIDDEN", "UPSTREAM_UNAVAILABLE",
  "UPSTREAM_TIMEOUT", "CONFLICT_DETECTED", "UNKNOWN_COMMIT_STATE",
  "RECONCILIATION_REQUIRED", "BACKUP_INVALID", "OUTPUT_DIR_UNSAFE",
  "PROTECTED_LINE_UNPROVEN", "PROBE_FAILED", "EVIDENCE_STALE",
  "ROLLBACK_REQUIRED", "ROLLBACK_UNSAFE", "MANUAL_ACTION_REQUIRED",
  "INSTALL_NOT_ELIGIBLE", "INSTALL_ADAPTER_UNTRUSTED", "CERTIFICATE_NOT_READY",
  "ORIGIN_NOT_VERIFIED", "CDN_NOT_VERIFIED", "SSL_MODE_NOT_STRICT_COMPATIBLE", "INTERNAL_ERROR",
]);
const ErrorBody = errorBodyOf(ERROR_CODES, S.EvidenceRef);

const LEASE_POLICIES = Object.freeze({
  NODE_P2: Object.freeze({ ttl: "PT45M", prompt: "HOST_PROMPT", scope: "node_p2" }),
  NODE_INSTALL_P3: Object.freeze({ ttl: "PT10M", prompt: "HOST_PROMPT", scope: "node_install_p3" }),
  HOST_P3: Object.freeze({ ttl: "PT15M", prompt: "HOST_PROMPT", scope: "host_p3" }),
  ROLLBACK: Object.freeze({ ttl: "PT15M", prompt: "PREAUTHORIZED_OR_HOST_PROMPT", scope: "rollback" }),
});
const EVIDENCE_TTLS = Object.freeze({
  INVENTORY: "PT15M", CLOUDFLARE_INVENTORY: "PT10M", PROTECTED_LINE: "PT5M",
  PLAN_BASELINE: "PT10M", ORIGIN_VERIFY: "PT5M", CDN_VERIFY: "PT5M",
  PROFILE_VERIFY: "PT15M", TRAFFIC_VERIFY: "PT5M", LOG_WINDOW: "PT10M",
  BBR_INVENTORY: "PT10M", BBR_VERIFY: "PT5M", IMMUTABLE_RECEIPT: "NO_TTL",
});

const RUN_MODE_POLICY = Object.freeze({
  ledgerField: "run_mode",
  immutableAfterBegin: true,
  callerSelectableAfterBegin: false,
  audit: Object.freeze({
    enableBbr: false,
    allowedTools: Object.freeze([
      "run_begin", "run_status", "evidence_list", "origin_inventory",
      "cloudflare_inventory", "xui_inventory", "client_inventory",
      "old_line_verify", "completion_evaluate", "run_close",
    ]),
    completionLabel: "audit_complete",
    closeOutcome: "audit_complete",
    leaseClasses: Object.freeze([]),
    externalMutation: "FORBIDDEN",
  }),
  configure: Object.freeze({
    planIntents: Object.freeze([
      "configure_existing", "install_then_configure", "enable_bbr",
      "rollback_owned_changes",
    ]),
    modeGate: "RUN_MODE_CONFIGURE_FROM_IMMUTABLE_LEDGER",
    bbrBranch: "REQUESTED_ONLY",
  }),
});

const OUTPUT_STATUS_POLICY = Object.freeze({
  allowedForEveryTool: Object.freeze(["ok", "error"]),
  noOpAllowedIffInputRequiresIdempotencyKey: true,
  pendingAllowedOnlyFor: "completion_evaluate:configured_not_verified",
  ok: Object.freeze({
    meaning: "FRESH_SUCCESS_AND_DECLARED_SUCCESS_BY_ORIGIN_OR_RESULT_MATRIX_EXECUTED",
    newStateOrPhasePreservation: "EXACT_DECLARED_RESOLVER",
    data: "CURRENT_INVOCATION_RESULT",
  }),
  noOp: Object.freeze({
    meaning: "EXACT_SAME_IDEMPOTENCY_KEY_CANONICAL_REPLAY",
    newSideEffect: false,
    stateOrCursorAdvance: false,
    data: "BYTE_EQUIVALENT_CANONICAL_ORIGINAL_RESULT_BINDING",
  }),
  pending: Object.freeze({
    tool: "completion_evaluate",
    label: "configured_not_verified",
    newSealedReport: false,
    destination: "UNCHANGED",
  }),
  completionFreshStatusByLabel: Object.freeze({
    audit_complete: "ok",
    configured_not_verified: "pending",
    end_to_end_verified: "ok",
  }),
  error: Object.freeze({ data: "NULL", errorBody: "NON_NULL_CLOSED_ERROR" }),
  callerSelectable: false,
});

const COMPLETION_STATUS_DATA_RULES = Object.freeze([
  {
    if: { properties: { status: { const: "pending" } }, required: ["status"] },
    then: { properties: { data: { type: "object", properties: { label: { const: "configured_not_verified" } }, required: ["label"] } } },
  },
  {
    if: { properties: { status: { const: "ok" } }, required: ["status"] },
    then: { properties: { data: { type: "object", properties: { label: enumOf("audit_complete", "end_to_end_verified") }, required: ["label"] } } },
  },
  {
    if: { properties: { data: { type: "object", properties: { label: { const: "configured_not_verified" } }, required: ["label"] } }, required: ["data"] },
    then: { properties: { status: enumOf("pending", "no_op") } },
  },
  {
    if: { properties: { data: { type: "object", properties: { label: enumOf("audit_complete", "end_to_end_verified") }, required: ["label"] } }, required: ["data"] },
    then: { properties: { status: enumOf("ok", "no_op") } },
  },
]);

const MUTATION_FAILURE_RESOLVER = Object.freeze({
  callerSelectable: false,
  contexts: Object.freeze([
    "MAIN_EXTERNAL_MUTATION", "BBR_EXTERNAL_MUTATION",
    "MAIN_ROLLBACK_EXECUTOR", "BBR_ROLLBACK_EXECUTOR",
  ]),
  rows: Object.freeze({
    PRE_DISPATCH: Object.freeze({
      commitObservation: "PRE_DISPATCH",
      retryable: false,
      errorCodeByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "WRONG_STATE", BBR_EXTERNAL_MUTATION: "WRONG_STATE",
        MAIN_ROLLBACK_EXECUTOR: "WRONG_STATE", BBR_ROLLBACK_EXECUTOR: "WRONG_STATE",
      }),
      destinationByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "UNCHANGED", BBR_EXTERNAL_MUTATION: "UNCHANGED",
        MAIN_ROLLBACK_EXECUTOR: "UNCHANGED", BBR_ROLLBACK_EXECUTOR: "UNCHANGED",
      }),
      reconcileBeforeRetry: false, overwriteAllowed: false,
    }),
    PROVEN_NOT_COMMITTED: Object.freeze({
      commitObservation: "PROVEN_NOT_COMMITTED",
      retryable: true,
      errorCodeByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "BASELINE_DRIFT", BBR_EXTERNAL_MUTATION: "BASELINE_DRIFT",
        MAIN_ROLLBACK_EXECUTOR: "ROLLBACK_UNSAFE", BBR_ROLLBACK_EXECUTOR: "ROLLBACK_UNSAFE",
      }),
      destinationByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "UNCHANGED", BBR_EXTERNAL_MUTATION: "UNCHANGED",
        MAIN_ROLLBACK_EXECUTOR: "UNCHANGED", BBR_ROLLBACK_EXECUTOR: "UNCHANGED",
      }),
      reconcileBeforeRetry: false, overwriteAllowed: false,
    }),
    KNOWN_COMMITTED_NEEDS_INVERSE: Object.freeze({
      commitObservation: "KNOWN_COMMITTED_NEEDS_INVERSE",
      retryable: false,
      errorCodeByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "ROLLBACK_REQUIRED", BBR_EXTERNAL_MUTATION: "ROLLBACK_REQUIRED",
        MAIN_ROLLBACK_EXECUTOR: "MANUAL_ACTION_REQUIRED", BBR_ROLLBACK_EXECUTOR: "MANUAL_ACTION_REQUIRED",
      }),
      destinationByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "ROLLBACK_REQUIRED", BBR_EXTERNAL_MUTATION: "BBR_APPLIED",
        MAIN_ROLLBACK_EXECUTOR: "MANUAL_ACTION_REQUIRED", BBR_ROLLBACK_EXECUTOR: "BBR_MANUAL_ACTION_REQUIRED",
      }),
      reconcileBeforeRetry: false, overwriteAllowed: false,
    }),
    UNKNOWN_COMMIT: Object.freeze({
      commitObservation: "UNKNOWN_COMMIT",
      retryable: false,
      errorCodeByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "UNKNOWN_COMMIT_STATE", BBR_EXTERNAL_MUTATION: "UNKNOWN_COMMIT_STATE",
        MAIN_ROLLBACK_EXECUTOR: "UNKNOWN_COMMIT_STATE", BBR_ROLLBACK_EXECUTOR: "UNKNOWN_COMMIT_STATE",
      }),
      destinationByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "MANUAL_ACTION_REQUIRED", BBR_EXTERNAL_MUTATION: "BBR_MANUAL_ACTION_REQUIRED",
        MAIN_ROLLBACK_EXECUTOR: "MANUAL_ACTION_REQUIRED", BBR_ROLLBACK_EXECUTOR: "BBR_MANUAL_ACTION_REQUIRED",
      }),
      reconcileBeforeRetry: true, overwriteAllowed: false,
    }),
    CONCURRENT_THIRD_DIGEST: Object.freeze({
      commitObservation: "CONCURRENT_THIRD_DIGEST",
      retryable: false,
      errorCodeByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "CONFLICT_DETECTED", BBR_EXTERNAL_MUTATION: "CONFLICT_DETECTED",
        MAIN_ROLLBACK_EXECUTOR: "CONFLICT_DETECTED", BBR_ROLLBACK_EXECUTOR: "CONFLICT_DETECTED",
      }),
      destinationByContext: Object.freeze({
        MAIN_EXTERNAL_MUTATION: "MANUAL_ACTION_REQUIRED", BBR_EXTERNAL_MUTATION: "BBR_MANUAL_ACTION_REQUIRED",
        MAIN_ROLLBACK_EXECUTOR: "MANUAL_ACTION_REQUIRED", BBR_ROLLBACK_EXECUTOR: "BBR_MANUAL_ACTION_REQUIRED",
      }),
      reconcileBeforeRetry: true, overwriteAllowed: false,
    }),
  }),
});

const RECONCILIATION_OBSERVATIONS = Object.freeze(["STILL_UNKNOWN", "PROVEN_NOT_COMMITTED", "PROVEN_COMMITTED", "PROVEN_INVERSE_PREFIX", "CONCURRENT_THIRD_DIGEST"]);
const NON_PREFIX_RECONCILIATION_OBSERVATIONS = Object.freeze(["STILL_UNKNOWN", "PROVEN_NOT_COMMITTED", "PROVEN_COMMITTED", "CONCURRENT_THIRD_DIGEST"]);
const RECONCILIATION_OUTCOME_RESOLVER = Object.freeze({
  authority: "SERVER_SELECTS_THE_SOLE_OPEN_RECONCILIATION_OBLIGATION_AND_ITS_FIXED_READ_ONLY_OBSERVER",
  callerSelectableOperationTargetOrMode: false,
  allowedStates: Object.freeze({ main: "MANUAL_ACTION_REQUIRED", bbr: "BBR_MANUAL_ACTION_REQUIRED" }),
  observations: RECONCILIATION_OBSERVATIONS,
  operationClassByOriginalTool: Object.freeze({
    rollback_run: "MAIN_ROLLBACK_EXECUTOR",
    bbr_apply: "BBR_APPLY",
    bbr_rollback: "BBR_ROLLBACK_EXECUTOR",
    active_checkpoint_refresh_tools: "ACTIVE_CHECKPOINT_DRIFT",
    every_other_external_mutator: "MAIN_EXTERNAL_MUTATION",
  }),
  commonUnresolved: Object.freeze({
    STILL_UNKNOWN: Object.freeze({ destination: "UNCHANGED", retry: false, nextAction: "STAY_MANUAL_NO_RETRY_OR_CLOSE" }),
    CONCURRENT_THIRD_DIGEST: Object.freeze({ destination: "UNCHANGED", retry: false, nextAction: "STAY_MANUAL_RECONCILE_NO_OVERWRITE" }),
  }),
  resultByOperationClass: Object.freeze({
    MAIN_EXTERNAL_MUTATION: Object.freeze({
      PROVEN_COMMITTED: "COMPILE_AND_AUTHORIZE_OWNED_ROLLBACK",
      PROVEN_NOT_COMMITTED_ZERO_PRIOR: "HOST_PROMPT_ABANDON_NO_WRITE_RESIDUAL_THEN_NEW_RUN",
      PROVEN_NOT_COMMITTED_WITH_PRIOR: "COMPILE_AND_AUTHORIZE_EARLIER_OWNED_GRAPH_ROLLBACK",
    }),
    MAIN_ROLLBACK_EXECUTOR: Object.freeze({
      PROVEN_COMMITTED: "PROJECT_MAIN_ROLLED_BACK_THEN_POST_ROLLBACK_OLD_LINE",
      PROVEN_NOT_COMMITTED: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK",
      PROVEN_INVERSE_PREFIX: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK_REMAINING_SUFFIX",
    }),
    BBR_APPLY: Object.freeze({
      PROVEN_COMMITTED: "COMPILE_AND_AUTHORIZE_BBR_ROLLBACK",
      PROVEN_NOT_COMMITTED: "HOST_PROMPT_BBR_PARTIAL_NO_WRITE_RECEIPT_THEN_CONTINUE_MAIN",
    }),
    BBR_ROLLBACK_EXECUTOR: Object.freeze({
      PROVEN_COMMITTED: "PROJECT_BBR_ROLLED_BACK_THEN_POST_INVERSE_REFRESH",
      PROVEN_NOT_COMMITTED: "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK",
      PROVEN_INVERSE_PREFIX: "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK_REMAINING_STAGE_SUFFIX",
    }),
    ACTIVE_CHECKPOINT_DRIFT: Object.freeze({
      PROVEN_NOT_COMMITTED_ZERO_PRIOR: "PROJECT_ACTIVE_CHECKPOINT_ZERO_COMMIT_TO_INVENTORIED",
      PROVEN_COMMITTED_OWNED_GRAPH: "PROJECT_ACTIVE_CHECKPOINT_OWNED_GRAPH_TO_ROLLBACK_REQUIRED",
    }),
  }),
  sufficientProofByOperationClass: Object.freeze({
    MAIN_ROLLBACK_EXECUTOR_PROVEN_NOT_COMMITTED: Object.freeze({
      originalTool: "rollback_run",
      observation: "PROVEN_NOT_COMMITTED",
      requires: Object.freeze([
        "EVERY_FROZEN_ATOMIC_STAGE_MATCHES_ITS_EXACT_PRE_INVERSE_DIGEST_AND_OWNERSHIP",
        "ZERO_DURABLE_ATOMIC_STAGE_RECEIPTS",
        "ALL_PROFILE_CLIENT_PANEL_AND_PRIVATE_KEY_DISPOSITIONS_MATCH_EXACT_PRE_INVERSE_STATE",
        "ROLLBACK_REQUEST_TERMINATED",
        "AUTHORITATIVE_CONSISTENCY_SETTLE_FENCE_SATISFIED",
      ]),
      nextAction: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK",
      anyMissingOrIncomplete: "STILL_UNKNOWN",
      anyForeignOwnershipOrThirdDigest: "CONCURRENT_THIRD_DIGEST",
      callerOverride: false,
    }),
    MAIN_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX: Object.freeze({
      originalTool: "rollback_run",
      observation: "PROVEN_INVERSE_PREFIX",
      requires: Object.freeze(["EXACT_NONEMPTY_CONTIGUOUS_COMPLETED_ATOMIC_STAGE_PREFIX_DURABLE_RECEIPTS", "COMPLETED_ATOMIC_STAGE_PREFIX_CURRENT_POST_INVERSE_READBACK_MATCH", "ACTIVE_STAGE_IS_FIRST_REMAINING_OR_NULL_BETWEEN_STAGES", "REMAINING_ATOMIC_STAGE_SUFFIX_EXACT_PRE_INVERSE_READBACK_AND_OWNERSHIP_MATCH", "SECRET_DISPOSITIONS_MATCH_ATOMIC_STAGE_BOUNDARY", "NO_THIRD_DIGEST", "ROLLBACK_REQUEST_TERMINATED", "AUTHORITATIVE_CONSISTENCY_SETTLE_FENCE_SATISFIED"]),
      nextAction: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK_REMAINING_SUFFIX",
      completedInverseReplay: false,
      callerOverride: false,
    }),
    BBR_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX: Object.freeze({
      originalTool: "bbr_rollback",
      observation: "PROVEN_INVERSE_PREFIX",
      requires: Object.freeze(["ONE_TO_THREE_DURABLE_ORDERED_STAGE_PREFIX_RECEIPTS", "CURRENT_STATE_MATCHES_COMPLETED_STAGE_PREFIX", "REMAINING_STAGE_VALUES_MATCH_EXACT_PRE_STAGE_STATE", "NO_THIRD_DIGEST", "ROLLBACK_REQUEST_TERMINATED", "AUTHORITATIVE_CONSISTENCY_SETTLE_FENCE_SATISFIED"]),
      nextAction: "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK_REMAINING_STAGE_SUFFIX",
      completedStageReplay: false,
      callerOverride: false,
    }),
    ACTIVE_CHECKPOINT_DRIFT: "DELEGATE_TO_ACTIVE_CHECKPOINT_DRIFT_RESOLVER",
  }),
  invalidates: Object.freeze(["PRIOR_OPERATION_REF", "PRIOR_PLAN_REF", "PRIOR_APPROVAL_CHALLENGE_REF", "PRIOR_APPROVAL_LEASE"]),
  evidenceTtl: "PT5M",
  noSameRunForwardResume: true,
});

const GENERATED_SECRET_POLICY = Object.freeze({
  source: "OS_CSPRNG_ONLY",
  uniqueness: "SERVER_SIDE_SCOPE_UNIQUENESS_CHECK_BOUNDED_COLLISION_RETRY_THEN_FAIL",
  plaintextBoundary: "BROKER_ONLY_MCP_RETURNS_SECRETREF_OR_DIGEST",
  defaultOrDictionaryValuesForbidden: true,
  panelAdminUsername: Object.freeze({ randomBytes: 12, entropyBits: 96, encoding: "BASE64URL_WITHOUT_PADDING", outputCharacters: 16, optionalFixedSafePrefix: true }),
  panelAdminPassword: Object.freeze({ randomBytes: 24, entropyBits: 192, encoding: "BASE64URL_WITHOUT_PADDING", outputCharacters: 32 }),
  vlessClientId: Object.freeze({ format: "RFC4122_UUIDV4", randomBits: 122, version: 4, serverGenerated: true }),
  websocketPath: Object.freeze({ randomBytes: 24, entropyBits: 192, encoding: "BASE64URL_WITHOUT_PADDING", exactPattern: "^/[A-Za-z0-9_-]{32}$", queryAllowed: false, fragmentAllowed: false, mcpProjection: "OPAQUE_REF_AND_DIGEST_ONLY_RAW_PATH_NEVER_ENTERS_MCP" }),
  callerOverride: false,
});
const WEBSOCKET_PATH_POLICY = GENERATED_SECRET_POLICY.websocketPath;
const LOW_ENTROPY_BINDING_POLICY = Object.freeze({
  primitive: "HMAC-SHA-256",
  key: "SERVER_KEPT_PER_INSTALL_RANDOM_HMAC_KEY",
  context: Object.freeze(["COMPARISON_DOMAIN", "REGISTERED_TARGET_ID", "RUN_ID"]),
  comparisonDomainByBinding: Object.freeze({
    DIRECT_EXPECTED_EGRESS: "EGRESS_EQUALITY_V1",
    PROXY_OBSERVED_EGRESS: "EGRESS_EQUALITY_V1",
    CURRENT_ORIGIN_ADDRESS: "RECORD_ORIGIN_EQUALITY_V1",
    RECORD_ORIGIN_ADDRESS: "RECORD_ORIGIN_EQUALITY_V1",
    PUBLIC_RESOLUTION: "PUBLIC_VS_ORIGIN_V1",
    PUBLIC_COMPARISON_ORIGIN: "PUBLIC_VS_ORIGIN_V1",
  }),
  evidenceRoleMetadataSeparateFromHmacInput: true,
  compare: "CONSTANT_TIME",
  rawValueInMcpHookOrLog: false,
  keyInMcpHookOrLog: false,
  bindings: Object.freeze(["CURRENT_ORIGIN_ADDRESS", "RECORD_ORIGIN_ADDRESS", "DIRECT_EXPECTED_EGRESS", "PROXY_OBSERVED_EGRESS", "PUBLIC_RESOLUTION", "PUBLIC_COMPARISON_ORIGIN"]),
  outputProjection: "OPAQUE_EVIDENCE_REF_AND_HMAC_DIGEST_ONLY",
});
const XUI_INBOUND_POLICY = Object.freeze({
  protocol: "vless", transport: "ws", listen: "LOOPBACK_ONLY",
  tls: "none", flow: "none", proxyProtocol: false,
  clientId: GENERATED_SECRET_POLICY.vlessClientId,
  websocketHost: "EMPTY_SERVER_UNCONSTRAINED",
  websocketPath: WEBSOCKET_PATH_POLICY,
});
const NGINX_ROUTE_POLICY = Object.freeze({
  serverName: "EXACT_NODE_HOSTNAME", websocketPath: WEBSOCKET_PATH_POLICY,
  publicTlsPort: 443, upstream: "http://127.0.0.1:OWNED_INBOUND_PORT",
  httpVersion: "1.1", upgradeHeader: "websocket", connectionHeader: "Upgrade",
  backendTls: false, proxyProtocol: false,
  unmatchedRequest: "FIXED_NONDISCLOSING_404", wildcardOrDefaultServer: false,
  certificateSlotRoles: Object.freeze(["fullchain", "private_key"]),
  certificateSlotInputs: Object.freeze({ fullchainMode: "0644", privateKeyMode: "0600", opaqueRefsOnly: true }),
  installNginx: false, createOnlyOwnedInclude: true,
});
const CLIENT_PROFILE_POLICY = Object.freeze({
  transport: "ws", tls: true, allowInsecure: false, publicPort: 443,
  address: "EXACT_NODE_HOSTNAME", sni: "EXACT_NODE_HOSTNAME",
  websocketHost: "EXACT_NODE_HOSTNAME", websocketPath: WEBSOCKET_PATH_POLICY,
  flow: "none",
});
const BBR_TARGET_POLICY = Object.freeze({
  targetValues: Object.freeze({
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.core.default_qdisc": "fq",
  }),
  inventoryRequires: Object.freeze([
    "AVAILABLE_CONGESTION_CONTROLS_CONTAINS_BBR", "QDISC_FQ_SUPPORTED",
    "NO_PERSISTENT_CONFLICT", "OWNED_DROPIN_ABSENT",
  ]),
  applyReadback: Object.freeze({
    liveCongestionControl: "bbr", persistentCongestionControl: "bbr",
    liveQdisc: "fq", persistentQdisc: "fq",
  }),
  otherValuesAccepted: false,
});
const operationStep = (stepId, tool, mode) => Object.freeze({ stepId, tool, mode });
const operationTemplate = (templateId, leaseClass, steps) => Object.freeze({
  templateId, leaseClass, steps: Object.freeze(steps.map((step) => Object.freeze({
    ...step, stepId: `${templateId}:${step.stepId}`,
  }))),
});
const XUI_RESOLUTION_CASES = Object.freeze({
  ABSENT_CLEAN_ELIGIBLE: Object.freeze({ resolution: "NODE_INSTALL_P3", requires: Object.freeze(["XUI_ABSENT", "CLEAN_HOST", "PINNED_ADAPTER_ELIGIBLE"]) }),
  COMPATIBLE_EXISTING_WITH_IMPORTED_ADMIN: Object.freeze({ resolution: "NODE_P2", requires: Object.freeze(["COMPATIBLE_EXISTING", "CURRENT_IMPORTED_XUI_PANEL_ADMIN_SECRET_REF"]) }),
  SAME_RUN_OWNED_WITH_GENERATED_ADMIN: Object.freeze({ resolution: "NODE_P2", requires: Object.freeze(["SAME_RUN_INSTALL_RECEIPT", "CURRENT_GENERATED_XUI_PANEL_ADMIN_SECRET_REF"]) }),
  ABSENT_NOT_INSTALL_ELIGIBLE: Object.freeze({ resolution: "DENY", errorCode: "INSTALL_NOT_ELIGIBLE" }),
  MISSING_REQUIRED_ADMIN_SECRET: Object.freeze({ resolution: "DENY", errorCode: "SECRET_REF_MISSING" }),
  SAME_RUN_OWNED_MISSING_GENERATED_ADMIN: Object.freeze({ resolution: "DENY", errorCode: "SECRET_REF_MISSING" }),
  SAME_RUN_OWNERSHIP_DRIFTED: Object.freeze({ resolution: "DENY", errorCode: "CONFLICT_DETECTED" }),
  INCOMPATIBLE_EXISTING: Object.freeze({ resolution: "DENY", errorCode: "INSTALL_NOT_ELIGIBLE" }),
  AMBIGUOUS_OR_DRIFTED: Object.freeze({ resolution: "DENY", errorCode: "CONFLICT_DETECTED" }),
});
const XUI_INVENTORY_OBSERVATION_CASES = Object.freeze({
  ABSENT_CLEAN_ELIGIBLE: Object.freeze({ installationStatus: "absent", cleanHostInstallEligible: true, ownershipReceipt: "NULL", panelFingerprint: "NULL", versionMasked: "NULL", ownedInboundRefs: "EMPTY", adminProvenance: "NONE" }),
  ABSENT_NOT_INSTALL_ELIGIBLE: Object.freeze({ installationStatus: "absent", cleanHostInstallEligible: false, ownershipReceipt: "NULL", panelFingerprint: "NULL", versionMasked: "NULL", ownedInboundRefs: "EMPTY", adminProvenance: "NONE" }),
  COMPATIBLE_EXISTING_WITH_IMPORTED_ADMIN: Object.freeze({ installationStatus: "compatible_existing", cleanHostInstallEligible: false, ownershipReceipt: "NULL", panelFingerprint: "NON_NULL", versionMasked: "NON_NULL", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "IMPORTED_CURRENT" }),
  MISSING_REQUIRED_ADMIN_SECRET: Object.freeze({ installationStatus: "compatible_existing", cleanHostInstallEligible: false, ownershipReceipt: "NULL", panelFingerprint: "NON_NULL", versionMasked: "NON_NULL", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "MISSING" }),
  SAME_RUN_OWNED_WITH_GENERATED_ADMIN: Object.freeze({ installationStatus: "owned_by_run", cleanHostInstallEligible: false, ownershipReceipt: "NON_NULL", panelFingerprint: "NON_NULL", versionMasked: "NON_NULL", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "SAME_RUN_CURRENT" }),
  SAME_RUN_OWNED_MISSING_GENERATED_ADMIN: Object.freeze({ installationStatus: "owned_by_run", cleanHostInstallEligible: false, ownershipReceipt: "NON_NULL", panelFingerprint: "NON_NULL", versionMasked: "NON_NULL", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "MISSING" }),
  SAME_RUN_OWNERSHIP_DRIFTED: Object.freeze({ installationStatus: "owned_by_run", cleanHostInstallEligible: false, ownershipReceipt: "NON_NULL", panelFingerprint: "NON_NULL", versionMasked: "NON_NULL", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "DRIFTED" }),
  INCOMPATIBLE_EXISTING: Object.freeze({ installationStatus: "incompatible_existing", cleanHostInstallEligible: false, ownershipReceipt: "NULL", panelFingerprint: "NON_NULL", versionMasked: "NON_NULL", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "NOT_APPLICABLE" }),
  AMBIGUOUS_OR_DRIFTED: Object.freeze({ installationStatus: "ambiguous", cleanHostInstallEligible: false, ownershipReceipt: "NULL", panelFingerprint: "NULLABLE", versionMasked: "NULLABLE", ownedInboundRefs: "SAME_RUN_ONLY", adminProvenance: "AMBIGUOUS" }),
});
const nullableMarkerSchema = (marker, schema) => marker === "NON_NULL" ? schema : marker === "NULL" ? Object.freeze({ type: "null" }) : nullable(schema);
const ownedInboundMarkerSchema = (marker) => marker === "EMPTY"
  ? Object.freeze({ type: "array", items: S.InboundRef, minItems: 0, maxItems: 0 })
  : Object.freeze({ ...arr(S.InboundRef, 0, 16), uniqueItems: true });
const XUI_INVENTORY_DEPENDENT_FIELDS = Object.freeze([
  "installation_status", "admin_secret_provenance", "version_masked",
  "ownership_receipt_ref", "clean_host_install_eligible", "owned_inbound_refs",
  "panel_fingerprint_digest",
]);
const CLOUDFLARE_RECORD_OBSERVATION_DEPENDENT_FIELDS = Object.freeze([
  "record_count_category", "current_record_ref", "proxy_enabled", "current_record_type",
  "current_record_digest", "current_record_origin_address_binding_digest",
  "current_record_owned_by_run", "record_matches_current_origin_address_digest",
]);
const XUI_INVENTORY_OBSERVATION_CLAUSES = Object.freeze(Object.entries(XUI_INVENTORY_OBSERVATION_CASES).map(([caseName, row]) => Object.freeze({
  if: { properties: { admin_binding_status: { const: caseName } }, required: ["admin_binding_status"] },
  then: { properties: {
    installation_status: { const: row.installationStatus },
    clean_host_install_eligible: { const: row.cleanHostInstallEligible },
    ownership_receipt_ref: nullableMarkerSchema(row.ownershipReceipt, S.ReceiptRef),
    panel_fingerprint_digest: nullableMarkerSchema(row.panelFingerprint, S.Digest),
    version_masked: nullableMarkerSchema(row.versionMasked, S.MaskedText),
    owned_inbound_refs: ownedInboundMarkerSchema(row.ownedInboundRefs),
    admin_secret_provenance: { const: row.adminProvenance },
  }, required: XUI_INVENTORY_DEPENDENT_FIELDS },
})));
const ACTIVE_CHECKPOINT_RECONCILIATION_OBSERVER_BY_TOOL = Object.freeze({
  origin_inventory: Object.freeze({ observer: Object.freeze(["origin.inventory.v1"]), authority: "SSH_ORIGIN_READ", proof: "REGISTERED_TARGET_BASELINE_AND_CURRENT_OWNERSHIP_DIGESTS" }),
  cloudflare_inventory: Object.freeze({ observer: Object.freeze(["cf.dns_read"]), authority: "BROKER_CF_AUDIT_FIXED", proof: "REGISTERED_ZONE_HOSTNAME_RECORD_OWNERSHIP_AND_CURRENT_DIGESTS" }),
  xui_inventory: Object.freeze({ observer: Object.freeze(["xui.inventory_existing_fixed.v1", "xui.inventory_owned_fixed.v1"]), authority: "IMMUTABLE_XUI_PROVENANCE_SELECTS_EXACTLY_ONE_FIXED_BROKER_READ", proof: "INSTALLATION_PANEL_AND_SAME_RUN_OWNERSHIP_DIGESTS" }),
  client_inventory: Object.freeze({ observer: Object.freeze(["client.inventory_fixed.v1"]), authority: "LOCAL_ALLOWLISTED_CLIENT_READ", proof: "ALLOWLISTED_RUNTIME_AND_DESTINATION_REGISTRY_DIGESTS" }),
});
const FORWARD_APPROVAL_EFFECTIVE_EXPIRY_POLICY = Object.freeze({
  formula: "MIN_OF_NOMINAL_APPROVAL_LEASE_EXPIRES_AT_AND_EVERY_CURRENTLY_CONSUMED_FINITE_EVIDENCE_EXPIRES_AT",
  evaluatedAt: Object.freeze(["PLAN_AUTHORIZE", "IMMEDIATELY_BEFORE_EVERY_EXTERNAL_MUTATION_DISPATCH"]),
  consumedFiniteSetByScope: Object.freeze({
    NODE_INSTALL_P3: Object.freeze(["ORIGIN_INVENTORY", "CLOUDFLARE_INVENTORY", "FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED", "XUI_INVENTORY", "CLIENT_INVENTORY", "PROTECTED_LINE_HEALTH"]),
    NODE_P2: Object.freeze(["ORIGIN_INVENTORY", "SAFE_STABLE_SLOT_EVIDENCE_WHEN_REUSE", "CURRENT_ORIGIN_ADDRESS_DIGEST", "CLOUDFLARE_INVENTORY", "FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED", "XUI_INVENTORY", "CLIENT_INVENTORY", "PROTECTED_LINE_HEALTH"]),
    HOST_P3: Object.freeze(["BBR_INVENTORY", "CURRENT_MAIN_AUTHENTICATED_E2E_BASELINE", "PROTECTED_LINE_HEALTH"]),
  }),
  exactPreDispatchRefreshByScope: Object.freeze({
    NODE_INSTALL_P3: Object.freeze(["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory", "old_line_verify"]),
    NODE_P2: Object.freeze(["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory", "old_line_verify"]),
    HOST_P3: Object.freeze(["bbr_inventory", "traffic_verify", "logs_correlate", "old_line_verify"]),
  }),
  refreshRule: "BEFORE_FIRST_AND_EVERY_EXTERNAL_MUTATION_REFRESH_EVERY_CURRENTLY_CONSUMED_FINITE_FAMILY; EXACT_NO_DRIFT_ONLY; NEVER_ADVANCE_CURSOR_OR_EXTEND_LEASE",
  beforeWriteExpired: "NO_DISPATCH_REFRESH_EXACT_CONSUMED_SET_INVALIDATE_OLD_APPROVAL_AND_REQUIRE_NEW_HOST_PROMPT",
  afterLastWriteReadOnlyCursor: "EXPIRED_WRITE_LEASE_DOES_NOT_BLOCK_READ_ONLY_VERIFICATION_BUT_CANNOT_AUTHORIZE_ANY_WRITE",
  callerOverride: false,
});
const HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT = Object.freeze({
  scope: "HOST_P3",
  tool: "bbr_inventory",
  origin: "BBR_HOST_APPROVED",
  authority: "SERVER_DERIVED_FROM_CURRENT_HOST_P3_PLAN_CURSOR_APPROVAL_LEASE_AND_EXACT_BBR_BASELINE",
  callerSelectableMode: false,
  noDrift: Object.freeze({
    requires: Object.freeze(["CURRENT_HOST_P3_PLAN_CURSOR_AND_APPROVAL", "CURRENT_NOMINAL_AND_EFFECTIVE_LEASE_UNEXPIRED", "EXACT_SAME_REGISTERED_TARGET_KERNEL_CAPABILITY_CONFLICT_DROPIN_AND_PRIOR_VALUE_BASELINE"]),
    replaces: Object.freeze(["BBR_INVENTORY"]),
    preserves: Object.freeze(["CURRENT_PLAN_REF", "CURRENT_TEMPLATE_ID", "CURRENT_CURSOR", "REMAINING_OPERATION_REFS", "CURRENT_APPROVAL_REF", "CURRENT_NOMINAL_LEASE_EXPIRES_AT", "CURRENT_EFFECTIVE_LEASE_EXPIRES_AT"]),
    destination: "UNCHANGED",
    cursorAdvance: false,
    nominalLeaseExtension: false,
    effectiveLeaseExtension: false,
  }),
  driftOrExpired: Object.freeze({
    predicates: Object.freeze(["ANY_BBR_BASELINE_DRIFT", "NOMINAL_OR_EFFECTIVE_LEASE_EXPIRED"]),
    destination: "BBR_PLAN_READY",
    invalidates: Object.freeze(["CURRENT_PLAN_REF", "CURRENT_TEMPLATE_ID", "CURRENT_CURSOR", "REMAINING_OPERATION_REFS", "CURRENT_APPROVAL_REF", "CURRENT_APPROVAL_LEASE"]),
    next: "FRESH_PLAN_COMPILE_AND_NEW_HOST_PROMPT",
    externalWrite: false,
  }),
});
const ROLLBACK_LEASE_EXPIRY_RESOLVER = Object.freeze({
  authority: "SERVER_DISPATCHER_AND_IMMUTABLE_ROLLBACK_LEDGER_ONLY",
  callerSelectable: false,
  precedence: "EXACT_LEASE_EXPIRY_ROWS_OVERRIDE_GENERIC_PRE_DISPATCH_UNCHANGED_ONLY_WHEN_EVERY_ROW_GUARD_IS_PROVEN",
  rows: Object.freeze({
    MAIN_ZERO_INVERSE_BEFORE_DISPATCH: Object.freeze({
      origin: "ROLLING_BACK",
      requires: Object.freeze(["ROLLBACK_LEASE_EXPIRED", "ZERO_DURABLE_INVERSE_STAGE_RECEIPTS", "NO_OPEN_EXECUTOR_DISPATCH"]),
      destination: "ROLLBACK_REQUIRED",
      invalidates: Object.freeze(["PRIOR_PLAN_REF", "PRIOR_OPERATION_REFS", "PRIOR_APPROVAL_REF", "PRIOR_APPROVAL_LEASE"]),
      admissionReceipt: "MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY_ADMISSION_RECEIPT",
      admissionReceiptTtl: "NO_TTL",
      reconciliationEvidenceRequired: false,
      atomicLedgerTransaction: "REVOKE_OLD_AUTHORITY_WRITE_ADMISSION_RECEIPT_AND_PROJECT_ROLLBACK_REQUIRED",
      next: "FRESH_FULL_GRAPH_ROLLBACK_COMPILE_AND_HOST_PROMPT",
    }),
    BBR_ZERO_STAGE_BEFORE_DISPATCH: Object.freeze({
      origin: "BBR_ROLLING_BACK",
      cause: "BBR_ZERO_STAGE_BEFORE_DISPATCH",
      requires: Object.freeze(["ROLLBACK_LEASE_EXPIRED", "EXACT_CURRENT_OLD_BBR_ROLLBACK_AUTHORITY_IDENTITY_ACTIVE", "ZERO_DURABLE_BBR_STAGE_RECEIPTS", "NO_OPEN_EXECUTOR_DISPATCH"]),
      destination: "BBR_MANUAL_ACTION_REQUIRED",
      invalidates: Object.freeze(["PRIOR_PLAN_REF", "PRIOR_OPERATION_REFS", "PRIOR_APPROVAL_REF", "PRIOR_APPROVAL_CHALLENGE_REF", "PRIOR_APPROVAL_LEASE", "PRIOR_PLAN_BOUND_BBR_ROLLBACK_SOURCE_BINDING", "PRIOR_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE"]),
      consumes: Object.freeze(["CURRENT_PLAN_BOUND_BBR_ROLLBACK_SOURCE_BINDING", "CURRENT_APPROVAL_CHALLENGE", "CURRENT_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE"]),
      inheritsFromConsumedSourceEpisode: Object.freeze(["EXACT_BBR_APPLY_BASELINE_KIND", "EXACT_OPAQUE_BBR_APPLY_BASELINE_RECEIPT_REF", "EXACT_OPAQUE_BBR_CHANGE_REF", "EXACT_BBR_APPLY_BASELINE_BINDING_DIGEST"]),
      creates: Object.freeze(["DURABLE_BBR_ZERO_STAGE_CAUSE", "NEW_CURRENT_UNCONSUMED_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE_BOUND_TO_INHERITED_EXACT_ONE_BASELINE"]),
      oldAuthorityRevoked: true,
      reconciliationEvidenceRequired: false,
      mainRollbackAdmissionReceiptAllowed: false,
      admissionReceipt: null,
      sourcePrecedence: "ZERO_STAGE_SOURCE_WINS_ONLY_THE_NEW_CURRENT_EXPIRY_EPISODE",
      atomicLedgerTransaction: "VERIFY_PRECONDITIONS_THEN_FIRST_REVOKE_OLD_BBR_AUTHORITY_CONSUME_PRIOR_SOURCE_BINDING_CHALLENGE_AND_EPISODE_INHERIT_EXACT_BASELINE_KIND_REF_CHANGE_REF_AND_BINDING_DIGEST_PERSIST_DURABLE_ZERO_STAGE_CAUSE_CREATE_NEW_CURRENT_UNCONSUMED_ZERO_STAGE_SOURCE_EPISODE_AND_PROJECT_BBR_MANUAL_ACTION_REQUIRED",
      next: "FRESH_BBR_ROLLBACK_COMPILE_AND_HOST_PROMPT",
    }),
    MAIN_PREFIX_STARTED: Object.freeze({ origin: "ROLLING_BACK", requires: Object.freeze(["ROLLBACK_LEASE_EXPIRED", "ONE_OR_MORE_DURABLE_CONTIGUOUS_ATOMIC_STAGE_PREFIX_RECEIPTS"]), destination: "MANUAL_ACTION_REQUIRED", next: "RECONCILE_PROVEN_INVERSE_PREFIX_THEN_FRESH_REMAINING_SUFFIX_PLAN" }),
    BBR_PREFIX_STARTED: Object.freeze({ origin: "BBR_ROLLING_BACK", requires: Object.freeze(["ROLLBACK_LEASE_EXPIRED", "ONE_OR_MORE_DURABLE_ORDERED_STAGE_PREFIX_RECEIPTS"]), destination: "BBR_MANUAL_ACTION_REQUIRED", next: "RECONCILE_PROVEN_INVERSE_PREFIX_THEN_FRESH_REMAINING_STAGE_SUFFIX_PLAN" }),
    UNKNOWN_OR_THIRD_DIGEST: Object.freeze({ destinationByColumn: Object.freeze({ main: "MANUAL_ACTION_REQUIRED", bbr: "BBR_MANUAL_ACTION_REQUIRED" }), next: "RECONCILE_NO_OVERWRITE" }),
  }),
  completedInverseOrStageReplay: false,
});
const ACTIVE_CHECKPOINT_DRIFT_RESOLVER = Object.freeze({
  authority: "SERVER_DERIVED_FROM_ACTIVE_NODE_CHECKPOINT_LEDGER_CURSOR_AND_CURRENT_OWNERSHIP_READBACK",
  sourceTools: Object.freeze(Object.keys(ACTIVE_CHECKPOINT_RECONCILIATION_OBSERVER_BY_TOOL)),
  callerSelectable: false,
  commonRequires: Object.freeze(["ACTIVE_NODE_INSTALL_OR_NODE_P2_FORWARD_CURSOR", "CURRENT_CHECKPOINT_OBSERVATION", "EXACT_PRIOR_COMMITTED_CHANGE_COUNT", "EXACT_CURRENT_OWNED_GRAPH_DIGEST", "NO_UNKNOWN_OPEN_DISPATCH"]),
  rows: Object.freeze({
    ZERO_COMMIT_SAFE_REBASE: Object.freeze({
      predicate: "PRIOR_COMMITTED_CHANGE_COUNT_EQ_0_AND_NO_OPEN_OPERATION_AND_NO_THIRD_DIGEST_OR_OWNERSHIP_MISMATCH",
      destination: "INVENTORIED",
      createsRecoveryObligation: false,
      invalidates: Object.freeze(["CURRENT_PLAN_REF", "CURRENT_TEMPLATE_ID", "CURRENT_CURSOR", "REMAINING_OPERATION_REFS", "CURRENT_APPROVAL_REF", "CURRENT_APPROVAL_LEASE"]),
      nextActions: Object.freeze(["FRESH_INVENTORIES_THEN_SAFE_REPLAN_WITH_NEW_HOST_PROMPT", "HOST_PROMPT_ABANDON_NO_WRITE_FROM_INVENTORIED"]),
    }),
    OWNED_COMMITTED_GRAPH: Object.freeze({
      predicate: "PRIOR_COMMITTED_CHANGE_COUNT_GTE_1_AND_EXACT_CURRENT_GRAPH_IS_SAME_RUN_OWNED_AND_ROLLBACK_SAFE_AND_NO_THIRD_DIGEST",
      destination: "ROLLBACK_REQUIRED",
      createsRecoveryObligation: "CURRENT_MAIN_RECOVERY_OBLIGATION_BOUND_TO_EXACT_OWNED_GRAPH_AND_CHECKPOINT_OBSERVATION",
      invalidates: Object.freeze(["CURRENT_PLAN_REF", "CURRENT_TEMPLATE_ID", "CURRENT_CURSOR", "REMAINING_OPERATION_REFS", "CURRENT_APPROVAL_REF", "CURRENT_APPROVAL_LEASE"]),
      nextActions: Object.freeze(["COMPILE_FRESH_MAIN_ROLLBACK", "NEW_HOST_PROMPT_REQUIRED"]),
    }),
    THIRD_DIGEST_OR_OWNERSHIP_MISMATCH: Object.freeze({
      predicate: "ANY_FOREIGN_OWNERSHIP_STALE_IDENTITY_AMBIGUOUS_MULTIPLICITY_OR_THIRD_DIGEST",
      destination: "MANUAL_ACTION_REQUIRED",
      createsRecoveryObligation: "ACTIVE_CHECKPOINT_RECONCILIATION_OBLIGATION",
      observerByTool: ACTIVE_CHECKPOINT_RECONCILIATION_OBSERVER_BY_TOOL,
      acceptedExitByFreshObservation: Object.freeze({
        ZERO_COMMIT_SAFE_REBASE: "INVENTORIED",
        OWNED_COMMITTED_GRAPH: "ROLLBACK_REQUIRED_WITH_CURRENT_MAIN_RECOVERY_OBLIGATION",
        STILL_UNKNOWN_OR_THIRD_DIGEST: "MANUAL_ACTION_REQUIRED_NO_OVERWRITE",
      }),
    }),
  }),
  planRewrite: false,
  overwrite: false,
  cursorAdvance: false,
});
const ACTIVE_CURSOR_WRITE_AUTHORITY_REVOCATIONS = Object.freeze([
  "CURRENT_PLAN_REF",
  "CURRENT_TEMPLATE_ID",
  "CURRENT_CURSOR",
  "REMAINING_OPERATION_REFS",
  "CURRENT_APPROVAL_REF",
  "CURRENT_NOMINAL_APPROVAL_LEASE",
  "CURRENT_EFFECTIVE_APPROVAL_LEASE",
]);
const ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER = Object.freeze({
  authority: "SERVER_PREDISPATCH_LEDGER_CURRENT_FORWARD_CURSOR_AND_COMMIT_OBSERVATION_ONLY",
  scope: Object.freeze(["NODE_INSTALL_P3", "NODE_P2"]),
  consumers: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"]),
  trigger: "CURRENT_EFFECTIVE_APPROVAL_EXPIRED_IMMEDIATELY_BEFORE_EXTERNAL_WRITE_DISPATCH",
  commonRequires: Object.freeze(["CURRENT_ACTIVE_FORWARD_CURSOR", "NO_OPEN_EXECUTOR_DISPATCH", "EXACT_PRIOR_COMMITTED_CHANGE_COUNT", "CURRENT_OWNERSHIP_AND_COMMIT_OBSERVATION"]),
  revokesBeforeProjection: ACTIVE_CURSOR_WRITE_AUTHORITY_REVOCATIONS,
  precedence: "OVERRIDES_GENERIC_PRE_DISPATCH_UNCHANGED_ONLY_WHEN_THE_EXACT_TRIGGER_AND_ROW_GUARDS_ARE_PROVEN",
  rows: Object.freeze({
    ZERO_COMMITTED_CHANGES: Object.freeze({
      predicate: "PRIOR_COMMITTED_CHANGE_COUNT_EQ_0_AND_NO_UNKNOWN_COMMIT_AND_NO_THIRD_DIGEST_OR_OWNERSHIP_MISMATCH",
      destination: "INVENTORIED",
      createsRecoveryObligation: false,
      atomicLedgerTransaction: "REVOKE_ALL_FORWARD_AUTHORITY_AND_PROJECT_INVENTORIED",
      next: "FULL_FRESH_INVENTORY_SET_THEN_FRESH_PLAN_COMPILE_AND_NEW_HOST_PROMPT",
    }),
    SAME_RUN_OWNED_COMMITTED_CHANGES: Object.freeze({
      predicate: "PRIOR_COMMITTED_CHANGE_COUNT_GTE_1_AND_EVERY_COMMIT_IS_EXACT_SAME_RUN_OWNED_CURRENT_AND_ROLLBACK_SAFE",
      destination: "ROLLBACK_REQUIRED",
      createsRecoveryObligation: "CURRENT_MAIN_RECOVERY_OBLIGATION_BOUND_TO_EXACT_COMMITTED_GRAPH_CREATED_ATOMICALLY_WITH_STATE_PROJECTION",
      atomicLedgerTransaction: "REVOKE_ALL_FORWARD_AUTHORITY_CREATE_CURRENT_RECOVERY_OBLIGATION_AND_PROJECT_ROLLBACK_REQUIRED",
      next: "FRESH_MAIN_ROLLBACK_PLAN_AND_NEW_HOST_PROMPT",
    }),
    UNKNOWN_OR_THIRD_DIGEST: Object.freeze({
      predicate: "ANY_UNKNOWN_COMMIT_CONCURRENT_THIRD_DIGEST_FOREIGN_OWNERSHIP_OR_OWNERSHIP_MISMATCH",
      destination: "MANUAL_ACTION_REQUIRED",
      createsRecoveryObligation: "FIXED_RECONCILIATION_OBLIGATION_BOUND_TO_CURRENT_CURSOR_AND_OBSERVED_DIGEST_RELATION",
      atomicLedgerTransaction: "REVOKE_ALL_FORWARD_AUTHORITY_CREATE_RECONCILIATION_OBLIGATION_AND_PROJECT_MANUAL_ACTION_REQUIRED",
      next: "RECONCILE_NO_OVERWRITE",
    }),
  }),
  forwardResume: false,
  inheritedPlanTemplateCursorRemainingOperationsApprovalOrLease: false,
  hostP3: "EXCLUDED_USE_HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT",
  callerSelectable: false,
});
const ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT = Object.freeze({
  scope: "ACTIVE_NODE_INSTALL_OR_NODE_P2_FORWARD_CURSOR",
  runMode: "configure",
  authority: "SERVER_DERIVED_FROM_CURRENT_TEMPLATE_STEP_REMAINING_CONSUMERS_AND_EVIDENCE_EXPIRY",
  refreshTools: Object.freeze(["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory"]),
  globalForwardEligibilityMutationConsumers: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"]),
  finiteInventoryCoverage: "SET_EQUAL_TO_EVERY_FINITE_INVENTORY_FAMILY_CONSUMED_BY_A_LATER_NODE_INSTALL_OR_NODE_P2_STEP",
  coordinatedPreMutationBarrier: "ALL_FOUR_REFRESH_TOOLS_HAVE_CURRENT_SAME_LEDGER_CHECKPOINT_EVIDENCE_BEFORE_EVERY_LISTED_EXTERNAL_MUTATION",
  forwardApprovalEffectiveExpiry: FORWARD_APPROVAL_EFFECTIVE_EXPIRY_POLICY,
  checkpointByTool: Object.freeze({
    origin_inventory: Object.freeze({
      evidenceFamilies: Object.freeze(["ORIGIN_INVENTORY", "SAFE_STABLE_SLOT_EVIDENCE", "CURRENT_ORIGIN_ADDRESS_DIGEST"]),
      beforeSteps: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "origin_verify"]),
      mandatoryNamedCheckpoints: Object.freeze(["PRE_RECORD", "POST_RECORD_BEFORE_DIRECT_ORIGIN_VERIFY"]),
    }),
    cloudflare_inventory: Object.freeze({
      evidenceFamilies: Object.freeze(["CLOUDFLARE_INVENTORY", "FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED", "FRESH_OWNED_UNPROXIED_RECORD_BOUND_TO_CURRENT_ORIGIN_ADDRESS_DIGEST"]),
      beforeSteps: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "origin_verify"]),
      mandatoryNamedCheckpoints: Object.freeze(["PRE_RECORD_EXPECT_ABSENT_AVAILABLE", "POST_RECORD_EXPECT_SAME_RUN_CURRENT_UNPROXIED"]),
    }),
    xui_inventory: Object.freeze({
      evidenceFamilies: Object.freeze(["XUI_INVENTORY"]),
      beforeSteps: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"]),
      mandatoryNamedCheckpoints: Object.freeze(["PRE_INBOUND"]),
    }),
    client_inventory: Object.freeze({
      evidenceFamilies: Object.freeze(["CLIENT_INVENTORY"]),
      beforeSteps: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "traffic_verify"]),
      mandatoryNamedCheckpoints: Object.freeze(["PRE_AUTHENTICATED_TRAFFIC"]),
    }),
  }),
  comparisonBasis: Object.freeze([
    "EXACT_IMMUTABLE_PLAN_BASELINE_DIGEST",
    "EXACT_REGISTERED_TARGET_AND_IDENTITY_BINDINGS",
    "EXACT_EXPECTED_SAME_RUN_RECEIPT_TRANSITIONS_UP_TO_CURRENT_CURSOR",
    "EXACT_CURRENT_LEDGER_DIGEST",
  ]),
  noDrift: Object.freeze({
    replaces: "ONLY_THE_REFRESH_TOOL_OWN_FINITE_EVIDENCE_FAMILIES",
    preserves: Object.freeze(["CURRENT_PLAN_REF", "CURRENT_TEMPLATE_ID", "CURRENT_CURSOR", "REMAINING_OPERATION_REFS", "CURRENT_APPROVAL_REF"]),
    leaseRuleByRemainingEffect: Object.freeze({
      BEFORE_ANY_REMAINING_EXTERNAL_WRITE: "CURRENT_EFFECTIVE_APPROVAL_LEASE_MUST_BE_UNEXPIRED_AFTER_MIN_EVIDENCE_EXPIRY_RULE",
      AFTER_LAST_EXTERNAL_WRITE_READ_ONLY_CURSOR: "WRITE_LEASE_MAY_EXPIRE_READ_PROBES_PRESERVE_IMMUTABLE_TEMPLATE_CURSOR_LEDGER_BINDING_AND_NEVER_GAIN_WRITE_AUTHORITY",
    }),
    cursorAdvance: false,
    stateTransition: "UNCHANGED",
    planRewrite: false,
    leaseExtension: false,
  }),
  expiredImmediatelyBeforeExternalWrite: ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER,
  driftOrForeignOrStaleIdentity: ACTIVE_CHECKPOINT_DRIFT_RESOLVER,
  callerSelectableModeOrCheckpoint: false,
  refreshBooleanIsNotAuthority: true,
});
const FORWARD_MUTATION_DISPATCH_REQUIREMENT = "CURRENT_ALL_FINITE_EVIDENCE_CHECKPOINT_AND_UNEXPIRED_EFFECTIVE_APPROVAL_IMMEDIATELY_BEFORE_THIS_EXTERNAL_MUTATION";
const FORWARD_MUTATION_DISPATCH_CONTROL = Object.freeze({
  activeInventoryCheckpoint: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT,
  activeCursorWriteExpiryResolver: ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER,
  effectiveApprovalExpiry: FORWARD_APPROVAL_EFFECTIVE_EXPIRY_POLICY,
  requirement: FORWARD_MUTATION_DISPATCH_REQUIREMENT,
  cursorAdvance: false,
  leaseExtension: false,
});
const MAIN_ROLLBACK_ATOMIC_STAGES = Object.freeze([
  Object.freeze({ stageId: "rb01_cf_proxy_restore", graphNode: "cloudflare_proxy", inverseOperation: "cf.dns_proxy_owned", observerOperations: Object.freeze(["cf.dns_read"]), observerAuthority: "BROKER_CF_AUDIT_FIXED" }),
  Object.freeze({ stageId: "rb02_cf_record_delete", graphNode: "cloudflare_record", inverseOperation: "cf.dns_delete_owned", observerOperations: Object.freeze(["cf.dns_read"]), observerAuthority: "BROKER_CF_AUDIT_FIXED" }),
  Object.freeze({ stageId: "rb03_nginx_route_delete", graphNode: "nginx_route", inverseOperation: "origin.nginx_route_delete_owned.v1", observerOperations: Object.freeze(["origin.rollback_graph_readback_fixed.v1"]), observerAuthority: "SSH_ORIGIN_READ" }),
  Object.freeze({ stageId: "rb04_certificate_slots_delete", graphNode: "certificate_slot", inverseOperation: "origin.certificate_delete_owned.v1", observerOperations: Object.freeze(["origin.rollback_graph_readback_fixed.v1"]), observerAuthority: "SSH_ORIGIN_READ" }),
  Object.freeze({ stageId: "rb05_origin_ca_private_key_dispose", graphNode: "certificate_issuance", inverseOperation: "certificate.revoke_same_run_private_key.v1", observerOperations: Object.freeze(["ledger.rollback_secret_disposition_receipts_fixed.v1"]), observerAuthority: "LOCAL_LEDGER_READ" }),
  Object.freeze({ stageId: "rb06_client_artifact_dispose", graphNode: "client_profile", inverseOperation: "origin.artifact_remove_owned_unchanged.v1", observerOperations: Object.freeze(["ledger.rollback_local_artifact_tombstone_fixed.v1"]), observerAuthority: "LOCAL_FILESYSTEM_READ" }),
  Object.freeze({ stageId: "rb07_profile_runtime_secret_dispose", graphNode: "client_profile", inverseOperation: "artifact.revoke_same_run_runtime_secrets.v1", observerOperations: Object.freeze(["ledger.rollback_secret_disposition_receipts_fixed.v1"]), observerAuthority: "LOCAL_LEDGER_READ" }),
  Object.freeze({ stageId: "rb08_xui_inbound_remove", graphNode: "xui_inbound", inverseOperation: "origin.xui_inbound_remove_owned.v1", observerOperations: Object.freeze(["origin.rollback_graph_readback_fixed.v1"]), observerAuthority: "SSH_ORIGIN_READ" }),
  Object.freeze({ stageId: "rb09_xui_client_secret_revoke", graphNode: "xui_inbound", inverseOperation: "xui.revoke_same_run_client_secret.v1", observerOperations: Object.freeze(["ledger.rollback_secret_disposition_receipts_fixed.v1"]), observerAuthority: "LOCAL_LEDGER_READ" }),
  Object.freeze({ stageId: "rb10_xui_install_uninstall", graphNode: "xui_install", inverseOperation: "origin.xui_uninstall_owned.v1", observerOperations: Object.freeze(["origin.rollback_graph_readback_fixed.v1"]), observerAuthority: "SSH_ORIGIN_READ" }),
  Object.freeze({ stageId: "rb11_xui_panel_admin_revoke", graphNode: "xui_install", inverseOperation: "xui.revoke_same_run_panel_admin.v1", observerOperations: Object.freeze(["ledger.rollback_secret_disposition_receipts_fixed.v1"]), observerAuthority: "LOCAL_LEDGER_READ" }),
].map((row) => Object.freeze({ ...row, durableStageReceiptRequired: true, currentReadbackRequired: true, disposedRunSecretRequired: false })));
const MAIN_ROLLBACK_ATOMIC_STAGE_IDS = Object.freeze(MAIN_ROLLBACK_ATOMIC_STAGES.map(({ stageId }) => stageId));
const MAIN_ROLLBACK_GRAPH_NODE_ORDER = Object.freeze([...new Set(MAIN_ROLLBACK_ATOMIC_STAGES.map(({ graphNode }) => graphNode))]);
const BBR_ROLLBACK_ATOMIC_STAGES = Object.freeze([
  Object.freeze({ stageId: "bbr_rb01_owned_dropin_remove", orderedAction: "REMOVE_EXACT_SAME_RUN_OWNED_DROPIN", readback: "OWNED_DROPIN_ABSENT", receiptType: "BBR_ROLLBACK_STAGE_RECEIPT" }),
  Object.freeze({ stageId: "bbr_rb02_prior_live_restore", orderedAction: "RESTORE_EXACT_RECORDED_PRIOR_LIVE_VALUES", readback: "LIVE_VALUES_MATCH_RECORDED_PRIOR_DIGEST", receiptType: "BBR_ROLLBACK_STAGE_RECEIPT" }),
  Object.freeze({ stageId: "bbr_rb03_prior_persistent_restore", orderedAction: "RESTORE_EXACT_RECORDED_PRIOR_PERSISTENT_VALUES", readback: "PERSISTENT_VALUES_MATCH_RECORDED_PRIOR_DIGEST", receiptType: "BBR_ROLLBACK_STAGE_RECEIPT" }),
  Object.freeze({ stageId: "bbr_rb04_final_exact_readback", orderedAction: "FINAL_READ_ONLY_EXACT_PRIOR_STATE_CONFIRMATION", readback: "DROPIN_ABSENT_AND_LIVE_AND_PERSISTENT_VALUES_MATCH_RECORDED_PRIOR_DIGESTS", receiptType: "BBR_ROLLBACK_STAGE_RECEIPT" }),
].map((row) => Object.freeze({
  ...row,
  executor: "bbr_rollback",
  helperOperation: "origin.bbr_restore_owned.v1",
  durableStageReceiptRequired: true,
  receiptCommittedAfterExactStageReadbackBeforeNextStage: true,
})));
const BBR_ROLLBACK_ATOMIC_STAGE_IDS = Object.freeze(BBR_ROLLBACK_ATOMIC_STAGES.map(({ stageId }) => stageId));
const BBR_ROLLBACK_FINALIZATION_TRANSACTION = Object.freeze({
  trigger: "FINAL_BBR_STAGE_EXACT_PRIOR_STATE_READBACK_ALL_TRUE",
  authority: "SINGLE_LOCAL_LEDGER_TRANSACTION",
  commitsTogether: Object.freeze(["FINAL_BBR_STAGE_DURABLE_RECEIPT", "AGGREGATE_BBR_ROLLBACK_RECEIPT"]),
  atomicity: "BOTH_OR_NEITHER",
  aggregateBinds: Object.freeze(["EXACT_FROZEN_BBR_STAGE_SELECTION", "EXACT_ORDERED_BBR_STAGE_RECEIPT_SET", "FINAL_PRIOR_STATE_DIGEST", "EXACT_BBR_APPLY_BASELINE_RECEIPT_BINDING"]),
  beforeTransactionCommitCrash: Object.freeze({
    visibleFinalReceiptAndAggregatePair: "NEITHER",
    maximumVisibleProperPrefixLength: 3,
    destination: "BBR_MANUAL_ACTION_REQUIRED",
    next: "FIXED_BBR_STAGE_RECONCILIATION_NO_FINAL_STAGE_REPLAY_UNTIL_PROVEN",
  }),
  afterTransactionCommit: Object.freeze({
    visibleFinalReceiptAndAggregatePair: "BOTH",
    observation: "PROVEN_COMMITTED",
    destination: "BBR_ROLLED_BACK",
    next: "POST_BBR_INVERSE_TRAFFIC_LOG_AND_OLD_LINE_REFRESH",
  }),
  fourStageReceiptsWithoutAggregateRepresentable: false,
  partialReceiptVisibility: false,
  externalEffectInsideTransaction: false,
  callerSelectable: false,
});
const MAIN_ROLLBACK_FINALIZATION_TRANSACTION = Object.freeze({
  trigger: "FINAL_SELECTED_ATOMIC_STAGE_EXACT_POST_INVERSE_READBACK_ALL_TRUE",
  authority: "SINGLE_LOCAL_LEDGER_TRANSACTION",
  commitsTogether: Object.freeze(["FINAL_ATOMIC_STAGE_DURABLE_RECEIPT", "AGGREGATE_MAIN_ROLLBACK_RECEIPT"]),
  atomicity: "BOTH_OR_NEITHER",
  aggregateBinds: Object.freeze(["EXACT_FROZEN_ATOMIC_STAGE_SELECTION", "EXACT_ORDERED_ATOMIC_STAGE_RECEIPT_SET", "FINAL_DIGEST", "RETAINED_COMPENSATION_PAIR_SET"]),
  beforeTransactionCommitCrash: Object.freeze({
    visibleReceiptPair: "NEITHER",
    destination: "MANUAL_ACTION_REQUIRED",
    next: "FIXED_MAIN_ROLLBACK_STAGE_RECONCILIATION_NO_INVERSE_REPLAY_UNTIL_PROVEN",
  }),
  afterTransactionCommit: Object.freeze({
    visibleReceiptPair: "BOTH",
    observation: "PROVEN_COMMITTED",
    destination: "ROLLED_BACK",
    next: "OLD_LINE_VERIFY_POST_MAIN_ROLLBACK_BOUND_TO_AGGREGATE_RECEIPT",
  }),
  partialReceiptVisibility: false,
  externalEffectInsideTransaction: false,
  callerSelectable: false,
});
const PLAN_OPERATION_RESOLVER = Object.freeze({
  authority: "SERVER_GENERATES_OPERATION_REFS_FROM_IMMUTABLE_LEDGER_FACTS_ONLY",
  callerSelectableOperations: false,
  catalog: "core-v1-31",
  cursorEnforcement: Object.freeze({
    authority: "SERVER_LEDGER_CURRENT_NEXT_CURSOR",
    currentNextBindingFields: Object.freeze(["run_id", "plan_ref", "operation_ref", "approval_ref", "template_id", "lease_class", "expected_ledger_digest"]),
    writeAndExecutorTools: Object.freeze(["rollback_run", "xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "bbr_apply", "bbr_rollback"]),
    explicitOperationRefTools: Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "bbr_apply", "bbr_rollback"]),
    writeAndExecutorRule: "EXPLICIT_OPERATION_REF_TOOLS_DISPATCH_ONLY_IFF_OPERATION_REF_IS_EXACT_CURRENT_NEXT_APPROVED_TEMPLATE_STEP_AND_TEMPLATE_LEASE_LEDGER_BINDINGS_ALL_MATCH",
    planResolvedExecutorTools: Object.freeze(["rollback_run"]),
    planResolvedExecutorRule: "ROLLBACK_RUN_HAS_NO_CALLER_OPERATION_SELECTOR_SERVER_RESOLVES_SOLE_MAIN_ROLLBACK_V1_RB01_FROM_EXACT_PLAN_APPROVAL_TEMPLATE_LEASE_AND_LEDGER",
    plannedReadProbeTools: Object.freeze(["old_line_verify", "xui_profile_inspect", "origin_verify", "cdn_verify", "traffic_verify", "logs_correlate", "bbr_verify"]),
    plannedReadProbeRule: "ADVANCE_CURSOR_ONLY_IFF_TOOL_AND_SERVER_DERIVED_MODE_MATCH_EXACT_CURRENT_NEXT_TEMPLATE_STEP",
    activeNodeCheckpointRefreshTools: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.refreshTools,
    activeNodeCheckpointRule: "REFRESH_NEVER_ADVANCES_CURSOR_AND_DELEGATES_TO_ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT",
    activeCursorWriteExpiryRule: "EXPIRED_EFFECTIVE_APPROVAL_AT_PREDISPATCH_NO_OPEN_DISPATCH_DELEGATES_TO_ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER_AND_NEVER_RESUMES_FORWARD_AUTHORITY",
    hostP3CheckpointRefreshTool: HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT.tool,
    hostP3CheckpointRule: "BBR_HOST_APPROVED_EXACT_NO_DRIFT_REFRESH_PRESERVES_CURRENT_AUTHORITY_WITHOUT_LEASE_EXTENSION_DRIFT_OR_EXPIRY_RETURNS_BBR_PLAN_READY",
    offCursorReadProbeRule: "ALLOW_REFRESH_ONLY_WITHOUT_CURSOR_ADVANCE",
    completionRule: "COMPLETION_EVALUATE_IS_NEVER_A_TEMPLATE_STEP",
    mismatch: "WRONG_STATE_NO_DISPATCH_NO_CURSOR_ADVANCE",
    callerSelectableCursorOrMode: false,
  }),
  activeNodeEvidenceRefreshCheckpoint: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT,
  activeCursorWriteExpiryResolver: ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER,
  hostP3BbrEvidenceRefreshCheckpoint: HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT,
  forwardApprovalEffectiveExpiry: FORWARD_APPROVAL_EFFECTIVE_EXPIRY_POLICY,
  rollbackLeaseExpiryResolver: ROLLBACK_LEASE_EXPIRY_RESOLVER,
  cloudflareForwardGate: Object.freeze({
    observedModes: Object.freeze(["off", "flexible", "full", "strict", "origin_pull", "unknown"]),
    strictCompatibleModes: Object.freeze(["strict", "origin_pull"]),
    strictCompatibleByMode: Object.freeze({
      strict: true, origin_pull: true,
      off: false, flexible: false, full: false,
      unknown: "UNRESOLVED_FAIL_CLOSED",
    }),
    websocketsRequired: true,
    evidenceRequired: Object.freeze(["FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED"]),
    onFalseOrUnknown: "DENY_BEFORE_ANY_CF_INSTALL_NODE_PLAN_LEASE_OR_WRITE",
    zoneWideWritesInCoreV1: false,
    callerOverride: false,
  }),
  globalForwardEligibility: Object.freeze({
    evaluatedBefore: "ANY_NODE_INSTALL_OR_NODE_P2_EXTERNAL_MUTATION_PLAN_OR_LEASE",
    requiredFacts: Object.freeze([
      "REGISTERED_ORIGIN_AND_CLOUDFLARE_TARGETS_CURRENT",
      "SUPPORTED_EXISTING_NGINX",
      "SAFE_PUBLIC_TLS_443_LISTENER_OWNERSHIP",
      "CREATE_ONLY_OWNED_INCLUDE_SLOT",
      "NO_SERVER_NAME_OR_WEBSOCKET_PATH_CONFLICT",
      "CLOUDFLARE_RECORD_CASE_ABSENT_OR_SAME_RUN_CURRENT_NOT_FOREIGN_OR_AMBIGUOUS",
      "ROLE_BOUND_CLOUDFLARE_CREDENTIALS_FOR_RESOLVED_CASE",
      "FRESH_ZONE_SSL_STRICT_COMPATIBLE",
      "FRESH_WEBSOCKETS_ENABLED",
      "CERTIFICATE_CASE_IS_REUSE_OR_ORIGIN_CA_NOT_DENY",
      "ORIGIN_CA_DEDICATED_ABSENT_ROOT_OWNED_SLOTS_WHEN_SELECTED",
      "ALLOWLISTED_CLIENT_RUNTIME_AND_PROBE_DESTINATION",
      "PROTECTED_LINE_PAIR_VALID_OR_SERVER_PROVEN_NOT_APPLICABLE",
      "SAFE_OUTPUT_DIRECTORY",
      "NO_UNKNOWN_COMMIT_OR_RECOVERY_OBLIGATION",
    ]),
    appliesToScopes: Object.freeze(["NODE_INSTALL_P3", "NODE_P2"]),
    deny: "FAIL_CLOSED_BEFORE_PLAN_LEASE_OR_WRITE",
    callerOverride: false,
  }),
  resolutionOrder: Object.freeze(["NODE_INSTALL_P3", "NODE_P2", "HOST_P3", "MAIN_OR_BBR_ROLLBACK_WHEN_REQUESTED"]),
  xuiCases: XUI_RESOLUTION_CASES,
  certificateReuseValidity: Object.freeze({
    clock: "TRUSTED_SERVER_CLOCK",
    minimumRemainingValidity: "P30D",
    sufficientIff: "SELECTED_CERTIFICATE_NOT_AFTER_MINUS_SERVER_EVALUATED_AT_GTE_P30D",
    covers: Object.freeze(["PT45M_NODE_PLAN", "DELIVERY_AND_VERIFICATION_WINDOW"]),
    insufficientResolution: "ORIGIN_CA_IF_ELIGIBLE_ELSE_DENY_BEFORE_PLAN_LEASE_OR_WRITE",
    callerOverride: false,
  }),
  certificateCases: Object.freeze({
    TT: Object.freeze({ safeReuse: true, originCaEligible: true, strategy: "reuse", resolution: "REUSE_PRECEDENCE" }),
    TF: Object.freeze({ safeReuse: true, originCaEligible: false, strategy: "reuse", resolution: "REUSE" }),
    FT: Object.freeze({ safeReuse: false, originCaEligible: true, strategy: "origin_ca", resolution: "ISSUE_ONE_SHOT_ORIGIN_CA" }),
    FF: Object.freeze({ safeReuse: false, originCaEligible: false, strategy: "not_applicable", resolution: "DENY_CERTIFICATE_NOT_READY" }),
  }),
  scopes: Object.freeze({
    NODE_INSTALL_P3: Object.freeze({
      leaseClass: "NODE_INSTALL_P3",
      templateId: "NODE_INSTALL_V1",
      mutationList: Object.freeze(["xui_install"]),
      operationList: Object.freeze(["xui_install", "old_line_verify"]),
      cursorCompletionRequires: Object.freeze(["XUI_INSTALL_RECEIPT", "FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_XUI_INSTALL_RECEIPT"]),
      nextScope: "NODE_P2_AFTER_FRESH_INVENTORIES_AND_POST_INSTALL_OLD_LINE",
    }),
    NODE_P2: Object.freeze({
      leaseClass: "NODE_P2",
      certificateStrategies: Object.freeze(["reuse", "origin_ca"]),
      templateByCertificateStrategy: Object.freeze({ reuse: "NODE_P2_REUSE_V1", origin_ca: "NODE_P2_ORIGIN_CA_V1" }),
      mutationListByCertificateStrategy: Object.freeze({
        reuse: Object.freeze(["xui_create_inbound", "xui_profile_publish", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"]),
        origin_ca: Object.freeze(["xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"]),
      }),
      operationListByCertificateStrategy: Object.freeze({
        reuse: Object.freeze(["old_line_verify", "xui_create_inbound", "xui_profile_publish", "nginx_route_apply", "old_line_verify", "cf_node_record_apply", "origin_verify", "cf_proxy_enable", "cdn_verify", "xui_profile_inspect", "traffic_verify", "logs_correlate", "old_line_verify"]),
        origin_ca: Object.freeze(["old_line_verify", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "old_line_verify", "cf_node_record_apply", "origin_verify", "cf_proxy_enable", "cdn_verify", "xui_profile_inspect", "traffic_verify", "logs_correlate", "old_line_verify"]),
      }),
      verificationSequence: Object.freeze([
        "old_line_verify:post_prerequisite_effect_or_initial_baseline",
        "ACTIVE_NODE_GLOBAL_ELIGIBILITY_CHECKPOINT:all_four_finite_inventories_before_every_external_mutation",
        "ACTIVE_NODE_CHECKPOINT:xui_inventory:pre_inbound",
        "ACTIVE_NODE_CHECKPOINT:origin_inventory:before_certificate_or_nginx",
        "old_line_verify:current_route_pre_proxy",
        "ACTIVE_NODE_CHECKPOINT:origin_inventory+cloudflare_inventory:pre_record",
        "ACTIVE_NODE_CHECKPOINT:origin_inventory+cloudflare_inventory:post_record_before_direct_origin_verify",
        "origin_verify:issuer_specific_direct_origin",
        "cdn_verify:api_owned_proxy_plus_independent_public_resolution",
        "xui_profile_inspect:non_secret_field_equality",
        "ACTIVE_NODE_CHECKPOINT:client_inventory:pre_authenticated_traffic",
        "traffic_verify:authenticated_request_and_expected_egress",
        "logs_correlate:bounded_same_probe_window",
        "old_line_verify:final_post_all_changes",
      ]),
      reuseEligibility: "EXISTING_EXACT_SAN_TRUST_VALIDITY_CERTIFICATE_ALREADY_IN_SAFE_STABLE_ROOT_OWNED_SERVICE_SLOTS_NO_DEPLOY_WRITE",
    }),
    HOST_P3: Object.freeze({
      leaseClass: "HOST_P3",
      templateId: "HOST_BBR_V1",
      operationList: Object.freeze(["bbr_apply", "bbr_verify", "traffic_verify", "logs_correlate", "old_line_verify"]),
      mainEvidenceRefreshAfterApply: Object.freeze(["traffic_verify", "logs_correlate", "old_line_verify"]),
      mainGate: "MAIN_PHASE_OLD_LINE_REVERIFIED_AND_NODE_CURSOR_COMPLETE_AND_REPORT_NOT_SEALED",
      inventoryMayPrecedeMainGate: true,
      compileAuthorizeApplyMayPrecedeMainGate: false,
      evidenceRefreshCheckpoint: HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT,
    }),
    MAIN_ROLLBACK: Object.freeze({
      leaseClass: "ROLLBACK", executor: "rollback_run",
      templateId: "MAIN_ROLLBACK_V1",
      operationList: Object.freeze(["rollback_run", "old_line_verify"]),
      reverseGraphOrder: MAIN_ROLLBACK_GRAPH_NODE_ORDER,
      atomicStages: MAIN_ROLLBACK_ATOMIC_STAGES,
      atomicStageIds: MAIN_ROLLBACK_ATOMIC_STAGE_IDS,
      finalizationTransaction: MAIN_ROLLBACK_FINALIZATION_TRANSACTION,
      graphAuthority: "PLAN_OPERATION_RESOLVER.scopes.MAIN_ROLLBACK.atomicStages",
      inverseStep: "ROLLBACK_RUN_SERVER_RESOLVES_SOLE_RB01_FROM_PLAN_AND_APPROVAL_NO_CALLER_OPERATION_SELECTOR",
      postInverseProbe: "OLD_LINE_VERIFY_POST_MAIN_ROLLBACK_BOUND_TO_EXACT_ROLLBACK_RECEIPT_NO_INVERSE_REEXECUTION",
      prefixResume: Object.freeze({ observation: "PROVEN_INVERSE_PREFIX", proofUnit: "ORDERED_ATOMIC_STAGE_ID", newPlanContains: "ONLY_EXACT_REMAINING_CONTIGUOUS_ATOMIC_STAGE_SUFFIX", activeStage: "FIRST_REMAINING_STAGE_OR_NULL_BETWEEN_STAGES", completedPrefixReplay: false, approval: "FRESH_HOST_PROMPT_AND_LEASE" }),
    }),
    BBR_ROLLBACK: Object.freeze({
      leaseClass: "ROLLBACK", executor: "bbr_rollback",
      templateId: "BBR_ROLLBACK_V1",
      operationList: Object.freeze(["bbr_rollback", "traffic_verify", "logs_correlate", "old_line_verify"]),
      allowedOrigins: Object.freeze(["BBR_APPLIED", "BBR_VERIFIED", "BBR_MANUAL_ACTION_REQUIRED"]),
      atomicStages: BBR_ROLLBACK_ATOMIC_STAGES,
      atomicStageIds: BBR_ROLLBACK_ATOMIC_STAGE_IDS,
      finalizationTransaction: BBR_ROLLBACK_FINALIZATION_TRANSACTION,
      stageReceiptFamily: "BBR_ROLLBACK_STAGE_RECEIPT",
      aggregateReceiptType: "BBR_ROLLBACK_RECEIPT",
      stageResume: Object.freeze({ orderedStageIds: BBR_ROLLBACK_ATOMIC_STAGE_IDS, observation: "PROVEN_INVERSE_PREFIX", newPlanContains: "ONLY_EXACT_REMAINING_ORDERED_STAGE_SUFFIX", completedStageReplay: false, approval: "FRESH_HOST_PROMPT_AND_LEASE" }),
    }),
  }),
  postTemplateResolution: Object.freeze({
    NODE_P2: Object.freeze({
      BBR_NOT_REQUESTED: Object.freeze({ next: "run_close:bbr:not_requested:BBR_CLOSED_NOT_REQUESTED_RECEIPT_THEN_COMPLETION", completionAllowedBeforeBbrClosure: false }),
      BBR_PENDING: Object.freeze({
        nextByDisposition: Object.freeze({
          continue_requested_branch: "bbr_inventory",
          close_before_inventory: "run_close:bbr:partial:NO_BBR_APPLY_RECEIPT_THEN_COMPLETION",
        }),
        completionAllowedBeforeBbrClosure: false,
      }),
      BBR_INVENTORIED: Object.freeze({
        nextByEligibility: Object.freeze({
          eligible: "plan_compile:HOST_P3",
          ineligible_or_unsupported: "run_close:bbr:partial:NO_BBR_APPLY_RECEIPT_THEN_COMPLETION",
        }),
        completionAllowedBeforeBbrClosure: false,
      }),
      preNodeCompletionAllowedBbrStates: Object.freeze(["BBR_NOT_REQUESTED", "BBR_PENDING", "BBR_INVENTORIED"]),
      preNodeCompletionForbiddenBbrStates: Object.freeze(["BBR_PLAN_READY", "BBR_HOST_APPROVED", "BBR_APPLIED", "BBR_VERIFIED", "BBR_ROLLING_BACK", "BBR_ROLLED_BACK", "BBR_MANUAL_ACTION_REQUIRED", "BBR_CLOSED"]),
    }),
    HOST_P3: Object.freeze({
      next: "run_close:bbr:accepted:BBR_CLOSED_VERIFIED_RECEIPT_THEN_completion_evaluate:end_to_end_verified",
      requires: Object.freeze(["BBR_VERIFIED", "POST_BBR_AUTHENTICATED_TRAFFIC_EGRESS_LOGS_AND_PROTECTED_LINE_REFRESHED"]),
      completionInsideApprovedTemplate: false,
      completionAllowedBeforeBbrClosure: false,
    }),
    BBR_ROLLBACK: Object.freeze({
      next: "run_close:bbr:partial:BBR_CLOSED_ROLLED_BACK_RECEIPT_THEN_completion_evaluate:end_to_end_verified",
      requires: Object.freeze(["BBR_ROLLED_BACK", "POST_BBR_AUTHENTICATED_TRAFFIC_EGRESS_LOGS_AND_PROTECTED_LINE_REFRESHED"]),
      completionInsideApprovedTemplate: false,
      completionAllowedBeforeBbrClosure: false,
    }),
  }),
  templates: Object.freeze({
    NODE_INSTALL_V1: operationTemplate("NODE_INSTALL_V1", "NODE_INSTALL_P3", [operationStep("install01", "xui_install", "clean_host_first_install"), operationStep("install02", "old_line_verify", "bind_exact_install_receipt")]),
    NODE_P2_REUSE_V1: operationTemplate("NODE_P2_REUSE_V1", "NODE_P2", [
      operationStep("node01", "old_line_verify", "post_prerequisite_or_initial"),
      operationStep("node02", "xui_create_inbound", "create_owned_loopback_ws"),
      operationStep("node03", "xui_profile_publish", "publish_private_profile"),
      operationStep("node04", "nginx_route_apply", "reuse_safe_stable_certificate_slots"),
      operationStep("node05", "old_line_verify", "current_route_pre_record"),
      operationStep("node06", "cf_node_record_apply", "create_unproxied_a_or_aaaa"),
      operationStep("node08", "origin_verify", "issuer_specific_direct_origin"),
      operationStep("node09", "cf_proxy_enable", "enable_owned_record_proxy"),
      operationStep("node10", "cdn_verify", "api_and_independent_public_resolution"),
      operationStep("node11", "xui_profile_inspect", "non_secret_field_equality"),
      operationStep("node12", "traffic_verify", "authenticated_request_expected_egress"),
      operationStep("node13", "logs_correlate", "same_probe_window"),
      operationStep("node14", "old_line_verify", "final_post_all_changes"),
    ]),
    NODE_P2_ORIGIN_CA_V1: operationTemplate("NODE_P2_ORIGIN_CA_V1", "NODE_P2", [
      operationStep("node01", "old_line_verify", "post_prerequisite_or_initial"),
      operationStep("node02", "xui_create_inbound", "create_owned_loopback_ws"),
      operationStep("node03", "xui_profile_publish", "publish_private_profile"),
      operationStep("node04", "certificate_issue_origin_ca", "one_shot_issue"),
      operationStep("node05", "certificate_deploy", "deploy_stable_owned_slots"),
      operationStep("node06", "nginx_route_apply", "bind_current_deploy_receipt"),
      operationStep("node07", "old_line_verify", "current_route_pre_record"),
      operationStep("node08", "cf_node_record_apply", "create_unproxied_a_or_aaaa"),
      operationStep("node10", "origin_verify", "issuer_specific_direct_origin"),
      operationStep("node11", "cf_proxy_enable", "enable_owned_record_proxy"),
      operationStep("node12", "cdn_verify", "api_and_independent_public_resolution"),
      operationStep("node13", "xui_profile_inspect", "non_secret_field_equality"),
      operationStep("node14", "traffic_verify", "authenticated_request_expected_egress"),
      operationStep("node15", "logs_correlate", "same_probe_window"),
      operationStep("node16", "old_line_verify", "final_post_all_changes"),
    ]),
    HOST_BBR_V1: operationTemplate("HOST_BBR_V1", "HOST_P3", [
      operationStep("bbr01", "bbr_apply", "apply_exact_bbr_fq_target"),
      operationStep("bbr02", "bbr_verify", "verify_live_persistent_and_protected_line"),
      operationStep("bbr03", "traffic_verify", "refresh_authenticated_traffic_and_egress"),
      operationStep("bbr04", "logs_correlate", "refresh_logs"),
      operationStep("bbr05", "old_line_verify", "refresh_final_protected_line"),
    ]),
    MAIN_ROLLBACK_V1: operationTemplate("MAIN_ROLLBACK_V1", "ROLLBACK", [
      operationStep("rb01", "rollback_run", "server_frozen_atomic_stage_selection"),
      operationStep("rb02", "old_line_verify", "post_main_rollback_bound_to_exact_receipt"),
    ]),
    BBR_ROLLBACK_V1: operationTemplate("BBR_ROLLBACK_V1", "ROLLBACK", [
      operationStep("bbrb01", "bbr_rollback", "dedicated_owned_inverse"),
      operationStep("bbrb02", "traffic_verify", "refresh_authenticated_traffic_and_egress"),
      operationStep("bbrb03", "logs_correlate", "refresh_logs"),
      operationStep("bbrb04", "old_line_verify", "refresh_final_protected_line"),
    ]),
  }),
});

const same = (origins) => Object.freeze(Object.fromEntries(origins.map((origin) => [origin, "UNCHANGED"])));
const P = ({
  governingColumn = "main", auth = [], lease = "NONE", allowedFrom,
  successByOrigin, failureTo = ["UNCHANGED"], requires = [], produces = [],
  invalidates = [], rollbackClass = "not_applicable", rollbackAction = "NONE",
  sideEffects = [], errors = ERROR_CODES, controls = {},
}) => Object.freeze({
  governingColumn,
  auth: Object.freeze([...auth]),
  lease,
  allowedFrom: Object.freeze([...allowedFrom]),
  successByOrigin: Object.freeze({ ...successByOrigin }),
  failureTo: Object.freeze([...failureTo]),
  requires: Object.freeze([...requires]),
  produces: Object.freeze([...produces]),
  invalidates: Object.freeze([...invalidates]),
  rollbackClass,
  rollbackAction,
  sideEffects: Object.freeze([...sideEffects]),
  errors: Object.freeze([...errors]),
  outputStatusPolicy: "OUTPUT_STATUS_POLICY",
  controls: Object.freeze({ ...controls }),
});

const RunOnly = closed({ run_id: S.RunRef });
const RefreshInput = (extra = {}) => closed({ run_id: S.RunRef, refresh: bool, ...extra });
const EXECUTION_BINDING_REQUIREMENT = "SERVER_REQUIRES_OPERATION_REF_EQUAL_CURRENT_NEXT_APPROVED_TEMPLATE_STEP_AND_TEMPLATE_LEASE_LEDGER_BINDINGS_MATCH_THEN_RESOLVES_TARGET_SECRET_ADAPTER_SPEC_SLOT_PATH_AND_EVIDENCE";
const ROLLBACK_EXECUTION_BINDING_REQUIREMENT = "SERVER_RESOLVES_SOLE_MAIN_ROLLBACK_RB01_FROM_EXACT_PLAN_REF_APPROVAL_REF_TEMPLATE_LEASE_AND_LEDGER_NO_CALLER_OPERATION_SELECTOR";
const CURSOR_READ_PROBE_REQUIREMENT = "SERVER_CURSOR_PLANNED_STEP_TOOL_AND_DERIVED_MODE_MATCH_OR_OFF_CURSOR_REFRESH_WITHOUT_ADVANCE";
const CONFIGURE_MODE_GATE = "RUN_MODE_CONFIGURE_FROM_IMMUTABLE_LEDGER";
const configureRequires = (...requirements) => Object.freeze([CONFIGURE_MODE_GATE, ...requirements]);
const mutationFailureControl = (context) => Object.freeze({
  resolver: "MUTATION_FAILURE_RESOLVER",
  context,
  rows: MUTATION_FAILURE_RESOLVER.rows,
});
const WriteInput = (extra = {}) => closed({
  run_id: S.RunRef,
  plan_ref: S.PlanRef,
  operation_ref: S.OperationRef,
  approval_ref: S.ApprovalRef,
  expected_ledger_digest: S.Digest,
  idempotency_key: S.IdempotencyKey,
  ...extra,
});
const MutationData = (rollbackClass, extra = {}) => closed({
  change_ref: S.ChangeRef,
  before_digest: nullable(S.Digest),
  after_digest: S.Digest,
  ownership_receipt_ref: S.ReceiptRef,
  rollback_class: constOf(rollbackClass),
  inverse_ref: rollbackClass === "exact_inverse" ? S.InverseRef : { type: "null" },
  compensation_ref: rollbackClass === "compensating_action" ? S.CompensationRef : { type: "null" },
  committed: constOf(true),
  ...extra,
});
const C = (definition) => contract({
  ...definition,
  errorBody: ErrorBody,
  successStatuses: definition.name === "completion_evaluate"
    ? ["ok", "no_op", "pending"]
    : Object.prototype.hasOwnProperty.call(definition.input.properties || {}, "idempotency_key")
      ? ["ok", "no_op"]
      : ["ok"],
  statusDataRules: definition.name === "completion_evaluate" ? COMPLETION_STATUS_DATA_RULES : [],
});

const MAIN_INVENTORY_ORIGINS = Object.freeze(MAIN_PHASES.filter((phase) =>
  !["CLOSED", "ROLLING_BACK", "ROLLED_BACK"].includes(phase)));
const READ_ORIGINS = Object.freeze([...MAIN_PHASES]);

const H = (callers, mutating, authority, inputSource, result) => Object.freeze({
  callers: Object.freeze([...callers]), mutating, authority, inputSource, result,
});
const PRIVILEGED_HELPER_OPERATIONS = Object.freeze({
  "origin.inventory.v1": H(["origin_inventory", "reconcile_status"], false, "SSH_ORIGIN_READ", "REGISTERED_TARGET_ONLY_OR_SERVER_SELECTED_UNKNOWN_GRAPH", "MASKED_HOST_INVENTORY_OR_BEFORE_AFTER_DIGEST_PROJECTION"),
  "origin.xui_install_owned.v1": H(["xui_install"], true, "SSH_ORIGIN_WRITE", "PINNED_INSTALL_PLAN_AND_ADAPTER", "OWNED_INSTALL_RECEIPT"),
  "origin.xui_install_readback.v1": H(["xui_install", "xui_inventory"], false, "SSH_ORIGIN_READ", "REGISTERED_TARGET_PLUS_OPTIONAL_SAME_RUN_OWNERSHIP_RECEIPT", "MASKED_FIXED_INSTALL_READBACK"),
  "origin.xui_uninstall_owned.v1": H(["rollback_run"], true, "SSH_ORIGIN_WRITE", "EXACT_OWNERSHIP_RECEIPT_AFTER_DEPENDENTS_REVERSED", "OWNED_UNINSTALL_RECEIPT"),
  "origin.xui_inbound_apply_owned.v1": H(["xui_create_inbound"], true, "SSH_ORIGIN_WRITE", "FROZEN_INBOUND_SPEC", "OWNED_INBOUND_RECEIPT"),
  "origin.xui_inbound_remove_owned.v1": H(["rollback_run"], true, "SSH_ORIGIN_WRITE", "OWNED_INBOUND_RECEIPT", "INBOUND_INVERSE_RECEIPT"),
  "origin.artifact_remove_owned_unchanged.v1": H(["rollback_run"], true, "LOCAL_FILESYSTEM_WRITE", "EXACT_SAME_RUN_ARTIFACT_RECEIPT_CURRENT_DIGEST_AND_DESCRIPTOR_RELATIVE_NOFOLLOW", "OWNED_ARTIFACT_DELETE_RECEIPT_OR_RESIDUAL_IF_CHANGED"),
  "origin.certificate_deploy_owned.v1": H(["certificate_deploy"], true, "SSH_ORIGIN_WRITE", "EXACT_APPROVED_OPERATION_BROKER_CUSTODY_PAIR_FULLCHAIN_REF_AND_ORIGIN_CA_PRIVATE_KEY_SECRET_REF_PLUS_FRESH_DEDICATED_ABSENT_ROOT_OWNED_SLOT_REFS_NO_CALLER_PATH_PAYLOAD_KEY_OR_SLOT_SELECTOR", "SAME_RUN_CREATED_FULLCHAIN_AND_PRIVATE_KEY_SLOT_RECEIPT_BOUND_TO_EXACT_CUSTODY_PAIR_AND_SLOT_DIGESTS"),
  "origin.certificate_delete_owned.v1": H(["rollback_run"], true, "SSH_ORIGIN_WRITE", "EXACT_SAME_RUN_SLOT_RECEIPT_AFTER_ROUTE_INVERSE", "CERTIFICATE_SLOT_DELETE_RECEIPT"),
  "origin.nginx_route_apply_owned.v1": H(["nginx_route_apply"], true, "SSH_ORIGIN_WRITE", "FROZEN_ROUTE_AND_SERVICE_SLOT_REFS", "OWNED_ROUTE_RECEIPT"),
  "origin.nginx_route_delete_owned.v1": H(["rollback_run"], true, "SSH_ORIGIN_WRITE", "EXACT_SAME_RUN_CREATED_INCLUDE_RECEIPT_CURRENT_DIGEST_DESCRIPTOR_RELATIVE_NOFOLLOW_THEN_RELOAD", "OWNED_INCLUDE_DELETE_AND_RELOAD_RECEIPT"),
  "origin.reconcile_xui_install_readback.v1": H(["reconcile_status"], false, "SSH_ORIGIN_READ", "SERVER_SELECTED_UNKNOWN_XUI_INSTALL_OPERATION_AND_REGISTERED_TARGET", "BEFORE_AFTER_DIGEST_PROJECTION"),
  "origin.reconcile_certificate_slot_readback.v1": H(["reconcile_status"], false, "SSH_ORIGIN_READ", "SERVER_SELECTED_UNKNOWN_CERTIFICATE_DEPLOY_OPERATION_AND_SLOT_REFS", "BEFORE_AFTER_DIGEST_PROJECTION"),
  "origin.reconcile_nginx_include_readback.v1": H(["reconcile_status"], false, "SSH_ORIGIN_READ", "SERVER_SELECTED_UNKNOWN_NGINX_OPERATION_AND_INCLUDE_REF", "BEFORE_AFTER_DIGEST_PROJECTION"),
  "origin.rollback_graph_readback_fixed.v1": H(["reconcile_status"], false, "SSH_ORIGIN_READ", "SERVER_SELECTED_FROZEN_HOST_GRAPH_NODES_ONLY_XUI_INSTALL_XUI_INBOUND_CERTIFICATE_SLOTS_AND_NGINX_ROUTE_WITH_OPERATION_OWNERSHIP_AND_DURABLE_INVERSE_RECEIPTS", "PER_HOST_GRAPH_NODE_TOMBSTONE_CURRENT_DIGEST_OWNERSHIP_AND_INVERSE_READBACK_NO_PANEL_OR_PROFILE_SECRET_REQUIRED"),
  "ledger.rollback_local_artifact_tombstone_fixed.v1": H(["reconcile_status"], false, "LOCAL_FILESYSTEM_READ", "SERVER_SELECTED_FROZEN_CLIENT_PROFILE_NODE_SAME_RUN_ARTIFACT_RECEIPT_CURRENT_DIGEST_AND_DISPOSITION_TOMBSTONE", "LOCAL_ARTIFACT_DELETE_OR_RETAINED_CHANGED_RESIDUAL_TOMBSTONE_READBACK_NO_RUNTIME_SECRET_REQUIRED"),
  "ledger.rollback_secret_disposition_receipts_fixed.v1": H(["reconcile_status"], false, "LOCAL_LEDGER_READ", "SERVER_SELECTED_FROZEN_MAIN_ROLLBACK_GRAPH_EXACT_PRE_INVERSE_SECRET_STATE_AND_DURABLE_PROFILE_CLIENT_PANEL_AND_PRIVATE_KEY_DISPOSITION_RECEIPTS", "PER_REQUIRED_SECRET_CURRENT_OR_PRE_INVERSE_DISPOSITION_STATUS_AND_BINDING_DIGEST"),
  "ledger.bbr_rollback_stage_receipts_fixed.v1": H(["reconcile_status"], false, "LOCAL_LEDGER_READ", "SERVER_SELECTED_BBR_ROLLBACK_OPERATION_EXACT_FROZEN_FOUR_STAGE_IDS_SAME_BBR_ROLLBACK_STAGE_RECEIPT_FAMILY_FINALIZATION_TRANSACTION_AGGREGATE_RECEIPT_AND_EXACT_RECORDED_PRIOR_DIGESTS", "EXACT_ZERO_PROPER_ORDERED_PREFIX_OR_ALL_FOUR_PLUS_ATOMIC_AGGREGATE_PROJECTION_NO_FOUR_WITHOUT_AGGREGATE_AND_NO_CROSS_FAMILY_RECEIPTS"),
  "client.inventory_fixed.v1": H(["client_inventory", "reconcile_status"], false, "LOCAL_PROBE", "ALLOWLISTED_CLIENT_RUNTIME_AND_DESTINATION_REGISTRY_ONLY", "MASKED_RUNTIME_DESTINATION_AND_REGISTRY_DIGEST_PROJECTION"),
  "origin.probe_fixed.v1": H(["old_line_verify", "origin_verify", "cdn_verify", "traffic_verify"], false, "LOCAL_PROBE", "ALLOWLISTED_PROBE_REFS", "BOUNDED_PROBE_RECEIPT"),
  "origin.expected_egress_fixed.v1": H(["traffic_verify"], false, "SSH_ORIGIN_READ", "SAME_ALLOWLISTED_PROBE_DESTINATION_REF_AND_LOW_ENTROPY_HMAC_CONTEXT", "DIRECT_EXPECTED_EGRESS_EVIDENCE_REF_AND_HMAC_DIGEST_NO_RAW_IP"),
  "origin.logs_correlate_fixed.v1": H(["logs_correlate"], false, "SSH_ORIGIN_READ", "PROBE_REF_AND_FIXED_WINDOW", "BOUNDED_CORRELATION_RECEIPT"),
  "origin.bbr_inventory_fixed.v1": H(["bbr_inventory", "bbr_verify", "reconcile_status"], false, "SSH_ORIGIN_READ", "REGISTERED_TARGET_PLUS_OPTIONAL_EXACT_BBR_CHANGE_OR_INVERSE_RECEIPT", "MASKED_KERNEL_CAPABILITY_CONFLICT_AND_LIVE_PERSISTENT_READBACK"),
  "origin.bbr_apply_owned.v1": H(["bbr_apply"], true, "SSH_ORIGIN_WRITE", "FROZEN_BBR_PLAN", "OWNED_DROPIN_RECEIPT"),
  "origin.bbr_restore_owned.v1": H(["bbr_rollback"], true, "SSH_ORIGIN_WRITE", "EXACT_PLAN_SELECTED_CURRENT_BBR_STAGE_ID_FROM_FULL_OR_PROVEN_REMAINING_SUFFIX_PLUS_OWNED_DROPIN_AND_RECORDED_PRIOR_DIGESTS", "EXACT_STAGE_READBACK_PROJECTION_STAGES_ONE_TO_THREE_COMMIT_RECEIPT_BEFORE_NEXT_FINAL_STAGE_RECEIPT_AND_AGGREGATE_COMMIT_BOTH_OR_NEITHER"),
});

const B = (callers, consumesSecretRole, producesSecretRole, consumerTools, binding, result) => Object.freeze({
  callers: Object.freeze([...callers]),
  consumesSecretRole,
  producesSecretRole,
  plaintextResult: false,
  consumerTools: Object.freeze([...consumerTools]),
  binding,
  result,
});
const BROKER_OPERATIONS = Object.freeze({
  "xui.install_generate_store_admin_secret": B(["xui_install"], null, "xui-panel-admin", ["xui_inventory", "xui_create_inbound"], "EXACT_SAME_RUN_OWNED_INSTALL_REGISTERED_TARGET_AND_GENERATED_SECRET_POLICY", "SAME_RUN_PANEL_ADMIN_SECRET_REF"),
  "xui.inventory_existing_fixed.v1": B(["xui_inventory", "reconcile_status"], "xui-panel-admin", null, ["xui_inventory", "reconcile_status"], "IMPORTED_ONBOARDING_SECRET_REF_PLUS_REGISTERED_TARGET", "MASKED_XUI_INVENTORY_OR_BEFORE_AFTER_DIGEST_PROJECTION"),
  "xui.inventory_owned_fixed.v1": B(["xui_inventory", "reconcile_status"], "xui-panel-admin", null, ["xui_inventory", "reconcile_status"], "SAME_RUN_INSTALL_RECEIPT_AND_GENERATED_SECRET_REF", "MASKED_XUI_INVENTORY_OR_BEFORE_AFTER_DIGEST_PROJECTION"),
  "xui.inbound_create_generate_store_client.v1": B(["xui_create_inbound"], "xui-panel-admin", "xui-client-credential", ["xui_profile_publish"], "EXACT_PLAN_OPERATION_CURRENT_PANEL_FINGERPRINT_AND_GENERATED_UUIDV4_POLICY", "OWNED_INBOUND_RECEIPT_AND_CLIENT_SECRET_REF"),
  "xui.profile_publish_derive_store.v1": B(["xui_profile_publish"], "xui-client-credential", "client-profile-runtime", ["xui_profile_inspect", "traffic_verify"], "EXACT_INBOUND_AND_DOMAIN_BINDING", "PROFILE_REF_AND_RUNTIME_SECRET_REF"),
  "xui.profile_inspect_projection.v1": B(["xui_profile_inspect"], "client-profile-runtime", null, ["xui_profile_inspect"], "EXACT_PROFILE_REF_AND_NODE_BINDING_DIGEST_NON_SECRET_PROJECTION_ONLY", "NON_SECRET_EQUALITY_PROJECTION"),
  "xui.logs_counter_read_fixed.v1": B(["logs_correlate"], "xui-panel-admin", null, ["logs_correlate"], "EXACT_PROBE_WINDOW_AND_CURRENT_OWNED_INBOUND_COUNTER_ONLY", "BOUNDED_COUNTER_EVIDENCE"),
  "xui.reconcile_change_readback_fixed.v1": B(["reconcile_status"], "xui-panel-admin", null, ["reconcile_status"], "SERVER_SELECTED_UNKNOWN_XUI_INBOUND_OPERATION_CURRENT_PANEL_FINGERPRINT_AND_SAME_RUN_RECEIPT", "BEFORE_AFTER_DIGEST_PROJECTION"),
  "artifact.reconcile_owned_fixed.v1": B(["reconcile_status"], "client-profile-runtime", null, ["reconcile_status"], "SERVER_SELECTED_UNKNOWN_PROFILE_PUBLICATION_OPERATION_AND_SAME_RUN_ARTIFACT_RECEIPT", "BEFORE_AFTER_DIGEST_PROJECTION"),
  "artifact.revoke_same_run_runtime_secrets.v1": B(["rollback_run"], "client-profile-runtime", null, ["rollback_run"], "AFTER_ARTIFACT_IS_DELETED_OR_CHANGED_ARTIFACT_IS_RETAINED_WITH_RESIDUAL; NEVER_WAITS_FOR_LATER_INBOUND_INVERSE", "PROFILE_RUNTIME_SECRET_REVOCATION_RECEIPT_AND_UNERASABLE_COPY_RESIDUAL"),
  "xui.revoke_same_run_client_secret.v1": B(["rollback_run"], "xui-client-credential", null, ["rollback_run"], "ONLY_AFTER_PROFILE_ARTIFACT_DISPOSITION_AND_SAME_RUN_INBOUND_INVERSE_CURRENT_OWNERSHIP_MATCH", "CLIENT_SECRET_REVOCATION_RECEIPT"),
  "xui.revoke_same_run_panel_admin.v1": B(["rollback_run"], "xui-panel-admin", null, ["rollback_run"], "GENERATED_SAME_RUN_INSTALL_ONLY_AFTER_ALL_XUI_DEPENDENTS_REVERSED_IMPORTED_ADMIN_FORBIDDEN", "GENERATED_PANEL_ADMIN_REVOCATION_RECEIPT"),
  "certificate.revoke_same_run_private_key.v1": B(["rollback_run"], "origin-ca-private-key", null, ["rollback_run"], "IF_NO_CERTIFICATE_SLOT_RECEIPT_EVER_COMMITTED_OR_AFTER_SAME_RUN_CREATED_CERTIFICATE_SLOTS_DELETED_CURRENT_OWNERSHIP_MATCH", "PRIVATE_KEY_SECRET_REVOCATION_RECEIPT"),
  "artifact.render_0600": B(["xui_profile_publish", "traffic_verify"], "client-profile-runtime", null, ["xui_profile_publish", "traffic_verify"], "EXACT_CURRENT_PROFILE_AND_ALLOWLISTED_RUNTIME", "MODE_0600_ARTIFACT_REF_ONLY"),
  "client.authenticated_egress_probe_fixed.v1": B(["traffic_verify"], "client-profile-runtime", null, ["traffic_verify"], "EXACT_CURRENT_PROFILE_NODE_BINDING_AND_SAME_ALLOWLISTED_DESTINATION_AS_ORIGIN_EXPECTED_EGRESS_HELPER", "AUTHENTICATED_RESULT_AND_PROXY_EGRESS_EVIDENCE_REF_HMAC_DIGEST_NO_RAW_IP"),
  "protected_line.runtime_probe_fixed.v1": B(["old_line_verify", "bbr_verify"], "protected-line-runtime", null, ["old_line_verify", "bbr_verify"], "OPTIONAL_ONBOARDING_PROTECTED_LINE_RUNTIME_SECRET_REF_AND_REGISTERED_PROTECTED_LINE_REF_OR_SERVER_PROVEN_NOT_APPLICABLE", "EPHEMERAL_PROTECTED_LINE_PROBE_MATERIAL_TO_FIXED_HELPER_ONLY"),
  "cf.dns_read": B(["cloudflare_inventory", "cdn_verify", "reconcile_status"], "cf-audit", null, ["cloudflare_inventory", "cdn_verify", "reconcile_status"], "REGISTERED_ZONE_AND_DEDICATED_NODE_HOSTNAME_ONLY_NO_CALLER_ZONE_OR_HOSTNAME_SELECTOR", "MASKED_DNS_FACTS"),
  "cf.dns_create_owned": B(["cf_node_record_apply"], "cf-node-dns", null, ["cf_node_record_apply"], "EXACT_CURRENT_APPROVED_CREATE_OPERATION_REGISTERED_ZONE_DEDICATED_HOSTNAME_AND_CURRENT_ORIGIN_ADDRESS_DIGEST_NO_CALLER_RECORD_VALUE", "OWNED_RECORD_RECEIPT"),
  "cf.dns_proxy_owned": B(["cf_proxy_enable", "rollback_run"], "cf-node-dns", null, ["cf_proxy_enable", "rollback_run"], "SAME_RUN_OWNED_RECORD_RECEIPT_CURRENT_RECORD_DIGEST_AND_DEDICATED_HOSTNAME_NO_CALLER_RECORD_SELECTOR", "PROXY_RECEIPT"),
  "cf.dns_delete_owned": B(["rollback_run"], "cf-node-dns", null, ["rollback_run"], "SAME_RUN_CREATED_RECORD_RECEIPT_CURRENT_DIGEST_REGISTERED_HOSTNAME_AND_SERVER_FROZEN_INVERSE_ONLY", "OWNED_RECORD_DELETE_RECEIPT"),
  "cf.origin_ca_list_reconcile_fixed.v1": B(["reconcile_status"], "cf-origin-ca", null, ["reconcile_status"], "SERVER_SELECTED_UNKNOWN_ORIGIN_CA_CREATE_OPERATION_FULLY_PAGINATED_LIST_MATCH_BY_RUN_CSR_PUBLIC_KEY_FINGERPRINT_HOSTNAME_REQUEST_TYPE_VALIDITY_AND_REQUEST_WINDOW", "ZERO_ONE_OR_MULTIPLE_MATCH_PROJECTION_NO_RAW_CSR_OR_CERTIFICATE"),
  "cf.origin_ca_issue_store_private_key": B(["certificate_issue_origin_ca"], "cf-origin-ca", "origin-ca-private-key", ["certificate_deploy"], "LOCAL_RSA_2048_KEY_AND_CSR_ORIGIN_RSA_EXACT_NODE_HOSTNAME_ONLY_365_DAYS_NO_WILDCARD_CSR_ONLY_TO_CLOUDFLARE_KEY_MATERIAL_NEVER_TO_CF_OR_MCP", "FULLCHAIN_REF_LEAF_THEN_REQUIRED_ISSUER_CHAIN_PUBLIC_METADATA_AND_OPAQUE_INTERNAL_PRIVATE_KEY_ROLE"),
});

const reconciliationObserver = (originalTool, failureContext, observerKind, observer, secretRole, possibleObservations, resolutionRule = "BEFORE_MATCH_PROVES_NOT_COMMITTED_AFTER_MATCH_PROVES_COMMITTED_THIRD_OR_INCOMPLETE_IS_CONFLICT_OR_UNKNOWN", rollbackExecutorProof = null) => Object.freeze({
  originalTool,
  failureContext,
  originalOperationClass: originalTool === "bbr_apply" ? "BBR_APPLY" : originalTool === "bbr_rollback" ? "BBR_ROLLBACK_EXECUTOR" : originalTool === "rollback_run" ? "MAIN_ROLLBACK_EXECUTOR" : "MAIN_EXTERNAL_MUTATION",
  observerKind,
  observer: Object.freeze(Array.isArray(observer) ? [...observer] : [observer]),
  secretRole,
  binding: "SERVER_SELECTED_SOLE_UNKNOWN_LEDGER_OPERATION_REGISTERED_TARGET_OWNERSHIP_RECEIPT_AND_EXPECTED_BEFORE_AFTER_DIGESTS",
  digestProjection: "BEFORE_AND_AFTER_HMAC_OR_SHA256_DIGESTS_ONLY_NO_RAW_VALUE",
  possibleObservations: Object.freeze([...possibleObservations]),
  resolutionRule,
  rollbackExecutorProof,
});
const ALL_RECONCILIATION_OBSERVATIONS = NON_PREFIX_RECONCILIATION_OBSERVATIONS;
const MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_OBSERVATIONS = RECONCILIATION_OBSERVATIONS;
const MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF = Object.freeze({
  graphAuthority: "EXACT_CURRENT_FROZEN_ORDERED_MAIN_ROLLBACK_ATOMIC_STAGE_SELECTION_AND_IMMUTABLE_RUN_LEDGER",
  xuiObserverByImmutableProvenance: Object.freeze({
    provenanceSource: "RUN_BEGIN_IMPORT_BINDING_OR_SAME_RUN_XUI_INSTALL_OWNERSHIP_RECEIPT_AS_FROZEN_IN_THE_ROLLBACK_GRAPH",
    IMPORTED_CURRENT: "HOST_TOMBSTONE_READBACK_PLUS_IMMUTABLE_IMPORTED_ADMIN_RETAINED_NEVER_DELETE_DISPOSITION_RECEIPT",
    SAME_RUN_CURRENT: "HOST_TOMBSTONE_READBACK_PLUS_IMMUTABLE_GENERATED_ADMIN_DISPOSITION_RECEIPT",
    selectionCardinality: "EXACTLY_ONE_WHEN_AN_XUI_GRAPH_NODE_REQUIRES_READBACK",
    callerSelectable: false,
    livePanelAdminSecretRequired: false,
    missingAmbiguousOrMismatch: "CONCURRENT_THIRD_DIGEST",
  }),
  graphNodeReadback: Object.freeze({
    authorityByReverseGraphNode: Object.freeze({
      cloudflare_proxy: Object.freeze({ operations: Object.freeze(["cf.dns_read"]), authority: "BROKER_CF_AUDIT_FIXED", disposedRunSecretRequired: false }),
      cloudflare_record: Object.freeze({ operations: Object.freeze(["cf.dns_read"]), authority: "BROKER_CF_AUDIT_FIXED", disposedRunSecretRequired: false }),
      nginx_route: Object.freeze({ operations: Object.freeze(["origin.rollback_graph_readback_fixed.v1"]), authority: "SSH_ORIGIN_READ", disposedRunSecretRequired: false }),
      certificate_slot: Object.freeze({ operations: Object.freeze(["origin.rollback_graph_readback_fixed.v1"]), authority: "SSH_ORIGIN_READ", disposedRunSecretRequired: false }),
      certificate_issuance: Object.freeze({ operations: Object.freeze(["ledger.rollback_secret_disposition_receipts_fixed.v1"]), authority: "LOCAL_LEDGER_READ", disposedRunSecretRequired: false }),
      client_profile: Object.freeze({ operations: Object.freeze(["ledger.rollback_local_artifact_tombstone_fixed.v1", "ledger.rollback_secret_disposition_receipts_fixed.v1"]), authority: "LOCAL_FILESYSTEM_AND_LEDGER_READ", disposedRunSecretRequired: false }),
      xui_inbound: Object.freeze({ operations: Object.freeze(["origin.rollback_graph_readback_fixed.v1", "ledger.rollback_secret_disposition_receipts_fixed.v1"]), authority: "SSH_ORIGIN_AND_LEDGER_READ", disposedRunSecretRequired: false }),
      xui_install: Object.freeze({ operations: Object.freeze(["origin.rollback_graph_readback_fixed.v1", "ledger.rollback_secret_disposition_receipts_fixed.v1"]), authority: "SSH_ORIGIN_AND_LEDGER_READ", disposedRunSecretRequired: false }),
    }),
    coverage: "UNION_OF_AUTHORITY_BY_REVERSE_GRAPH_NODE_SET_EQUAL_TO_EVERY_NODE_IN_THE_EXACT_CURRENT_FROZEN_MAIN_ROLLBACK_GRAPH",
    rowFields: Object.freeze([
      "graph_node", "frozen_operation_ref", "inverse_receipt_ref",
      "expected_pre_inverse_digest", "expected_post_inverse_digest", "observed_current_digest",
      "ownership_receipt_match", "inverse_readback_match",
    ]),
    durablePerSubstep: true,
  }),
  atomicStageReadback: Object.freeze({
    orderedStageIds: MAIN_ROLLBACK_ATOMIC_STAGE_IDS,
    authorityByStageId: Object.freeze(Object.fromEntries(MAIN_ROLLBACK_ATOMIC_STAGES.map((stage) => [stage.stageId, Object.freeze({
      graphNode: stage.graphNode,
      observerOperations: stage.observerOperations,
      observerAuthority: stage.observerAuthority,
      disposedRunSecretRequired: false,
    })]))),
    coverage: "SET_EQUAL_TO_EVERY_STAGE_IN_THE_CURRENT_FROZEN_ORDERED_ATOMIC_STAGE_SELECTION",
    durableReceiptPerCompletedStage: true,
    activeStage: "EXACT_FIRST_REMAINING_STAGE_OR_NULL_BETWEEN_STAGE_DISPATCHES",
    completedPrefix: "EXACT_CONTIGUOUS_PREFIX_ONLY",
    remainingSuffix: "EXACT_ORDERED_SUFFIX_ONLY",
    completedStageReplay: false,
    finalizationTransaction: MAIN_ROLLBACK_FINALIZATION_TRANSACTION,
  }),
  secretDispositionReadback: Object.freeze({
    operation: "ledger.rollback_secret_disposition_receipts_fixed.v1",
    coverage: Object.freeze({
      client_profile_runtime: "PROFILE_RUNTIME_DISPOSITION_RECEIPT_REQUIRED_IFF_PROFILE_NODE_EXISTS; REVOKED_AFTER_DELETE_OR_REVOKED_AFTER_CHANGED_ARTIFACT_RESIDUAL",
      xui_client_credential: "CLIENT_SECRET_DISPOSITION_RECEIPT_REQUIRED_IFF_INBOUND_NODE_EXISTS; REVOKED_AFTER_EXACT_INBOUND_INVERSE",
      xui_panel_admin: "IMPORTED_PROVENANCE_REQUIRES_RETAINED_NEVER_DELETE_RECEIPT; SAME_RUN_PROVENANCE_REQUIRES_REVOKED_AFTER_DEPENDENTS_RECEIPT",
      origin_ca_private_key: "PRIVATE_KEY_DISPOSITION_RECEIPT_REQUIRED_IFF_ISSUANCE_NODE_EXISTS; REVOKED_WITH_NO_SLOT_COMMIT_OR_AFTER_EXACT_SLOT_DELETE",
    }),
    requiredStatusFields: Object.freeze([
      "profile_runtime_disposition_receipt_status",
      "xui_client_disposition_receipt_status",
      "xui_panel_admin_disposition_receipt_status",
      "origin_ca_private_key_disposition_receipt_status",
    ]),
    rawSecretBytesObserved: false,
  }),
  finalizationTransaction: MAIN_ROLLBACK_FINALIZATION_TRANSACTION,
  provenCommittedIff: "EVERY_FROZEN_ATOMIC_STAGE_HAS_ITS_EXACT_DURABLE_STAGE_RECEIPT_AND_CURRENT_POST_INVERSE_READBACK_AND_THE_FINAL_ATOMIC_STAGE_DURABLE_RECEIPT_AND_AGGREGATE_MAIN_ROLLBACK_RECEIPT_ARE_BOTH_VISIBLE_FROM_ONE_LOCAL_LEDGER_TRANSACTION_AND_THE_AGGREGATE_RECEIPT_SET_IS_COMPLETE_AND_EVERY_REQUIRED_SECRET_DISPOSITION_HAS_ITS_EXACT_PROVENANCE_BOUND_STATUS",
  provenNotCommittedIff: Object.freeze({
    atomicStages: "EVERY_FROZEN_ATOMIC_STAGE_MATCHES_ITS_EXACT_PRE_INVERSE_DIGEST_AND_OWNERSHIP_RECEIPT",
    stageReceipts: "ZERO_DURABLE_ATOMIC_STAGE_RECEIPTS",
    secretDispositions: "ALL_PROFILE_CLIENT_PANEL_AND_PRIVATE_KEY_DISPOSITIONS_MATCH_THEIR_EXACT_PRE_INVERSE_STATE",
    requestTerminated: true,
    authoritativeConsistencySettleFenceSatisfied: true,
    nextAction: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK",
  }),
  provenInversePrefixIff: Object.freeze({
    completedPrefix: "DURABLE_STAGE_RECEIPTS_AND_EXACT_POST_INVERSE_READBACK_COVER_ONE_NONEMPTY_CONTIGUOUS_PREFIX_OF_FROZEN_ATOMIC_STAGE_IDS",
    activeStage: "EXACT_FIRST_REMAINING_STAGE_OR_NULL_BETWEEN_STAGE_DISPATCHES",
    remainingSuffix: "EVERY_REMAINING_ATOMIC_STAGE_MATCHES_EXACT_PRE_INVERSE_DIGEST_AND_OWNERSHIP",
    secretDispositions: "EVERY_SECRET_DISPOSITION_STATUS_MATCHES_THE_EXACT_COMPLETED_ATOMIC_STAGE_BOUNDARY",
    thirdDigest: false,
    requestTerminated: true,
    authoritativeConsistencySettleFenceSatisfied: true,
    nextAction: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK_REMAINING_SUFFIX",
    completedInverseReplay: false,
  }),
  otherwiseByEvidence: Object.freeze({
    missingOrIncompleteReadbackOrReceipt: "STILL_UNKNOWN",
    foreignOwnershipOrUnexpectedCurrentDigestOrProvenanceMismatch: "CONCURRENT_THIRD_DIGEST",
  }),
});
const MAIN_ROLLBACK_COMMITTED_PROOF_SCHEMA = closed({
  frozen_graph_digest: S.Digest,
  final_atomic_stage_id: enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS),
  final_atomic_stage_receipt_ref: S.ReceiptRef,
  aggregate_rollback_receipt_ref: S.ReceiptRef,
  final_atomic_stage_exact_post_inverse_readback: constOf(true),
  final_stage_and_aggregate_receipt_same_local_ledger_transaction: constOf(true),
  finalization_receipts_both_visible: constOf(true),
  aggregate_receipt_binds_exact_selected_atomic_stage_receipts: constOf(true),
  finalization_transaction_commit_digest: S.Digest,
});
const MAIN_ROLLBACK_NOT_COMMITTED_PROOF_SCHEMA = closed({
  frozen_graph_digest: S.Digest,
  frozen_atomic_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
  every_atomic_stage_matches_exact_pre_inverse_digest_and_ownership: constOf(true),
  durable_atomic_stage_receipt_count: Object.freeze({ type: "integer", const: 0 }),
  durable_atomic_stage_receipt_refs: arr(S.ReceiptRef, 0, 0),
  all_secret_dispositions_match_exact_pre_inverse_state: constOf(true),
  rollback_request_terminated: constOf(true),
  authoritative_consistency_settle_fence_satisfied: constOf(true),
  proof_binding_digest: S.Digest,
});
const MAIN_ROLLBACK_INVERSE_PREFIX_PROOF_SCHEMA = closed({
  frozen_graph_digest: S.Digest,
  frozen_atomic_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 2, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
  completed_prefix_length: int(1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length - 1),
  completed_prefix_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length - 1), uniqueItems: true }),
  completed_prefix_stage_receipt_refs: arr(S.ReceiptRef, 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length - 1),
  active_stage_id: nullable(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS)),
  remaining_suffix_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length - 1), uniqueItems: true }),
  completed_prefix_receipt_and_stage_cardinality_equal: constOf(true),
  prefix_active_suffix_exact_ordered_partition: constOf(true),
  completed_prefix_exact_post_inverse_readback: constOf(true),
  active_and_remaining_suffix_exact_pre_inverse_readback: constOf(true),
  secret_dispositions_consistent_with_atomic_stage_boundary: constOf(true),
  no_third_digest_or_foreign_ownership: constOf(true),
  rollback_request_terminated: constOf(true),
  authoritative_consistency_settle_fence_satisfied: constOf(true),
  remaining_suffix_binding_digest: S.Digest,
});
const BBR_ROLLBACK_STAGE_PREFIX_PROOF_SCHEMA = closed({
  exact_change_ref: S.ChangeRef,
  frozen_stage_ids: Object.freeze({ ...arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), BBR_ROLLBACK_ATOMIC_STAGE_IDS.length, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
  completed_stage_count: int(1, 3),
  completed_stage_ids: Object.freeze({ ...arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 1, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length - 1), uniqueItems: true }),
  completed_stage_receipt_refs: arr(S.ReceiptRef, 1, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length - 1),
  remaining_suffix_stage_ids: Object.freeze({ ...arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 1, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length - 1), uniqueItems: true }),
  exact_ordered_prefix_suffix_partition_and_cardinality_match: constOf(true),
  completed_stage_receipts_are_exact_bbr_rollback_stage_receipt_family: constOf(true),
  each_completed_stage_receipt_committed_after_exact_readback_before_next_stage: constOf(true),
  remaining_stage_current_values_match_expected_pre_stage: constOf(true),
  no_third_digest_or_foreign_ownership: constOf(true),
  rollback_request_terminated: constOf(true),
  authoritative_consistency_settle_fence_satisfied: constOf(true),
  remaining_stage_suffix_binding_digest: S.Digest,
});
const BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF = Object.freeze({
  orderedStages: BBR_ROLLBACK_ATOMIC_STAGES,
  orderedStageIds: BBR_ROLLBACK_ATOMIC_STAGE_IDS,
  stageReceiptProducer: "bbr_rollback",
  stageReceiptFamily: "BBR_ROLLBACK_STAGE_RECEIPT",
  aggregateReceiptFamily: "BBR_ROLLBACK_RECEIPT",
  finalizationTransaction: BBR_ROLLBACK_FINALIZATION_TRANSACTION,
  observers: Object.freeze(["origin.bbr_inventory_fixed.v1", "ledger.bbr_rollback_stage_receipts_fixed.v1"]),
  observerReceiptFamily: "EXACT_SAME_BBR_ROLLBACK_STAGE_RECEIPT_FAMILY_PRODUCED_BY_BBR_ROLLBACK",
  provenCommittedIff: "FINAL_STAGE_RECEIPT_AND_AGGREGATE_BOTH_VISIBLE_FROM_BBR_ROLLBACK_FINALIZATION_TRANSACTION_PLUS_ALL_FOUR_EXACT_ORDERED_STAGE_RECEIPTS_AND_FINAL_EXACT_PRIOR_LIVE_AND_PERSISTENT_READBACK",
  provenNotCommittedIff: "ZERO_EXACT_BBR_STAGE_RECEIPTS_AND_EXACT_PRE_INVERSE_DROPIN_LIVE_AND_PERSISTENT_STATE_WITH_TERMINATION_AND_SETTLE_FENCE",
  provenInversePrefixIff: "ONE_TO_THREE_EXACT_DURABLE_ORDERED_PREFIX_STAGE_RECEIPTS_CURRENT_STATE_MATCHES_PREFIX_AND_REMAINING_PRE_STAGE_VALUES_NO_THIRD_DIGEST",
  prefixNextAction: "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK_REMAINING_STAGE_SUFFIX",
  fourStageReceiptsWithoutAggregateRepresentable: false,
  completedStageReplay: false,
});
const ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA = closed({
  source_checkpoint_tool: enumOf(...ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.refreshTools),
  checkpoint_observation_ref: S.EvidenceRef,
  prior_committed_change_count: int(0, 64),
  current_owned_graph_digest: nullable(S.Digest),
  no_open_operation: constOf(true),
  fixed_observer_set_complete: constOf(true),
  current_ownership_safe: bool,
  no_third_digest: bool,
  proof_binding_digest: S.Digest,
});
const ACTIVE_CHECKPOINT_ZERO_COMMIT_PROOF_SCHEMA = Object.freeze({
  ...ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA,
  properties: Object.freeze({
    ...ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA.properties,
    prior_committed_change_count: { type: "integer", const: 0 },
    current_owned_graph_digest: { type: "null" },
    current_ownership_safe: { const: true },
    no_third_digest: { const: true },
  }),
});
const ACTIVE_CHECKPOINT_OWNED_GRAPH_PROOF_SCHEMA = Object.freeze({
  ...ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA,
  properties: Object.freeze({
    ...ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA.properties,
    prior_committed_change_count: int(1, 64),
    current_owned_graph_digest: S.Digest,
    current_ownership_safe: { const: true },
    no_third_digest: { const: true },
  }),
});
const RECONCILIATION_OBSERVER_BY_TOOL = Object.freeze({
  xui_install: reconciliationObserver("xui_install", "MAIN_EXTERNAL_MUTATION", "helper", "origin.reconcile_xui_install_readback.v1", "xui-panel-admin", ALL_RECONCILIATION_OBSERVATIONS),
  xui_create_inbound: reconciliationObserver("xui_create_inbound", "MAIN_EXTERNAL_MUTATION", "broker", "xui.reconcile_change_readback_fixed.v1", "xui-panel-admin", ALL_RECONCILIATION_OBSERVATIONS),
  xui_profile_publish: reconciliationObserver("xui_profile_publish", "MAIN_EXTERNAL_MUTATION", "broker", "artifact.reconcile_owned_fixed.v1", "client-profile-runtime", ALL_RECONCILIATION_OBSERVATIONS),
  certificate_issue_origin_ca: reconciliationObserver("certificate_issue_origin_ca", "MAIN_EXTERNAL_MUTATION", "broker", "cf.origin_ca_list_reconcile_fixed.v1", "cf-origin-ca", ALL_RECONCILIATION_OBSERVATIONS, "FULLY_PAGINATED_LIST_ONE_EXACT_RUN_CSR_PUBLIC_KEY_FINGERPRINT_HOSTNAME_REQUEST_TYPE_VALIDITY_AND_REQUEST_WINDOW_MATCH_PROVES_COMMITTED_AND_PERSISTS_CERTIFICATE_ID; ZERO_MATCH_IS_PROVEN_NOT_COMMITTED_ONLY_WITH_FROZEN_REQUEST_TERMINATION_PLUS_AUTHORITATIVE_CONSISTENCY_SETTLE_FENCE_OTHERWISE_STILL_UNKNOWN; MULTIPLE_MATCH_OR_INCOMPLETE_PAGINATION_IS_CONCURRENT_OR_UNKNOWN; RAW_CSR_CERTIFICATE_NEVER_MCP"),
  certificate_deploy: reconciliationObserver("certificate_deploy", "MAIN_EXTERNAL_MUTATION", "helper", "origin.reconcile_certificate_slot_readback.v1", "origin-ca-private-key", ALL_RECONCILIATION_OBSERVATIONS),
  nginx_route_apply: reconciliationObserver("nginx_route_apply", "MAIN_EXTERNAL_MUTATION", "helper", "origin.reconcile_nginx_include_readback.v1", null, ALL_RECONCILIATION_OBSERVATIONS),
  cf_node_record_apply: reconciliationObserver("cf_node_record_apply", "MAIN_EXTERNAL_MUTATION", "broker", "cf.dns_read", "cf-audit", ALL_RECONCILIATION_OBSERVATIONS),
  cf_proxy_enable: reconciliationObserver("cf_proxy_enable", "MAIN_EXTERNAL_MUTATION", "broker", "cf.dns_read", "cf-audit", ALL_RECONCILIATION_OBSERVATIONS),
  bbr_apply: reconciliationObserver("bbr_apply", "BBR_EXTERNAL_MUTATION", "helper", "origin.bbr_inventory_fixed.v1", null, ALL_RECONCILIATION_OBSERVATIONS),
  rollback_run: reconciliationObserver(
    "rollback_run",
    "MAIN_ROLLBACK_EXECUTOR",
    "provenance_bound_composite",
    [
      "origin.rollback_graph_readback_fixed.v1",
      "ledger.rollback_local_artifact_tombstone_fixed.v1",
      "cf.dns_read",
      "ledger.rollback_secret_disposition_receipts_fixed.v1",
    ],
    null,
    MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_OBSERVATIONS,
    "PROVEN_COMMITTED_ONLY_IFF_ALL_POST_INVERSE_PROOF_IS_TRUE; PROVEN_NOT_COMMITTED_ONLY_IFF_ALL_PRE_INVERSE_ZERO_RECEIPT_TERMINATION_AND_SETTLE_FENCE_PROOF_IS_TRUE; PROVEN_INVERSE_PREFIX_ONLY_IFF_EXACT_CONTIGUOUS_DURABLE_PREFIX_POST_READBACK_AND_REMAINING_SUFFIX_PRE_READBACK_WITH_MATCHING_SECRET_DISPOSITIONS_AND_NO_THIRD_DIGEST; INCOMPLETE_IS_STILL_UNKNOWN; THIRD_DIGEST_OWNERSHIP_OR_PROVENANCE_MISMATCH_IS_CONCURRENT_THIRD_DIGEST",
    MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF,
  ),
  bbr_rollback: reconciliationObserver(
    "bbr_rollback",
    "BBR_ROLLBACK_EXECUTOR",
    "staged_helper_composite",
    ["origin.bbr_inventory_fixed.v1", "ledger.bbr_rollback_stage_receipts_fixed.v1"],
    null,
    RECONCILIATION_OBSERVATIONS,
    "PROVEN_INVERSE_PREFIX_ONLY_IFF_DURABLE_ORDERED_STAGE_PREFIX_MATCHES_CURRENT_STATE_AND_REMAINING_PRE_STAGE_VALUES_WITH_NO_THIRD_DIGEST; COMPLETED_STAGE_NEVER_REPLAYS",
    BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF,
  ),
});

const XUI_INSTALL_POLICY = Object.freeze({
  eligibility: "XUI_ABSENT_AND_CLEAN_HOST_EXACTLY",
  forbiddenObservedStates: Object.freeze(["COMPATIBLE_EXISTING", "INCOMPATIBLE_EXISTING", "AMBIGUOUS", "DRIFTED_OWNED_INSTALL"]),
  requiredLease: "NODE_INSTALL_P3",
  adapter: "BUILD_TIME_ALLOWLISTED_DIGEST_PINNED_VERSIONED_ADAPTER",
  helperOperation: "origin.xui_install_owned.v1",
  brokerOperation: "xui.install_generate_store_admin_secret",
  generatedSecretPolicy: GENERATED_SECRET_POLICY,
  callerForbiddenFields: Object.freeze(["command", "argv", "script", "url", "path", "username", "password", "port", "panel_secret", "credential", "payload", "source", "installer_bytes"]),
  ownershipCommit: "IMMUTABLE_RECEIPT_BEFORE_DEPENDENT_MUTATION",
  readback: "SERVICE_FILES_DATABASE_USER_VERSION_AND_LOOPBACK_BINDING",
  inverse: "OWNED_ONLY_AFTER_DEPENDENTS_REVERSED_AND_CURRENT_DIGESTS_EQUAL_RECEIPT",
  existingInstallAction: "FAIL_CLOSED_NO_UPGRADE_REINSTALL_OR_REMOVE",
  subplanChain: Object.freeze({
    leaseClass: "NODE_INSTALL_P3",
    exactMutators: Object.freeze(["xui_install"]),
    whileCursorOpenTo: "APPLYING",
    cursorCompleteEnables: "GATED_REPLAN_FROM_APPLYING",
    nextLeaseClass: "NODE_P2",
    leaseInheritance: false,
    nextPlanRequires: Object.freeze(["NO_OPEN_OPERATION", "ALL_COMMITS_KNOWN", "FRESH_REQUIRED_INVENTORIES", "GLOBAL_FORWARD_ELIGIBILITY_REEVALUATED", "FRESH_PROTECTED_LINE_BOUND_TO_COMPLETED_PREREQUISITE_RECEIPTS", "NO_ROLLBACK_OR_MANUAL_OBLIGATION"]),
  }),
});

const DOMAIN_IDENTITY_BINDING_POLICY = Object.freeze({
  hostnameAuthority: "ONBOARDING_REGISTERED_DEDICATED_NODE_HOSTNAME_REF",
  panelHostnameReuse: "FORBIDDEN",
  cloudflareRecordName: "NODE_HOSTNAME",
  certificateSan: "NODE_HOSTNAME",
  nginxServerName: "NODE_HOSTNAME",
  profileAddress: "NODE_HOSTNAME",
  profileSni: "NODE_HOSTNAME",
  profileWebsocketHost: "NODE_HOSTNAME",
  websocketPath: WEBSOCKET_PATH_POLICY,
  xrayBind: "LOOPBACK_ONLY_REGISTERED_PORT_REF",
  xrayTls: "NONE",
  originTlsOwner: "NGINX_STABLE_SERVICE_SLOT",
  proxyOrder: "RECORD_CREATE_UNPROXIED_THEN_DIRECT_ORIGIN_PROOF_THEN_PROXY_ENABLE",
  equalityFields: Object.freeze(["cloudflare_record", "certificate_san", "nginx_server_name", "profile_address", "profile_sni", "profile_websocket_host"]),
});

const NO_CLOBBER_POLICY = Object.freeze({
  createOnlyResources: Object.freeze(["cloudflare_record", "xui_inbound", "stable_service_slot", "nginx_include", "sysctl_dropin", "client_artifact"]),
  successBeforeDigest: "NULL_FOR_EVERY_NEW_RESOURCE",
  requiredObservation: "ABSENT_AND_UNAMBIGUOUS",
  receipt: "SAME_RUN_CREATED_RESOURCE_RECEIPT_BOUND_TO_CURRENT_DIGEST",
  precondition: "EXPECTED_BEFORE_DIGEST_AND_OWNERSHIP_MATCH",
  concurrentThirdDigest: "FAIL_TO_MANUAL_WITHOUT_WRITE",
  pathAuthority: "SERVER_INTERNAL_RUNTIME_REFS_ONLY",
  filesystemOpen: "DESCRIPTOR_RELATIVE_NOFOLLOW_EXCLUSIVE_CREATE_AND_READBACK",
});
const CORE_ROLLBACK_POLICY = Object.freeze({
  planSource: "SERVER_FROZEN_SAME_RUN_CHANGE_GRAPH",
  callerSelectableRows: false,
  order: PLAN_OPERATION_RESOLVER.scopes.MAIN_ROLLBACK.reverseGraphOrder,
  atomicStages: MAIN_ROLLBACK_ATOMIC_STAGES,
  atomicStageOrder: MAIN_ROLLBACK_ATOMIC_STAGE_IDS,
  finalizationTransaction: MAIN_ROLLBACK_FINALIZATION_TRANSACTION,
  planSelection: "FULL_FROZEN_ATOMIC_STAGE_SELECTION_OR_EXACT_REMAINING_CONTIGUOUS_SUFFIX_AFTER_PROVEN_PREFIX",
  mutationCoverage: Object.freeze({
    xui_install: "xui_install",
    xui_create_inbound: "xui_inbound",
    xui_profile_publish: "client_profile",
    certificate_issue_origin_ca: "certificate_issuance",
    certificate_deploy: "certificate_slot",
    nginx_route_apply: "nginx_route",
    cf_node_record_apply: "cloudflare_record",
    cf_proxy_enable: "cloudflare_proxy",
  }),
  operationByNode: Object.freeze({
    cloudflare_proxy: Object.freeze({ executor: "rollback_run", operation: "cf.dns_proxy_owned", action: "DISABLE_ONLY_SAME_RUN_OWNED_CURRENT_RECORD_PROXY_FLAG" }),
    cloudflare_record: Object.freeze({ executor: "rollback_run", operation: "cf.dns_delete_owned", action: "DELETE_ONLY_SAME_RUN_CREATED_CURRENT_RECORD" }),
    nginx_route: Object.freeze({ executor: "rollback_run", operation: "origin.nginx_route_delete_owned.v1", action: "DELETE_SAME_RUN_CREATED_INCLUDE_AND_RELOAD" }),
    certificate_slot: Object.freeze({ executor: "rollback_run", operation: "origin.certificate_delete_owned.v1", action: "DELETE_SAME_RUN_CREATED_SERVICE_SLOT_COPIES_ONLY_AFTER_ROUTE_INVERSE" }),
    certificate_issuance: Object.freeze({ executor: "rollback_run", operation: "certificate.revoke_same_run_private_key.v1", action: "DELETE_SAME_RUN_BROKER_PRIVATE_KEY_AFTER_SLOT_NODE_INVERSED_OR_IF_NO_SLOT_RECEIPT_EVER_COMMITTED; NO_REMOTE_CERTIFICATE_REVOKE; RETAIN_PUBLIC_CERTIFICATE_METADATA_AS_IRREVERSIBLE_COMPENSATION_RESIDUAL" }),
    client_profile: Object.freeze({ executor: "rollback_run", operation: "origin.artifact_remove_owned_unchanged.v1+artifact.revoke_same_run_runtime_secrets.v1", action: "DELETE_ONLY_UNCHANGED_SAME_RUN_ARTIFACT_AND_REVOKE_SAME_RUN_RUNTIME_SECRET_PERSIST_UNERASABLE_COPY_RESIDUAL" }),
    xui_inbound: Object.freeze({ executor: "rollback_run", operation: "origin.xui_inbound_remove_owned.v1+xui.revoke_same_run_client_secret.v1", action: "REMOVE_SAME_RUN_INBOUND_THEN_REVOKE_SAME_RUN_CLIENT_SECRET" }),
    xui_install: Object.freeze({ executor: "rollback_run", operation: "origin.xui_uninstall_owned.v1+xui.revoke_same_run_panel_admin.v1", action: "UNINSTALL_SAME_RUN_ONLY_THEN_REVOKE_GENERATED_ADMIN_IMPORTED_ADMIN_FORBIDDEN" }),
  }),
  installInverseLast: true,
  ownershipRequired: true,
  currentDigestRequired: true,
  thirdPartyDrift: "MANUAL_ACTION_REQUIRED_NO_OVERWRITE",
  previousServiceReverify: "SEPARATE_OLD_LINE_VERIFY_AFTER_ROLLED_BACK_RECEIPT_NEVER_INSIDE_OR_REEXECUTES_INVERSE",
  issuanceCompensation: "NO_AUTOMATIC_ORIGIN_CA_REVOCATION_DELETE_SAME_RUN_BROKER_PRIVATE_KEY_WHEN_NO_CURRENT_SLOT_RECEIPT_OR_SLOT_NODE_ALREADY_INVERSED_RETAIN_PUBLIC_METADATA_AND_REPORT_RESIDUAL",
  unknownCommit: "RECONCILE_BEFORE_RETRY",
  secretDisposition: Object.freeze({
    generatedSameRun: "DELETE_OR_REVOKE_ONLY_AFTER_DEPENDENT_INVERSES_SUCCEED_AND_OWNERSHIP_RECEIPTS_MATCH",
    importedOrPreExisting: "NEVER_DELETE_OR_REVOKE",
    openRecovery: "RETAIN_ONLY_WHILE_REQUIRED_BY_OPEN_ROLLBACK_MANUAL_OR_RECONCILE_PATH",
  }),
});
const AUTHENTICATED_E2E_POLICY = Object.freeze({
  acceptedLabel: "end_to_end_verified",
  requiredEvidence: Object.freeze(["DIRECT_ORIGIN_TLS_WEBSOCKET", "CLOUDFLARE_TLS_WEBSOCKET", "CLIENT_FIELD_BINDING_EQUALITY", "AUTHENTICATED_PROXY_REQUEST", "EXPECTED_PUBLIC_EGRESS", "NGINX_XRAY_LOG_CORRELATION", "PROTECTED_PRIOR_LINE_HEALTHY_OR_PROVEN_NA"]),
  insufficientSignals: Object.freeze(["LATENCY_ONLY", "OPEN_PORT_ONLY", "CERTIFICATE_ONLY", "TLS_ONLY", "HTTP_101_ONLY", "STATIC_PROFILE_ONLY"]),
  closureGate: "SEALED_REPORT_ALL_REQUIREMENTS_TRUE_AND_LIVE_HOST_PROMPT_SERVER_ACKNOWLEDGEMENT",
  bbrResolutionBeforeMainSeal: Object.freeze({
    allowed: Object.freeze(["BBR_CLOSED_NOT_REQUESTED_RECEIPT", "BBR_CLOSED_VERIFIED_RECEIPT", "BBR_CLOSED_ROLLED_BACK_RECEIPT", "BBR_CLOSED_NO_WRITE_RECEIPT"]),
    afterApplyRequires: Object.freeze(["AUTHENTICATED_PROXY_REQUEST", "EXPECTED_PUBLIC_EGRESS", "NGINX_XRAY_LOG_CORRELATION", "PROTECTED_PRIOR_LINE_HEALTHY_OR_PROVEN_NA"]),
  }),
});
const BBR_ROLLBACK_MAIN_GATE = Object.freeze({
  requiredMainPhase: "OLD_LINE_REVERIFIED",
  nodeTemplateCursorComplete: true,
  completionReportSealed: false,
  mainClosed: false,
  appliesTo: Object.freeze(["plan_compile:BBR_ROLLBACK", "plan_authorize:BBR_ROLLBACK", "bbr_rollback"]),
  mismatch: "WRONG_STATE_NO_PLAN_NO_AUTHORIZATION_NO_INVERSE",
  postDeliveryBbrChangeSupported: false,
});
const RECONCILED_BBR_APPLY_CHANGE_RECEIPT_SCHEMA = closed({
  reconciled_bbr_apply_receipt_ref: S.ReceiptRef,
  reconciled_bbr_change_ref: S.ChangeRef,
  original_operation_ref: S.OperationRef,
  planned_owned_dropin_ref: S.RuntimeRef,
  planned_before_digest: { type: "null" },
  planned_descriptor_relative_nofollow: constOf(true),
  planned_exclusive_create: constOf(true),
  expected_owned_dropin_digest: S.Digest,
  current_owned_dropin_digest: S.Digest,
  recorded_prior_live_values_digest: S.Digest,
  recorded_prior_persistent_values_digest: S.Digest,
  reconciliation_evidence_ref: S.EvidenceRef,
  receipt_binding_digest: S.Digest,
});
const RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY = Object.freeze({
  producer: "reconcile_status",
  trigger: Object.freeze({
    originalTool: "bbr_apply",
    originalOperationClass: "BBR_APPLY",
    observation: "PROVEN_COMMITTED",
    observedDigestRelation: "matches_after",
  }),
  authority: "SINGLE_LOCAL_LEDGER_TRANSACTION_AFTER_FIXED_ORIGIN_BBR_READBACK",
  receiptSchema: RECONCILED_BBR_APPLY_CHANGE_RECEIPT_SCHEMA,
  atomicLedgerTransaction: Object.freeze({
    commitsTogether: Object.freeze(["RECONCILIATION_EVIDENCE", "RECONCILED_BBR_APPLY_RECEIPT", "RECONCILED_BBR_CHANGE_RECEIPT", "CURRENT_FRESH_RECONCILIATION_SOURCE_OBLIGATION_EPISODE"]),
    atomicity: "ALL_OR_NONE",
    destination: "BBR_MANUAL_ACTION_REQUIRED",
  }),
  receiptBinding: Object.freeze({
    originalOperationRef: "EXACT_SERVER_SELECTED_RECONCILIATION_OPERATION_REF",
    plannedOwnedDropinRuntimeRef: "EXACT_IMMUTABLE_PLAN_BOUND_OPAQUE_OWNED_DROPIN_REF",
    plannedBeforeDigest: null,
    plannedDescriptorRelativeNofollow: true,
    plannedExclusiveCreate: true,
    expectedOwnedDropinDigest: "EXACT_IMMUTABLE_PLAN_EXPECTED_DROPIN_DIGEST",
    currentOwnedDropinDigest: "EXACT_FIXED_READBACK_CURRENT_DROPIN_DIGEST_MATCHING_EXPECTED",
    recordedPriorLiveValuesDigest: "EXACT_IMMUTABLE_PRE_DISPATCH_PRIOR_LIVE_VALUES_DIGEST",
    recordedPriorPersistentValuesDigest: "EXACT_IMMUTABLE_PRE_DISPATCH_PRIOR_PERSISTENT_VALUES_DIGEST",
    reconciliationEvidenceRef: "EXACT_CURRENT_RECONCILIATION_EVIDENCE_REF",
  }),
  outputProjection: Object.freeze({
    reconciledBbrApplyReceiptRef: "OPAQUE_RECEIPT_REF",
    reconciledBbrChangeRef: "OPAQUE_CHANGE_REF",
    rawPathValuesOrDigestsInMcp: false,
  }),
  durableTtl: "NO_TTL",
  normalBbrApplyReceiptRequired: false,
  callerSelectable: false,
});
const BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY = Object.freeze({
  exactKindIds: Object.freeze(["NORMAL_COMMITTED_APPLY", "RECONCILED_APPLY_CHANGE"]),
  rows: Object.freeze({
    NORMAL_COMMITTED_APPLY: Object.freeze({
      authority: "DURABLE_SUCCESSFUL_BBR_APPLY_RECEIPT_AND_CHANGE_REF",
      receiptType: "BBR_APPLY_RECEIPT",
      changeRefRequired: true,
      eligibleSource: "COMMITTED_BBR_APPLY_TOOL_RESULT",
    }),
    RECONCILED_APPLY_CHANGE: Object.freeze({
      authority: "RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY_ATOMIC_LEDGER_RESULT",
      receiptType: "RECONCILED_BBR_APPLY_CHANGE_RECEIPT",
      changeRefRequired: true,
      eligibleSource: "BBR_APPLY_PROVEN_COMMITTED_RECONCILIATION",
    }),
  }),
  resolution: Object.freeze({
    authority: "SERVER_DERIVED_FROM_CURRENT_BBR_SOURCE_OBLIGATION_EPISODE_ONLY",
    exactCurrentBindingCount: 1,
    normalAndReconciledBothPresent: "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION",
    neitherPresent: "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION",
    staleConsumedOrSupersededBindingAccepted: false,
    callerSelectableKindOrRef: false,
  }),
  bindingFields: Object.freeze(["BASELINE_KIND", "OPAQUE_APPLY_RECEIPT_REF", "OPAQUE_CHANGE_REF", "BASELINE_BINDING_DIGEST", "CURRENT_OWNED_DROPIN_DIGEST"]),
  commonPredicate: "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING",
  zeroStageInheritance: Object.freeze({
    source: "EXACT_CONSUMED_PRIOR_BBR_ROLLBACK_SOURCE_EPISODE",
    inheritedFields: Object.freeze(["BASELINE_KIND", "OPAQUE_APPLY_RECEIPT_REF", "OPAQUE_CHANGE_REF", "BASELINE_BINDING_DIGEST"]),
    bindsNewZeroStageEpisodeAtomically: true,
    callerOverride: false,
  }),
});
const BBR_ROLLBACK_AUTHORIZATION_SOURCE_ROW_IDS = Object.freeze([
  "EXPLICIT_COMMITTED_APPLY",
  "CONCLUSIVE_VERIFY_FALSE",
  "FRESH_RECONCILIATION_OUTCOME",
  "BBR_ZERO_STAGE_BEFORE_DISPATCH",
]);
const BBR_ROLLBACK_RECONCILIATION_SOURCE_OUTCOMES = Object.freeze({
  BBR_APPLY_PROVEN_COMMITTED: Object.freeze({
    originalTool: "bbr_apply",
    observation: "PROVEN_COMMITTED",
    planSelection: "FULL_BBR_ROLLBACK_TEMPLATE",
    requires: Object.freeze(["FRESH_CONTEXT_BOUND_RECONCILIATION_EVIDENCE", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_RECONCILED_APPLY_CHANGE", "CURRENT_OWNED_DROPIN_DIGEST_MATCH", "NO_UNKNOWN_COMMIT"]),
  }),
  BBR_ROLLBACK_EXECUTOR_PROVEN_NOT_COMMITTED: Object.freeze({
    originalTool: "bbr_rollback",
    observation: "PROVEN_NOT_COMMITTED",
    planSelection: "FULL_BBR_ROLLBACK_TEMPLATE",
    requires: Object.freeze(["FRESH_CONTEXT_BOUND_RECONCILIATION_EVIDENCE", "STRICT_ALL_STAGE_PRE_INVERSE_ZERO_RECEIPT_PROOF", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_AND_REFS_INHERITED_FROM_CURRENT_SOURCE_EPISODE", "CURRENT_OWNED_DROPIN_DIGEST_MATCH", "NO_UNKNOWN_COMMIT"]),
  }),
  BBR_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX: Object.freeze({
    originalTool: "bbr_rollback",
    observation: "PROVEN_INVERSE_PREFIX",
    planSelection: "EXACT_REMAINING_ORDERED_STAGE_SUFFIX",
    requires: Object.freeze(["FRESH_CONTEXT_BOUND_RECONCILIATION_EVIDENCE", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_AND_REFS_INHERITED_FROM_CURRENT_SOURCE_EPISODE", "EXACT_NONEMPTY_PROVEN_COMPLETED_STAGE_PREFIX", "CURRENT_STATE_MATCHES_COMPLETED_STAGE_PREFIX", "EXACT_PRE_INVERSE_REMAINING_STAGE_SUFFIX", "COMPLETED_STAGE_REPLAY_FORBIDDEN", "NO_UNKNOWN_COMMIT"]),
  }),
});
const bbrRollbackAuthorizationSourceRow = ({
  compileAllowedOrigins, durableCause, requiredEvidence,
  reconciliationEvidenceRequired, reconciliationOutcomes, planSelection,
  zeroStageLeaseExpiryResolverRow = null,
}) => Object.freeze({
  compileAllowedOrigins: Object.freeze([...compileAllowedOrigins]),
  durableCause,
  requiredEvidence: Object.freeze([...requiredEvidence]),
  reconciliationEvidenceRequired,
  reconciliationOutcomes: Object.freeze({ ...reconciliationOutcomes }),
  planSelection,
  zeroStageLeaseExpiryResolverRow,
  compileDestination: "BBR_MANUAL_ACTION_REQUIRED",
  authorizeAllowedOrigin: "BBR_MANUAL_ACTION_REQUIRED",
  authorizeDestination: "BBR_ROLLING_BACK",
  immutablePlanBindingField: "bbr_rollback_authorization_source_row_id",
  baselineReceiptBindingPolicy: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
  mainRollbackAdmissionReceiptAllowed: false,
  callerSelectable: false,
});
const BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET = Object.freeze({
  exactRowIds: BBR_ROLLBACK_AUTHORIZATION_SOURCE_ROW_IDS,
  rows: Object.freeze({
    EXPLICIT_COMMITTED_APPLY: bbrRollbackAuthorizationSourceRow({
      compileAllowedOrigins: ["BBR_APPLIED", "BBR_VERIFIED"],
      durableCause: "EXPLICIT_ROLLBACK_REQUEST",
      requiredEvidence: ["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_NORMAL_COMMITTED_APPLY", "CURRENT_OWNED_DROPIN_DIGEST_MATCH", "NO_UNKNOWN_COMMIT"],
      reconciliationEvidenceRequired: false,
      reconciliationOutcomes: {},
      planSelection: "FULL_BBR_ROLLBACK_TEMPLATE",
    }),
    CONCLUSIVE_VERIFY_FALSE: bbrRollbackAuthorizationSourceRow({
      compileAllowedOrigins: ["BBR_MANUAL_ACTION_REQUIRED"],
      durableCause: "CONCLUSIVE_BBR_VERIFY_FALSE",
      requiredEvidence: ["DURABLE_CONCLUSIVE_BBR_VERIFY_FALSE_CAUSE", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_NORMAL_COMMITTED_APPLY", "CURRENT_OWNED_DROPIN_DIGEST_MATCH", "NO_UNKNOWN_COMMIT"],
      reconciliationEvidenceRequired: false,
      reconciliationOutcomes: {},
      planSelection: "FULL_BBR_ROLLBACK_TEMPLATE",
    }),
    FRESH_RECONCILIATION_OUTCOME: bbrRollbackAuthorizationSourceRow({
      compileAllowedOrigins: ["BBR_MANUAL_ACTION_REQUIRED"],
      durableCause: "FRESH_RECONCILIATION_OUTCOME",
      requiredEvidence: ["ONE_EXACT_FRESH_BBR_RECONCILIATION_OUTCOME_ROW", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "NO_UNKNOWN_COMMIT"],
      reconciliationEvidenceRequired: true,
      reconciliationOutcomes: BBR_ROLLBACK_RECONCILIATION_SOURCE_OUTCOMES,
      planSelection: "RESOLVED_BY_EXACT_RECONCILIATION_OUTCOME_ROW",
    }),
    BBR_ZERO_STAGE_BEFORE_DISPATCH: bbrRollbackAuthorizationSourceRow({
      compileAllowedOrigins: ["BBR_MANUAL_ACTION_REQUIRED"],
      durableCause: "BBR_ZERO_STAGE_BEFORE_DISPATCH",
      requiredEvidence: ["DURABLE_BBR_ZERO_STAGE_CAUSE", "OLD_BBR_ROLLBACK_AUTHORITY_REVOKED", "ZERO_DURABLE_BBR_STAGE_RECEIPTS", "NO_OPEN_EXECUTOR_DISPATCH", "CURRENT_UNCONSUMED_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_REF_AND_BINDING_DIGEST_INHERITED_FROM_CONSUMED_PRIOR_EPISODE", "CURRENT_OWNED_DROPIN_DIGEST_MATCH", "NO_UNKNOWN_COMMIT"],
      reconciliationEvidenceRequired: false,
      reconciliationOutcomes: {},
      planSelection: "FULL_BBR_ROLLBACK_TEMPLATE",
      zeroStageLeaseExpiryResolverRow: "BBR_ZERO_STAGE_BEFORE_DISPATCH",
    }),
  }),
  currentSourceObligationPolicy: Object.freeze({
    authority: "IMMUTABLE_LOCAL_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE_LEDGER",
    currentCompileCandidate: Object.freeze({
      currentEpisode: true,
      unconsumed: true,
      unsuperseded: true,
      exactSourceRowIdBound: true,
      sourceEvidenceCurrent: true,
    }),
    planCompileVisibleRowCount: 1,
    zeroVisibleRows: "DENY_NO_PLAN",
    multipleVisibleRows: "DENY_NO_PLAN_STAY_BBR_MANUAL_ACTION_REQUIRED",
    staleConsumedOrSupersededRowsVisible: false,
    zeroStageExpiryTransition: Object.freeze({
      resolverRow: "BBR_ZERO_STAGE_BEFORE_DISPATCH",
      consumesPriorPlanBoundSourceBindingChallengeAndEpisode: true,
      createsNewCurrentUnconsumedZeroStageEpisode: true,
      inheritsExactOneBaselineKindRefChangeRefAndBindingDigest: true,
      precedence: "ZERO_STAGE_WINS_ONLY_THE_NEW_CURRENT_EXPIRY_EPISODE",
      priorConclusiveOrReconciliationRowRemainsCurrent: false,
    }),
    callerSelectableEpisodeOrRow: false,
  }),
  planCompile: Object.freeze({
    resolvesExactlyOneSourceRow: true,
    readsOnlyCurrentUnconsumedUnsupersededEpisode: true,
    requiresExactOneBaselineReceiptBinding: true,
    baselineReceiptBindingPolicy: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
    persistsSourceRowIdInImmutablePlan: true,
    bindsSourceEvidencePlanDigestChallengeAndOperationRefs: true,
    callerSelectableSourceRow: false,
  }),
  planAuthorize: Object.freeze({
    requiresCurrentBbrRollbackPlan: true,
    requiresExactPersistedSourceRowId: true,
    revalidatesSourceRowEvidenceAndMainGate: true,
    revalidatesExactOneBaselineReceiptBinding: true,
    baselineReceiptBindingPolicy: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
    consumesChallengeBoundToSourceRow: true,
    destination: "BBR_ROLLING_BACK",
  }),
  executor: Object.freeze({
    requiresAuthorizedPlanWithSameSourceRowId: true,
    requiresExactOneBaselineReceiptBinding: true,
    baselineReceiptBindingPolicy: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
    fullSelectionBaselineBySourceRow: Object.freeze({
      EXPLICIT_COMMITTED_APPLY: Object.freeze(["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_NORMAL_COMMITTED_APPLY", "CURRENT_OWNED_DROPIN_DIGEST_MATCH"]),
      CONCLUSIVE_VERIFY_FALSE: Object.freeze(["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_NORMAL_COMMITTED_APPLY", "CURRENT_OWNED_DROPIN_DIGEST_MATCH"]),
      FRESH_RECONCILIATION_OUTCOME_BBR_APPLY_PROVEN_COMMITTED: Object.freeze(["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_RECONCILED_APPLY_CHANGE", "CURRENT_OWNED_DROPIN_DIGEST_MATCH"]),
      FRESH_RECONCILIATION_OUTCOME_BBR_ROLLBACK_EXECUTOR_PROVEN_NOT_COMMITTED: Object.freeze(["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_AND_REFS_INHERITED_FROM_CURRENT_SOURCE_EPISODE", "STRICT_ALL_STAGE_PRE_INVERSE_ZERO_RECEIPT_PROOF", "CURRENT_OWNED_DROPIN_DIGEST_MATCH"]),
      BBR_ZERO_STAGE_BEFORE_DISPATCH: Object.freeze(["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_REF_AND_BINDING_DIGEST_INHERITED_FROM_CONSUMED_PRIOR_EPISODE", "CURRENT_OWNED_DROPIN_DIGEST_MATCH", "DURABLE_BBR_ZERO_STAGE_CAUSE"]),
    }),
    suffixSelectionBaseline: Object.freeze(["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_AND_REFS_INHERITED_FROM_CURRENT_SOURCE_EPISODE", "EXACT_NONEMPTY_PROVEN_COMPLETED_STAGE_PREFIX", "CURRENT_STATE_MATCHES_COMPLETED_STAGE_PREFIX", "EXACT_PRE_INVERSE_REMAINING_STAGE_SUFFIX", "EXACT_DURABLE_BBR_STAGE_RECEIPT_FAMILY"]),
  }),
  zeroStagePolicy: Object.freeze({
    resolverRow: ROLLBACK_LEASE_EXPIRY_RESOLVER.rows.BBR_ZERO_STAGE_BEFORE_DISPATCH,
    reconciliationEvidenceRequired: false,
    mainRollbackAdmissionReceiptAllowed: false,
    admissionReceipt: null,
  }),
  trajectories: Object.freeze({
    CONCLUSIVE_AUTHORIZE_ZERO_STAGE_REAUTHORIZE: Object.freeze([
      "CONCLUSIVE_VERIFY_FALSE_SOURCE_EPISODE_CURRENT",
      "PLAN_COMPILE_BINDS_CONCLUSIVE_SOURCE_ROW",
      "PLAN_AUTHORIZE_CONSUMES_CONCLUSIVE_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
      "ROLLBACK_LEASE_EXPIRES_BEFORE_ANY_STAGE_DISPATCH",
      "ATOMIC_ZERO_STAGE_TRANSITION_CONSUMES_PRIOR_SOURCE_BINDING_CHALLENGE_AND_EPISODE",
      "NEW_CURRENT_UNCONSUMED_ZERO_STAGE_SOURCE_EPISODE_ONLY",
      "PLAN_COMPILE_BINDS_ZERO_STAGE_SOURCE_ROW",
      "PLAN_AUTHORIZE_CONSUMES_ZERO_STAGE_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
    ]),
    RECONCILED_AUTHORIZE_ZERO_STAGE_REAUTHORIZE: Object.freeze([
      "BBR_APPLY_PROVEN_COMMITTED_MINTS_RECONCILED_BASELINE_AND_SOURCE_EPISODE",
      "PLAN_COMPILE_BINDS_RECONCILED_SOURCE_ROW_AND_EXACT_ONE_RECONCILED_BASELINE",
      "PLAN_AUTHORIZE_CONSUMES_RECONCILED_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
      "ROLLBACK_LEASE_EXPIRES_BEFORE_ANY_STAGE_DISPATCH",
      "ATOMIC_ZERO_STAGE_TRANSITION_INHERITS_RECONCILED_BASELINE_KIND_REF_CHANGE_REF_AND_BINDING_DIGEST",
      "NEW_CURRENT_UNCONSUMED_ZERO_STAGE_SOURCE_EPISODE_HAS_EXACT_ONE_RECONCILED_BASELINE",
      "PLAN_COMPILE_BINDS_ZERO_STAGE_SOURCE_ROW_WITH_INHERITED_RECONCILED_BASELINE",
      "PLAN_AUTHORIZE_CONSUMES_ZERO_STAGE_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
    ]),
    BASELINE_BINDING_NEGATIVE_CONTROLS: Object.freeze({
      NORMAL_AND_RECONCILED_BOTH_CURRENT: "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION",
      NORMAL_AND_RECONCILED_BOTH_ABSENT: "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION",
      CALLER_SELECTED_KIND_OR_REF: "INVALID_INPUT_NO_AUTHORITY",
    }),
  }),
});
const BBR_SAFETY_POLICY = Object.freeze({
  eligibility: "CURRENT_KERNEL_ALREADY_EXPOSES_BBR_AND_NO_PERSISTENT_CONFLICT_AND_OWNED_DROPIN_ABSENT",
  allowedKeys: Object.freeze(["net.core.default_qdisc", "net.ipv4.tcp_congestion_control"]),
  ownedDropin: "PLUGIN_OWNED_ETC_SYSCTL_D_REF_ONLY",
  forbiddenActions: Object.freeze(["KERNEL_INSTALL", "KERNEL_UPGRADE", "BOOTLOADER_EDIT", "SHARED_SYSCTL_CONF_EDIT", "REBOOT"]),
  approvalLease: "HOST_P3",
  acceptedRequires: "LIVE_AND_PERSISTENT_VALUES_PLUS_FRESH_PROTECTED_LINE",
  rollback: "REMOVE_OWNED_DROPIN_RESTORE_RECORDED_PRIOR_LIVE_AND_PERSISTENT_VALUES_THEN_SEPARATELY_REFRESH_TRAFFIC_LOGS_AND_PROTECTED_LINE",
  rollbackMainGate: BBR_ROLLBACK_MAIN_GATE,
  applyBeforeMainSeal: true,
  mainCompletionResolvedSet: Object.freeze(["BBR_CLOSED_NOT_REQUESTED_RECEIPT", "BBR_CLOSED_VERIFIED_RECEIPT", "BBR_CLOSED_ROLLED_BACK_RECEIPT", "BBR_CLOSED_NO_WRITE_RECEIPT"]),
  noWriteCloseRule: "BBR_CLOSED_PARTIAL_REQUIRES_ABSENT_BBR_APPLY_RECEIPT",
  postApplyInvalidates: Object.freeze(["AUTHENTICATED_PROXY_REQUEST", "EXPECTED_PUBLIC_EGRESS", "PROBE_WINDOW", "NGINX_XRAY_LOG_CORRELATION", "PROTECTED_LINE_HEALTH", "SEALED_COMPLETION_REPORT"]),
  postApplyMainAcceptance: "REFRESH_ALL_INVALIDATED_E2E_EVIDENCE_AFTER_EXACT_BBR_CHANGE",
  inverseExecutor: "bbr_rollback",
  genericRollbackForbidden: true,
});

const SUBPLAN_CHAINING_POLICY = Object.freeze({
  resolver: "SERVER_RECORDED_ORDERED_PLAN_CURSOR",
  leaseInheritance: false,
  replanOrigin: "APPLYING",
  replanDestination: "PLAN_READY",
  replanRequires: Object.freeze(["NO_OPEN_OPERATION", "ALL_COMMITS_KNOWN", "FRESH_REQUIRED_INVENTORIES", "GLOBAL_FORWARD_ELIGIBILITY_REEVALUATED", "FRESH_PROTECTED_LINE_BOUND_TO_COMPLETED_PREREQUISITE_RECEIPTS", "NO_ROLLBACK_OR_MANUAL_OBLIGATION"]),
  scopes: Object.freeze({
    NODE_INSTALL_P3: Object.freeze({
      operationList: PLAN_OPERATION_RESOLVER.scopes.NODE_INSTALL_P3.operationList,
      nextLeaseClass: "NODE_P2",
    }),
  }),
});

const BASE_ERRORS = Object.freeze([
  "INVALID_INPUT", "UNAUTHORIZED_TARGET", "WRONG_STATE", "DEPENDENCY_MISSING",
  "BASELINE_DRIFT", "IDEMPOTENCY_CONFLICT", "EVIDENCE_STALE", "INTERNAL_ERROR",
]);
const READ_ERRORS = Object.freeze([
  ...BASE_ERRORS, "SECRET_REF_MISSING", "SECRET_SCOPE_MISMATCH",
  "UPSTREAM_AUTH_FAILED", "UPSTREAM_FORBIDDEN", "UPSTREAM_UNAVAILABLE", "UPSTREAM_TIMEOUT",
]);
const WRITE_ERRORS = Object.freeze([
  ...READ_ERRORS, "APPROVAL_REQUIRED", "APPROVAL_STALE", "APPROVAL_REPLAYED",
  "CONFLICT_DETECTED", "UNKNOWN_COMMIT_STATE", "RECONCILIATION_REQUIRED",
  "BACKUP_INVALID", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED",
]);

const CORE_CLOSE_MATRIX = Object.freeze({
  main: Object.freeze({
    NEW: Object.freeze(["abandoned"]),
    INVENTORIED: Object.freeze(["abandoned"]),
    PLAN_READY: Object.freeze(["abandoned"]),
    APPROVED: Object.freeze(["abandoned"]),
    MANUAL_ACTION_REQUIRED: Object.freeze(["abandoned"]),
    DELIVERY_REPORT_SEALED: Object.freeze(["accepted", "audit_complete"]),
    ROLLED_BACK: Object.freeze(["partial"]),
  }),
  bbr: Object.freeze({
    BBR_NOT_REQUESTED: Object.freeze(["not_requested"]),
    BBR_PENDING: Object.freeze(["partial"]),
    BBR_INVENTORIED: Object.freeze(["partial"]),
    BBR_PLAN_READY: Object.freeze(["partial"]),
    BBR_HOST_APPROVED: Object.freeze(["partial"]),
    BBR_MANUAL_ACTION_REQUIRED: Object.freeze(["partial"]),
    BBR_VERIFIED: Object.freeze(["accepted"]),
    BBR_ROLLED_BACK: Object.freeze(["partial"]),
  }),
});
const MAIN_CLOSE_OUTCOME_RESOLVER = Object.freeze({
  audit: Object.freeze({
    audit_complete: Object.freeze({ allowedOrigins: Object.freeze(["DELIVERY_REPORT_SEALED"]), requiredReportLabel: "audit_complete", residual: "NULL" }),
    abandoned: Object.freeze({ allowedOrigins: Object.freeze(["NEW", "INVENTORIED"]), requiredReportLabel: "NULL", residual: "NON_NULL" }),
  }),
  configure: Object.freeze({
    accepted: Object.freeze({ allowedOrigins: Object.freeze(["DELIVERY_REPORT_SEALED"]), requiredReportLabel: "end_to_end_verified", residual: "NON_NULL_PROFILE_PUBLICATION" }),
    partial: Object.freeze({ allowedOrigins: Object.freeze(["ROLLED_BACK"]), requiredReportLabel: "NULL", residual: "NON_NULL" }),
    abandoned: Object.freeze({ allowedOrigins: Object.freeze(["NEW", "INVENTORIED", "PLAN_READY", "APPROVED", "MANUAL_ACTION_REQUIRED"]), requiredReportLabel: "NULL", residual: "NON_NULL" }),
  }),
  forbiddenCrossMode: Object.freeze(["audit:accepted", "configure:audit_complete"]),
  authority: "IMMUTABLE_RUN_MODE_PLUS_SERVER_SEALED_REPORT_LABEL_NOT_CALLER_INPUT",
});

const MAIN_ROLLBACK_COMPILE_ORIGINS = Object.freeze([
  "APPLYING", "ORIGIN_CONFIGURED", "ORIGIN_VERIFIED", "CDN_ENABLED", "CDN_VERIFIED",
  "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED",
  "OLD_LINE_REVERIFIED", "DELIVERY_REPORT_SEALED",
]);
const MAIN_ROLLBACK_BBR_GATE = Object.freeze({
  authority: "CURRENT_IMMUTABLE_BBR_LEDGER_STATE_RECEIPTS_AND_OPEN_OPERATION_SET",
  appliesTo: Object.freeze(["plan_compile:MAIN_ROLLBACK", "plan_authorize:MAIN_ROLLBACK", "rollback_run"]),
  allowedClosedReceipts: Object.freeze([
    "BBR_CLOSED_NOT_REQUESTED_RECEIPT", "BBR_CLOSED_NO_WRITE_RECEIPT",
    "BBR_CLOSED_VERIFIED_RECEIPT", "BBR_CLOSED_ROLLED_BACK_RECEIPT",
  ]),
  allowedRawProvenNoWrite: Object.freeze({
    states: Object.freeze(["BBR_NOT_REQUESTED", "BBR_PENDING", "BBR_INVENTORIED", "BBR_PLAN_READY", "BBR_HOST_APPROVED"]),
    requires: Object.freeze(["NO_BBR_APPLY_RECEIPT", "NO_OPEN_BBR_OPERATION"]),
    manualReconciledException: "BBR_MANUAL_ACTION_REQUIRED_WITH_FRESH_PROVEN_NOT_COMMITTED_BBR_APPLY_NO_APPLY_RECEIPT_NO_OPEN_OPERATION",
  }),
  consumerRules: Object.freeze({
    plan_compile: Object.freeze({
      requires: Object.freeze(["EXACT_SCOPE_ROLLBACK_INTENT_ROLLBACK_OWNED_CHANGES", "KNOWN_COMMITTED_MAIN_GRAPH_OR_FRESH_RECONCILED_PRIOR_COMMITS"]),
      mainRecoveryObligation: "CREATE_IMMUTABLY_IN_SAME_LOCAL_LEDGER_TRANSACTION_AS_PLAN",
    }),
    plan_authorize: Object.freeze({ requires: Object.freeze(["CURRENT_MAIN_RECOVERY_OBLIGATION", "CURRENT_MAIN_ROLLBACK_PLAN_AND_CHALLENGE"]) }),
    rollback_run: Object.freeze({ requires: Object.freeze(["CURRENT_MAIN_RECOVERY_OBLIGATION", "CURRENT_AUTHORIZED_MAIN_ROLLBACK_PLAN"]) }),
  }),
  deniedRawStates: Object.freeze(["BBR_APPLIED", "BBR_VERIFIED", "BBR_ROLLING_BACK", "BBR_ROLLED_BACK", "BBR_MANUAL_ACTION_REQUIRED_COMMITTED_OR_UNKNOWN"]),
  deniedResolution: "FIRST_COMPLETE_DEDICATED_BBR_ROLLBACK_WHEN_COMMITTED_THEN_RUN_CLOSE_BBR_OR_RECONCILE_UNKNOWN_NO_STALE_MAIN_PLAN_REUSE",
  retainedAcceptedBbr: Object.freeze({ receipt: "BBR_CLOSED_VERIFIED_RECEIPT", mainRollbackAllowed: true, mainPartialResidualRequired: true, reopenBbr: false }),
  reevaluateAtEveryConsumer: true,
  mismatch: "WRONG_STATE_INVALIDATE_MAIN_ROLLBACK_PLAN_OR_APPROVAL_NO_INVERSE",
  callerSelectable: false,
});
const CONFIGURED_PENDING_ORIGINS = Object.freeze([
  "ORIGIN_CONFIGURED", "ORIGIN_VERIFIED", "CDN_ENABLED", "CDN_VERIFIED",
  "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED",
  "OLD_LINE_REVERIFIED",
]);
const MAIN_FORWARD_PLAN_REQUESTS = Object.freeze([
  Object.freeze({ scope: "node_install_p3", intent: "install_then_configure", resolverScope: "NODE_INSTALL_P3" }),
  Object.freeze({ scope: "node_p2", intent: "configure_existing", resolverScope: "NODE_P2" }),
]);
const BBR_FORWARD_PLAN_REQUESTS = Object.freeze([
  Object.freeze({ scope: "host_p3", intent: "enable_bbr", resolverScope: "HOST_P3", mainGate: "MAIN_PHASE_OLD_LINE_REVERIFIED_AND_NODE_CURSOR_COMPLETE_AND_REPORT_NOT_SEALED" }),
]);
const AUDIT_COMPLETION_REQUIREMENTS = Object.freeze([
  "ORIGIN_INVENTORY", "CLOUDFLARE_INVENTORY", "XUI_INVENTORY",
  "CLIENT_INVENTORY", "PROTECTED_LINE_HEALTHY_OR_PROVEN_NA",
]);
const COMPLETION_RESULT_BY_LABEL = Object.freeze({
  audit_complete: Object.freeze({
    runMode: "audit",
    allowedOrigins: Object.freeze(["INVENTORIED"]),
    status: "ok",
    destinationByOrigin: Object.freeze({ INVENTORIED: "DELIVERY_REPORT_SEALED" }),
    requirements: AUDIT_COMPLETION_REQUIREMENTS,
    additionalGates: Object.freeze(["RUN_MODE_AUDIT_FROM_IMMUTABLE_LEDGER", "NO_UNKNOWN_COMMIT", "NO_OPEN_ROLLBACK"]),
    output: Object.freeze({ reportRef: "NON_NULL", reportDigest: "NON_NULL", satisfiedRequirementIds: "EXACT_AUDIT_COMPLETION_REQUIREMENTS", allRequiredTrue: true, residualDisclosureRef: "NULL" }),
    sideEffect: "SEAL_IMMUTABLE_AUDIT_REPORT",
  }),
  configured_not_verified: Object.freeze({
    runMode: "configure",
    allowedOrigins: CONFIGURED_PENDING_ORIGINS,
    status: "pending",
    destinationByOrigin: Object.freeze(Object.fromEntries(CONFIGURED_PENDING_ORIGINS.map((origin) => [origin, "UNCHANGED"]))),
    requirements: Object.freeze(["TRUE_AUTHENTICATED_E2E_REQUIREMENT_SUBSET_ZERO_TO_SIX"]),
    additionalGates: Object.freeze(["RUN_MODE_CONFIGURE_FROM_IMMUTABLE_LEDGER", "KNOWN_COMMITTED_CONFIGURATION_NOT_FULLY_VERIFIED", "NO_UNKNOWN_COMMIT", "HONEST_RESIDUAL_DISCLOSURE"]),
    output: Object.freeze({ reportRef: "NULL", reportDigest: "NULL", satisfiedRequirementIds: "TRUE_E2E_SUBSET_ZERO_TO_SIX", allRequiredTrue: false, residualDisclosureRef: "NON_NULL" }),
    sideEffect: "NO_SEALED_REPORT_WRITE",
  }),
  end_to_end_verified: Object.freeze({
    runMode: "configure",
    allowedOrigins: Object.freeze(["OLD_LINE_REVERIFIED"]),
    status: "ok",
    destinationByOrigin: Object.freeze({ OLD_LINE_REVERIFIED: "DELIVERY_REPORT_SEALED" }),
    requirements: AUTHENTICATED_E2E_POLICY.requiredEvidence,
    additionalGates: Object.freeze(["RUN_MODE_CONFIGURE_FROM_IMMUTABLE_LEDGER", "NO_UNKNOWN_COMMIT", "NO_OPEN_ROLLBACK", "BBR_RESOLVED_BEFORE_MAIN_REPORT_SEAL", "AFTER_BBR_APPLY_REFRESH_AUTHENTICATED_TRAFFIC_EGRESS_LOGS_AND_PROTECTED_LINE", "PROFILE_PUBLICATION_RESIDUAL_BOUND_IN_REPORT"]),
    output: Object.freeze({ reportRef: "NON_NULL", reportDigest: "NON_NULL", satisfiedRequirementIds: "EXACT_AUTHENTICATED_E2E_REQUIRED_EVIDENCE", allRequiredTrue: true, residualDisclosureRef: "NON_NULL" }),
    sideEffect: "SEAL_IMMUTABLE_END_TO_END_REPORT",
  }),
});
const PLAN_COMPILE_REQUEST_MATRIX = Object.freeze({
  normal: Object.freeze({
    INVENTORIED: MAIN_FORWARD_PLAN_REQUESTS,
    APPLYING: Object.freeze([
      Object.freeze({ scope: "node_p2", intent: "configure_existing", resolverScope: "NODE_P2" }),
    ]),
    BBR_INVENTORIED: BBR_FORWARD_PLAN_REQUESTS,
  }),
  forwardRefreshRecompile: Object.freeze({
    PLAN_READY: Object.freeze({
      governingColumn: "main", requests: MAIN_FORWARD_PLAN_REQUESTS, destination: "UNCHANGED",
      requires: Object.freeze(["FRESH_REQUIRED_INVENTORIES", "SERVER_RESOLVED_FORWARD_SCOPE_AND_INTENT_MATCH", "PRIOR_PLAN_OR_CHALLENGE_INVALIDATED", "NO_OPEN_OPERATION", "NO_RECOVERY_OBLIGATION"]),
      invalidates: Object.freeze(["PRIOR_PLAN_REF", "PRIOR_APPROVAL_CHALLENGE_REF", "PRIOR_APPROVAL_LEASE"]),
      authorization: "NEW_HOST_PROMPT_REQUIRED_NO_PRIOR_ACK_OR_LEASE_REUSE",
    }),
    APPROVED: Object.freeze({
      governingColumn: "main", requests: MAIN_FORWARD_PLAN_REQUESTS, destination: "PLAN_READY",
      requires: Object.freeze(["FRESH_REQUIRED_INVENTORIES", "SERVER_RESOLVED_FORWARD_SCOPE_AND_INTENT_MATCH", "PRIOR_PLAN_OR_CHALLENGE_INVALIDATED", "NO_OPEN_OPERATION", "NO_RECOVERY_OBLIGATION"]),
      invalidates: Object.freeze(["PRIOR_PLAN_REF", "PRIOR_APPROVAL_CHALLENGE_REF", "PRIOR_APPROVAL_LEASE"]),
      authorization: "NEW_HOST_PROMPT_REQUIRED_NO_PRIOR_ACK_OR_LEASE_REUSE",
    }),
    BBR_PLAN_READY: Object.freeze({
      governingColumn: "bbr", requests: BBR_FORWARD_PLAN_REQUESTS, destination: "UNCHANGED",
      requires: Object.freeze(["FRESH_BBR_INVENTORY", "SERVER_RESOLVED_FORWARD_SCOPE_AND_INTENT_MATCH", "PRIOR_PLAN_OR_CHALLENGE_INVALIDATED", "NO_OPEN_OPERATION", "NO_BBR_RECOVERY_OBLIGATION"]),
      invalidates: Object.freeze(["PRIOR_PLAN_REF", "PRIOR_APPROVAL_CHALLENGE_REF", "PRIOR_APPROVAL_LEASE"]),
      authorization: "NEW_HOST_PROMPT_REQUIRED_NO_PRIOR_ACK_OR_LEASE_REUSE",
    }),
    BBR_HOST_APPROVED: Object.freeze({
      governingColumn: "bbr", requests: BBR_FORWARD_PLAN_REQUESTS, destination: "BBR_PLAN_READY",
      requires: Object.freeze(["HOST_P3_CHECKPOINT_PROVED_BBR_BASELINE_DRIFT_OR_NOMINAL_OR_EFFECTIVE_LEASE_EXPIRY", "FRESH_BBR_INVENTORY", "SERVER_RESOLVED_FORWARD_SCOPE_AND_INTENT_MATCH", "PRIOR_PLAN_CURSOR_APPROVAL_AND_LEASE_INVALIDATED", "NO_OPEN_OPERATION", "NO_BBR_RECOVERY_OBLIGATION"]),
      invalidates: Object.freeze(["PRIOR_PLAN_REF", "PRIOR_APPROVAL_CHALLENGE_REF", "PRIOR_APPROVAL_LEASE"]),
      authorization: "NEW_HOST_PROMPT_REQUIRED_NO_PRIOR_ACK_OR_LEASE_REUSE",
    }),
  }),
  mainRollbackEscalation: Object.freeze({
    allowedOrigins: MAIN_ROLLBACK_COMPILE_ORIGINS,
    request: Object.freeze({ scope: "rollback", intent: "rollback_owned_changes", resolverScope: "MAIN_ROLLBACK" }),
    destination: "ROLLBACK_REQUIRED",
    requires: Object.freeze(["KNOWN_COMMITTED_RUN_OWNED_CHANGE", "NO_UNKNOWN_COMMIT", "FROZEN_SERVER_DERIVED_REVERSE_GRAPH", "MAIN_ROLLBACK_BBR_GATE_ALL_TRUE"]),
  }),
  existingMainRecovery: Object.freeze({
    allowedOrigins: Object.freeze(["ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"]),
    request: Object.freeze({ scope: "rollback", intent: "rollback_owned_changes", resolverScope: "MAIN_ROLLBACK" }),
    destination: "UNCHANGED",
    requires: Object.freeze(["ONE_EXACT_EXISTING_MAIN_RECOVERY_ADMISSION_ROW_MATCHES_FRESH_RECONCILIATION_EVIDENCE_OR_DURABLE_ZERO_DISPATCH_LEASE_EXPIRY_RECEIPT", "OWNED_GRAPH_CURRENT_DIGESTS_SAFE", "ROLLBACK_EXECUTION_PROVEN_SAFE", "NO_UNKNOWN_COMMIT", "MAIN_ROLLBACK_BBR_GATE_ALL_TRUE"]),
    reconciliationAdmission: Object.freeze({
      MAIN_EXTERNAL_MUTATION_PROVEN_COMMITTED: "ALLOW_OWNED_GRAPH_ROLLBACK",
      MAIN_EXTERNAL_MUTATION_PROVEN_NOT_COMMITTED_WITH_PRIOR_COMMITS: "ALLOW_EARLIER_OWNED_GRAPH_ROLLBACK",
      MAIN_ROLLBACK_EXECUTOR_PROVEN_NOT_COMMITTED: "ALLOW_ONLY_WITH_RECONCILIATION_OUTCOME_RESOLVER_STRICT_PRE_INVERSE_ZERO_RECEIPT_TERMINATION_AND_SETTLE_FENCE_PROOF",
      MAIN_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX: "ALLOW_ONLY_REMAINING_CONTIGUOUS_SUFFIX_COMPLETED_PREFIX_REPLAY_FORBIDDEN",
      ACTIVE_CHECKPOINT_DIRECT_OWNED_GRAPH_RECOVERY_OBLIGATION: "ALLOW_EXACT_OWNED_GRAPH_ROLLBACK",
      ACTIVE_CHECKPOINT_DRIFT_PROVEN_COMMITTED_OWNED_GRAPH: "ALLOW_AFTER_FIXED_OBSERVER_PROJECTS_CURRENT_RECOVERY_OBLIGATION",
      ROLLBACK_LEASE_EXPIRED_ZERO_INVERSE: Object.freeze({
        allow: "FRESH_FULL_GRAPH_PLAN_AFTER_OLD_AUTHORITY_REVOKED",
        requires: Object.freeze(["MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY_ADMISSION_RECEIPT", "ZERO_DURABLE_ATOMIC_STAGE_RECEIPTS", "NO_OPEN_EXECUTOR_DISPATCH", "CURRENT_OWNED_GRAPH_STILL_SAFE"]),
        reconciliationEvidenceRequired: false,
        oldAuthorityRevoked: true,
        newHostPromptRequired: true,
      }),
      EVERY_OTHER_RESULT: "DENY_STAY_MANUAL",
    }),
  }),
  bbrRollbackEscalation: Object.freeze({
    allowedOrigins: Object.freeze(["BBR_APPLIED", "BBR_VERIFIED"]),
    request: Object.freeze({ scope: "rollback", intent: "rollback_owned_changes", resolverScope: "BBR_ROLLBACK" }),
    destination: "BBR_MANUAL_ACTION_REQUIRED",
    authorizationSourceRowIds: Object.freeze(["EXPLICIT_COMMITTED_APPLY"]),
    authorizationSourceRows: Object.freeze({
      EXPLICIT_COMMITTED_APPLY: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.rows.EXPLICIT_COMMITTED_APPLY,
    }),
    requires: Object.freeze(["EXACTLY_ONE_ALLOWED_BBR_ROLLBACK_AUTHORIZATION_SOURCE_ROW", "SOURCE_ROW_EVIDENCE_CURRENT", "DEDICATED_BBR_ROLLBACK_TEMPLATE", "BBR_ROLLBACK_MAIN_GATE_ALL_TRUE"]),
    mainGate: BBR_ROLLBACK_MAIN_GATE,
  }),
  existingBbrRecovery: Object.freeze({
    allowedOrigins: Object.freeze(["BBR_MANUAL_ACTION_REQUIRED"]),
    request: Object.freeze({ scope: "rollback", intent: "rollback_owned_changes", resolverScope: "BBR_ROLLBACK" }),
    destination: "UNCHANGED",
    authorizationSourceRowIds: Object.freeze(["CONCLUSIVE_VERIFY_FALSE", "FRESH_RECONCILIATION_OUTCOME", "BBR_ZERO_STAGE_BEFORE_DISPATCH"]),
    authorizationSourceRows: Object.freeze({
      CONCLUSIVE_VERIFY_FALSE: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.rows.CONCLUSIVE_VERIFY_FALSE,
      FRESH_RECONCILIATION_OUTCOME: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.rows.FRESH_RECONCILIATION_OUTCOME,
      BBR_ZERO_STAGE_BEFORE_DISPATCH: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.rows.BBR_ZERO_STAGE_BEFORE_DISPATCH,
    }),
    requires: Object.freeze(["EXACTLY_ONE_ALLOWED_BBR_ROLLBACK_AUTHORIZATION_SOURCE_ROW", "SOURCE_ROW_EVIDENCE_CURRENT", "DEDICATED_BBR_ROLLBACK_PROVEN_SAFE", "BBR_ROLLBACK_MAIN_GATE_ALL_TRUE"]),
    sourceSet: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET,
    mainGate: BBR_ROLLBACK_MAIN_GATE,
  }),
});

const EVIDENCE_LIST_ROW_SCHEMA = closed({ evidence_ref: S.EvidenceRef, masked_summary: S.MaskedText });
const EVIDENCE_PAGE_LIMIT_CLAUSES = Object.freeze(Array.from({ length: 100 }, (_, index) => {
  const requestedMaxItems = index + 1;
  return Object.freeze({
    if: { properties: { requested_max_items: { const: requestedMaxItems } }, required: ["requested_max_items"] },
    then: { properties: { rows: arr(EVIDENCE_LIST_ROW_SCHEMA, 0, requestedMaxItems) }, required: ["rows"] },
  });
}));

const TOOLS = {
  run_begin: C({
    name: "run_begin",
    title: "Begin a core-v1 run",
    description: "Create one audit or configure run from onboarding-owned target and SecretRefs; initialize main and BBR state without resolving secret bytes.",
    input: Object.freeze({ ...closed({
      mode: enumOf("audit", "configure"),
      origin_target_ref: S.TargetRef,
      cloudflare_target_ref: S.TargetRef,
      node_hostname_ref: S.RuntimeRef,
      ssh_identity_secret_ref: S.SecretRef,
      cf_audit_secret_ref: S.SecretRef,
      cf_node_dns_secret_ref: S.NullableSecretRef,
      cf_origin_ca_secret_ref: S.NullableSecretRef,
      existing_xui_admin_secret_ref: S.NullableSecretRef,
      protected_line_ref: S.NullableRuntimeRef,
      protected_line_runtime_secret_ref: S.NullableSecretRef,
      output_dir_ref: S.RuntimeRef,
      enable_bbr: bool,
      idempotency_key: S.IdempotencyKey,
    }), allOf: Object.freeze([
      {
        if: { properties: { mode: { const: "audit" } }, required: ["mode"] },
        then: { properties: { enable_bbr: constOf(false) } },
      },
      {
        if: { properties: { protected_line_ref: { type: "null" } }, required: ["protected_line_ref"] },
        then: { properties: { protected_line_runtime_secret_ref: { type: "null" } } },
        else: { properties: { protected_line_runtime_secret_ref: S.SecretRef } },
      },
    ]) }),
    data: closed({
      run_ref: S.RunRef,
      run_mode: enumOf("audit", "configure"),
      main_phase: constOf("NEW"),
      bbr_phase: enumOf("BBR_NOT_REQUESTED", "BBR_PENDING"),
      target_set_digest: S.Digest,
      node_binding_digest: S.Digest,
      ledger_digest: S.Digest,
    }),
    annotations: A(false, false, true, false),
    policy: P({
      governingColumn: "none", auth: ["LOCAL_LEDGER"], allowedFrom: [],
      successByOrigin: {}, failureTo: ["NO_STATE_CHANGE"],
      requires: ["ONBOARDING_TARGETS_AND_ROLE_BOUND_SECRET_REFS", "DEDICATED_NODE_HOSTNAME_REF", "PROTECTED_LINE_DESCRIPTOR_AND_RUNTIME_SECRET_SERVER_BOUND", "PROTECTED_LINE_RUNTIME_SECRET_REF_NULL_IFF_SERVER_PROVEN_NOT_APPLICABLE"],
      produces: [E("RUN_CREATED", "NO_TTL")],
      rollbackClass: "compensating_action", rollbackAction: "ABANDON_UNMUTATED_RUN",
      sideEffects: ["create local run ledger"], errors: BASE_ERRORS,
      controls: {
        creationWrites: Object.freeze({
          main_phase: "NEW",
          bbr_phase_when_requested: "BBR_PENDING",
          bbr_phase_when_absent: "BBR_NOT_REQUESTED",
        }),
        runModeBinding: RUN_MODE_POLICY,
        protectedLineBinding: Object.freeze({
          pairRule: "BOTH_NON_NULL_OR_BOTH_NULL",
          bothNullRequires: "SERVER_REGISTERED_PROTECTED_LINE_NOT_APPLICABLE",
          bothNonNullConsumer: "protected_line.runtime_probe_fixed.v1",
          callerMayNotOverrideApplicability: true,
        }),
      },
    }),
  }),

  run_status: C({
    name: "run_status",
    title: "Read run status",
    description: "Return the two active phase columns, immutable receipts, stale evidence and next legal actions without changing state.",
    input: RunOnly,
    data: closed({
      main_phase: S.MainPhase, bbr_phase: S.BbrPhase, ledger_digest: S.Digest,
      plan_ref: nullable(S.PlanRef), pending_operation_refs: arr(S.OperationRef, 0, 64),
      stale_evidence_refs: arr(S.EvidenceRef, 0, 128), next_actions: arr(S.MaskedText, 0, 16),
    }),
    annotations: A(false, false, true, false),
    policy: P({
      auth: ["LOCAL_LEDGER"], allowedFrom: READ_ORIGINS, successByOrigin: same(READ_ORIGINS),
      requires: ["RUN_CREATED"], produces: [], sideEffects: [], errors: BASE_ERRORS,
    }),
  }),

  reconcile_status: C({
    name: "reconcile_status",
    title: "Reconcile the sole unknown operation",
    description: "Observe only the server-selected open reconciliation obligation through its fixed read-only helper/broker composite; return fresh opaque evidence and a closed next action. It never retries or writes externally. Its closed local projections include a proven committed rollback phase and the atomic opaque reconciled BBR apply/change receipt required after a response-lost committed bbr_apply.",
    input: closed({ run_id: S.RunRef, expected_ledger_digest: S.Digest, idempotency_key: S.IdempotencyKey }),
    data: Object.freeze({ ...closed({
      reconciliation_evidence_ref: S.EvidenceRef,
      governing_column: enumOf("main", "bbr"),
      reconciliation_operation_ref: S.OperationRef,
      original_tool: enumOf(...PLAN_OPERATION_RESOLVER.cursorEnforcement.writeAndExecutorTools, ...ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.refreshTools),
      original_failure_cause: enumOf("UNKNOWN_COMMIT", "CONCURRENT_THIRD_DIGEST", "ACTIVE_CHECKPOINT_DRIFT", "ROLLBACK_LEASE_EXPIRED"),
      failure_context: enumOf("MAIN_EXTERNAL_MUTATION", "MAIN_ROLLBACK_EXECUTOR", "BBR_EXTERNAL_MUTATION", "BBR_ROLLBACK_EXECUTOR", "ACTIVE_CHECKPOINT_DRIFT"),
      original_operation_class: enumOf("MAIN_EXTERNAL_MUTATION", "MAIN_ROLLBACK_EXECUTOR", "BBR_APPLY", "BBR_ROLLBACK_EXECUTOR", "ACTIVE_CHECKPOINT_DRIFT"),
      observation: enumOf(...RECONCILIATION_OUTCOME_RESOLVER.observations),
      observed_digest_relation: enumOf("matches_before", "matches_after", "matches_inverse_prefix", "third_digest", "unresolved"),
      prior_committed_change_count: int(0, 64),
      prior_committed_graph_digest: nullable(S.Digest),
      main_rollback_committed_proof: nullable(MAIN_ROLLBACK_COMMITTED_PROOF_SCHEMA),
      main_rollback_not_committed_proof: nullable(MAIN_ROLLBACK_NOT_COMMITTED_PROOF_SCHEMA),
      main_rollback_inverse_prefix_proof: nullable(MAIN_ROLLBACK_INVERSE_PREFIX_PROOF_SCHEMA),
      bbr_rollback_stage_prefix_proof: nullable(BBR_ROLLBACK_STAGE_PREFIX_PROOF_SCHEMA),
      active_checkpoint_recovery_proof: nullable(ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA),
      reconciled_bbr_apply_receipt_ref: nullable(S.ReceiptRef),
      reconciled_bbr_change_ref: nullable(S.ChangeRef),
      next_action: enumOf("STAY_MANUAL_NO_RETRY_OR_CLOSE", "STAY_MANUAL_RECONCILE_NO_OVERWRITE", "COMPILE_AND_AUTHORIZE_OWNED_ROLLBACK", "HOST_PROMPT_ABANDON_NO_WRITE_RESIDUAL_THEN_NEW_RUN", "COMPILE_AND_AUTHORIZE_EARLIER_OWNED_GRAPH_ROLLBACK", "PROJECT_MAIN_ROLLED_BACK_THEN_POST_ROLLBACK_OLD_LINE", "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK", "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK_REMAINING_SUFFIX", "COMPILE_AND_AUTHORIZE_BBR_ROLLBACK", "HOST_PROMPT_BBR_PARTIAL_NO_WRITE_RECEIPT_THEN_CONTINUE_MAIN", "PROJECT_BBR_ROLLED_BACK_THEN_POST_INVERSE_REFRESH", "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK", "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK_REMAINING_STAGE_SUFFIX", "PROJECT_ACTIVE_CHECKPOINT_ZERO_COMMIT_TO_INVENTORIED", "PROJECT_ACTIVE_CHECKPOINT_OWNED_GRAPH_TO_ROLLBACK_REQUIRED"),
      observed_at: S.Timestamp,
    }), allOf: Object.freeze([
      { if: { properties: { original_tool: { const: "rollback_run" } }, required: ["original_tool"] }, then: { properties: { failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" }, original_operation_class: { const: "MAIN_ROLLBACK_EXECUTOR" }, governing_column: { const: "main" } } } },
      { if: { properties: { original_tool: { const: "bbr_apply" } }, required: ["original_tool"] }, then: { properties: { failure_context: { const: "BBR_EXTERNAL_MUTATION" }, original_operation_class: { const: "BBR_APPLY" }, governing_column: { const: "bbr" } } } },
      { if: { properties: { original_tool: { const: "bbr_rollback" } }, required: ["original_tool"] }, then: { properties: { failure_context: { const: "BBR_ROLLBACK_EXECUTOR" }, original_operation_class: { const: "BBR_ROLLBACK_EXECUTOR" }, governing_column: { const: "bbr" } } } },
      { if: { properties: { original_tool: { enum: ["origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory"] } }, required: ["original_tool"] }, then: { properties: { failure_context: { const: "ACTIVE_CHECKPOINT_DRIFT" }, original_operation_class: { const: "ACTIVE_CHECKPOINT_DRIFT" }, original_failure_cause: { const: "ACTIVE_CHECKPOINT_DRIFT" }, governing_column: { const: "main" } } } },
      { if: { properties: { original_tool: { enum: ["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"] } }, required: ["original_tool"] }, then: { properties: { failure_context: { const: "MAIN_EXTERNAL_MUTATION" }, original_operation_class: { const: "MAIN_EXTERNAL_MUTATION" }, governing_column: { const: "main" } } } },
      {
        if: { properties: { observation: { const: "PROVEN_COMMITTED" }, failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" }, original_tool: { const: "rollback_run" } }, required: ["observation", "failure_context", "original_tool"] },
        then: { properties: { main_rollback_committed_proof: MAIN_ROLLBACK_COMMITTED_PROOF_SCHEMA } },
        else: { properties: { main_rollback_committed_proof: { type: "null" } } },
      },
      {
        if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" }, original_tool: { const: "rollback_run" } }, required: ["observation", "failure_context", "original_tool"] },
        then: { properties: { main_rollback_not_committed_proof: MAIN_ROLLBACK_NOT_COMMITTED_PROOF_SCHEMA } },
        else: { properties: { main_rollback_not_committed_proof: { type: "null" } } },
      },
      {
        if: { properties: { observation: { const: "PROVEN_INVERSE_PREFIX" }, failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" }, original_tool: { const: "rollback_run" } }, required: ["observation", "failure_context", "original_tool"] },
        then: { properties: { main_rollback_inverse_prefix_proof: MAIN_ROLLBACK_INVERSE_PREFIX_PROOF_SCHEMA } },
        else: { properties: { main_rollback_inverse_prefix_proof: { type: "null" } } },
      },
      {
        if: { properties: { observation: { const: "PROVEN_INVERSE_PREFIX" }, failure_context: { const: "BBR_ROLLBACK_EXECUTOR" }, original_tool: { const: "bbr_rollback" } }, required: ["observation", "failure_context", "original_tool"] },
        then: { properties: { bbr_rollback_stage_prefix_proof: BBR_ROLLBACK_STAGE_PREFIX_PROOF_SCHEMA } },
        else: { properties: { bbr_rollback_stage_prefix_proof: { type: "null" } } },
      },
      {
        if: { properties: { failure_context: { const: "ACTIVE_CHECKPOINT_DRIFT" } }, required: ["failure_context"] },
        then: { properties: { active_checkpoint_recovery_proof: ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA } },
        else: { properties: { active_checkpoint_recovery_proof: { type: "null" } } },
      },
      {
        if: { properties: { original_tool: { const: "bbr_apply" }, original_operation_class: { const: "BBR_APPLY" }, observation: { const: "PROVEN_COMMITTED" } }, required: ["original_tool", "original_operation_class", "observation"] },
        then: { properties: { reconciled_bbr_apply_receipt_ref: S.ReceiptRef, reconciled_bbr_change_ref: S.ChangeRef } },
        else: { properties: { reconciled_bbr_apply_receipt_ref: { type: "null" }, reconciled_bbr_change_ref: { type: "null" } } },
      },
      { if: { properties: { observation: { const: "STILL_UNKNOWN" } }, required: ["observation"] }, then: { properties: { observed_digest_relation: { const: "unresolved" }, next_action: { const: "STAY_MANUAL_NO_RETRY_OR_CLOSE" } } } },
      { if: { properties: { observation: { const: "CONCURRENT_THIRD_DIGEST" } }, required: ["observation"] }, then: { properties: { observed_digest_relation: { const: "third_digest" }, next_action: { const: "STAY_MANUAL_RECONCILE_NO_OVERWRITE" } } } },
      { if: { properties: { observation: { const: "PROVEN_COMMITTED" }, failure_context: { const: "MAIN_EXTERNAL_MUTATION" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "main" }, observed_digest_relation: { const: "matches_after" }, next_action: { const: "COMPILE_AND_AUTHORIZE_OWNED_ROLLBACK" } } } },
      { if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, failure_context: { const: "MAIN_EXTERNAL_MUTATION" }, prior_committed_change_count: { const: 0 } }, required: ["observation", "failure_context", "prior_committed_change_count"] }, then: { properties: { governing_column: { const: "main" }, observed_digest_relation: { const: "matches_before" }, prior_committed_graph_digest: { type: "null" }, next_action: { const: "HOST_PROMPT_ABANDON_NO_WRITE_RESIDUAL_THEN_NEW_RUN" } } } },
      { if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, failure_context: { const: "MAIN_EXTERNAL_MUTATION" }, prior_committed_change_count: { type: "integer", minimum: 1 } }, required: ["observation", "failure_context", "prior_committed_change_count"] }, then: { properties: { governing_column: { const: "main" }, observed_digest_relation: { const: "matches_before" }, prior_committed_graph_digest: S.Digest, next_action: { const: "COMPILE_AND_AUTHORIZE_EARLIER_OWNED_GRAPH_ROLLBACK" } } } },
      { if: { properties: { observation: { const: "PROVEN_COMMITTED" }, failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "main" }, original_tool: { const: "rollback_run" }, observed_digest_relation: { const: "matches_after" }, next_action: { const: "PROJECT_MAIN_ROLLED_BACK_THEN_POST_ROLLBACK_OLD_LINE" } } } },
      { if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "main" }, original_tool: { const: "rollback_run" }, observed_digest_relation: { const: "matches_before" }, next_action: { const: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK" } } } },
      { if: { properties: { observation: { const: "PROVEN_INVERSE_PREFIX" }, failure_context: { const: "MAIN_ROLLBACK_EXECUTOR" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "main" }, original_tool: { const: "rollback_run" }, observed_digest_relation: { const: "matches_inverse_prefix" }, next_action: { const: "RECOMPILE_AND_REAUTHORIZE_MAIN_ROLLBACK_REMAINING_SUFFIX" } } } },
      { if: { properties: { observation: { const: "PROVEN_COMMITTED" }, original_operation_class: { const: "BBR_APPLY" } }, required: ["observation", "original_operation_class"] }, then: { properties: { governing_column: { const: "bbr" }, failure_context: { const: "BBR_EXTERNAL_MUTATION" }, original_tool: { const: "bbr_apply" }, observed_digest_relation: { const: "matches_after" }, next_action: { const: "COMPILE_AND_AUTHORIZE_BBR_ROLLBACK" } } } },
      { if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, original_operation_class: { const: "BBR_APPLY" } }, required: ["observation", "original_operation_class"] }, then: { properties: { governing_column: { const: "bbr" }, failure_context: { const: "BBR_EXTERNAL_MUTATION" }, original_tool: { const: "bbr_apply" }, observed_digest_relation: { const: "matches_before" }, next_action: { const: "HOST_PROMPT_BBR_PARTIAL_NO_WRITE_RECEIPT_THEN_CONTINUE_MAIN" } } } },
      { if: { properties: { observation: { const: "PROVEN_COMMITTED" }, failure_context: { const: "BBR_ROLLBACK_EXECUTOR" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "bbr" }, original_tool: { const: "bbr_rollback" }, observed_digest_relation: { const: "matches_after" }, next_action: { const: "PROJECT_BBR_ROLLED_BACK_THEN_POST_INVERSE_REFRESH" } } } },
      { if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, failure_context: { const: "BBR_ROLLBACK_EXECUTOR" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "bbr" }, original_tool: { const: "bbr_rollback" }, observed_digest_relation: { const: "matches_before" }, next_action: { const: "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK" } } } },
      { if: { properties: { observation: { const: "PROVEN_INVERSE_PREFIX" }, failure_context: { const: "BBR_ROLLBACK_EXECUTOR" } }, required: ["observation", "failure_context"] }, then: { properties: { governing_column: { const: "bbr" }, original_tool: { const: "bbr_rollback" }, observed_digest_relation: { const: "matches_inverse_prefix" }, next_action: { const: "RECOMPILE_AND_REAUTHORIZE_BBR_ROLLBACK_REMAINING_STAGE_SUFFIX" } } } },
      { if: { properties: { observation: { const: "PROVEN_NOT_COMMITTED" }, failure_context: { const: "ACTIVE_CHECKPOINT_DRIFT" }, prior_committed_change_count: { const: 0 } }, required: ["observation", "failure_context", "prior_committed_change_count"] }, then: { properties: { governing_column: { const: "main" }, observed_digest_relation: { const: "matches_before" }, prior_committed_graph_digest: { type: "null" }, next_action: { const: "PROJECT_ACTIVE_CHECKPOINT_ZERO_COMMIT_TO_INVENTORIED" }, active_checkpoint_recovery_proof: ACTIVE_CHECKPOINT_ZERO_COMMIT_PROOF_SCHEMA } } },
      { if: { properties: { observation: { const: "PROVEN_COMMITTED" }, failure_context: { const: "ACTIVE_CHECKPOINT_DRIFT" }, prior_committed_change_count: { type: "integer", minimum: 1 } }, required: ["observation", "failure_context", "prior_committed_change_count"] }, then: { properties: { governing_column: { const: "main" }, observed_digest_relation: { const: "matches_after" }, prior_committed_graph_digest: S.Digest, next_action: { const: "PROJECT_ACTIVE_CHECKPOINT_OWNED_GRAPH_TO_ROLLBACK_REQUIRED" }, active_checkpoint_recovery_proof: ACTIVE_CHECKPOINT_OWNED_GRAPH_PROOF_SCHEMA } } },
      { if: { properties: { observation: { const: "PROVEN_INVERSE_PREFIX" } }, required: ["observation"] }, then: { properties: { original_tool: { enum: ["rollback_run", "bbr_rollback"] }, failure_context: { enum: ["MAIN_ROLLBACK_EXECUTOR", "BBR_ROLLBACK_EXECUTOR"] } } } },
    ]) }),
    annotations: A(false, false, true, true),
    policy: P({
      governingColumn: "server_resolved_manual_column",
      auth: ["LOCAL_LEDGER", "FIXED_RECONCILIATION_OBSERVER"],
      allowedFrom: ["MANUAL_ACTION_REQUIRED", "BBR_MANUAL_ACTION_REQUIRED"],
      successByOrigin: { MANUAL_ACTION_REQUIRED: "DELEGATE_TO_RECONCILIATION_CONTEXT", BBR_MANUAL_ACTION_REQUIRED: "DELEGATE_TO_RECONCILIATION_CONTEXT" },
      failureTo: ["UNCHANGED"],
      requires: configureRequires("EXACTLY_ONE_OPEN_RECONCILIATION_OBLIGATION", "ORIGINAL_FAILURE_CAUSE_UNKNOWN_COMMIT_CONCURRENT_THIRD_DIGEST_ACTIVE_CHECKPOINT_DRIFT_OR_ROLLBACK_LEASE_EXPIRY", "SERVER_SELECTS_FIXED_HELPER_OR_BROKER_FROM_ORIGINAL_OPERATION", "READ_ONLY_CURRENT_DIGEST_OBSERVATION", "NO_TARGET_OPERATION_OR_MODE_SELECTOR"),
      produces: [E("RECONCILIATION_EVIDENCE", "PT5M"), E("RECONCILED_BBR_APPLY_CHANGE_RECEIPT", "NO_TTL")],
      invalidates: RECONCILIATION_OUTCOME_RESOLVER.invalidates,
      sideEffects: ["bounded read-only external observation selected from immutable ledger", "write reconciliation evidence and only the closed local ledger projection"],
      errors: [...READ_ERRORS, "RECONCILIATION_REQUIRED"],
      controls: {
        outcomeResolver: RECONCILIATION_OUTCOME_RESOLVER,
        observerByTool: RECONCILIATION_OBSERVER_BY_TOOL,
        activeCheckpointObserverByTool: ACTIVE_CHECKPOINT_RECONCILIATION_OBSERVER_BY_TOOL,
        activeCheckpointDriftResolver: ACTIVE_CHECKPOINT_DRIFT_RESOLVER,
        mainRollbackCommittedProof: Object.freeze({ schema: MAIN_ROLLBACK_COMMITTED_PROOF_SCHEMA, policy: MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.provenCommittedIff, finalizationTransaction: MAIN_ROLLBACK_FINALIZATION_TRANSACTION, callerSelectable: false }),
        mainRollbackNotCommittedProof: Object.freeze({ schema: MAIN_ROLLBACK_NOT_COMMITTED_PROOF_SCHEMA, policy: MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.provenNotCommittedIff, callerSelectable: false }),
        mainRollbackInversePrefixProof: Object.freeze({ schema: MAIN_ROLLBACK_INVERSE_PREFIX_PROOF_SCHEMA, policy: MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.provenInversePrefixIff, callerSelectable: false }),
        bbrRollbackStagePrefixProof: Object.freeze({ schema: BBR_ROLLBACK_STAGE_PREFIX_PROOF_SCHEMA, policy: BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF, callerSelectable: false }),
        reconciledBbrApplyChangeReceipt: RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY,
        rollbackLeaseExpiryResolver: ROLLBACK_LEASE_EXPIRY_RESOLVER,
        ledgerDestinationByNextAction: Object.freeze({
          PROJECT_MAIN_ROLLED_BACK_THEN_POST_ROLLBACK_OLD_LINE: "ROLLED_BACK",
          PROJECT_BBR_ROLLED_BACK_THEN_POST_INVERSE_REFRESH: "BBR_ROLLED_BACK",
          PROJECT_ACTIVE_CHECKPOINT_ZERO_COMMIT_TO_INVENTORIED: "INVENTORIED",
          PROJECT_ACTIVE_CHECKPOINT_OWNED_GRAPH_TO_ROLLBACK_REQUIRED: "ROLLBACK_REQUIRED_AND_CREATE_CURRENT_MAIN_RECOVERY_OBLIGATION",
          EVERY_OTHER_NEXT_ACTION: "UNCHANGED",
        }),
        externalWrite: false, localLedgerWrite: true, rawEvidenceInMcp: false,
      },
    }),
  }),

  plan_compile: C({
    name: "plan_compile",
    title: "Compile an exact core plan",
    description: "Derive an ordered immutable plan from current inventories; caller selects only a closed scope and intent, never commands or configuration bodies.",
    input: closed({
      run_id: S.RunRef,
      scope: enumOf("node_p2", "node_install_p3", "host_p3", "rollback"),
      intent: enumOf("configure_existing", "install_then_configure", "enable_bbr", "rollback_owned_changes"),
      expected_ledger_digest: S.Digest,
      idempotency_key: S.IdempotencyKey,
    }),
    data: Object.freeze({ ...closed({
      plan_ref: S.PlanRef, plan_digest: S.Digest, baseline_digest: S.Digest,
      template_id: enumOf(...Object.keys(PLAN_OPERATION_RESOLVER.templates)),
      approval_challenge_ref: S.RuntimeRef,
      operation_refs: arr(S.OperationRef, 1, 32),
      rollback_atomic_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 0, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
      rollback_atomic_stage_selection_digest: nullable(S.Digest),
      bbr_rollback_stage_ids: Object.freeze({ ...arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 0, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
      bbr_rollback_stage_selection_digest: nullable(S.Digest),
      impact_digest: S.Digest,
      lease_class: enumOf("NODE_P2", "NODE_INSTALL_P3", "HOST_P3", "ROLLBACK"),
      certificate_strategy: enumOf("reuse", "origin_ca", "not_applicable"),
      node_binding_digest: S.Digest,
    }), allOf: Object.freeze([
      {
        if: { properties: { template_id: { const: "MAIN_ROLLBACK_V1" } }, required: ["template_id"] },
        then: { properties: {
          rollback_atomic_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
          rollback_atomic_stage_selection_digest: S.Digest,
          bbr_rollback_stage_ids: arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 0, 0),
          bbr_rollback_stage_selection_digest: { type: "null" },
        } },
        else: { properties: {
          rollback_atomic_stage_ids: arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 0, 0),
          rollback_atomic_stage_selection_digest: { type: "null" },
        } },
      },
      {
        if: { properties: { template_id: { const: "BBR_ROLLBACK_V1" } }, required: ["template_id"] },
        then: { properties: {
          rollback_atomic_stage_ids: arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 0, 0),
          rollback_atomic_stage_selection_digest: { type: "null" },
          bbr_rollback_stage_ids: Object.freeze({ ...arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 1, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
          bbr_rollback_stage_selection_digest: S.Digest,
        } },
        else: { properties: {
          bbr_rollback_stage_ids: arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 0, 0),
          bbr_rollback_stage_selection_digest: { type: "null" },
        } },
      },
    ]) }),
    annotations: A(false, false, true, false),
    policy: P({
      governingColumn: "scope_resolver", auth: ["LOCAL_LEDGER"],
      allowedFrom: ["INVENTORIED", "PLAN_READY", "APPROVED", ...MAIN_ROLLBACK_COMPILE_ORIGINS, "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED", "BBR_INVENTORIED", "BBR_PLAN_READY", "BBR_HOST_APPROVED", "BBR_APPLIED", "BBR_VERIFIED", "BBR_MANUAL_ACTION_REQUIRED"],
      successByOrigin: {
        INVENTORIED: "PLAN_READY", PLAN_READY: "UNCHANGED", APPROVED: "PLAN_READY",
        ...Object.fromEntries(MAIN_ROLLBACK_COMPILE_ORIGINS.map((origin) => [origin, "ROLLBACK_REQUIRED"])),
        APPLYING: "DELEGATE_TO_REQUEST_MATRIX",
        ROLLBACK_REQUIRED: "UNCHANGED", MANUAL_ACTION_REQUIRED: "UNCHANGED",
        BBR_INVENTORIED: "BBR_PLAN_READY", BBR_PLAN_READY: "UNCHANGED", BBR_HOST_APPROVED: "BBR_PLAN_READY", BBR_APPLIED: "BBR_MANUAL_ACTION_REQUIRED",
        BBR_VERIFIED: "BBR_MANUAL_ACTION_REQUIRED", BBR_MANUAL_ACTION_REQUIRED: "UNCHANGED",
      },
      requires: configureRequires("CLOSED_SCOPE_INTENT_ORIGIN_MATRIX", "OPERATION_REFS_EXACTLY_FROM_PLAN_OPERATION_RESOLVER", "MAIN_ROLLBACK_REQUEST_DELEGATES_TO_SHARED_BBR_GATE", "BBR_ROLLBACK_TEMPLATE_BINDS_EXACTLY_ONE_SERVER_RESOLVED_AUTHORIZATION_SOURCE_ROW", "BBR_ROLLBACK_TEMPLATE_BINDS_EXACT_ONE_SERVER_DERIVED_APPLY_BASELINE_RECEIPT", "NO_UNKNOWN_COMMIT"),
      produces: [E("PLAN_BASELINE", "PT10M"), E("APPROVAL_CHALLENGE", "PT10M")],
      invalidates: ["OLDER_PLAN_AND_APPROVAL"],
      rollbackClass: "compensating_action", rollbackAction: "SUPERSEDE_ONLY_UNCONSUMED_LOCAL_PLAN",
      sideEffects: ["write immutable local plan"], errors: BASE_ERRORS,
      controls: {
        executionBoundary: Object.freeze({
          effectClass: "LOCAL_LEDGER_ONLY",
          privilegedHelperRequired: false,
          brokerOperationRequired: false,
          externalTargetMutation: false,
        }),
        operationResolver: PLAN_OPERATION_RESOLVER,
        cursorEnforcement: PLAN_OPERATION_RESOLVER.cursorEnforcement,
        requestMatrix: PLAN_COMPILE_REQUEST_MATRIX,
        rollbackLeaseExpiryAdmission: ROLLBACK_LEASE_EXPIRY_RESOLVER.rows.MAIN_ZERO_INVERSE_BEFORE_DISPATCH,
        mainRollbackBbrGate: MAIN_ROLLBACK_BBR_GATE,
        bbrRollbackAuthorizationSourceSet: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET,
        bbrApplyBaselineReceiptBinding: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
        rollbackStageSelectionByTemplate: Object.freeze({
          MAIN_ROLLBACK_V1: Object.freeze({ mainStageIds: MAIN_ROLLBACK_ATOMIC_STAGE_IDS, bbrStageIds: Object.freeze([]), selection: "FULL_OR_EXACT_REMAINING_CONTIGUOUS_MAIN_SUFFIX" }),
          BBR_ROLLBACK_V1: Object.freeze({ mainStageIds: Object.freeze([]), bbrStageIds: BBR_ROLLBACK_ATOMIC_STAGE_IDS, selection: "FULL_OR_EXACT_REMAINING_CONTIGUOUS_BBR_SUFFIX" }),
          EVERY_NON_ROLLBACK_TEMPLATE: Object.freeze({ mainStageIds: Object.freeze([]), bbrStageIds: Object.freeze([]), selection: "EMPTY" }),
        }),
        successResolution: Object.freeze({
          INVENTORIED: "FORWARD_REQUEST_TO_PLAN_READY",
          PLAN_READY: "FRESH_FORWARD_RECOMPILE_UNCHANGED_NEW_CHALLENGE_AND_PROMPT_REQUIRED",
          APPROVED: "FRESH_FORWARD_RECOMPILE_TO_PLAN_READY_OLD_LEASE_REVOKED_NEW_PROMPT_REQUIRED",
          APPLYING: "DELEGATE_TO_REQUEST_MATRIX_FORWARD_PLAN_READY_OR_MAIN_ROLLBACK_REQUIRED",
          POSTCOMMIT_MAIN_ORIGIN: "ROLLBACK_REQUEST_TO_ROLLBACK_REQUIRED",
          BBR_INVENTORIED: "FORWARD_REQUEST_TO_BBR_PLAN_READY",
          BBR_PLAN_READY: "FRESH_FORWARD_RECOMPILE_UNCHANGED_NEW_CHALLENGE_AND_PROMPT_REQUIRED",
          BBR_HOST_APPROVED: "FRESH_FORWARD_RECOMPILE_TO_BBR_PLAN_READY_OLD_LEASE_REVOKED_NEW_PROMPT_REQUIRED",
          BBR_APPLIED: "ROLLBACK_REQUEST_TO_BBR_MANUAL_ACTION_REQUIRED",
          BBR_VERIFIED: "ROLLBACK_REQUEST_TO_BBR_MANUAL_ACTION_REQUIRED",
        }),
        forwardRequirements: Object.freeze(["GLOBAL_FORWARD_ELIGIBILITY_ALL_TRUE", "FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED", "FRESH_SCOPE_INVENTORIES", "FRESH_PROTECTED_LINE_OR_PROVEN_NA", "DOMAIN_IDENTITY_BINDING", "APPLYING_REPLAN_ONLY_AFTER_SUBPLAN_CURSOR_COMPLETE", "NO_OPEN_OPERATION", "ALL_COMMITS_KNOWN", "FRESH_REQUIRED_INVENTORIES", "NO_ROLLBACK_OR_MANUAL_OBLIGATION", "SAFE_PREREQUISITE_LEASE_RESOLVER_OPTIONAL_INSTALL_THEN_NODE"]),
        subplanChaining: SUBPLAN_CHAINING_POLICY,
      },
    }),
  }),

  plan_authorize: C({
    name: "plan_authorize",
    title: "Authorize an exact plan",
    description: "Consume the host prompt for one displayed plan digest and mint only its exact lease.",
    input: closed({
      run_id: S.RunRef, plan_ref: S.PlanRef, approval_challenge_ref: S.RuntimeRef,
      displayed_impact_digest: S.Digest, expected_ledger_digest: S.Digest,
      idempotency_key: S.IdempotencyKey,
    }),
    data: closed({
      approval_ref: S.ApprovalRef,
      lease_class: enumOf("NODE_P2", "NODE_INSTALL_P3", "HOST_P3", "ROLLBACK"),
      approved_operation_refs: arr(S.OperationRef, 1, 32),
      expires_at: S.Timestamp, plan_digest: S.Digest,
    }),
    annotations: A(false, false, true, false),
    policy: P({
      governingColumn: "scope_resolver", auth: ["HOST_PROMPT", "LOCAL_LEDGER"], lease: "HOST_PROMPT",
      allowedFrom: ["PLAN_READY", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED", "BBR_PLAN_READY", "BBR_MANUAL_ACTION_REQUIRED"],
      successByOrigin: {
        PLAN_READY: "APPROVED", ROLLBACK_REQUIRED: "ROLLING_BACK", MANUAL_ACTION_REQUIRED: "ROLLING_BACK",
        BBR_PLAN_READY: "BBR_HOST_APPROVED", BBR_MANUAL_ACTION_REQUIRED: "BBR_ROLLING_BACK",
      },
      failureTo: ["UNCHANGED"], requires: configureRequires("CURRENT_PLAN_AND_CHALLENGE", "DISPLAYED_IMPACT_DIGEST_MATCH", "HOST_PROMPT_ARRIVAL", "EXACT_SINGLE_LEASE_CLASS", "NO_LEASE_INHERITANCE_ACROSS_SUBPLANS", "APPROVED_OPERATION_REFS_EQUAL_PLAN_OPERATION_RESOLVER_OUTPUT", "FORWARD_APPROVAL_EFFECTIVE_EXPIRY_IS_MIN_NOMINAL_AND_ALL_CONSUMED_FINITE_EVIDENCE", "MAIN_ROLLBACK_AUTHORIZATION_DELEGATES_TO_SHARED_BBR_GATE", "BBR_ROLLBACK_AUTHORIZATION_REVALIDATES_EXACT_PLAN_BOUND_SOURCE_ROW", "BBR_ROLLBACK_AUTHORIZATION_REVALIDATES_EXACT_ONE_SERVER_DERIVED_APPLY_BASELINE_RECEIPT"),
      produces: [E("APPROVAL_LEASE", "LEASE_SPECIFIC")], invalidates: ["CHALLENGE_ON_CONSUME"],
      sideEffects: ["consume one host approval"], errors: ["INVALID_INPUT", "WRONG_STATE", "APPROVAL_STALE", "APPROVAL_REPLAYED", "BASELINE_DRIFT", "IDEMPOTENCY_CONFLICT", "INTERNAL_ERROR"],
      controls: { authorizationRouteByOrigin: Object.freeze({
        PLAN_READY: "APPROVED_FORWARD_PLAN",
        ROLLBACK_REQUIRED: "ROLLING_BACK_MAIN",
        MANUAL_ACTION_REQUIRED: "ROLLING_BACK_MAIN_AFTER_RECONCILIATION",
        BBR_PLAN_READY: "BBR_HOST_APPROVED_FORWARD_PLAN",
        BBR_MANUAL_ACTION_REQUIRED: "BBR_ROLLING_BACK_DEDICATED_PLAN",
      }),
      forwardAuthorizationAdditionalGate: "PLAN_READY_FORWARD_SCOPE_REQUIRES_CURRENT_GLOBAL_FORWARD_ELIGIBILITY_RECEIPT",
      forwardApprovalEffectiveExpiry: FORWARD_APPROVAL_EFFECTIVE_EXPIRY_POLICY,
      rollbackLeaseExpiryResolver: ROLLBACK_LEASE_EXPIRY_RESOLVER,
      hostP3MainGate: "BBR_PLAN_READY_REQUIRES_MAIN_PHASE_OLD_LINE_REVERIFIED_NODE_CURSOR_COMPLETE_REPORT_NOT_SEALED",
      bbrRollbackAuthorizationMainGate: BBR_ROLLBACK_MAIN_GATE,
      bbrRollbackAuthorizationSourceSet: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET,
      bbrApplyBaselineReceiptBinding: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
      mainRollbackAuthorizationBbrGate: MAIN_ROLLBACK_BBR_GATE,
      manualAuthorizationCauseGate: Object.freeze({
        MANUAL_ACTION_REQUIRED: "CURRENT_MAIN_ROLLBACK_PLAN_FROM_FRESH_RECONCILIATION_OR_CONCLUSIVE_KNOWN_COMMITTED_GRAPH",
        BBR_MANUAL_ACTION_REQUIRED: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.planAuthorize,
      }),
      },
    }),
  }),

  evidence_list: C({
    name: "evidence_list",
    title: "List redacted evidence",
    description: "Page through refs and masked summaries only; never return raw configuration, paths, credentials, keys, or log bodies.",
    input: closed({ run_id: S.RunRef, cursor: nullable(S.RuntimeRef), max_items: int(1, 100) }),
    data: Object.freeze({ ...closed({
      rows: arr(EVIDENCE_LIST_ROW_SCHEMA, 0, 100),
      next_cursor: nullable(S.RuntimeRef),
      continuation_state: enumOf("terminal", "has_more"),
      requested_max_items: int(1, 100),
      returned_item_count: int(0, 100),
      returned_item_count_matches_rows_length: constOf(true),
      rows_length_lte_requested_max_items: constOf(true),
      cursor_snapshot_binding_digest: S.Digest,
      rows_and_next_cursor_bound_to_same_snapshot_filter_and_last_row: constOf(true),
    }), allOf: Object.freeze([
      ...EVIDENCE_PAGE_LIMIT_CLAUSES,
      {
        if: { properties: { continuation_state: { const: "terminal" } }, required: ["continuation_state"] },
        then: { properties: { next_cursor: { type: "null" } }, required: ["rows", "next_cursor"] },
        else: { properties: { next_cursor: S.RuntimeRef, rows: { type: "array", items: EVIDENCE_LIST_ROW_SCHEMA, minItems: 1, maxItems: 100 } }, required: ["rows", "next_cursor"] },
      },
    ]) }),
    annotations: A(true, false, true, false),
    policy: P({
      auth: ["LOCAL_LEDGER"], allowedFrom: READ_ORIGINS, successByOrigin: same(READ_ORIGINS),
      requires: ["RUN_CREATED", "CURSOR_BOUND_TO_RUN_SNAPSHOT_FILTER_AND_LAST_EMITTED_ROW"], errors: BASE_ERRORS,
      controls: {
        pagination: Object.freeze({
          cursorAuthority: "SERVER_MINTED_OPAQUE_CURSOR_FROM_PREVIOUS_EVIDENCE_LIST_PAGE",
          binding: Object.freeze(["run_id", "ledger_snapshot_digest", "fixed_redaction_filter", "last_emitted_row_identity"]),
          maxItemsAffectsBinding: false,
          continuation: "STRICTLY_AFTER_LAST_EMITTED_ROW_IN_SAME_BOUND_SNAPSHOT",
          responseCoupling: Object.freeze({
            requestedMaxItems: "EXACT_INPUT_MAX_ITEMS",
            rowsLength: "RETURNED_ITEM_COUNT_EQUALS_ROWS_LENGTH_AND_LTE_EXACT_INPUT_MAX_ITEMS",
            terminalIff: "NEXT_CURSOR_NULL_IFF_NO_REMAINING_ROWS_IN_BOUND_SNAPSHOT",
            hasMore: "NEXT_CURSOR_NON_NULL_AND_ROWS_NONEMPTY_IFF_REMAINING_ROWS_EXIST",
            requiredDataFields: Object.freeze(["rows", "next_cursor", "continuation_state", "requested_max_items", "returned_item_count", "returned_item_count_matches_rows_length", "rows_length_lte_requested_max_items", "cursor_snapshot_binding_digest", "rows_and_next_cursor_bound_to_same_snapshot_filter_and_last_row"]),
          }),
          mismatch: "INVALID_INPUT_NO_PAGE",
        }),
      },
    }),
  }),

  completion_evaluate: C({
    name: "completion_evaluate",
    title: "Evaluate audit or E2E completion",
    description: "Return exactly one server-derived result label: seal an audit report from the audit inventory set, seal an authenticated-E2E report from the exact seven predicates, or return an honest pending result without a report or state change.",
    input: closed({ run_id: S.RunRef, expected_ledger_digest: S.Digest, idempotency_key: S.IdempotencyKey }),
    data: Object.freeze({ ...closed({
      report_ref: nullable(S.ArtifactRef), report_digest: nullable(S.Digest),
      label: enumOf("audit_complete", "configured_not_verified", "end_to_end_verified"),
      satisfied_requirement_ids: Object.freeze({ type: "array", items: enumOf(...AUDIT_COMPLETION_REQUIREMENTS, ...AUTHENTICATED_E2E_POLICY.requiredEvidence), minItems: 0, maxItems: 7, uniqueItems: true }),
      all_required_true: bool, residual_disclosure_ref: nullable(S.EvidenceRef),
    }), allOf: Object.freeze([
      {
        if: { properties: { label: { const: "audit_complete" } }, required: ["label"] },
        then: { properties: {
          report_ref: S.ArtifactRef,
          report_digest: S.Digest,
          satisfied_requirement_ids: {
            type: "array",
            items: enumOf(...AUDIT_COMPLETION_REQUIREMENTS),
            minItems: 5, maxItems: 5, uniqueItems: true,
          },
          all_required_true: constOf(true),
          residual_disclosure_ref: { type: "null" },
        } },
      },
      {
        if: { properties: { label: { const: "configured_not_verified" } }, required: ["label"] },
        then: { properties: {
          report_ref: { type: "null" },
          report_digest: { type: "null" },
          satisfied_requirement_ids: { type: "array", items: enumOf(...AUTHENTICATED_E2E_POLICY.requiredEvidence), minItems: 0, maxItems: 6, uniqueItems: true },
          all_required_true: constOf(false),
          residual_disclosure_ref: S.EvidenceRef,
        } },
      },
      {
        if: { properties: { label: { const: "end_to_end_verified" } }, required: ["label"] },
        then: { properties: {
          report_ref: S.ArtifactRef,
          report_digest: S.Digest,
          satisfied_requirement_ids: { type: "array", items: enumOf(...AUTHENTICATED_E2E_POLICY.requiredEvidence), minItems: 7, maxItems: 7, uniqueItems: true },
          all_required_true: constOf(true),
          residual_disclosure_ref: S.EvidenceRef,
        } },
      },
    ]) }),
    annotations: A(false, false, true, false),
    policy: P({
      auth: ["LOCAL_LEDGER"], allowedFrom: ["INVENTORIED", ...CONFIGURED_PENDING_ORIGINS],
      successByOrigin: Object.fromEntries(["INVENTORIED", ...CONFIGURED_PENDING_ORIGINS].map((origin) => [origin, "DELEGATE_TO_RESULT_BY_LABEL_MATRIX"])),
      failureTo: ["UNCHANGED"],
      requires: ["COMPLETION_RESULT_BY_LABEL_IS_SOLE_GATE_AND_RESOLVER"],
      produces: [E("SEALED_COMPLETION_REPORT", "NO_TTL_CONDITIONAL_BY_RESULT_LABEL"), E("RESIDUAL_DISCLOSURE", "NO_TTL_CONDITIONAL_BY_RESULT_LABEL")],
      invalidates: ["OLDER_UNSEALED_REPORT"], sideEffects: ["DELEGATE_TO_RESULT_BY_LABEL_MATRIX"], errors: ["INVALID_INPUT", "WRONG_STATE", "EVIDENCE_STALE", "PROTECTED_LINE_UNPROVEN", "CDN_NOT_VERIFIED", "RECONCILIATION_REQUIRED", "IDEMPOTENCY_CONFLICT", "INTERNAL_ERROR"],
      controls: {
        resultByLabel: COMPLETION_RESULT_BY_LABEL,
        genericSuccessResolver: "DELEGATE_TO_RESULT_BY_LABEL_MATRIX",
        crossColumnGateRunMode: Object.freeze({
          audit: "EXEMPT_BBR_NOT_REQUESTED_IS_IMMUTABLE_LEDGER_FACT_NO_BBR_CLOSE_OR_RECEIPT",
          configure: "ENFORCE_CROSS_COLUMN_GATE_BELOW",
        }),
        crossColumnGate: Object.freeze({
          BBR_NOT_REQUESTED: "DENY_REQUIRE_NOT_REQUESTED_CLOSE_AND_BBR_CLOSED_NOT_REQUESTED_RECEIPT",
          BBR_PENDING: "DENY_REQUIRE_HOST_P3",
          BBR_INVENTORIED: "DENY_REQUIRE_HOST_P3_OR_HONEST_NO_WRITE_CLOSE",
          BBR_PLAN_READY: "DENY_REQUIRE_HOST_P3_AUTHORIZATION",
          BBR_HOST_APPROVED: "DENY_REQUIRE_HOST_P3_EXECUTION",
          BBR_APPLIED: "DENY_REQUIRE_VERIFY_AND_POST_APPLY_MAIN_EVIDENCE_REFRESH",
          BBR_VERIFIED: "DENY_REQUIRE_BBR_ACCEPTED_CLOSE_AND_BBR_CLOSED_VERIFIED_RECEIPT",
          BBR_ROLLING_BACK: "DENY_REQUIRE_DEDICATED_ROLLBACK_COMPLETION",
          BBR_ROLLED_BACK: "DENY_REQUIRE_BBR_PARTIAL_CLOSE_AND_BBR_CLOSED_ROLLED_BACK_RECEIPT",
          BBR_MANUAL_ACTION_REQUIRED: "DENY_REQUIRE_RECONCILE_OR_DEDICATED_ROLLBACK",
          BBR_CLOSED: "ALLOW_ONLY_ONE_CURRENT_SERVER_RESOLUTION_RECEIPT_FROM_BBR_CLOSED_NOT_REQUESTED_OR_VERIFIED_OR_ROLLED_BACK_OR_NO_WRITE_SET",
        }),
        postTemplateResolution: PLAN_OPERATION_RESOLVER.postTemplateResolution,
      },
    }),
  }),

  run_close: C({
    name: "run_close",
    title: "Close main or BBR scope",
    description: "Close only main or BBR under the exhaustive outcome matrix; accepted main requires the sealed authenticated-E2E report and acknowledgement.",
    input: closed({
      run_id: S.RunRef, scope: enumOf("main", "bbr"),
      outcome: enumOf("accepted", "audit_complete", "not_requested", "partial", "abandoned"),
      expected_ledger_digest: S.Digest, idempotency_key: S.IdempotencyKey,
    }),
    data: Object.freeze({ ...closed({
      closure_ref: S.ClosureRef, scope: enumOf("main", "bbr"),
      outcome: enumOf("accepted", "audit_complete", "not_requested", "partial", "abandoned"),
      closure_digest: S.Digest, residual_disclosure_ref: nullable(S.EvidenceRef),
      bound_completion_label: nullable(enumOf("audit_complete", "end_to_end_verified")),
      bound_completion_report_digest: nullable(S.Digest),
      final_ledger_digest: S.Digest,
    }), allOf: Object.freeze([
      {
        if: { anyOf: [
          { properties: { scope: { const: "main" }, outcome: { enum: ["accepted", "partial", "abandoned"] } }, required: ["scope", "outcome"] },
          { properties: { scope: { const: "bbr" }, outcome: { const: "partial" } }, required: ["scope", "outcome"] },
        ] },
        then: { properties: { residual_disclosure_ref: S.EvidenceRef } },
        else: { properties: { residual_disclosure_ref: { type: "null" } } },
      },
      {
        if: { properties: { scope: { const: "main" }, outcome: { const: "accepted" } }, required: ["scope", "outcome"] },
        then: { properties: { bound_completion_label: { type: "string", const: "end_to_end_verified" }, bound_completion_report_digest: S.Digest } },
        else: {
          if: { properties: { scope: { const: "main" }, outcome: { const: "audit_complete" } }, required: ["scope", "outcome"] },
          then: { properties: { bound_completion_label: { type: "string", const: "audit_complete" }, bound_completion_report_digest: S.Digest } },
          else: { properties: { bound_completion_label: { type: "null" }, bound_completion_report_digest: { type: "null" } } },
        },
      },
    ]) }),
    annotations: A(false, false, true, false),
    policy: P({
      governingColumn: "scope_resolver", auth: ["HOST_PROMPT", "LOCAL_LEDGER"], lease: "HOST_PROMPT",
      allowedFrom: ["NEW", "INVENTORIED", "PLAN_READY", "APPROVED", "DELIVERY_REPORT_SEALED", "ROLLED_BACK", "MANUAL_ACTION_REQUIRED", "BBR_NOT_REQUESTED", "BBR_PENDING", "BBR_INVENTORIED", "BBR_PLAN_READY", "BBR_HOST_APPROVED", "BBR_VERIFIED", "BBR_ROLLED_BACK", "BBR_MANUAL_ACTION_REQUIRED"],
      successByOrigin: {
        NEW: "CLOSED", INVENTORIED: "CLOSED", PLAN_READY: "CLOSED", APPROVED: "CLOSED", DELIVERY_REPORT_SEALED: "CLOSED", ROLLED_BACK: "CLOSED", MANUAL_ACTION_REQUIRED: "CLOSED",
        BBR_NOT_REQUESTED: "BBR_CLOSED", BBR_PENDING: "BBR_CLOSED", BBR_INVENTORIED: "BBR_CLOSED", BBR_PLAN_READY: "BBR_CLOSED", BBR_HOST_APPROVED: "BBR_CLOSED", BBR_VERIFIED: "BBR_CLOSED", BBR_ROLLED_BACK: "BBR_CLOSED", BBR_MANUAL_ACTION_REQUIRED: "BBR_CLOSED",
      },
      failureTo: ["UNCHANGED"], requires: ["CORE_CLOSE_MATRIX", "OUTCOME_BOUND_RESIDUAL", "RECONCILIATION_OUTCOME_RESOLVER_WHEN_MANUAL", "NO_UNKNOWN_COMMIT", "NO_UNREVERSED_APPLY", "AUTHENTICATED_E2E_GATE_FOR_MAIN_ACCEPTED", "BBR_CLOSE_DELEGATES_TO_HAPPY_PATH_OR_MAIN_NO_WRITE_RECOVERY_GATE_MAIN_SCOPE_NOT_APPLICABLE", "LIVE_HOST_PROMPT", "SERVER_RECORDED_ACKNOWLEDGEMENT_NOT_CALLER_INPUT"],
      produces: [E("CLOSURE_RECEIPT", "NO_TTL"), E("RESIDUAL_DISCLOSURE", "NO_TTL_CONDITIONAL")],
      sideEffects: ["record non-destructive closure", "purge unreferenced run-owned transient refs"], errors: ["INVALID_INPUT", "WRONG_STATE", "EVIDENCE_STALE", "PROTECTED_LINE_UNPROVEN", "RECONCILIATION_REQUIRED", "IDEMPOTENCY_CONFLICT", "INTERNAL_ERROR"],
      controls: {
        closeMatrix: CORE_CLOSE_MATRIX,
        mainOutcomeByRunModeAndReportLabel: MAIN_CLOSE_OUTCOME_RESOLVER,
        mainRolledBackPartialGate: Object.freeze({
          origin: "ROLLED_BACK", outcome: "partial",
          requires: Object.freeze(["IMMUTABLE_MAIN_ROLLBACK_RECEIPT", "FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_MAIN_ROLLBACK_RECEIPT", "ONE_CURRENT_BBR_CLOSED_NOT_REQUESTED_OR_NO_WRITE_OR_VERIFIED_OR_ROLLED_BACK_RECEIPT"]),
          retainedAcceptedBbr: Object.freeze({
            receipt: "BBR_CLOSED_VERIFIED_RECEIPT",
            reopenBbrColumn: false,
            mainPartialResidualMustDisclose: "RETAINED_ACCEPTED_BBR_CHANGE_AND_EXACT_CHANGE_RECEIPT",
          }),
          noUnreversedApplyScope: "MAIN_ROLLBACK_GRAPH_ONLY_BBR_IS_INDEPENDENT_AND_MUST_HAVE_ONE_CLOSED_RESOLUTION_RECEIPT",
          inverseMayNotReexecuteForProbeRetry: true,
        }),
        reconciliationOutcomeResolver: RECONCILIATION_OUTCOME_RESOLVER,
        manualCloseByReconciliation: Object.freeze({
          main: Object.freeze({
            origin: "MANUAL_ACTION_REQUIRED", observation: "PROVEN_NOT_COMMITTED",
            failureContext: "MAIN_EXTERNAL_MUTATION", priorCommittedChangeCount: 0,
            requiredNextAction: "HOST_PROMPT_ABANDON_NO_WRITE_RESIDUAL_THEN_NEW_RUN",
            outcome: "abandoned", destination: "CLOSED", residual: "NON_NULL_NO_WRITE_RESIDUAL",
          }),
          bbr: Object.freeze({
            origin: "BBR_MANUAL_ACTION_REQUIRED", observation: "PROVEN_NOT_COMMITTED",
            failureContext: "BBR_EXTERNAL_MUTATION", originalOperationClass: "BBR_APPLY", applyReceipt: "NULL",
            requiredNextAction: "HOST_PROMPT_BBR_PARTIAL_NO_WRITE_RECEIPT_THEN_CONTINUE_MAIN",
            outcome: "partial", destination: "BBR_CLOSED", mainBarrierProjection: "BBR_CLOSED_NO_WRITE_RECEIPT",
          }),
          otherManualObservations: "CLOSE_FORBIDDEN",
          evidenceFreshness: "PT5M_AND_CURRENT_LEDGER_DIGEST",
        }),
        acceptedEvidenceLabelByScope: Object.freeze({ main: "end_to_end_verified", bbr: "BBR_VERIFY_ALL_TRUE" }),
        bbrCloseMainGate: Object.freeze({
          appliesToEveryBbrOutcome: true,
          requiredRunMode: "configure",
          happyPath: Object.freeze({
            requiredMainPhase: "OLD_LINE_REVERIFIED",
            nodeTemplateCursorComplete: true,
            completionReportSealed: false,
            mainClosed: false,
          }),
          mainNoWriteRecovery: Object.freeze({
            allowedMainPhases: Object.freeze(["ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED", "ROLLED_BACK"]),
            currentMainRecoveryObligation: true,
            completionReportSealed: false,
            mainClosed: false,
            noBbrApplyReceipt: true,
            noOpenBbrOperation: true,
            notRequested: "ALLOW_NOT_REQUESTED_ONLY_WITH_NO_BBR_APPLY_RECEIPT_AND_NO_OPEN_BBR_OPERATION",
            preApply: "ALLOW_NO_WRITE_PARTIAL_ONLY_FROM_PENDING_INVENTORIED_PLAN_READY_OR_HOST_APPROVED_WITH_NO_BBR_APPLY_RECEIPT_AND_NO_OPEN_BBR_OPERATION",
            committedOrUnknownApply: "DENY_MAIN_RECOVERY_CANNOT_START_UNTIL_DEDICATED_BBR_ROLLBACK_AND_CLOSE_COMPLETE_AT_MAIN_OLD_LINE_REVERIFIED_OR_RECONCILIATION_PROVES_NOT_COMMITTED",
            rolledBack: "ALLOW_PARTIAL_TO_BBR_CLOSED_ROLLED_BACK_RECEIPT",
          }),
          mismatch: "WRONG_STATE_NO_CLOSURE_RECEIPT",
          auditBehavior: "FORBIDDEN_NOT_REQUIRED_AUDIT_USES_IMMUTABLE_BBR_NOT_REQUESTED_LEDGER_FACT",
        }),
        bbrResolvedCloseProjections: Object.freeze({
          BBR_NOT_REQUESTED: Object.freeze({ outcome: "not_requested", projection: "BBR_CLOSED_NOT_REQUESTED_RECEIPT", residual: "NULL" }),
          BBR_VERIFIED: Object.freeze({ outcome: "accepted", projection: "BBR_CLOSED_VERIFIED_RECEIPT" }),
          BBR_ROLLED_BACK: Object.freeze({ outcome: "partial", projection: "BBR_CLOSED_ROLLED_BACK_RECEIPT" }),
        }),
        bbrNoWriteClose: Object.freeze({
          allowedOrigins: Object.freeze(["BBR_PENDING", "BBR_INVENTORIED", "BBR_PLAN_READY", "BBR_HOST_APPROVED", "BBR_MANUAL_ACTION_REQUIRED"]),
          outcome: "partial",
          destination: "BBR_CLOSED",
          requires: Object.freeze(["NO_BBR_APPLY_RECEIPT", "NO_OPEN_BBR_OPERATION", "HONEST_NOT_STARTED_OR_UNSUPPORTED_RESIDUAL", "IF_MANUAL_FRESH_RECONCILIATION_PROOF_PROVEN_NOT_COMMITTED_BBR_APPLY"]),
          mainBarrierProjection: "BBR_CLOSED_NO_WRITE_RECEIPT",
        }),
      },
    }),
  }),

  rollback_run: C({
    name: "rollback_run",
    title: "Rollback run-owned changes",
    description: "Execute and read back only the exact current ordered atomic-stage selection frozen inside the main rollback plan; each completed stage commits its own durable receipt before the next stage and completed stages never replay. Caller cannot select stages, changes, order, paths, helpers, inverse content, or the rb01 operation. Protected-line proof is a separate retryable old_line_verify step after the immutable aggregate rollback receipt.",
    input: closed({
      run_id: S.RunRef, plan_ref: S.PlanRef, approval_ref: S.ApprovalRef,
      expected_ledger_digest: S.Digest, idempotency_key: S.IdempotencyKey,
    }),
    data: Object.freeze({ ...closed({
      rollback_receipt_ref: S.ReceiptRef, reversed_change_refs: arr(S.ChangeRef, 1, 32),
      completed_atomic_stage_ids: Object.freeze({ ...arr(enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS), 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
      atomic_stage_receipt_refs: arr(S.ReceiptRef, 1, MAIN_ROLLBACK_ATOMIC_STAGE_IDS.length),
      atomic_stage_and_receipt_cardinality_equal: constOf(true),
      atomic_stage_set_exactly_equals_frozen_plan_selection: constOf(true),
      final_atomic_stage_id: enumOf(...MAIN_ROLLBACK_ATOMIC_STAGE_IDS),
      final_atomic_stage_receipt_ref: S.ReceiptRef,
      final_atomic_stage_is_last_selected_stage: constOf(true),
      final_atomic_stage_receipt_is_last_ordered_stage_receipt: constOf(true),
      final_stage_and_aggregate_receipt_same_local_ledger_transaction: constOf(true),
      finalization_receipts_both_visible: constOf(true),
      aggregate_receipt_binds_exact_selected_atomic_stage_receipts: constOf(true),
      finalization_transaction_commit_digest: S.Digest,
      aggregate_atomic_stage_receipts_complete: constOf(true),
      retained_compensation_pairs: arr(closed({
        change_ref: S.ChangeRef,
        compensation_receipt_ref: S.ReceiptRef,
      }), 0, 32),
      retained_set_binding_digest: nullable(S.Digest),
      residual_binds_exact_retained_set: constOf(true),
      inverse_readbacks_all_true: constOf(true),
      retained_compensation_residual_ref: nullable(S.EvidenceRef), final_digest: S.Digest,
    }), allOf: Object.freeze([
      {
        if: { properties: { retained_compensation_residual_ref: { type: "null" } }, required: ["retained_compensation_residual_ref"] },
        then: { properties: {
          retained_compensation_pairs: { type: "array", items: closed({ change_ref: S.ChangeRef, compensation_receipt_ref: S.ReceiptRef }), minItems: 0, maxItems: 0 },
          retained_set_binding_digest: { type: "null" },
        } },
        else: { properties: {
          retained_compensation_pairs: arr(closed({ change_ref: S.ChangeRef, compensation_receipt_ref: S.ReceiptRef }), 1, 32),
          retained_set_binding_digest: S.Digest,
        } },
      },
    ]) }),
    annotations: A(false, true, true, true),
    policy: P({
      governingColumn: "main", auth: ["LOCAL_LEDGER", "SSH_ORIGIN_WRITE", "CF_NODE_DNS", "BROKER_XUI_FIXED", "BROKER_PROFILE_FIXED", "BROKER_ORIGIN_CA_KEY_CUSTODY"], lease: "ROLLBACK",
      allowedFrom: ["ROLLING_BACK"],
      successByOrigin: { ROLLING_BACK: "ROLLED_BACK" },
      failureTo: ["UNCHANGED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(ROLLBACK_EXECUTION_BINDING_REQUIREMENT, "SERVER_FROZEN_ORDERED_ATOMIC_STAGE_SELECTION", "EXACT_CURRENT_FIRST_REMAINING_ATOMIC_STAGE_ONLY", "OWNERSHIP_AND_CURRENT_DIGEST_MATCH", "DURABLE_STAGE_RECEIPT_BEFORE_NEXT_STAGE", "ATOMIC_STAGE_READBACKS_ALL_TRUE", "MAIN_ROLLBACK_BBR_GATE_ALL_TRUE"),
      produces: [E("ROLLBACK_ATOMIC_STAGE_RECEIPTS", "NO_TTL"), E("ROLLBACK_FINALIZATION_ATOMIC_RECEIPT_PAIR", "NO_TTL"), E("ROLLBACK_RECEIPT", "NO_TTL"), E("MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY_ADMISSION_RECEIPT", "NO_TTL_CONDITIONAL")], invalidates: ["DESCENDANTS_OF_REVERSED_CHANGES"],
      rollbackClass: "not_applicable", rollbackAction: "THIS_IS_THE_BOUNDED_RECOVERY_EXECUTOR",
      sideEffects: ["execute exact inverse or bounded compensation for main-column run-owned changes; BBR is excluded"], errors: ["INVALID_INPUT", "UNAUTHORIZED_TARGET", "WRONG_STATE", "APPROVAL_REQUIRED", "APPROVAL_STALE", "BASELINE_DRIFT", "CONFLICT_DETECTED", "ROLLBACK_UNSAFE", "PROBE_FAILED", "UNKNOWN_COMMIT_STATE", "RECONCILIATION_REQUIRED", "MANUAL_ACTION_REQUIRED", "INTERNAL_ERROR"],
      controls: {
        cursorBinding: Object.freeze({ template: "MAIN_ROLLBACK_V1", stepId: "MAIN_ROLLBACK_V1:rb01", operationSelectorInput: false, resolution: ROLLBACK_EXECUTION_BINDING_REQUIREMENT }),
        inverseOnly: true,
        protectedLineProbeInsideExecutor: false,
        postInverseStep: "old_line_verify:post_main_rollback_bound_to_exact_rollback_receipt",
        mainRollbackBbrGate: MAIN_ROLLBACK_BBR_GATE,
        rollbackLeaseExpiryResolver: ROLLBACK_LEASE_EXPIRY_RESOLVER,
        zeroDispatchLeaseExpiry: ROLLBACK_LEASE_EXPIRY_RESOLVER.rows.MAIN_ZERO_INVERSE_BEFORE_DISPATCH,
        prefixResume: PLAN_OPERATION_RESOLVER.scopes.MAIN_ROLLBACK.prefixResume,
        atomicStages: MAIN_ROLLBACK_ATOMIC_STAGES,
        atomicStageExecution: Object.freeze({
          dispatch: "EXACT_CURRENT_FIRST_REMAINING_FROZEN_ATOMIC_STAGE_ONLY",
          durableReceiptBeforeNextStage: true,
          finalAggregate: "COMPLETED_STAGE_IDS_AND_RECEIPTS_EXACTLY_EQUAL_FROZEN_SELECTION",
          finalizationTransaction: MAIN_ROLLBACK_FINALIZATION_TRANSACTION,
          completedStageReplay: false,
        }),
        retainedCompensationCoupling: Object.freeze({
          pairArray: "CLOSED_CHANGE_REF_AND_COMPENSATION_RECEIPT_REF_PAIR_PER_RETAINED_GRAPH_NODE",
          residualNullIffPairSetEmpty: true,
          residualNonNullIffPairSetNonEmpty: true,
          residualAndBindingDigest: "EXACT_SERVER_FROZEN_RETAINED_PAIR_SET",
          requiredRetainedClasses: Object.freeze(["ORIGIN_CA_REMOTE_PUBLIC_ISSUANCE_METADATA", "PROFILE_UNPROVABLE_COPIES_WHEN_PRESENT"]),
          omission: "INTERNAL_ERROR_NO_ROLLBACK_SUCCESS_RECEIPT",
        }),
        failureContext: mutationFailureControl("MAIN_ROLLBACK_EXECUTOR"),
      },
    }),
  }),

  origin_inventory: C({
    name: "origin_inventory", title: "Inventory the registered origin",
    description: "Read masked host, listener, service, installer-adapter, certificate and stable-slot facts through fixed helper operations.",
    input: RefreshInput(),
    data: Object.freeze({ ...closed({
      origin_inventory_ref: S.EvidenceRef, host_fingerprint_digest: S.Digest,
      os_family: enumOf("debian", "ubuntu", "other_supported", "unsupported"),
      installed_adapter_refs: arr(S.RuntimeRef, 0, 16), stable_service_slot_refs: arr(S.RuntimeRef, 0, 8),
      stable_service_slot_roles: { type: "array", items: enumOf("fullchain", "private_key"), minItems: 0, maxItems: 2, uniqueItems: true },
      current_certificate_refs: arr(S.CertificateRef, 0, 8), node_hostname_coverage: bool,
      sufficient_certificate_validity: bool,
      certificate_validity_evaluated_at: S.Timestamp,
      minimum_remaining_validity: constOf("P30D"),
      selected_certificate_not_after: nullable(S.Timestamp),
      safe_stable_certificate_reuse_eligible: bool,
      safe_stable_certificate_slot_evidence_ref: nullable(S.EvidenceRef),
      safe_stable_certificate_issuer: nullable(enumOf("public", "origin_ca")),
      safe_stable_certificate_trust: nullable(enumOf("system_public", "recognized_cloudflare_origin_ca")),
      certificate_key_pair_matches: bool,
      origin_ca_dedicated_slot_status: enumOf("absent_root_owned_available", "preexisting", "foreign", "unsafe", "unavailable"),
      origin_ca_dedicated_slot_parent_digest: S.Digest,
      nginx_installation_status: enumOf("supported_existing", "absent", "unsupported", "ambiguous"),
      public_tls_listener_owner: enumOf("nginx_safe", "foreign", "absent", "ambiguous"),
      node_server_name_conflict: bool, websocket_path_conflict: bool,
      owned_include_slot_available: bool, sole_exact_node_route_observed: bool,
      listener_digest: S.Digest, nginx_effective_config_digest: S.Digest,
      registered_origin_address_type: enumOf("A", "AAAA"),
      current_origin_address_digest: S.Digest,
    }), allOf: Object.freeze([
      {
        if: { properties: { safe_stable_certificate_reuse_eligible: { const: true } }, required: ["safe_stable_certificate_reuse_eligible"] },
        then: { properties: {
          node_hostname_coverage: constOf(true),
          stable_service_slot_refs: { type: "array", items: S.RuntimeRef, minItems: 2, maxItems: 2, uniqueItems: true },
          stable_service_slot_roles: { type: "array", items: enumOf("fullchain", "private_key"), minItems: 2, maxItems: 2, uniqueItems: true },
          safe_stable_certificate_slot_evidence_ref: S.EvidenceRef,
          safe_stable_certificate_issuer: enumOf("public", "origin_ca"),
          safe_stable_certificate_trust: enumOf("system_public", "recognized_cloudflare_origin_ca"),
          certificate_key_pair_matches: constOf(true),
          sufficient_certificate_validity: constOf(true),
          selected_certificate_not_after: S.Timestamp,
        } },
        else: { properties: {
          safe_stable_certificate_slot_evidence_ref: { type: "null" },
          safe_stable_certificate_issuer: { type: "null" },
          safe_stable_certificate_trust: { type: "null" },
        } },
      },
      {
        if: { properties: { safe_stable_certificate_issuer: { const: "public" } }, required: ["safe_stable_certificate_issuer"] },
        then: { properties: { safe_stable_certificate_trust: { type: "string", const: "system_public" } } },
      },
      {
        if: { properties: { safe_stable_certificate_issuer: { const: "origin_ca" } }, required: ["safe_stable_certificate_issuer"] },
        then: { properties: { safe_stable_certificate_trust: { type: "string", const: "recognized_cloudflare_origin_ca" } } },
      },
    ]) }),
    annotations: A(true, false, true, true),
    policy: P({
      auth: ["SSH_ORIGIN_READ"], allowedFrom: MAIN_INVENTORY_ORIGINS,
      successByOrigin: { ...same(MAIN_INVENTORY_ORIGINS), NEW: "INVENTORIED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: ["REGISTERED_ORIGIN_TARGET", "ROLE_BOUND_SSH_IDENTITY", "FIXED_INVENTORY_HELPER", "ACTIVE_NODE_CHECKPOINT_OR_OFF_CURSOR_REFRESH_RESOLVER"],
      produces: [E("ORIGIN_INVENTORY", "PT15M"), E("SAFE_STABLE_SLOT_EVIDENCE", "PT15M_CONDITIONAL"), E("CURRENT_ORIGIN_ADDRESS_DIGEST", "PT15M")], invalidates: ["DELEGATE_TO_ACTIVE_NODE_OR_OFF_CURSOR_INVENTORY_REFRESH_RESOLVER"],
      errors: READ_ERRORS,
      controls: {
        nginxNoClobberObservation: Object.freeze({
          requiredStatus: "supported_existing", safeListenerOwners: Object.freeze(["nginx_safe", "absent"]),
          conflictFields: Object.freeze(["node_server_name_conflict", "websocket_path_conflict"]),
          createOnlyIncludeRequires: "owned_include_slot_available",
          installNginx: false,
        }),
        originAddressProjection: Object.freeze({ type: "A_OR_AAAA_ONLY", value: "HMAC_DIGEST_ONLY_NO_RAW_ADDRESS", bindingPolicy: LOW_ENTROPY_BINDING_POLICY }),
        safeReuseProjection: Object.freeze({
          evidenceNonNullIffEligible: true,
          eligibilityIff: Object.freeze(["NODE_HOSTNAME_COVERAGE_TRUE", "SUFFICIENT_VALIDITY_P30D_FROM_TRUSTED_SERVER_CLOCK_TRUE", "STABLE_ROOT_OWNED_SERVICE_SLOTS_TRUE", "CERTIFICATE_KEY_PAIR_MATCHES_TRUE", "ISSUER_AND_RECOGNIZED_TRUST_MATCH"]),
          stableSlotProjection: "EXACT_TWO_UNIQUE_RUNTIME_REFS_WITH_EXACT_FULLCHAIN_AND_PRIVATE_KEY_ROLES",
          validityPolicy: PLAN_OPERATION_RESOLVER.certificateReuseValidity,
          trustByIssuer: Object.freeze({ public: "system_public", origin_ca: "recognized_cloudflare_origin_ca" }),
          deployWriteRequired: false,
        }),
        originCaSlotProjection: Object.freeze({
          eligibleStatus: "absent_root_owned_available",
          createPolicy: "DESCRIPTOR_RELATIVE_NOFOLLOW_O_EXCL",
          preexistingUnsafeOrForeign: "DENY_NO_BACKUP_REPLACE_OR_ADOPT",
          callerSelectableSlot: false,
        }),
        activeNodeEvidenceRefreshCheckpoint: Object.freeze({ common: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT, tool: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.checkpointByTool.origin_inventory }),
        activeCheckpointDriftResolver: ACTIVE_CHECKPOINT_DRIFT_RESOLVER,
        offCursorRefresh: Object.freeze({ cursorAdvance: false, invalidates: Object.freeze(["OLDER_ORIGIN_INVENTORY_AND_DESCENDANTS", "DEPENDENT_PLAN_CHALLENGE_AND_APPROVAL_LEASE"]) }),
      },
    }),
  }),

  cloudflare_inventory: C({
    name: "cloudflare_inventory", title: "Inventory the registered Cloudflare zone",
    description: "Read one registered zone, the dedicated hostname slot, relevant settings and certificate coverage without changing them.",
    input: RefreshInput(),
    data: Object.freeze({ ...closed({
      cloudflare_inventory_ref: S.EvidenceRef, zone_ref: S.RuntimeRef,
      record_observation_case: enumOf("ABSENT_AVAILABLE", "SAME_RUN_CURRENT_UNPROXIED", "SAME_RUN_CURRENT_PROXIED", "FOREIGN_OR_STALE", "AMBIGUOUS_MULTIPLE"),
      record_count_category: enumOf("zero", "one", "multiple"),
      current_record_ref: nullable(S.RecordRef), proxy_enabled: nullable(bool),
      current_record_type: nullable(enumOf("A", "AAAA")),
      current_record_digest: nullable(S.Digest),
      current_record_origin_address_binding_digest: nullable(S.Digest),
      current_record_owned_by_run: nullable(bool),
      record_matches_current_origin_address_digest: nullable(bool),
      ssl_mode: enumOf("off", "flexible", "full", "strict", "origin_pull", "unknown"), websockets_enabled: bool,
      hostname_binding_digest: S.Digest,
    }), allOf: Object.freeze([
      {
        if: { properties: { record_observation_case: { const: "ABSENT_AVAILABLE" } }, required: ["record_observation_case"] },
        then: { properties: { record_count_category: { const: "zero" }, current_record_ref: { type: "null" }, current_record_type: { type: "null" }, current_record_digest: { type: "null" }, current_record_origin_address_binding_digest: { type: "null" }, current_record_owned_by_run: { type: "null" }, record_matches_current_origin_address_digest: { type: "null" }, proxy_enabled: { type: "null" } }, required: CLOUDFLARE_RECORD_OBSERVATION_DEPENDENT_FIELDS },
      },
      {
        if: { properties: { record_observation_case: { const: "SAME_RUN_CURRENT_UNPROXIED" } }, required: ["record_observation_case"] },
        then: { properties: { record_count_category: { const: "one" }, current_record_ref: S.RecordRef, current_record_type: enumOf("A", "AAAA"), current_record_digest: S.Digest, current_record_origin_address_binding_digest: S.Digest, current_record_owned_by_run: { const: true }, record_matches_current_origin_address_digest: { const: true }, proxy_enabled: { const: false } }, required: CLOUDFLARE_RECORD_OBSERVATION_DEPENDENT_FIELDS },
      },
      {
        if: { properties: { record_observation_case: { const: "SAME_RUN_CURRENT_PROXIED" } }, required: ["record_observation_case"] },
        then: { properties: { record_count_category: { const: "one" }, current_record_ref: S.RecordRef, current_record_type: enumOf("A", "AAAA"), current_record_digest: S.Digest, current_record_origin_address_binding_digest: S.Digest, current_record_owned_by_run: { const: true }, record_matches_current_origin_address_digest: { const: true }, proxy_enabled: { const: true } }, required: CLOUDFLARE_RECORD_OBSERVATION_DEPENDENT_FIELDS },
      },
      {
        if: { properties: { record_observation_case: { const: "FOREIGN_OR_STALE" } }, required: ["record_observation_case"] },
        then: { properties: { record_count_category: { const: "one" }, current_record_ref: S.RecordRef, current_record_type: enumOf("A", "AAAA"), current_record_digest: S.Digest, current_record_origin_address_binding_digest: S.Digest, proxy_enabled: bool }, required: CLOUDFLARE_RECORD_OBSERVATION_DEPENDENT_FIELDS, anyOf: [{ properties: { current_record_owned_by_run: { const: false } }, required: ["current_record_owned_by_run"] }, { properties: { record_matches_current_origin_address_digest: { const: false } }, required: ["record_matches_current_origin_address_digest"] }] },
      },
      {
        if: { properties: { record_observation_case: { const: "AMBIGUOUS_MULTIPLE" } }, required: ["record_observation_case"] },
        then: { properties: { record_count_category: { const: "multiple" }, current_record_ref: { type: "null" }, current_record_type: { type: "null" }, current_record_digest: { type: "null" }, current_record_origin_address_binding_digest: { type: "null" }, current_record_owned_by_run: { type: "null" }, record_matches_current_origin_address_digest: { type: "null" }, proxy_enabled: { type: "null" } }, required: CLOUDFLARE_RECORD_OBSERVATION_DEPENDENT_FIELDS },
      },
    ]) }),
    annotations: A(true, false, true, true),
    policy: P({
      auth: ["CF_AUDIT"], allowedFrom: MAIN_INVENTORY_ORIGINS,
      successByOrigin: { ...same(MAIN_INVENTORY_ORIGINS), NEW: "INVENTORIED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: ["REGISTERED_ZONE", "ROLE_BOUND_CF_AUDIT_SECRET", "DEDICATED_NODE_HOSTNAME_REF", "ACTIVE_NODE_CHECKPOINT_OR_OFF_CURSOR_REFRESH_RESOLVER"],
      produces: [E("CLOUDFLARE_INVENTORY", "PT10M"), E("FRESH_ZONE_SSL_STRICT_COMPATIBLE", "PT10M_CONDITIONAL"), E("FRESH_WEBSOCKETS_ENABLED", "PT10M_CONDITIONAL"), E("FRESH_OWNED_UNPROXIED_RECORD_BOUND_TO_CURRENT_ORIGIN_ADDRESS_DIGEST", "PT10M_CONDITIONAL")], invalidates: ["DELEGATE_TO_CLOUDFLARE_REFRESH_MODE_RESOLVER"], errors: READ_ERRORS,
      controls: { activeCheckpointDriftResolver: ACTIVE_CHECKPOINT_DRIFT_RESOLVER, cloudflareForwardGate: PLAN_OPERATION_RESOLVER.cloudflareForwardGate, recordObservationResolver: Object.freeze({
        ABSENT_AVAILABLE: "ALLOW_CREATE_ONLY",
        SAME_RUN_CURRENT_UNPROXIED: "ALLOW_PROXY_OR_READ_REFRESH_NO_CREATE",
        SAME_RUN_CURRENT_PROXIED: "ALLOW_CDN_READ_VERIFY_OR_CANONICAL_REPLAY_NO_CREATE_OR_PROXY_WRITE",
        FOREIGN_OR_STALE: "DENY_NO_WRITE",
        AMBIGUOUS_MULTIPLE: "DENY_NO_WRITE",
      }), postRecordRefresh: Object.freeze({
        trigger: "NODE_TEMPLATE_AFTER_CF_NODE_RECORD_APPLY",
        requires: Object.freeze(["CURRENT_ORIGIN_ADDRESS_DIGEST", "CURRENT_OWNED_RECORD_RECEIPT"]),
        successProjection: Object.freeze(["FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED", "FRESH_OWNED_UNPROXIED_RECORD_BOUND_TO_CURRENT_ORIGIN_ADDRESS_DIGEST"]),
      }), refreshModeResolver: Object.freeze({
        ACTIVE_NODE_CHECKPOINT: Object.freeze({
          policy: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT,
          tool: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.checkpointByTool.cloudflare_inventory,
          expectedObservationByCheckpoint: Object.freeze({ PRE_RECORD_EXPECT_ABSENT_AVAILABLE: "ABSENT_AVAILABLE", POST_RECORD_EXPECT_SAME_RUN_CURRENT_UNPROXIED: "SAME_RUN_CURRENT_UNPROXIED" }),
          cursorAdvance: false,
        }),
        OFF_CURSOR_REFRESH: Object.freeze({
          preserves: Object.freeze([]),
          invalidates: Object.freeze(["OLDER_CLOUDFLARE_INVENTORY_AND_DESCENDANTS", "DEPENDENT_PLAN_CHALLENGE_AND_APPROVAL_LEASE"]),
          cursorAdvance: false,
        }),
        callerSelectableMode: false,
      }) },
    }),
  }),

  xui_inventory: C({
    name: "xui_inventory", title: "Inventory 3x-ui ownership and compatibility",
    description: "Distinguish absence, compatible pre-existing installation, incompatible/ambiguous installation, and exact same-run ownership; never upgrades or removes.",
    input: RefreshInput(),
    data: Object.freeze({ ...closed({
      xui_inventory_ref: S.EvidenceRef,
      installation_status: enumOf("absent", "compatible_existing", "incompatible_existing", "ambiguous", "owned_by_run"),
      admin_binding_status: enumOf(...Object.keys(XUI_RESOLUTION_CASES)),
      admin_secret_provenance: enumOf("NONE", "IMPORTED_CURRENT", "SAME_RUN_CURRENT", "MISSING", "DRIFTED", "NOT_APPLICABLE", "AMBIGUOUS"),
      version_masked: nullable(S.MaskedText), ownership_receipt_ref: nullable(S.ReceiptRef),
      clean_host_install_eligible: bool, owned_inbound_refs: arr(S.InboundRef, 0, 16),
      panel_fingerprint_digest: nullable(S.Digest),
    }), allOf: XUI_INVENTORY_OBSERVATION_CLAUSES }),
    annotations: A(true, false, true, true),
    policy: P({
      auth: ["SSH_ORIGIN_READ", "BROKER_XUI_FIXED"], allowedFrom: MAIN_INVENTORY_ORIGINS,
      successByOrigin: { ...same(MAIN_INVENTORY_ORIGINS), NEW: "INVENTORIED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: ["CURRENT_ORIGIN_INVENTORY", "FIXED_XUI_READBACK_HELPER", "EXACT_XUI_INVENTORY_BROKER_COMPOSITE", "IMPORTED_ADMIN_REF_FOR_EXISTING_OR_SAME_RUN_RECEIPT_AND_GENERATED_REF_FOR_OWNED", "ACTIVE_NODE_CHECKPOINT_OR_OFF_CURSOR_REFRESH_RESOLVER"],
      produces: [E("XUI_INVENTORY", "PT15M")], invalidates: ["DELEGATE_TO_ACTIVE_NODE_OR_OFF_CURSOR_INVENTORY_REFRESH_RESOLVER"], errors: READ_ERRORS,
      controls: {
        resolverObservation: Object.freeze({ field: "admin_binding_status", cases: XUI_RESOLUTION_CASES, observationCases: XUI_INVENTORY_OBSERVATION_CASES, callerSelectable: false, producer: "SERVER_DERIVED_FROM_FIXED_BROKER_READBACK_AND_LEDGER" }),
        activeNodeEvidenceRefreshCheckpoint: Object.freeze({ common: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT, tool: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.checkpointByTool.xui_inventory }),
        activeCheckpointDriftResolver: ACTIVE_CHECKPOINT_DRIFT_RESOLVER,
        offCursorRefresh: Object.freeze({ cursorAdvance: false, invalidates: Object.freeze(["OLDER_XUI_INVENTORY_AND_DESCENDANTS", "DEPENDENT_PLAN_CHALLENGE_AND_APPROVAL_LEASE"]) }),
      },
    }),
  }),

  client_inventory: C({
    name: "client_inventory", title: "Inventory allowlisted local client runtimes",
    description: "Discover only allowlisted client binaries and probe-destination policies; never reads arbitrary client configuration.",
    input: RefreshInput(),
    data: closed({ client_inventory_ref: S.EvidenceRef, client_runtime_refs: arr(S.RuntimeRef, 1, 8), probe_destination_refs: arr(S.RuntimeRef, 1, 8), runtime_digest: S.Digest }),
    annotations: A(true, false, true, false),
    policy: P({
      auth: ["LOCAL_PROBE"], allowedFrom: MAIN_INVENTORY_ORIGINS,
      successByOrigin: { ...same(MAIN_INVENTORY_ORIGINS), NEW: "INVENTORIED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: ["ALLOWLISTED_CLIENT_RUNTIME_REGISTRY", "ACTIVE_NODE_CHECKPOINT_OR_OFF_CURSOR_REFRESH_RESOLVER"], produces: [E("CLIENT_INVENTORY", "PT15M")],
      invalidates: ["DELEGATE_TO_ACTIVE_NODE_OR_OFF_CURSOR_INVENTORY_REFRESH_RESOLVER"], errors: BASE_ERRORS,
      controls: {
        activeNodeEvidenceRefreshCheckpoint: Object.freeze({ common: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT, tool: ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT.checkpointByTool.client_inventory }),
        activeCheckpointDriftResolver: ACTIVE_CHECKPOINT_DRIFT_RESOLVER,
        offCursorRefresh: Object.freeze({ cursorAdvance: false, invalidates: Object.freeze(["OLDER_CLIENT_INVENTORY_AND_TRAFFIC_EVIDENCE", "DEPENDENT_PLAN_CHALLENGE_AND_APPROVAL_LEASE"]) }),
      },
    }),
  }),

  old_line_verify: C({
    name: "old_line_verify", title: "Verify the protected prior line",
    description: "Send bounded authenticated traffic through the registered prior line or produce a server-proven not-applicable receipt.",
    input: closed({
      run_id: S.RunRef, probe_destination_ref: S.RuntimeRef,
      idempotency_key: S.IdempotencyKey,
    }),
    data: Object.freeze({ ...closed({
      protected_line_status: enumOf("healthy", "not_applicable"),
      health_evidence_ref: S.EvidenceRef,
      authenticated_or_server_proven_na: constOf(true),
      expected_egress_or_server_proven_na: constOf(true),
      binding_scope: enumOf("pre_change", "post_xui_install", "current_route", "post_main_rollback"),
      bound_current_route_digest: nullable(S.Digest),
      bound_prerequisite_effect_digest: nullable(S.Digest),
      bound_rollback_receipt_ref: nullable(S.ReceiptRef),
      completed_at: S.Timestamp,
    }), allOf: Object.freeze([
      {
        if: { properties: { binding_scope: { const: "current_route" } }, required: ["binding_scope"] },
        then: { properties: { bound_current_route_digest: S.Digest, bound_prerequisite_effect_digest: { type: "null" }, bound_rollback_receipt_ref: { type: "null" } } },
      },
      {
        if: { properties: { binding_scope: { const: "post_xui_install" } }, required: ["binding_scope"] },
        then: { properties: { bound_current_route_digest: { type: "null" }, bound_prerequisite_effect_digest: S.Digest, bound_rollback_receipt_ref: { type: "null" } } },
      },
      {
        if: { properties: { binding_scope: { const: "pre_change" } }, required: ["binding_scope"] },
        then: { properties: { bound_current_route_digest: { type: "null" }, bound_prerequisite_effect_digest: { type: "null" }, bound_rollback_receipt_ref: { type: "null" } } },
      },
      {
        if: { properties: { binding_scope: { const: "post_main_rollback" } }, required: ["binding_scope"] },
        then: { properties: { bound_current_route_digest: { type: "null" }, bound_prerequisite_effect_digest: { type: "null" }, bound_rollback_receipt_ref: S.ReceiptRef } },
      },
    ]) }),
    annotations: A(false, false, true, true),
    policy: P({
      auth: ["LOCAL_PROBE", "LOCAL_LEDGER", "BROKER_PROTECTED_LINE_FIXED"], allowedFrom: ["NEW", "INVENTORIED", "PLAN_READY", "APPROVED", "APPLYING", "ORIGIN_CONFIGURED", "ORIGIN_VERIFIED", "CDN_ENABLED", "CDN_VERIFIED", "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED", "OLD_LINE_REVERIFIED", "ROLLED_BACK"],
      successByOrigin: {
        NEW: "INVENTORIED", INVENTORIED: "UNCHANGED", PLAN_READY: "UNCHANGED", APPROVED: "UNCHANGED", APPLYING: "UNCHANGED",
        ORIGIN_CONFIGURED: "UNCHANGED", ORIGIN_VERIFIED: "UNCHANGED", CDN_ENABLED: "UNCHANGED", CDN_VERIFIED: "UNCHANGED",
        CLIENT_PROFILE_VERIFIED: "UNCHANGED", TRAFFIC_VERIFIED: "UNCHANGED", LOGS_CORRELATED: "OLD_LINE_REVERIFIED",
        OLD_LINE_REVERIFIED: "UNCHANGED", ROLLED_BACK: "UNCHANGED",
      },
      failureTo: ["UNCHANGED"], requires: ["ALLOWLISTED_PROBE_DESTINATION", "PROTECTED_LINE_RUNTIME_PROBE_FIXED_COMPOSITE", "PROTECTED_LINE_SECRET_RESOLVED_SERVER_SIDE_OR_PROVEN_ABSENT", "SERVER_RESOLVES_BINDING_SCOPE_FROM_PLAN_TEMPLATE_STEP_NOT_CALLER", "CURRENT_ROUTE_OR_EXACT_PREREQUISITE_EFFECT_RECEIPT_BINDING_WHEN_REQUIRED", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [
        E("PROTECTED_LINE_HEALTH", "PT5M"),
        E("FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_CURRENT_ROUTE", "PT5M_CONDITIONAL_BY_BINDING_SCOPE"),
        E("FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_XUI_INSTALL_RECEIPT", "PT5M_CONDITIONAL_BY_BINDING_SCOPE"),
        E("FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_MAIN_ROLLBACK_RECEIPT", "PT5M_CONDITIONAL_BY_BINDING_SCOPE"),
      ], invalidates: ["OLDER_PROTECTED_LINE_HEALTH"],
      sideEffects: ["bounded authenticated prior-line traffic", "ephemeral mode-0600 broker artifact removed before return"],
      errors: ["INVALID_INPUT", "UNAUTHORIZED_TARGET", "DEPENDENCY_MISSING", "SECRET_REF_MISSING", "SECRET_SCOPE_MISMATCH", "PROBE_FAILED", "IDEMPOTENCY_CONFLICT", "INTERNAL_ERROR"],
      controls: {
        callerSelectableBindingScope: false,
        bindingScopeByStepMode: Object.freeze({
          post_prerequisite_or_initial: "SERVER_RESOLVES_PRE_CHANGE_OR_EXACT_COMPLETED_PREREQUISITE",
          bind_exact_install_receipt: "post_xui_install",
          current_route_pre_record: "current_route",
          refresh_final_protected_line: "current_route",
          final_post_all_changes: "current_route",
          post_main_rollback_bound_to_exact_receipt: "post_main_rollback",
        }),
        digestProjectionByScope: Object.freeze({
          pre_change: Object.freeze({ currentRouteDigest: "NULL", prerequisiteEffectDigest: "NULL" }),
          post_xui_install: Object.freeze({ currentRouteDigest: "NULL", prerequisiteEffectDigest: "EXACT_XUI_INSTALL_RECEIPT_DIGEST" }),
          current_route: Object.freeze({ currentRouteDigest: "EXACT_CURRENT_NGINX_ROUTE_DIGEST", prerequisiteEffectDigest: "NULL" }),
          post_main_rollback: Object.freeze({ currentRouteDigest: "NULL", prerequisiteEffectDigest: "NULL", rollbackReceiptRef: "EXACT_CURRENT_MAIN_ROLLBACK_RECEIPT" }),
        }),
        prerequisiteCursorCompletion: Object.freeze({
          post_xui_install: "REQUIRED_BEFORE_NODE_INSTALL_CURSOR_COMPLETE",
          post_main_rollback: "REQUIRED_BEFORE_MAIN_PARTIAL_CLOSE_PROBE_RETRY_NEVER_REEXECUTES_RB01",
        }),
        reconciledRollbackProbeAuthority: Object.freeze({
          origin: "ROLLED_BACK",
          requires: Object.freeze(["UNIQUE_CURRENT_IMMUTABLE_MAIN_ROLLBACK_RECEIPT", "NO_CURRENT_ROLLBACK_PLAN_OPERATION_OR_APPROVAL"]),
          serverDerivedMode: "post_main_rollback",
          cursorTreatment: "OFF_CURSOR_RECOVERY_PROBE_NO_ADVANCE",
          callerSelectableModeOrReceipt: false,
        }),
      },
    }),
  }),

  xui_install: C({
    name: "xui_install", title: "Install 3x-ui on a proven clean host",
    description: "Perform first installation only through a fixed digest-pinned adapter; generate/store the panel administrator secret inside the broker and return only opaque refs and masked metadata.",
    input: WriteInput(),
    data: MutationData("exact_inverse", {
      before_digest: { type: "null" },
      installation_ref: S.RuntimeRef,
      installation_ownership_receipt_ref: S.ReceiptRef,
      panel_admin_secret_ref: S.SecretRef,
      installed_version_masked: S.MaskedText,
      adapter_digest: S.Digest,
      readback_digest: S.Digest,
      service_active: constOf(true),
      panel_loopback_only: constOf(true),
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["SSH_ORIGIN_WRITE", "LOCAL_LEDGER"], lease: "NODE_INSTALL_P3",
      allowedFrom: ["APPROVED", "APPLYING"], successByOrigin: { APPROVED: "APPLYING", APPLYING: "UNCHANGED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "GLOBAL_FORWARD_ELIGIBILITY_RECEIPT", "XUI_ABSENT_CLEAN_HOST_EXACTLY", "SUPPORTED_PINNED_INSTALL_ADAPTER", "NODE_INSTALL_P3_LEASE", "INSTALL_SUBPLAN_CONTAINS_XUI_INSTALL_ONLY", "NO_LEASE_INHERITANCE", "NO_EXISTING_XUI_FILES_SERVICE_DATABASE_USERS"),
      produces: [E("OWNED_XUI_INSTALL_RECEIPT", "NO_TTL"), E("XUI_PANEL_ADMIN_SECRET_REF", "RUN_TTL")],
      invalidates: ["ALL_MAIN_INVENTORIES", "PLAN_BASELINE", "PROTECTED_LINE_HEALTH", "DEPENDENT_EVIDENCE"], rollbackClass: "exact_inverse",
      rollbackAction: "OWNED_UNINSTALL_LAST_AFTER_DEPENDENTS_REVERSED_AND_DIGESTS_MATCH",
      sideEffects: ["fixed-adapter clean-host install", "broker generate/store panel administrator secret", "service start and fixed readback"],
      errors: [...WRITE_ERRORS, "INSTALL_NOT_ELIGIBLE", "INSTALL_ADAPTER_UNTRUSTED"],
      controls: { subplanProgress: XUI_INSTALL_POLICY.subplanChain, forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL, failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION") },
    }),
  }),

  xui_create_inbound: C({
    name: "xui_create_inbound", title: "Create the owned loopback WebSocket inbound",
    description: "Create one run-owned Xray inbound bound only to a registered loopback port; Xray carries neither public domain nor TLS configuration.",
    input: WriteInput(),
    data: MutationData("exact_inverse", {
      before_digest: { type: "null" },
      inbound_ref: S.InboundRef, client_secret_ref: S.SecretRef,
      inbound_receipt_ref: S.ReceiptRef, loopback_listener_ref: S.RuntimeRef,
      websocket_path_digest: S.Digest, listen_loopback_only: constOf(true),
      inbound_protocol: constOf("vless"), inbound_transport: constOf("ws"),
      inbound_tls: constOf("none"), inbound_flow: constOf("none"),
      proxy_protocol_enabled: constOf(false), websocket_host: constOf(""),
      inbound_public_domain: { type: "null" },
      inbound_absent_before_create: constOf(true), created_same_run: constOf(true),
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["BROKER_XUI_FIXED", "SSH_ORIGIN_WRITE", "LOCAL_LEDGER"], lease: "NODE_P2",
      allowedFrom: ["APPROVED", "APPLYING"], successByOrigin: { APPROVED: "APPLYING", APPLYING: "UNCHANGED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "GLOBAL_FORWARD_ELIGIBILITY_RECEIPT", "COMPATIBLE_OR_SAME_RUN_OWNED_XUI_INSTALL", "ROLE_BOUND_PANEL_ADMIN_SECRET", "XUI_INBOUND_CREATE_GENERATE_STORE_COMPOSITE", "UNUSED_LOOPBACK_PORT", "NODE_P2_LEASE"),
      produces: [E("OWNED_XUI_INBOUND_RECEIPT", "NO_TTL"), E("XUI_CLIENT_SECRET_REF", "RUN_TTL")],
      invalidates: ["XUI_INVENTORY", "PROFILE_VERIFY", "TRAFFIC_VERIFY"],
      rollbackClass: "exact_inverse", rollbackAction: "REMOVE_ONLY_SAME_RUN_INBOUND_AFTER_CURRENT_DIGEST_MATCH",
      sideEffects: ["create one loopback-only owned inbound", "broker generate/store client credential"], errors: WRITE_ERRORS,
      controls: { bindingPolicy: XUI_INBOUND_POLICY, forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL, failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION") },
    }),
  }),

  xui_profile_publish: C({
    name: "xui_profile_publish", title: "Publish the private client profile",
    description: "Derive a mode-0600 importable profile from server-held refs; address, SNI and WebSocket Host equal the dedicated node hostname and the credential never enters MCP.",
    input: WriteInput(),
    data: MutationData("compensating_action", {
      before_digest: { type: "null" },
      profile_ref: S.ProfileRef, client_profile_secret_ref: S.SecretRef,
      client_artifact_ref: S.ArtifactRef, artifact_digest: S.Digest,
      artifact_mode: constOf("0600"), node_binding_digest: S.Digest,
      address_sni_host_equal: constOf(true),
      transport: constOf("ws"), tls_enabled: constOf(true), allow_insecure: constOf(false),
      public_port: Object.freeze({ type: "integer", const: 443 }), flow: constOf("none"),
      artifact_absent_before_create: constOf(true), descriptor_relative_nofollow_o_excl: constOf(true),
      created_same_run_artifact: constOf(true), artifact_readback_matches: constOf(true),
      residual_disclosure_ref: S.EvidenceRef,
    }),
    annotations: A(false, true, true, false),
    policy: P({
      auth: ["BROKER_PROFILE_FIXED", "LOCAL_LEDGER"], lease: "NODE_P2",
      allowedFrom: ["APPROVED", "APPLYING"], successByOrigin: { APPROVED: "APPLYING", APPLYING: "UNCHANGED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "OWNED_INBOUND_RECEIPT", "XUI_PROFILE_PUBLISH_DERIVE_STORE_COMPOSITE", "DOMAIN_IDENTITY_BINDING", "SAFE_OUTPUT_DIRECTORY", "CLIENT_ARTIFACT_SLOT_ABSENT", "DESCRIPTOR_RELATIVE_NOFOLLOW_O_EXCL", "NODE_P2_LEASE"),
      produces: [E("CLIENT_PROFILE_PUBLISHED", "DIGEST_BOUND"), E("PRIVATE_CLIENT_ARTIFACT", "USER_RETAINED"), E("RESIDUAL_DISCLOSURE", "NO_TTL")],
      invalidates: ["PROFILE_VERIFY", "TRAFFIC_VERIFY", "LOG_CORRELATION"],
      rollbackClass: "compensating_action", rollbackAction: "REMOVE_ONLY_UNCHANGED_OWNED_ARTIFACT_THEN_REVOKE_SAME_RUN_PROFILE_RUNTIME_SECRET; CLIENT_CREDENTIAL_IS_REVOKED_LATER_WITH_INBOUND_NODE; RETAIN_COPY_DISCLOSURE_RESIDUAL",
      sideEffects: ["broker derive/store runtime profile secret", "exclusive no-follow mode-0600 artifact render"],
      errors: [...WRITE_ERRORS, "OUTPUT_DIR_UNSAFE"],
      controls: { profilePolicy: CLIENT_PROFILE_POLICY, createOnlyArtifact: Object.freeze({ beforeDigest: "NULL", absent: true, nofollow: true, exclusiveCreate: true, sameRunReceipt: true }), forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL, failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION") },
    }),
  }),

  xui_profile_inspect: C({
    name: "xui_profile_inspect", title: "Inspect public client-field equality",
    description: "Verify structure and the hostname/SNI/Host/path binding from refs and digests only; never return the credential or full path.",
    input: closed({ run_id: S.RunRef, profile_ref: S.ProfileRef, expected_node_binding_digest: S.Digest }),
    data: closed({
      profile_ref: S.ProfileRef, profile_digest: S.Digest,
      address_matches_node_hostname: constOf(true), sni_matches_node_hostname: constOf(true),
      websocket_host_matches_node_hostname: constOf(true), websocket_path_digest_matches: constOf(true),
      transport: constOf("ws"), tls_enabled: constOf(true), allow_insecure: constOf(false),
      public_port: Object.freeze({ type: "integer", const: 443 }), flow_is_none: constOf(true), backend_security_is_none: constOf(true),
      importable: constOf(true), node_binding_digest: S.Digest,
    }),
    annotations: A(true, false, true, true),
    policy: P({
      auth: ["BROKER_PROFILE_PROJECTION"], allowedFrom: ["CDN_VERIFIED", "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED", "OLD_LINE_REVERIFIED"],
      successByOrigin: { CDN_VERIFIED: "CLIENT_PROFILE_VERIFIED", CLIENT_PROFILE_VERIFIED: "UNCHANGED", TRAFFIC_VERIFIED: "UNCHANGED", LOGS_CORRELATED: "UNCHANGED", OLD_LINE_REVERIFIED: "UNCHANGED" },
      failureTo: ["UNCHANGED"], requires: ["CURRENT_PUBLISHED_PROFILE", "XUI_PROFILE_INSPECT_PROJECTION_COMPOSITE", "DOMAIN_IDENTITY_BINDING", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [E("CLIENT_PROFILE_VERIFY", "PT15M")], invalidates: ["OLDER_PROFILE_VERIFY_AND_TRAFFIC"], errors: READ_ERRORS,
      controls: { profilePolicy: CLIENT_PROFILE_POLICY, exactFieldsAllTrue: true },
    }),
  }),

  certificate_issue_origin_ca: C({
    name: "certificate_issue_origin_ca", title: "Issue a Cloudflare Origin CA certificate",
    description: "Issue one certificate only for the registered Cloudflare-only origin path; the broker generates the private key and CSR locally, sends only CSR/hostname/request-type/validity to Cloudflare, retains the key internally, returns no private-key ref or bytes to MCP, and creates no renewal/reload actor.",
    input: WriteInput(),
    data: MutationData("compensating_action", {
      before_digest: { type: "null" },
      fullchain_ref: S.CertificateRef,
      certificate_fingerprint: S.Digest,
      san_binding_digest: S.Digest, issuer: constOf("origin_ca"),
      csr_generated_locally: constOf(true), csr_only_request_verified: constOf(true),
      csr_key_algorithm: constOf("RSA-2048"), origin_ca_request_type: constOf("origin-rsa"),
      requested_validity_days: Object.freeze({ type: "integer", const: 365 }), wildcard_requested: constOf(false),
      response_san_matches_exact_node_hostname: constOf(true), response_expiry_matches_request: constOf(true),
      fullchain_assembled_in_broker: constOf(true), fullchain_order: constOf("leaf_then_required_issuer_chain"),
      not_after: S.Timestamp, broker_custody_verified: constOf(true),
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["CF_ORIGIN_CA", "LOCAL_LEDGER"], lease: "NODE_P2",
      allowedFrom: ["APPROVED", "APPLYING"], successByOrigin: { APPROVED: "APPLYING", APPLYING: "UNCHANGED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "PLAN_SELECTED_ORIGIN_CA_EXACTLY", "CLOUDFLARE_ONLY_ORIGIN_PATH", "LOCAL_KEY_AND_CSR_PRIVATE_KEY_NEVER_TO_CLOUDFLARE_OR_MCP", "CERTIFICATE_SAN_EQUALS_NODE_HOSTNAME", "ONE_SHOT_NO_BACKGROUND_RENEWAL_OR_RELOAD_ACTOR", "NODE_P2_LEASE"),
      produces: [E("CERTIFICATE_METADATA", "UNTIL_NOT_AFTER")],
      rollbackClass: "compensating_action", rollbackAction: "NO_REMOTE_REVOKE_RETAIN_CLOUDFLARE_ISSUED_CERTIFICATE_METADATA_AS_HONEST_IRREVERSIBLE_RESIDUAL_DELETE_ONLY_SAME_RUN_LOCAL_KEY_AND_SLOTS_WHEN_SAFE",
      sideEffects: ["broker issue one certificate and store private key without MCP bytes; no background renewal/reload actor"], errors: [...WRITE_ERRORS, "CERTIFICATE_NOT_READY"],
      controls: {
        oneShotOnly: "ONE_SHOT_BOOTSTRAP_NO_RENEWAL_UPDATE_OR_REISSUE_TOOL_SUBSEQUENT_CERTIFICATE_WORK_IS_EXTERNAL_OR_FUTURE_V2",
        originCaRequestPolicy: Object.freeze({
          localCsrKeyAlgorithm: "RSA-2048", requestType: "origin-rsa",
          hostnames: "EXACT_NODE_HOSTNAME_ONLY", requestedValidityDays: 365,
          wildcard: false, responseVerification: "SAN_AND_EXPIRY_MATCH_EXACT_REQUEST",
        }),
        keyAndCsrBoundary: Object.freeze({ keyGeneration: "BROKER_LOCAL", cloudflareReceives: Object.freeze(["CSR", "NODE_HOSTNAME", "REQUEST_TYPE_ORIGIN_CA", "VALIDITY"]), cloudflareNeverReceivesPrivateKey: true, mcpNeverReceivesPrivateKey: true, fullchainAssembly: "LEAF_THEN_REQUIRED_ISSUER_CHAIN_IN_BROKER", deployIsSoleStableSlotWriter: true }),
        compensation: Object.freeze({ remoteRevocation: false, issuedMetadataRetained: true, residualRequired: true, localPrivateKeyDisposition: "REVOKE_IF_NO_SLOT_RECEIPT_OR_AFTER_SAME_RUN_SLOT_DELETE" }),
        forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL,
        failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION"),
      },
    }),
  }),

  certificate_deploy: C({
    name: "certificate_deploy", title: "Deploy to stable root-owned service slots",
    description: "Deploy a current certificate through server-internal service-slot refs; Nginx never reads an issuer working directory and no path or key enters MCP.",
    input: WriteInput(),
    data: MutationData("exact_inverse", {
      before_digest: { type: "null" },
      fullchain_slot_ref: S.RuntimeRef, private_key_slot_ref: S.RuntimeRef,
      certificate_slot_receipt_ref: S.ReceiptRef,
      certificate_fingerprint: S.Digest, san_binding_digest: S.Digest,
      stable_service_slots_verified: constOf(true), private_key_exposed: constOf(false),
      dedicated_slots_absent_before_create: constOf(true),
      descriptor_relative_nofollow_o_excl: constOf(true),
      created_same_run_slots: constOf(true),
      exact_slot_readback_verified: constOf(true),
      regular_files: constOf(true), root_owned: constOf(true), no_symlink: constOf(true),
      no_hardlink: constOf(true), trusted_parent: constOf(true),
      private_key_mode: constOf("0600"), fullchain_mode: constOf("0644"),
      fsync_complete: constOf(true), atomic_receipt_written: constOf(true),
      nginx_consumes_opaque_slot_refs_only: constOf(true),
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["SSH_ORIGIN_WRITE", "LOCAL_LEDGER", "BROKER_ORIGIN_CA_KEY_CUSTODY"], lease: "NODE_P2",
      allowedFrom: ["APPROVED", "APPLYING"], successByOrigin: { APPROVED: "APPLYING", APPLYING: "UNCHANGED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "CURRENT_CERTIFICATE_METADATA", "SUFFICIENT_REMAINING_VALIDITY", "CERTIFICATE_SAN_EQUALS_NODE_HOSTNAME", "BROKER_ORIGIN_CA_FULLCHAIN_AND_PRIVATE_KEY_CUSTODY", "FRESH_DEDICATED_ABSENT_ROOT_OWNED_SERVICE_SLOT_REFS", "DESCRIPTOR_RELATIVE_NOFOLLOW_O_EXCL_CREATE", "NODE_P2_LEASE"),
      produces: [E("CERTIFICATE_DEPLOY_RECEIPT", "NO_TTL")], invalidates: ["ORIGIN_VERIFY", "CDN_VERIFY"],
      rollbackClass: "exact_inverse", rollbackAction: "DELETE_ONLY_EXACT_SAME_RUN_CREATED_SLOTS_AFTER_ROUTE_INVERSE_AND_CURRENT_DIGEST_MATCH",
      sideEffects: ["exclusive-create exact dedicated fullchain/private-key slots", "readback and service validation"],
      errors: [...WRITE_ERRORS, "CERTIFICATE_NOT_READY"],
      controls: { brokerCustody: Object.freeze({ authority: "BROKER_ORIGIN_CA_KEY_CUSTODY", consumes: Object.freeze(["fullchain_ref", "origin-ca-private-key"]), exactPairBinding: "CURRENT_ORIGIN_CA_ISSUANCE_RECEIPT_AND_APPROVED_CERTIFICATE_DEPLOY_OPERATION", plaintextAcrossMcp: false, helperDestination: "EXACT_APPROVED_FRESH_DEDICATED_SERVICE_SLOTS_ONLY" }),
      publicInputSurface: Object.freeze({ exactPropertyAndRequiredSet: Object.freeze(["run_id", "plan_ref", "operation_ref", "approval_ref", "expected_ledger_digest", "idempotency_key"]), forbidden: Object.freeze(["private_key_ref", "fullchain_ref", "payload", "path", "slot_ref", "selector"]), additionalProperties: false }),
      helperBinding: Object.freeze({ operation: "origin.certificate_deploy_owned.v1", inputSource: "EXACT_APPROVED_OPERATION_BROKER_CUSTODY_PAIR_FULLCHAIN_REF_AND_ORIGIN_CA_PRIVATE_KEY_SECRET_REF_PLUS_FRESH_DEDICATED_ABSENT_ROOT_OWNED_SLOT_REFS_NO_CALLER_PATH_PAYLOAD_KEY_OR_SLOT_SELECTOR", result: "SAME_RUN_CREATED_FULLCHAIN_AND_PRIVATE_KEY_SLOT_RECEIPT_BOUND_TO_EXACT_CUSTODY_PAIR_AND_SLOT_DIGESTS" }),
      slotNoClobber: Object.freeze({
        beforeDigest: "NULL",
        requiredInventoryStatus: "absent_root_owned_available",
        open: "DESCRIPTOR_RELATIVE_NOFOLLOW_O_EXCL",
        overwriteBackupOrAdoptExisting: false,
        exactSlotRoles: Object.freeze(["fullchain", "private_key"]),
        filePolicy: Object.freeze({ regular: true, rootOwned: true, noSymlink: true, noHardlink: true, trustedParent: true, privateKeyMode: "0600", fullchainMode: "0644", fsync: true, atomicReceipt: true }),
        nginxConsumer: "OPAQUE_SLOT_REFS_ONLY",
        rollback: "DELETE_SAME_RUN_SLOTS_ONLY_AFTER_NGINX_ROUTE_INVERSE",
      }), forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL, failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION") },
    }),
  }),

  nginx_route_apply: C({
    name: "nginx_route_apply", title: "Apply the dedicated Nginx WebSocket route",
    description: "Create one owned server block/include binding the node hostname and exact opaque fullchain/private-key slots to the exact loopback inbound/path.",
    input: WriteInput(),
    data: MutationData("exact_inverse", {
      before_digest: { type: "null" },
      route_ref: S.RuntimeRef, route_receipt_ref: S.ReceiptRef,
      fullchain_slot_ref: S.RuntimeRef, private_key_slot_ref: S.RuntimeRef,
      nginx_config_digest: S.Digest, node_binding_digest: S.Digest,
      syntax_valid: constOf(true), reload_verified: constOf(true),
      supported_existing_nginx: constOf(true), safe_public_tls_listener_ownership: constOf(true),
      no_server_name_conflict: constOf(true), no_websocket_path_conflict: constOf(true),
      create_only_owned_include: constOf(true), nginx_install_performed: constOf(false),
      sole_exact_server_name: constOf(true), sole_exact_websocket_path: constOf(true),
      loopback_upstream_exact: constOf(true), public_tls_listener_443: constOf(true),
      http11_upgrade_connection_exact: constOf(true), unmatched_request_nondisclosing_404: constOf(true),
      backend_tls_disabled: constOf(true), proxy_protocol_disabled: constOf(true),
      no_wildcard_or_default_server: constOf(true),
      exact_node_hostname_and_high_entropy_path: constOf(true),
      include_absent_before_create: constOf(true), descriptor_relative_nofollow_o_excl: constOf(true),
      created_same_run_include: constOf(true), include_readback_matches: constOf(true),
      effective_route_digest: S.Digest,
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["SSH_ORIGIN_WRITE", "LOCAL_LEDGER"], lease: "NODE_P2",
      allowedFrom: ["APPROVED", "APPLYING"], successByOrigin: { APPROVED: "ORIGIN_CONFIGURED", APPLYING: "ORIGIN_CONFIGURED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "FRESH_ORIGIN_INVENTORY", "SUPPORTED_EXISTING_NGINX", "SAFE_PUBLIC_TLS_LISTENER_OWNERSHIP", "NO_SERVER_NAME_OR_WEBSOCKET_PATH_CONFLICT", "CREATE_ONLY_OWNED_INCLUDE_NO_NGINX_INSTALL", "DEDICATED_INCLUDE_SLOT_ABSENT", "DESCRIPTOR_RELATIVE_NOFOLLOW_O_EXCL", "OWNED_INBOUND_RECEIPT", "CURRENT_SAFE_STABLE_FULLCHAIN_AND_PRIVATE_KEY_SLOT_EVIDENCE_OR_ORIGIN_CA_DEPLOY_RECEIPT", "EXACT_OPAQUE_FULLCHAIN_AND_PRIVATE_KEY_SLOT_REFS", "DOMAIN_IDENTITY_BINDING", "NODE_P2_LEASE"),
      produces: [E("NGINX_ROUTE_RECEIPT", "NO_TTL")], invalidates: ["ORIGIN_VERIFY", "CDN_VERIFY", "PROTECTED_LINE_HEALTH"],
      rollbackClass: "exact_inverse", rollbackAction: "DELETE_ONLY_SAME_RUN_CREATED_INCLUDE_AND_RELOAD_AFTER_CURRENT_DIGEST_MATCH_NO_PREEXISTING_INCLUDE_RESTORE",
      sideEffects: ["exclusive-create exact owned Nginx include", "syntax test and reload"], errors: WRITE_ERRORS,
      controls: {
        routePolicy: NGINX_ROUTE_POLICY,
        createOnlyInclude: Object.freeze({ beforeDigest: "NULL", absent: true, nofollow: true, exclusiveCreate: true, preExistingIncludeAdoptionBackupOrOverwrite: false, rollbackOperation: "origin.nginx_route_delete_owned.v1" }),
        readbackAllTrue: Object.freeze(["syntax_valid", "reload_verified", "supported_existing_nginx", "safe_public_tls_listener_ownership", "no_server_name_conflict", "no_websocket_path_conflict", "create_only_owned_include", "sole_exact_server_name", "sole_exact_websocket_path", "loopback_upstream_exact", "public_tls_listener_443", "http11_upgrade_connection_exact", "unmatched_request_nondisclosing_404", "backend_tls_disabled", "proxy_protocol_disabled", "no_wildcard_or_default_server", "exact_node_hostname_and_high_entropy_path"]),
        forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL,
        failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION"),
      },
    }),
  }),

  origin_verify: C({
    name: "origin_verify", title: "Verify the direct origin",
    description: "Prove direct-origin certificate/SNI and WebSocket routing to the exact loopback inbound before Cloudflare proxy enablement.",
    input: closed({ run_id: S.RunRef, idempotency_key: S.IdempotencyKey }),
    data: closed({
      origin_verify_ref: S.EvidenceRef, tls_valid: constOf(true), san_matches: constOf(true),
      websocket_upgrade_valid: constOf(true), expected_route_reached: constOf(true),
      node_binding_digest: S.Digest, completed_at: S.Timestamp,
    }),
    annotations: A(false, false, true, true),
    policy: P({
      auth: ["LOCAL_PROBE"], allowedFrom: ["ORIGIN_CONFIGURED", "ORIGIN_VERIFIED", "CDN_ENABLED", "CDN_VERIFIED", "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED", "OLD_LINE_REVERIFIED"],
      successByOrigin: { ORIGIN_CONFIGURED: "ORIGIN_VERIFIED", ORIGIN_VERIFIED: "UNCHANGED", CDN_ENABLED: "UNCHANGED", CDN_VERIFIED: "UNCHANGED", CLIENT_PROFILE_VERIFIED: "UNCHANGED", TRAFFIC_VERIFIED: "UNCHANGED", LOGS_CORRELATED: "UNCHANGED", OLD_LINE_REVERIFIED: "UNCHANGED" },
      failureTo: ["UNCHANGED"], requires: ["CURRENT_NGINX_ROUTE", "CURRENT_SAFE_STABLE_SLOT_EVIDENCE_OR_ORIGIN_CA_DEPLOY_RECEIPT_WITH_ISSUER_BINDING", "DOMAIN_IDENTITY_BINDING", "ALLOWLISTED_DIRECT_ORIGIN_PROBE", "ISSUER_SPECIFIC_VERIFIED_TRUST_NO_INSECURE_SKIP", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [E("DIRECT_ORIGIN_TLS_WEBSOCKET", "PT5M")], invalidates: ["OLDER_ORIGIN_VERIFY_AND_CDN_DESCENDANTS"],
      sideEffects: ["bounded direct-origin TLS and WebSocket traffic"], errors: [...BASE_ERRORS, "CERTIFICATE_NOT_READY", "ORIGIN_NOT_VERIFIED", "PROBE_FAILED"],
      controls: {
        trustByCertificateStrategy: Object.freeze({
          reuse: "DERIVE_SYSTEM_PUBLIC_OR_PINNED_RECOGNIZED_CF_ORIGIN_CA_FROM_SAFE_STABLE_SLOT_EVIDENCE",
          origin_ca: "PINNED_RECOGNIZED_CLOUDFLARE_ORIGIN_CA_CHAIN",
        }),
        certificateSourceByStrategy: Object.freeze({
          reuse: "SAFE_STABLE_CERTIFICATE_SLOT_EVIDENCE_NO_DEPLOY_RECEIPT",
          origin_ca: "CURRENT_ORIGIN_CA_DEPLOY_RECEIPT",
        }),
        insecureSkipVerify: false,
      },
    }),
  }),

  cf_node_record_apply: C({
    name: "cf_node_record_apply", title: "Create the dedicated Cloudflare record",
    description: "Create only a missing dedicated node record in the registered zone, initially unproxied; any conflicting existing record stops the run.",
    input: WriteInput(),
    data: MutationData("exact_inverse", {
      before_digest: { type: "null" },
      record_ref: S.RecordRef, record_receipt_ref: S.ReceiptRef,
      prior_record_observation_case: constOf("ABSENT_AVAILABLE"),
      record_digest: S.Digest, hostname_binding_digest: S.Digest,
      record_type: enumOf("A", "AAAA"),
      origin_address_binding_digest: S.Digest,
      record_value_source: constOf("server_registered_current_origin_address"),
      proxied: constOf(false), create_only: constOf(true),
      absent_before_create: constOf(true), created_same_run: constOf(true),
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["CF_NODE_DNS", "LOCAL_LEDGER"], lease: "NODE_P2",
      allowedFrom: ["APPROVED", "APPLYING", "ORIGIN_CONFIGURED"], successByOrigin: { APPROVED: "APPLYING", APPLYING: "UNCHANGED", ORIGIN_CONFIGURED: "UNCHANGED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "RECORD_OBSERVATION_CASE_EXACTLY_ABSENT_AVAILABLE", "RECORD_NAME_EQUALS_NODE_HOSTNAME", "CURRENT_NGINX_ROUTE", "FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_CURRENT_ROUTE", "CURRENT_ORIGIN_ADDRESS_DIGEST", "SERVER_DERIVES_A_OR_AAAA_RECORD_TYPE_AND_VALUE_NO_CALLER_VALUE", "CREATE_ONLY_UNPROXIED", "NODE_P2_LEASE"),
      produces: [E("OWNED_CF_RECORD_RECEIPT", "NO_TTL")], invalidates: ["CLOUDFLARE_INVENTORY", "CDN_VERIFY"],
      rollbackClass: "exact_inverse", rollbackAction: "DELETE_ONLY_SAME_RECORD_ID_OWNERSHIP_AND_CURRENT_DIGEST_MATCH",
      sideEffects: ["create one unproxied DNS record"], errors: WRITE_ERRORS,
      controls: {
        phaseByOrigin: Object.freeze({
          APPROVED: "APPLYING",
          APPLYING: "UNCHANGED",
          ORIGIN_CONFIGURED: "UNCHANGED_AFTER_CURRENT_ROUTE_PROTECTED_LINE_BEFORE_DIRECT_ORIGIN_PROOF",
        }),
        recordValuePolicy: Object.freeze({
          allowedTypes: Object.freeze(["A", "AAAA"]),
          valueSource: "SERVER_REGISTERED_CURRENT_ORIGIN_ADDRESS",
          receiptBinds: Object.freeze(["NODE_HOSTNAME", "ORIGIN_ADDRESS_DIGEST", "RECORD_TYPE", "RECORD_DIGEST"]),
          lowEntropyBindingPolicy: LOW_ENTROPY_BINDING_POLICY,
          callerValueForbidden: true, cnameForbidden: true, foreignOrStaleAddressForbidden: true,
          observationCaseRequired: "ABSENT_AVAILABLE",
          sameOperationReplay: "RETURN_CANONICAL_RECEIPT_NO_SECOND_CREATE",
        }),
        forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL,
        failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION"),
      },
    }),
  }),

  cf_proxy_enable: C({
    name: "cf_proxy_enable", title: "Enable proxy after direct-origin proof",
    description: "Proxy only the exact run-owned record after fresh direct-origin TLS/WebSocket proof and strict certificate binding.",
    input: WriteInput(),
    data: MutationData("exact_inverse", {
      before_digest: S.Digest,
      record_ref: S.RecordRef, proxy_receipt_ref: S.ReceiptRef,
      record_digest: S.Digest, proxied: constOf(true), origin_proof_bound: constOf(true),
    }),
    annotations: A(false, true, true, true),
    policy: P({
      auth: ["CF_NODE_DNS", "LOCAL_LEDGER"], lease: "NODE_P2",
      allowedFrom: ["ORIGIN_VERIFIED"], successByOrigin: { ORIGIN_VERIFIED: "CDN_ENABLED" },
      failureTo: ["UNCHANGED", "INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, FORWARD_MUTATION_DISPATCH_REQUIREMENT, "RECORD_OBSERVATION_CASE_SAME_RUN_CURRENT_UNPROXIED", "FRESH_OWNED_UNPROXIED_RECORD_BOUND_TO_CURRENT_ORIGIN_ADDRESS_DIGEST", "FRESH_DIRECT_ORIGIN_TLS_WEBSOCKET_ALL_TRUE", "FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_CURRENT_ROUTE", "CERTIFICATE_SAN_EQUALS_NODE_HOSTNAME", "FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED", "NODE_P2_LEASE"),
      produces: [E("CF_PROXY_RECEIPT", "NO_TTL")], invalidates: ["CLOUDFLARE_INVENTORY", "CDN_VERIFY"],
      rollbackClass: "exact_inverse", rollbackAction: "RESTORE_ONLY_OWNED_RECORD_PROXY_FLAG_AFTER_DIGEST_MATCH",
      sideEffects: ["enable proxy on one owned record"], errors: [...WRITE_ERRORS, "ORIGIN_NOT_VERIFIED"],
      controls: { freshCloudflareGate: Object.freeze(["FRESH_OWNED_UNPROXIED_RECORD_BOUND_TO_CURRENT_ORIGIN_ADDRESS_DIGEST", "FRESH_ZONE_SSL_STRICT_COMPATIBLE", "FRESH_WEBSOCKETS_ENABLED"]), forwardDispatchSafety: FORWARD_MUTATION_DISPATCH_CONTROL, failureContext: mutationFailureControl("MAIN_EXTERNAL_MUTATION") },
    }),
  }),

  cdn_verify: C({
    name: "cdn_verify", title: "Verify Cloudflare TLS and WebSocket",
    description: "Prove the proxied hostname reaches the exact route under strict TLS; HTTP 101 alone is insufficient.",
    input: closed({ run_id: S.RunRef, probe_destination_ref: S.RuntimeRef, idempotency_key: S.IdempotencyKey }),
    data: closed({
      cdn_verify_ref: S.EvidenceRef, tls_valid: constOf(true), san_matches: constOf(true),
      websocket_upgrade_valid: constOf(true), strict_compatible_mode_observed: constOf(true),
      expected_route_reached: constOf(true), node_binding_digest: S.Digest,
      cf_api_owned_proxied_record_current: constOf(true),
      cf_api_ssl_strict_compatible_current: constOf(true), cf_api_websockets_enabled_current: constOf(true),
      independent_public_resolution_cloudflare_fronted: constOf(true),
      public_resolution_not_origin: constOf(true),
      public_resolution_not_198_18_0_0_15: constOf(true),
      public_resolution_not_proxy_mediated: constOf(true),
      public_resolution_digest: S.Digest,
      origin_comparison_binding_digest: S.Digest,
      completed_at: S.Timestamp,
    }),
    annotations: A(false, false, true, true),
    policy: P({
      auth: ["LOCAL_PROBE", "CF_AUDIT"], allowedFrom: ["CDN_ENABLED", "CDN_VERIFIED", "CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED", "OLD_LINE_REVERIFIED"],
      successByOrigin: { CDN_ENABLED: "CDN_VERIFIED", CDN_VERIFIED: "UNCHANGED", CLIENT_PROFILE_VERIFIED: "UNCHANGED", TRAFFIC_VERIFIED: "UNCHANGED", LOGS_CORRELATED: "UNCHANGED", OLD_LINE_REVERIFIED: "UNCHANGED" },
      failureTo: ["UNCHANGED"], requires: ["RECORD_OBSERVATION_CASE_SAME_RUN_CURRENT_PROXIED", "FRESH_DIRECT_ORIGIN_PROOF", "SAME_CALL_CF_API_CURRENT_OWNED_PROXIED_RECORD_STRICT_COMPATIBLE_AND_WEBSOCKETS", "INDEPENDENT_CLEAN_DOH_OR_PUBLIC_RESOLUTION_CLOUDFLARE_FRONTED_NOT_ORIGIN_NOT_198_18_0_0_15_NOT_PROXY_MEDIATED", "DOMAIN_IDENTITY_BINDING", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [E("CLOUDFLARE_TLS_WEBSOCKET", "PT5M")], invalidates: ["OLDER_CDN_VERIFY_AND_TRAFFIC"],
      sideEffects: ["bounded public TLS and WebSocket traffic"], errors: [...READ_ERRORS, "CDN_NOT_VERIFIED", "SSL_MODE_NOT_STRICT_COMPATIBLE", "PROBE_FAILED"],
      controls: { publicResolutionProof: Object.freeze({
        apiIdentity: "SAME_CALL_CURRENT_SAME_RUN_OWNED_PROXIED_RECORD_RECEIPT_STRICT_COMPATIBLE_AND_WEBSOCKETS",
        resolver: "INDEPENDENT_CLEAN_DOH_OR_PUBLIC_RESOLVER",
        lowEntropyBindingPolicy: LOW_ENTROPY_BINDING_POLICY,
        comparisonDomain: "PUBLIC_VS_ORIGIN_V1_FOR_BOTH_PUBLIC_RESOLUTION_AND_ORIGIN_COMPARISON_BINDINGS",
        cloudflareFronted: true, originAddressForbidden: true,
        surgeFakeIp198_18_0_0_15Forbidden: true, proxyMediatedObservationForbidden: true,
        rawAddressInMcp: false,
      }) },
    }),
  }),

  traffic_verify: C({
    name: "traffic_verify", title: "Verify authenticated proxy traffic and egress",
    description: "Use the broker-held current profile secret with an allowlisted runtime to perform a real authenticated request and record expected public egress plus one correlation window.",
    input: closed({
      run_id: S.RunRef, client_runtime_ref: S.RuntimeRef, profile_ref: S.ProfileRef,
      client_profile_secret_ref: S.SecretRef, probe_destination_ref: S.RuntimeRef,
      expected_node_binding_digest: S.Digest, idempotency_key: S.IdempotencyKey,
    }),
    data: closed({
      probe_ref: S.ProbeRef, authenticated: constOf(true), request_succeeded: constOf(true),
      expected_public_egress: constOf(true),
      expected_egress_evidence_ref: S.EvidenceRef,
      proxy_observed_egress_evidence_ref: S.EvidenceRef,
      expected_egress_binding_digest: S.Digest,
      proxy_observed_egress_binding_digest: S.Digest,
      same_allowlisted_destination: constOf(true),
      observed_egress_equals_expected: constOf(true),
      raw_egress_value_exposed: constOf(false),
      correlation_window_ref: S.RuntimeRef, ephemeral_artifact_removed: constOf(true),
      completed_at: S.Timestamp,
    }),
    annotations: A(false, false, true, true),
    policy: P({
      auth: ["LOCAL_PROBE", "SSH_ORIGIN_READ", "BROKER_CLIENT_EGRESS_FIXED", "LOCAL_LEDGER"], allowedFrom: ["CLIENT_PROFILE_VERIFIED", "TRAFFIC_VERIFIED", "LOGS_CORRELATED", "OLD_LINE_REVERIFIED"],
      successByOrigin: { CLIENT_PROFILE_VERIFIED: "TRAFFIC_VERIFIED", TRAFFIC_VERIFIED: "UNCHANGED", LOGS_CORRELATED: "UNCHANGED", OLD_LINE_REVERIFIED: "UNCHANGED" },
      failureTo: ["UNCHANGED"], requires: ["FRESH_CDN_VERIFY", "FRESH_CLIENT_PROFILE_VERIFY", "DOMAIN_IDENTITY_BINDING", "CLIENT_SECRET_SCOPE_MATCH", "ALLOWLISTED_PROBE_DESTINATION", "FIXED_EXPECTED_EGRESS_HELPER_AND_CLIENT_AUTHENTICATED_EGRESS_BROKER_USE_SAME_DESTINATION", "LOW_ENTROPY_HMAC_BINDINGS_SHARE_EGRESS_EQUALITY_V1_AND_COMPARE_CONSTANT_TIME", "UNKNOWN_OR_MISMATCHED_EGRESS_FAILS", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [E("AUTHENTICATED_PROXY_REQUEST", "PT5M"), E("EXPECTED_PUBLIC_EGRESS", "PT5M"), E("PROBE_WINDOW", "PT10M")],
      invalidates: ["OLDER_TRAFFIC_AND_LOG_CORRELATION"],
      sideEffects: ["bounded authenticated public proxy traffic", "ephemeral mode-0600 broker artifact removed before return"],
      errors: [...READ_ERRORS, "CDN_NOT_VERIFIED", "PROBE_FAILED"],
      controls: { successPredicate: Object.freeze({
        authenticated: true,
        request_succeeded: true,
        expected_public_egress: true,
        same_allowlisted_destination: true,
        observed_egress_equals_expected: true,
        evidenceBindings: LOW_ENTROPY_BINDING_POLICY,
        rawIpInMcp: false,
        requiresNodeBinding: "DOMAIN_IDENTITY_BINDING",
      }) },
    }),
  }),

  logs_correlate: C({
    name: "logs_correlate", title: "Correlate Nginx and Xray/3x-ui evidence",
    description: "Read only the fixed preceding ProbeRef and bounded window through pinned selectors; no generic log source or query is representable.",
    input: closed({ run_id: S.RunRef, probe_ref: S.ProbeRef, correlation_window_ref: S.RuntimeRef, max_lines_per_source: int(1, 200) }),
    data: closed({ probe_ref: S.ProbeRef, nginx_correlated: constOf(true), xray_correlated: constOf(true), xui_counter_correlated: nullable(bool), correlation_complete: constOf(true), evidence_refs: arr(S.EvidenceRef, 1, 8) }),
    annotations: A(true, false, true, true),
    policy: P({
      auth: ["SSH_ORIGIN_READ", "BROKER_XUI_FIXED"], allowedFrom: ["TRAFFIC_VERIFIED", "LOGS_CORRELATED", "OLD_LINE_REVERIFIED"],
      successByOrigin: { TRAFFIC_VERIFIED: "LOGS_CORRELATED", LOGS_CORRELATED: "UNCHANGED", OLD_LINE_REVERIFIED: "UNCHANGED" },
      failureTo: ["UNCHANGED"], requires: ["SAME_PROBE_WINDOW", "FIXED_BOUNDED_LOG_SELECTORS", "XUI_LOGS_COUNTER_READ_FIXED_COMPOSITE", "CURRENT_OWNED_ROUTE_AND_INBOUND", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [E("NGINX_XRAY_LOG_CORRELATION", "PT10M")], invalidates: ["OLDER_LOG_CORRELATION"], errors: READ_ERRORS,
    }),
  }),

  bbr_inventory: C({
    name: "bbr_inventory", title: "Inventory existing-kernel BBR capability",
    description: "Read current kernel support, live/persistent values and conflicts; never installs a kernel, edits bootloader/shared sysctl, or reboots.",
    input: closed({ run_id: S.RunRef, refresh: bool }),
    data: Object.freeze({ ...closed({
      bbr_inventory_ref: S.EvidenceRef, kernel_exposes_bbr: bool,
      available_congestion_controls_contains_bbr: bool,
      qdisc_fq_supported: bool,
      persistent_conflict_present: bool, eligible: bool,
      current_qdisc: S.MaskedText, current_congestion_control: S.MaskedText,
      owned_dropin_present: bool, inventory_digest: S.Digest,
    }), allOf: Object.freeze([
      {
        if: { properties: { owned_dropin_present: { const: true } }, required: ["owned_dropin_present"] },
        then: { properties: { persistent_conflict_present: { const: true }, eligible: { const: false } } },
      },
      {
        if: { properties: { eligible: { const: true } }, required: ["eligible"] },
        then: { properties: {
          kernel_exposes_bbr: { const: true },
          available_congestion_controls_contains_bbr: { const: true },
          qdisc_fq_supported: { const: true },
          persistent_conflict_present: { const: false },
          owned_dropin_present: { const: false },
        } },
      },
    ]) }),
    annotations: A(true, false, true, true),
    policy: P({
      governingColumn: "bbr", auth: ["SSH_ORIGIN_READ"],
      allowedFrom: ["BBR_PENDING", "BBR_INVENTORIED", "BBR_PLAN_READY", "BBR_HOST_APPROVED"],
      successByOrigin: { BBR_PENDING: "BBR_INVENTORIED", BBR_INVENTORIED: "UNCHANGED", BBR_PLAN_READY: "UNCHANGED", BBR_HOST_APPROVED: "DELEGATE_TO_HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT" },
      failureTo: ["UNCHANGED", "BBR_PLAN_READY"], requires: [CONFIGURE_MODE_GATE, "BBR_BRANCH_REQUESTED", "FIXED_BBR_READ_HELPER", "BBR_HOST_APPROVED_REFRESH_DELEGATES_TO_SERVER_DERIVED_CHECKPOINT"],
      produces: [E("BBR_INVENTORY", "PT10M")], invalidates: ["DELEGATE_TO_BBR_INVENTORY_REFRESH_CONTEXT"], errors: READ_ERRORS,
      controls: { eligibilityResolver: Object.freeze({
        eligibleIff: Object.freeze(["kernel_exposes_bbr", "available_congestion_controls_contains_bbr", "qdisc_fq_supported", "NO_PERSISTENT_CONFLICT", "owned_dropin_present=false"]),
        preExistingDropin: "CONFLICT_NO_ADOPT_NO_OVERWRITE_HONEST_NO_WRITE_PARTIAL",
        targetPolicy: BBR_TARGET_POLICY,
      }), hostP3EvidenceRefreshCheckpoint: HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT,
      offCheckpointRefresh: Object.freeze({ states: Object.freeze(["BBR_INVENTORIED", "BBR_PLAN_READY"]), invalidates: Object.freeze(["OLDER_BBR_INVENTORY", "DEPENDENT_PLAN_CHALLENGE_AND_APPROVAL_LEASE"]), destination: "UNCHANGED" }) },
    }),
  }),

  bbr_apply: C({
    name: "bbr_apply", title: "Apply the owned BBR sysctl drop-in",
    description: "Write one plugin-owned drop-in containing only the frozen qdisc/congestion-control keys and record prior live/persistent values; no kernel, bootloader, shared sysctl, or reboot action exists.",
    input: WriteInput(),
    data: Object.freeze({ ...MutationData("exact_inverse", {
      before_digest: { type: "null" },
      bbr_receipt_ref: S.ReceiptRef, owned_dropin_ref: S.RuntimeRef,
      dropin_digest: S.Digest, prior_qdisc: S.MaskedText,
      prior_congestion_control: S.MaskedText, live_apply_readback: constOf(true),
      persistent_readback: constOf(true),
      live_congestion_control: constOf("bbr"), persistent_congestion_control: constOf("bbr"),
      live_default_qdisc: constOf("fq"), persistent_default_qdisc: constOf("fq"),
      descriptor_relative_nofollow: constOf(true), exclusive_create: constOf(true),
      owned_dropin_absent_before_create: constOf(true), dropin_readback_matches: constOf(true),
      owned_dropin_path_bound_to_approved_runtime_ref: constOf(true),
      receipt_binds_owned_path_and_dropin_digest: constOf(true),
    }), allOf: Object.freeze([{
      if: { properties: { committed: { const: true } }, required: ["committed"] },
      then: {
        properties: {
          before_digest: { type: "null" },
          bbr_receipt_ref: S.ReceiptRef,
          owned_dropin_ref: S.RuntimeRef,
          ownership_receipt_ref: S.ReceiptRef,
          owned_dropin_absent_before_create: constOf(true),
          descriptor_relative_nofollow: constOf(true),
          exclusive_create: constOf(true),
          dropin_readback_matches: constOf(true),
          owned_dropin_path_bound_to_approved_runtime_ref: constOf(true),
          receipt_binds_owned_path_and_dropin_digest: constOf(true),
        },
        required: ["before_digest", "bbr_receipt_ref", "owned_dropin_ref", "ownership_receipt_ref", "owned_dropin_absent_before_create", "descriptor_relative_nofollow", "exclusive_create", "dropin_readback_matches", "owned_dropin_path_bound_to_approved_runtime_ref", "receipt_binds_owned_path_and_dropin_digest"],
      },
    }]) }),
    annotations: A(false, true, true, true),
    policy: P({
      governingColumn: "bbr", auth: ["SSH_ORIGIN_WRITE", "LOCAL_LEDGER"], lease: "HOST_P3",
      allowedFrom: ["BBR_HOST_APPROVED"], successByOrigin: { BBR_HOST_APPROVED: "BBR_APPLIED" },
      failureTo: ["UNCHANGED", "BBR_APPLIED", "BBR_MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, "FORWARD_APPROVAL_EFFECTIVE_EXPIRY_IS_MIN_NOMINAL_AND_ALL_CONSUMED_FINITE_EVIDENCE", "FRESH_ELIGIBLE_BBR_INVENTORY", "CURRENT_KERNEL_ALREADY_SUPPORTS_BBR", "AVAILABLE_CONGESTION_CONTROLS_CONTAINS_BBR", "QDISC_FQ_SUPPORTED", "NO_PERSISTENT_CONFLICT", "OWNED_DROPIN_ABSENT", "DESCRIPTOR_RELATIVE_NOFOLLOW_O_EXCL", "EXACT_TARGET_CONGESTION_CONTROL_BBR_AND_DEFAULT_QDISC_FQ", "MAIN_PHASE_OLD_LINE_REVERIFIED_AND_NODE_CURSOR_COMPLETE_AND_REPORT_NOT_SEALED", "HOST_P3_LEASE", "OWNED_DROPIN_PATH_REF"),
      produces: [E("BBR_APPLY_RECEIPT", "NO_TTL")], invalidates: ["BBR_VERIFY", ...BBR_SAFETY_POLICY.postApplyInvalidates],
      rollbackClass: "exact_inverse", rollbackAction: "REMOVE_ONLY_OWNED_DROPIN_AND_RESTORE_RECORDED_PRIOR_VALUES",
      sideEffects: ["write one owned sysctl.d drop-in", "apply only two frozen keys", "read back live and persistent values"],
      errors: WRITE_ERRORS,
      controls: {
        crossColumnGate: Object.freeze({
          requiredMainPhase: "OLD_LINE_REVERIFIED",
          nodeCursorComplete: true,
          forbiddenMainPhases: Object.freeze(["DELIVERY_REPORT_SEALED", "CLOSED"]),
          onForbidden: "WRONG_STATE_NO_WRITE",
          afterCommitInvalidates: BBR_SAFETY_POLICY.postApplyInvalidates,
        }),
        targetPolicy: BBR_TARGET_POLICY,
        createOnlyDropin: Object.freeze({ beforeDigest: "NULL", observedAbsent: true, nofollow: true, exclusiveCreate: true, approvedRuntimePathBinding: true, receiptBindsOwnedPathAndDigest: true, requiredDataFields: Object.freeze(["before_digest", "bbr_receipt_ref", "owned_dropin_ref", "ownership_receipt_ref", "owned_dropin_absent_before_create", "descriptor_relative_nofollow", "exclusive_create", "dropin_readback_matches", "owned_dropin_path_bound_to_approved_runtime_ref", "receipt_binds_owned_path_and_dropin_digest"]), readbackRequired: true, preExistingOwnedOrForeign: "INELIGIBLE_NO_ADOPT_NO_OVERWRITE" }),
        forwardApprovalEffectiveExpiry: FORWARD_APPROVAL_EFFECTIVE_EXPIRY_POLICY,
        failureContext: mutationFailureControl("BBR_EXTERNAL_MUTATION"),
      },
    }),
  }),

  bbr_verify: C({
    name: "bbr_verify", title: "Verify BBR and the protected line",
    description: "Prove live and persistent values match the exact BBR change and re-run protected-line health before accepted branch closure.",
    input: closed({ run_id: S.RunRef, bbr_change_ref: S.ChangeRef, probe_destination_ref: S.RuntimeRef, idempotency_key: S.IdempotencyKey }),
    data: closed({
      bbr_verify_ref: S.EvidenceRef, live_qdisc_matches: constOf(true),
      live_congestion_control_matches: constOf(true), persistent_dropin_matches: constOf(true),
      live_congestion_control: constOf("bbr"), persistent_congestion_control: constOf("bbr"),
      live_default_qdisc: constOf("fq"), persistent_default_qdisc: constOf("fq"),
      protected_line_status: enumOf("healthy", "not_applicable"),
      protected_line_evidence_ref: S.EvidenceRef,
      protected_line_bound_change_ref: S.ChangeRef, completed_at: S.Timestamp,
    }),
    annotations: A(false, false, true, true),
    policy: P({
      governingColumn: "bbr", auth: ["SSH_ORIGIN_READ", "LOCAL_PROBE", "BROKER_PROTECTED_LINE_FIXED"],
      allowedFrom: ["BBR_APPLIED", "BBR_VERIFIED"],
      successByOrigin: { BBR_APPLIED: "BBR_VERIFIED", BBR_VERIFIED: "UNCHANGED" },
      failureTo: ["UNCHANGED", "BBR_MANUAL_ACTION_REQUIRED"],
      requires: ["EXACT_BBR_APPLY_RECEIPT", "FIXED_BBR_READ_HELPER", "EXACT_LIVE_AND_PERSISTENT_CONGESTION_CONTROL_BBR_AND_DEFAULT_QDISC_FQ", "PROTECTED_LINE_RUNTIME_PROBE_FIXED_COMPOSITE", "LIVE_AND_PERSISTENT_VALUES_MATCH", "FRESH_PROTECTED_LINE_HEALTH_BOUND_TO_BBR_CHANGE", CURSOR_READ_PROBE_REQUIREMENT],
      produces: [E("BBR_VERIFY", "PT5M"), E("BBR_POST_APPLY_PROTECTED_LINE_HEALTH", "PT5M")],
      invalidates: ["OLDER_BBR_VERIFY"], sideEffects: ["bounded protected-line authenticated traffic"],
      errors: [...READ_ERRORS, "PROTECTED_LINE_UNPROVEN", "PROBE_FAILED"],
      controls: {
        targetPolicy: BBR_TARGET_POLICY,
        exactReadbackAllTrue: true,
        failureRouteByCause: Object.freeze({
          CONCLUSIVE_FALSE_WITH_EXACT_CURRENT_APPLY_RECEIPT: "BBR_MANUAL_ACTION_REQUIRED_THEN_COMPILE_DEDICATED_ROLLBACK_NO_RECONCILE_REQUIRED",
          UNKNOWN_COMMIT: "BBR_MANUAL_ACTION_REQUIRED_THEN_RECONCILE_STATUS",
          CONCURRENT_THIRD_DIGEST: "BBR_MANUAL_ACTION_REQUIRED_THEN_RECONCILE_STATUS_NO_OVERWRITE",
        }),
        durableFailureCauseRequired: true,
      },
    }),
  }),

  bbr_rollback: C({
    name: "bbr_rollback", title: "Rollback the owned BBR change",
    description: "Execute only the authorized full BBR inverse or its exact reconciliation-proven remaining ordered stage suffix; remove only the same-run owned drop-in and restore/read back recorded prior live and persistent values. Traffic, log and protected-line probes are separate retryable template steps after the immutable inverse receipt.",
    input: WriteInput(),
    data: closed({
      rollback_receipt_ref: S.ReceiptRef, bbr_change_ref: S.ChangeRef,
      selected_bbr_stage_ids: Object.freeze({ ...arr(enumOf(...BBR_ROLLBACK_ATOMIC_STAGE_IDS), 1, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length), uniqueItems: true }),
      bbr_stage_receipt_refs: arr(S.ReceiptRef, 1, BBR_ROLLBACK_ATOMIC_STAGE_IDS.length),
      bbr_stage_selection_digest: S.Digest,
      selected_stage_and_receipt_cardinality_equal: constOf(true),
      selected_stages_are_full_or_exact_remaining_ordered_suffix: constOf(true),
      each_stage_receipt_committed_after_exact_readback_before_next_stage: constOf(true),
      aggregate_receipt_binds_exact_selected_stage_ids_and_receipts: constOf(true),
      final_bbr_stage_id: constOf("bbr_rb04_final_exact_readback"),
      final_bbr_stage_receipt_ref: S.ReceiptRef,
      final_bbr_stage_receipt_is_last_selected_receipt: constOf(true),
      final_bbr_stage_and_aggregate_receipt_same_local_ledger_transaction: constOf(true),
      finalization_receipts_both_visible: constOf(true),
      finalization_transaction_commit_digest: S.Digest,
      owned_dropin_removed: constOf(true), prior_live_values_restored: constOf(true),
      prior_persistent_values_restored: constOf(true),
      prior_values_digest: S.Digest, inverse_readback_matches_recorded_prior: constOf(true),
      final_digest: S.Digest,
    }),
    annotations: A(false, true, true, true),
    policy: P({
      governingColumn: "bbr", auth: ["SSH_ORIGIN_WRITE", "LOCAL_LEDGER"], lease: "ROLLBACK",
      allowedFrom: ["BBR_ROLLING_BACK"],
      successByOrigin: { BBR_ROLLING_BACK: "BBR_ROLLED_BACK" },
      failureTo: ["UNCHANGED", "BBR_MANUAL_ACTION_REQUIRED"],
      requires: configureRequires(EXECUTION_BINDING_REQUIREMENT, "EXACT_OWNED_BBR_INVERSE", "EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "CURRENT_BBR_ROLLBACK_SELECTION_BASELINE_MATCHES_PLAN_SOURCE_ROW", "RECORDED_PRIOR_LIVE_AND_PERSISTENT_VALUES_DIGEST", "NO_CONCURRENT_EDIT", "BBR_ROLLBACK_MAIN_GATE_ALL_TRUE"),
      produces: [E("BBR_ROLLBACK_STAGE_RECEIPT", "NO_TTL"), E("BBR_ROLLBACK_RECEIPT", "NO_TTL")], invalidates: ["BBR_VERIFY", ...BBR_SAFETY_POLICY.postApplyInvalidates],
      rollbackClass: "not_applicable", rollbackAction: "THIS_IS_THE_EXACT_BBR_INVERSE_EXECUTOR",
      sideEffects: ["remove one owned drop-in", "restore and read back recorded prior live and persistent values"],
      errors: ["INVALID_INPUT", "UNAUTHORIZED_TARGET", "WRONG_STATE", "APPROVAL_REQUIRED", "APPROVAL_STALE", "BASELINE_DRIFT", "CONFLICT_DETECTED", "ROLLBACK_UNSAFE", "PROTECTED_LINE_UNPROVEN", "PROBE_FAILED", "UNKNOWN_COMMIT_STATE", "RECONCILIATION_REQUIRED", "MANUAL_ACTION_REQUIRED", "INTERNAL_ERROR"],
      controls: {
        inverseReadbackPolicy: Object.freeze({
          ownedDropinRemoved: true, priorLiveValuesRestored: true,
          priorPersistentValuesRestored: true, exactPriorDigestReadback: true,
          finalTargetIsRecordedPriorNotBbrPolicy: true,
        }),
        mainGate: BBR_ROLLBACK_MAIN_GATE,
        authorizationSourceSet: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET,
        authorizationSourceBinding: BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.executor,
        applyBaselineReceiptBinding: BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
        atomicStageExecution: Object.freeze({
          atomicStages: BBR_ROLLBACK_ATOMIC_STAGES,
          exactStageOrder: BBR_ROLLBACK_ATOMIC_STAGE_IDS,
          selection: "FULL_OR_EXACT_RECONCILIATION_PROVEN_REMAINING_ORDERED_SUFFIX",
          stageReceiptFamily: "BBR_ROLLBACK_STAGE_RECEIPT",
          stageReceiptCommitRule: "STAGES_ONE_TO_THREE_AFTER_EXACT_READBACK_BEFORE_NEXT_STAGE_FINAL_STAGE_RECEIPT_COMMITS_WITH_AGGREGATE_BOTH_OR_NEITHER",
          aggregateReceiptFamily: "BBR_ROLLBACK_RECEIPT",
          aggregateBindsExactSelectedStageIdsAndReceipts: true,
          finalizationTransaction: BBR_ROLLBACK_FINALIZATION_TRANSACTION,
          completedStageReplay: false,
        }),
        inverseOnly: true,
        protectedLineProbeInsideExecutor: false,
        postInverseTemplateSteps: Object.freeze(["traffic_verify", "logs_correlate", "old_line_verify"]),
        rollbackLeaseExpiryResolver: ROLLBACK_LEASE_EXPIRY_RESOLVER,
        stageResume: PLAN_OPERATION_RESOLVER.scopes.BBR_ROLLBACK.stageResume,
        failureContext: mutationFailureControl("BBR_ROLLBACK_EXECUTOR"),
      },
    }),
  }),
};

const TOOL_LIST = Object.freeze(FROZEN_TOOL_NAMES.map((name) => {
  if (!TOOLS[name]) throw new Error(`Missing frozen Tool: ${name}`);
  return TOOLS[name];
}));
const reconciliationCoverage = [...PLAN_OPERATION_RESOLVER.cursorEnforcement.writeAndExecutorTools].sort();
if (JSON.stringify(Object.keys(RECONCILIATION_OBSERVER_BY_TOOL).sort()) !== JSON.stringify(reconciliationCoverage)) {
  throw new Error("RECONCILIATION_OBSERVER_BY_TOOL must be set-equal to every external mutator and inverse executor");
}
for (const row of Object.values(RECONCILIATION_OBSERVER_BY_TOOL)) {
  for (const operation of row.observer) {
    if (!(operation in PRIVILEGED_HELPER_OPERATIONS) && !(operation in BROKER_OPERATIONS)) {
      throw new Error(`Unknown reconciliation observer operation: ${operation}`);
    }
  }
}
if (TOOL_LIST.length !== 31) throw new Error(`Expected 31 Tools, received ${TOOL_LIST.length}`);
if (new Set(TOOL_LIST.map(({ name }) => name)).size !== 31) throw new Error("Duplicate Tool name");
if (Object.keys(TOOLS).length !== 31) throw new Error("Active Tool map contains a non-frozen member");
for (const tool of TOOL_LIST) {
  const origins = Object.keys(tool.policy.successByOrigin);
  if (JSON.stringify([...origins].sort()) !== JSON.stringify([...tool.policy.allowedFrom].sort())) {
    throw new Error(`${tool.name}: successByOrigin must cover every allowedFrom origin exactly`);
  }
  if (!tool.policy.failureTo.length) throw new Error(`${tool.name}: failureTo is empty`);
}
const expectedMainRollbackAtomicStageIds = Object.freeze([
  "rb01_cf_proxy_restore", "rb02_cf_record_delete", "rb03_nginx_route_delete",
  "rb04_certificate_slots_delete", "rb05_origin_ca_private_key_dispose",
  "rb06_client_artifact_dispose", "rb07_profile_runtime_secret_dispose",
  "rb08_xui_inbound_remove", "rb09_xui_client_secret_revoke",
  "rb10_xui_install_uninstall", "rb11_xui_panel_admin_revoke",
]);
if (JSON.stringify(MAIN_ROLLBACK_ATOMIC_STAGE_IDS) !== JSON.stringify(expectedMainRollbackAtomicStageIds)) {
  throw new Error("MAIN_ROLLBACK_ATOMIC_STAGES order or membership drifted");
}
if (JSON.stringify(Object.keys(MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.atomicStageReadback.authorityByStageId)) !== JSON.stringify(MAIN_ROLLBACK_ATOMIC_STAGE_IDS)) {
  throw new Error("main rollback atomic-stage observer authority must be set-equal and ordered");
}
const expectedBbrRollbackAtomicStageIds = Object.freeze([
  "bbr_rb01_owned_dropin_remove",
  "bbr_rb02_prior_live_restore",
  "bbr_rb03_prior_persistent_restore",
  "bbr_rb04_final_exact_readback",
]);
if (JSON.stringify(BBR_ROLLBACK_ATOMIC_STAGE_IDS) !== JSON.stringify(expectedBbrRollbackAtomicStageIds) ||
    JSON.stringify(PLAN_OPERATION_RESOLVER.scopes.BBR_ROLLBACK.atomicStageIds) !== JSON.stringify(expectedBbrRollbackAtomicStageIds) ||
    JSON.stringify(BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.orderedStageIds) !== JSON.stringify(expectedBbrRollbackAtomicStageIds) ||
    !BBR_ROLLBACK_ATOMIC_STAGES.every((stage) => stage.executor === "bbr_rollback" && stage.durableStageReceiptRequired === true && stage.receiptCommittedAfterExactStageReadbackBeforeNextStage === true) ||
    BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.stageReceiptProducer !== "bbr_rollback" ||
    BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.stageReceiptFamily !== "BBR_ROLLBACK_STAGE_RECEIPT" ||
    BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.observerReceiptFamily !== "EXACT_SAME_BBR_ROLLBACK_STAGE_RECEIPT_FAMILY_PRODUCED_BY_BBR_ROLLBACK") {
  throw new Error("BBR rollback four-stage order, receipt producer, or reconciliation receipt family drifted");
}
const expectedActiveCursorWriteExpiryConsumers = Object.freeze(["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable"]);
if (JSON.stringify(ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.consumers) !== JSON.stringify(expectedActiveCursorWriteExpiryConsumers) ||
    JSON.stringify(Object.keys(ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.rows)) !== JSON.stringify(["ZERO_COMMITTED_CHANGES", "SAME_RUN_OWNED_COMMITTED_CHANGES", "UNKNOWN_OR_THIRD_DIGEST"]) ||
    ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.rows.ZERO_COMMITTED_CHANGES.destination !== "INVENTORIED" ||
    ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.rows.SAME_RUN_OWNED_COMMITTED_CHANGES.destination !== "ROLLBACK_REQUIRED" ||
    ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.rows.UNKNOWN_OR_THIRD_DIGEST.destination !== "MANUAL_ACTION_REQUIRED" ||
    ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.forwardResume !== false ||
    ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.inheritedPlanTemplateCursorRemainingOperationsApprovalOrLease !== false ||
    ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER.scope.includes("HOST_P3")) {
  throw new Error("ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER closed scope or three-way resolver drifted");
}
for (const toolName of expectedActiveCursorWriteExpiryConsumers) {
  const policy = TOOLS[toolName].policy;
  if (policy.controls.forwardDispatchSafety?.activeCursorWriteExpiryResolver !== ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER ||
      !["INVENTORIED", "ROLLBACK_REQUIRED", "MANUAL_ACTION_REQUIRED"].every((destination) => policy.failureTo.includes(destination))) {
    throw new Error(`${toolName}: active cursor write-expiry resolver or state destinations are incomplete`);
  }
}
const rollbackFinalizationFields = Object.freeze([
  "final_atomic_stage_id",
  "final_atomic_stage_receipt_ref",
  "final_atomic_stage_is_last_selected_stage",
  "final_atomic_stage_receipt_is_last_ordered_stage_receipt",
  "final_stage_and_aggregate_receipt_same_local_ledger_transaction",
  "finalization_receipts_both_visible",
  "aggregate_receipt_binds_exact_selected_atomic_stage_receipts",
  "finalization_transaction_commit_digest",
]);
if (!rollbackFinalizationFields.every((field) => TOOLS.rollback_run.dataSchema.required.includes(field)) ||
    TOOLS.rollback_run.policy.controls.atomicStageExecution.finalizationTransaction !== MAIN_ROLLBACK_FINALIZATION_TRANSACTION ||
    CORE_ROLLBACK_POLICY.finalizationTransaction !== MAIN_ROLLBACK_FINALIZATION_TRANSACTION ||
    MAIN_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.finalizationTransaction !== MAIN_ROLLBACK_FINALIZATION_TRANSACTION ||
    MAIN_ROLLBACK_FINALIZATION_TRANSACTION.atomicity !== "BOTH_OR_NEITHER" ||
    MAIN_ROLLBACK_FINALIZATION_TRANSACTION.beforeTransactionCommitCrash.next !== "FIXED_MAIN_ROLLBACK_STAGE_RECONCILIATION_NO_INVERSE_REPLAY_UNTIL_PROVEN" ||
    MAIN_ROLLBACK_FINALIZATION_TRANSACTION.afterTransactionCommit.observation !== "PROVEN_COMMITTED" ||
    !MAIN_ROLLBACK_COMMITTED_PROOF_SCHEMA.required.includes("final_stage_and_aggregate_receipt_same_local_ledger_transaction") ||
    !TOOLS.reconcile_status.dataSchema.required.includes("main_rollback_committed_proof")) {
  throw new Error("main rollback final-stage and aggregate receipt transaction is incomplete");
}
if (HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT.noDrift.destination !== "UNCHANGED" ||
    HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT.noDrift.nominalLeaseExtension !== false ||
    HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT.noDrift.effectiveLeaseExtension !== false ||
    HOST_P3_BBR_EVIDENCE_REFRESH_CHECKPOINT.driftOrExpired.destination !== "BBR_PLAN_READY") {
  throw new Error("HOST_P3 BBR evidence refresh checkpoint is not the frozen two-branch resolver");
}
if (ROLLBACK_LEASE_EXPIRY_RESOLVER.rows.MAIN_ZERO_INVERSE_BEFORE_DISPATCH.destination !== "ROLLBACK_REQUIRED" ||
    ROLLBACK_LEASE_EXPIRY_RESOLVER.rows.MAIN_ZERO_INVERSE_BEFORE_DISPATCH.reconciliationEvidenceRequired !== false ||
    !TOOLS.rollback_run.policy.failureTo.includes("ROLLBACK_REQUIRED")) {
  throw new Error("zero-dispatch main rollback lease-expiry admission is incomplete");
}
const expectedBbrRollbackAuthorizationSourceRowIds = Object.freeze([
  "EXPLICIT_COMMITTED_APPLY",
  "CONCLUSIVE_VERIFY_FALSE",
  "FRESH_RECONCILIATION_OUTCOME",
  "BBR_ZERO_STAGE_BEFORE_DISPATCH",
]);
const bbrRollbackAuthorizationRows = BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.rows;
const expectedBbrReconciliationSourceOutcomes = Object.freeze([
  "BBR_APPLY_PROVEN_COMMITTED",
  "BBR_ROLLBACK_EXECUTOR_PROVEN_NOT_COMMITTED",
  "BBR_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX",
]);
const expectedBbrAuthorizationSourceRowKeys = Object.freeze([
  "compileAllowedOrigins", "durableCause", "requiredEvidence",
  "reconciliationEvidenceRequired", "reconciliationOutcomes", "planSelection",
  "zeroStageLeaseExpiryResolverRow", "compileDestination",
  "authorizeAllowedOrigin", "authorizeDestination", "immutablePlanBindingField",
  "baselineReceiptBindingPolicy", "mainRollbackAdmissionReceiptAllowed", "callerSelectable",
]);
const bbrZeroStageResolverRow = ROLLBACK_LEASE_EXPIRY_RESOLVER.rows.BBR_ZERO_STAGE_BEFORE_DISPATCH;
if (JSON.stringify(BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.exactRowIds) !== JSON.stringify(expectedBbrRollbackAuthorizationSourceRowIds) ||
    JSON.stringify(Object.keys(bbrRollbackAuthorizationRows)) !== JSON.stringify(expectedBbrRollbackAuthorizationSourceRowIds) ||
    !Object.values(bbrRollbackAuthorizationRows).every((row) => JSON.stringify(Object.keys(row).sort()) === JSON.stringify([...expectedBbrAuthorizationSourceRowKeys].sort())) ||
    !Object.values(bbrRollbackAuthorizationRows).every((row) => row.compileDestination === "BBR_MANUAL_ACTION_REQUIRED" && row.authorizeAllowedOrigin === "BBR_MANUAL_ACTION_REQUIRED" && row.authorizeDestination === "BBR_ROLLING_BACK" && row.callerSelectable === false && row.mainRollbackAdmissionReceiptAllowed === false) ||
    !Object.values(bbrRollbackAuthorizationRows).every((row) => row.baselineReceiptBindingPolicy === BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY && row.requiredEvidence.includes("EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING")) ||
    !["EXPLICIT_COMMITTED_APPLY", "CONCLUSIVE_VERIFY_FALSE"].every((id) => ["BASELINE_KIND_NORMAL_COMMITTED_APPLY", "CURRENT_OWNED_DROPIN_DIGEST_MATCH"].every((guard) => bbrRollbackAuthorizationRows[id].requiredEvidence.includes(guard))) ||
    JSON.stringify(Object.keys(bbrRollbackAuthorizationRows.FRESH_RECONCILIATION_OUTCOME.reconciliationOutcomes)) !== JSON.stringify(expectedBbrReconciliationSourceOutcomes) ||
    !["EXACT_ONE_SERVER_DERIVED_BBR_APPLY_BASELINE_RECEIPT_BINDING", "BASELINE_KIND_RECONCILED_APPLY_CHANGE"].every((guard) => bbrRollbackAuthorizationRows.FRESH_RECONCILIATION_OUTCOME.reconciliationOutcomes.BBR_APPLY_PROVEN_COMMITTED.requires.includes(guard)) ||
    !expectedBbrRollbackAuthorizationSourceRowIds.filter((id) => id !== "FRESH_RECONCILIATION_OUTCOME").every((id) => Object.keys(bbrRollbackAuthorizationRows[id].reconciliationOutcomes).length === 0) ||
    bbrRollbackAuthorizationRows.FRESH_RECONCILIATION_OUTCOME.reconciliationOutcomes.BBR_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX.planSelection !== "EXACT_REMAINING_ORDERED_STAGE_SUFFIX" ||
    !bbrRollbackAuthorizationRows.FRESH_RECONCILIATION_OUTCOME.reconciliationOutcomes.BBR_ROLLBACK_EXECUTOR_PROVEN_INVERSE_PREFIX.requires.includes("COMPLETED_STAGE_REPLAY_FORBIDDEN")) {
  throw new Error("BBR rollback authorization source set or reconciliation suffix outcomes are not the exact closed rows");
}
if (bbrZeroStageResolverRow.cause !== "BBR_ZERO_STAGE_BEFORE_DISPATCH" ||
    bbrZeroStageResolverRow.oldAuthorityRevoked !== true ||
    bbrZeroStageResolverRow.reconciliationEvidenceRequired !== false ||
    bbrZeroStageResolverRow.mainRollbackAdmissionReceiptAllowed !== false ||
    bbrZeroStageResolverRow.admissionReceipt !== null ||
    bbrZeroStageResolverRow.requires.includes("OLD_BBR_ROLLBACK_AUTHORITY_REVOKED") ||
    JSON.stringify(bbrZeroStageResolverRow.requires) !== JSON.stringify(["ROLLBACK_LEASE_EXPIRED", "EXACT_CURRENT_OLD_BBR_ROLLBACK_AUTHORITY_IDENTITY_ACTIVE", "ZERO_DURABLE_BBR_STAGE_RECEIPTS", "NO_OPEN_EXECUTOR_DISPATCH"]) ||
    !["CURRENT_PLAN_BOUND_BBR_ROLLBACK_SOURCE_BINDING", "CURRENT_APPROVAL_CHALLENGE", "CURRENT_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE"].every((value) => bbrZeroStageResolverRow.consumes.includes(value)) ||
    !["DURABLE_BBR_ZERO_STAGE_CAUSE", "NEW_CURRENT_UNCONSUMED_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE_BOUND_TO_INHERITED_EXACT_ONE_BASELINE"].every((value) => bbrZeroStageResolverRow.creates.includes(value)) ||
    !["EXACT_BBR_APPLY_BASELINE_KIND", "EXACT_OPAQUE_BBR_APPLY_BASELINE_RECEIPT_REF", "EXACT_OPAQUE_BBR_CHANGE_REF", "EXACT_BBR_APPLY_BASELINE_BINDING_DIGEST"].every((value) => bbrZeroStageResolverRow.inheritsFromConsumedSourceEpisode.includes(value)) ||
    bbrZeroStageResolverRow.sourcePrecedence !== "ZERO_STAGE_SOURCE_WINS_ONLY_THE_NEW_CURRENT_EXPIRY_EPISODE" ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.zeroStagePolicy.resolverRow !== bbrZeroStageResolverRow ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.zeroStagePolicy.reconciliationEvidenceRequired !== false ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.zeroStagePolicy.mainRollbackAdmissionReceiptAllowed !== false ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.zeroStagePolicy.admissionReceipt !== null ||
    bbrRollbackAuthorizationRows.BBR_ZERO_STAGE_BEFORE_DISPATCH.reconciliationEvidenceRequired !== false ||
    bbrRollbackAuthorizationRows.BBR_ZERO_STAGE_BEFORE_DISPATCH.zeroStageLeaseExpiryResolverRow !== "BBR_ZERO_STAGE_BEFORE_DISPATCH" ||
    !["DURABLE_BBR_ZERO_STAGE_CAUSE", "OLD_BBR_ROLLBACK_AUTHORITY_REVOKED", "ZERO_DURABLE_BBR_STAGE_RECEIPTS", "NO_OPEN_EXECUTOR_DISPATCH", "CURRENT_UNCONSUMED_BBR_ROLLBACK_SOURCE_OBLIGATION_EPISODE"].every((guard) => bbrRollbackAuthorizationRows.BBR_ZERO_STAGE_BEFORE_DISPATCH.requiredEvidence.includes(guard))) {
  throw new Error("BBR zero-stage rollback reauthorization must revoke old authority without reconciliation or a main admission receipt");
}
const bbrExplicitCompile = PLAN_COMPILE_REQUEST_MATRIX.bbrRollbackEscalation;
const bbrRecoveryCompile = PLAN_COMPILE_REQUEST_MATRIX.existingBbrRecovery;
if (JSON.stringify(bbrExplicitCompile.authorizationSourceRowIds) !== JSON.stringify(["EXPLICIT_COMMITTED_APPLY"]) ||
    bbrExplicitCompile.authorizationSourceRows.EXPLICIT_COMMITTED_APPLY !== bbrRollbackAuthorizationRows.EXPLICIT_COMMITTED_APPLY ||
    JSON.stringify(bbrRecoveryCompile.authorizationSourceRowIds) !== JSON.stringify(["CONCLUSIVE_VERIFY_FALSE", "FRESH_RECONCILIATION_OUTCOME", "BBR_ZERO_STAGE_BEFORE_DISPATCH"]) ||
    !bbrRecoveryCompile.authorizationSourceRowIds.every((id) => bbrRecoveryCompile.authorizationSourceRows[id] === bbrRollbackAuthorizationRows[id]) ||
    !bbrExplicitCompile.allowedOrigins.every((origin) => TOOLS.plan_compile.policy.successByOrigin[origin] === "BBR_MANUAL_ACTION_REQUIRED") ||
    TOOLS.plan_compile.policy.successByOrigin.BBR_MANUAL_ACTION_REQUIRED !== "UNCHANGED" ||
    !TOOLS.plan_authorize.policy.allowedFrom.includes("BBR_MANUAL_ACTION_REQUIRED") ||
    TOOLS.plan_authorize.policy.successByOrigin.BBR_MANUAL_ACTION_REQUIRED !== "BBR_ROLLING_BACK" ||
    TOOLS.plan_compile.policy.controls.bbrRollbackAuthorizationSourceSet !== BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET ||
    TOOLS.plan_compile.policy.controls.bbrApplyBaselineReceiptBinding !== BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY ||
    TOOLS.plan_authorize.policy.controls.bbrRollbackAuthorizationSourceSet !== BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET ||
    TOOLS.plan_authorize.policy.controls.bbrApplyBaselineReceiptBinding !== BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY ||
    TOOLS.bbr_rollback.policy.controls.authorizationSourceSet !== BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET ||
    TOOLS.bbr_rollback.policy.controls.applyBaselineReceiptBinding !== BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.planCompile.persistsSourceRowIdInImmutablePlan !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.planCompile.readsOnlyCurrentUnconsumedUnsupersededEpisode !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.planAuthorize.requiresExactPersistedSourceRowId !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.executor.requiresAuthorizedPlanWithSameSourceRowId !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.currentSourceObligationPolicy.planCompileVisibleRowCount !== 1 ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.currentSourceObligationPolicy.multipleVisibleRows !== "DENY_NO_PLAN_STAY_BBR_MANUAL_ACTION_REQUIRED" ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.currentSourceObligationPolicy.staleConsumedOrSupersededRowsVisible !== false ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.currentSourceObligationPolicy.zeroStageExpiryTransition.consumesPriorPlanBoundSourceBindingChallengeAndEpisode !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.currentSourceObligationPolicy.zeroStageExpiryTransition.inheritsExactOneBaselineKindRefChangeRefAndBindingDigest !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.currentSourceObligationPolicy.zeroStageExpiryTransition.priorConclusiveOrReconciliationRowRemainsCurrent !== false ||
    JSON.stringify(BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.trajectories.CONCLUSIVE_AUTHORIZE_ZERO_STAGE_REAUTHORIZE) !== JSON.stringify([
      "CONCLUSIVE_VERIFY_FALSE_SOURCE_EPISODE_CURRENT",
      "PLAN_COMPILE_BINDS_CONCLUSIVE_SOURCE_ROW",
      "PLAN_AUTHORIZE_CONSUMES_CONCLUSIVE_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
      "ROLLBACK_LEASE_EXPIRES_BEFORE_ANY_STAGE_DISPATCH",
      "ATOMIC_ZERO_STAGE_TRANSITION_CONSUMES_PRIOR_SOURCE_BINDING_CHALLENGE_AND_EPISODE",
      "NEW_CURRENT_UNCONSUMED_ZERO_STAGE_SOURCE_EPISODE_ONLY",
      "PLAN_COMPILE_BINDS_ZERO_STAGE_SOURCE_ROW",
      "PLAN_AUTHORIZE_CONSUMES_ZERO_STAGE_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
    ])) {
  throw new Error("BBR rollback plan_compile to plan_authorize source-row binding is not reachable and closed");
}
const expectedBbrApplyBaselineKinds = Object.freeze(["NORMAL_COMMITTED_APPLY", "RECONCILED_APPLY_CHANGE"]);
if (JSON.stringify(BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.exactKindIds) !== JSON.stringify(expectedBbrApplyBaselineKinds) ||
    JSON.stringify(Object.keys(BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.rows)) !== JSON.stringify(expectedBbrApplyBaselineKinds) ||
    BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.resolution.exactCurrentBindingCount !== 1 ||
    BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.resolution.normalAndReconciledBothPresent !== "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION" ||
    BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.resolution.neitherPresent !== "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION" ||
    BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.resolution.callerSelectableKindOrRef !== false ||
    BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY.zeroStageInheritance.bindsNewZeroStageEpisodeAtomically !== true ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.planCompile.baselineReceiptBindingPolicy !== BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.planAuthorize.baselineReceiptBindingPolicy !== BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY ||
    BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.executor.baselineReceiptBindingPolicy !== BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY ||
    JSON.stringify(BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.trajectories.RECONCILED_AUTHORIZE_ZERO_STAGE_REAUTHORIZE) !== JSON.stringify([
      "BBR_APPLY_PROVEN_COMMITTED_MINTS_RECONCILED_BASELINE_AND_SOURCE_EPISODE",
      "PLAN_COMPILE_BINDS_RECONCILED_SOURCE_ROW_AND_EXACT_ONE_RECONCILED_BASELINE",
      "PLAN_AUTHORIZE_CONSUMES_RECONCILED_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
      "ROLLBACK_LEASE_EXPIRES_BEFORE_ANY_STAGE_DISPATCH",
      "ATOMIC_ZERO_STAGE_TRANSITION_INHERITS_RECONCILED_BASELINE_KIND_REF_CHANGE_REF_AND_BINDING_DIGEST",
      "NEW_CURRENT_UNCONSUMED_ZERO_STAGE_SOURCE_EPISODE_HAS_EXACT_ONE_RECONCILED_BASELINE",
      "PLAN_COMPILE_BINDS_ZERO_STAGE_SOURCE_ROW_WITH_INHERITED_RECONCILED_BASELINE",
      "PLAN_AUTHORIZE_CONSUMES_ZERO_STAGE_BOUND_CHALLENGE_TO_BBR_ROLLING_BACK",
    ]) ||
    JSON.stringify(BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET.trajectories.BASELINE_BINDING_NEGATIVE_CONTROLS) !== JSON.stringify({
      NORMAL_AND_RECONCILED_BOTH_CURRENT: "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION",
      NORMAL_AND_RECONCILED_BOTH_ABSENT: "DENY_NO_PLAN_NO_AUTHORIZATION_NO_EXECUTION",
      CALLER_SELECTED_KIND_OR_REF: "INVALID_INPUT_NO_AUTHORITY",
    })) {
  throw new Error("BBR apply baseline must resolve exactly one normal or reconciled binding and survive zero-stage episode replacement");
}
const planCompileDataSchema = TOOLS.plan_compile.dataSchema;
const mainRollbackPlanClause = planCompileDataSchema.allOf.find((clause) => clause.if?.properties?.template_id?.const === "MAIN_ROLLBACK_V1");
const bbrRollbackPlanClause = planCompileDataSchema.allOf.find((clause) => clause.if?.properties?.template_id?.const === "BBR_ROLLBACK_V1");
if (!planCompileDataSchema.required.includes("bbr_rollback_stage_ids") ||
    !planCompileDataSchema.required.includes("bbr_rollback_stage_selection_digest") ||
    !mainRollbackPlanClause || !bbrRollbackPlanClause ||
    mainRollbackPlanClause.then.properties.rollback_atomic_stage_ids.minItems !== 1 ||
    mainRollbackPlanClause.then.properties.bbr_rollback_stage_ids.maxItems !== 0 ||
    mainRollbackPlanClause.then.properties.bbr_rollback_stage_selection_digest.type !== "null" ||
    bbrRollbackPlanClause.then.properties.rollback_atomic_stage_ids.maxItems !== 0 ||
    bbrRollbackPlanClause.then.properties.rollback_atomic_stage_selection_digest.type !== "null" ||
    bbrRollbackPlanClause.then.properties.bbr_rollback_stage_ids.minItems !== 1 ||
    bbrRollbackPlanClause.then.properties.bbr_rollback_stage_selection_digest !== S.Digest ||
    !planCompileDataSchema.allOf.every((clause) => clause.if?.properties?.template_id) ||
    TOOLS.plan_compile.policy.controls.rollbackStageSelectionByTemplate.BBR_ROLLBACK_V1.bbrStageIds !== BBR_ROLLBACK_ATOMIC_STAGE_IDS ||
    TOOLS.plan_compile.policy.controls.rollbackStageSelectionByTemplate.MAIN_ROLLBACK_V1.mainStageIds !== MAIN_ROLLBACK_ATOMIC_STAGE_IDS) {
  throw new Error("plan_compile rollback stage carriers must be discriminated by exact main versus BBR template ID");
}
const bbrRollbackDataRequired = TOOLS.bbr_rollback.dataSchema.required;
const bbrRollbackProduceTypes = TOOLS.bbr_rollback.policy.produces.map(({ type }) => type);
if (!["selected_bbr_stage_ids", "bbr_stage_receipt_refs", "bbr_stage_selection_digest", "selected_stage_and_receipt_cardinality_equal", "selected_stages_are_full_or_exact_remaining_ordered_suffix", "each_stage_receipt_committed_after_exact_readback_before_next_stage", "aggregate_receipt_binds_exact_selected_stage_ids_and_receipts", "final_bbr_stage_id", "final_bbr_stage_receipt_ref", "final_bbr_stage_receipt_is_last_selected_receipt", "final_bbr_stage_and_aggregate_receipt_same_local_ledger_transaction", "finalization_receipts_both_visible", "finalization_transaction_commit_digest", "rollback_receipt_ref"].every((field) => bbrRollbackDataRequired.includes(field)) ||
    !["BBR_ROLLBACK_STAGE_RECEIPT", "BBR_ROLLBACK_RECEIPT"].every((type) => bbrRollbackProduceTypes.includes(type)) ||
    TOOLS.bbr_rollback.policy.controls.atomicStageExecution.atomicStages !== BBR_ROLLBACK_ATOMIC_STAGES ||
    TOOLS.bbr_rollback.policy.controls.atomicStageExecution.exactStageOrder !== BBR_ROLLBACK_ATOMIC_STAGE_IDS ||
    TOOLS.bbr_rollback.policy.controls.atomicStageExecution.completedStageReplay !== false ||
    TOOLS.bbr_rollback.policy.controls.atomicStageExecution.finalizationTransaction !== BBR_ROLLBACK_FINALIZATION_TRANSACTION ||
    PLAN_OPERATION_RESOLVER.scopes.BBR_ROLLBACK.finalizationTransaction !== BBR_ROLLBACK_FINALIZATION_TRANSACTION ||
    BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.finalizationTransaction !== BBR_ROLLBACK_FINALIZATION_TRANSACTION ||
    BBR_ROLLBACK_FINALIZATION_TRANSACTION.atomicity !== "BOTH_OR_NEITHER" ||
    BBR_ROLLBACK_FINALIZATION_TRANSACTION.beforeTransactionCommitCrash.visibleFinalReceiptAndAggregatePair !== "NEITHER" ||
    BBR_ROLLBACK_FINALIZATION_TRANSACTION.beforeTransactionCommitCrash.maximumVisibleProperPrefixLength !== 3 ||
    BBR_ROLLBACK_FINALIZATION_TRANSACTION.afterTransactionCommit.visibleFinalReceiptAndAggregatePair !== "BOTH" ||
    BBR_ROLLBACK_FINALIZATION_TRANSACTION.afterTransactionCommit.observation !== "PROVEN_COMMITTED" ||
    BBR_ROLLBACK_FINALIZATION_TRANSACTION.fourStageReceiptsWithoutAggregateRepresentable !== false ||
    BBR_ROLLBACK_EXECUTOR_RECONCILIATION_PROOF.fourStageReceiptsWithoutAggregateRepresentable !== false ||
    !BBR_ROLLBACK_STAGE_PREFIX_PROOF_SCHEMA.required.includes("completed_stage_receipts_are_exact_bbr_rollback_stage_receipt_family") ||
    !BBR_ROLLBACK_STAGE_PREFIX_PROOF_SCHEMA.required.includes("remaining_suffix_stage_ids")) {
  throw new Error("bbr_rollback does not produce the frozen per-stage receipt family and aggregate for full or suffix execution");
}
const reconcileDataSchema = TOOLS.reconcile_status.dataSchema;
const reconciledBbrApplyClause = reconcileDataSchema.allOf.find((clause) =>
  clause.if?.properties?.original_tool?.const === "bbr_apply" &&
  clause.if?.properties?.observation?.const === "PROVEN_COMMITTED");
const reconcileProduceTypes = TOOLS.reconcile_status.policy.produces.map(({ type }) => type);
if (!reconcileDataSchema.required.includes("reconciled_bbr_apply_receipt_ref") ||
    !reconcileDataSchema.required.includes("reconciled_bbr_change_ref") ||
    !reconciledBbrApplyClause ||
    reconciledBbrApplyClause.then.properties.reconciled_bbr_apply_receipt_ref !== S.ReceiptRef ||
    reconciledBbrApplyClause.then.properties.reconciled_bbr_change_ref !== S.ChangeRef ||
    !["RECONCILIATION_EVIDENCE", "RECONCILED_BBR_APPLY_CHANGE_RECEIPT"].every((type) => reconcileProduceTypes.includes(type)) ||
    TOOLS.reconcile_status.policy.controls.reconciledBbrApplyChangeReceipt !== RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.receiptSchema !== RECONCILED_BBR_APPLY_CHANGE_RECEIPT_SCHEMA ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_SCHEMA.additionalProperties !== false ||
    !["original_operation_ref", "planned_owned_dropin_ref", "planned_before_digest", "planned_descriptor_relative_nofollow", "planned_exclusive_create", "expected_owned_dropin_digest", "current_owned_dropin_digest", "recorded_prior_live_values_digest", "recorded_prior_persistent_values_digest", "reconciliation_evidence_ref", "receipt_binding_digest"].every((field) => RECONCILED_BBR_APPLY_CHANGE_RECEIPT_SCHEMA.required.includes(field)) ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.atomicLedgerTransaction.atomicity !== "ALL_OR_NONE" ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.receiptBinding.plannedBeforeDigest !== null ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.receiptBinding.plannedDescriptorRelativeNofollow !== true ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.receiptBinding.plannedExclusiveCreate !== true ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.outputProjection.rawPathValuesOrDigestsInMcp !== false ||
    RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY.normalBbrApplyReceiptRequired !== false) {
  throw new Error("proven committed bbr_apply reconciliation lacks its atomic opaque durable apply/change receipt");
}
if (JSON.stringify(TOOLS.cf_proxy_enable.dataSchema.properties.before_digest) !== JSON.stringify(S.Digest)) {
  throw new Error("cf_proxy_enable before_digest must be the non-null Digest primitive");
}
const evidenceDataRequired = TOOLS.evidence_list.dataSchema.required;
for (const field of ["rows", "next_cursor", "continuation_state", "requested_max_items", "returned_item_count", "rows_length_lte_requested_max_items", "cursor_snapshot_binding_digest"]) {
  if (!evidenceDataRequired.includes(field)) throw new Error(`evidence_list missing required pagination field: ${field}`);
}
if (!Object.values(XUI_INVENTORY_OBSERVATION_CASES).every((row) => row.ownedInboundRefs && row.versionMasked)) {
  throw new Error("XUI inventory observation cases do not close every dependent field");
}
if (JSON.stringify(Object.entries(XUI_INVENTORY_OBSERVATION_CASES).filter(([, row]) => row.ownedInboundRefs === "EMPTY").map(([name]) => name)) !==
    JSON.stringify(["ABSENT_CLEAN_ELIGIBLE", "ABSENT_NOT_INSTALL_ELIGIBLE"])) {
  throw new Error("only the two absent XUI cases may force owned_inbound_refs empty");
}
if ("retained_change_refs" in TOOLS.rollback_run.dataSchema.properties ||
    "retained_compensation_receipt_refs" in TOOLS.rollback_run.dataSchema.properties ||
    !("retained_compensation_pairs" in TOOLS.rollback_run.dataSchema.properties)) {
  throw new Error("rollback retained compensation must use the closed pair carrier only");
}
const writeInputKeys = ["run_id", "plan_ref", "operation_ref", "approval_ref", "expected_ledger_digest", "idempotency_key"];
if (JSON.stringify(Object.keys(TOOLS.certificate_deploy.inputSchema.properties)) !== JSON.stringify(writeInputKeys) ||
    JSON.stringify(TOOLS.certificate_deploy.inputSchema.required) !== JSON.stringify(writeInputKeys) ||
    PRIVILEGED_HELPER_OPERATIONS["origin.certificate_deploy_owned.v1"].callers.join(",") !== "certificate_deploy") {
  throw new Error("certificate_deploy public input or fixed helper caller closure drifted");
}
const bbrApplyRequired = TOOLS.bbr_apply.dataSchema.required;
for (const field of ["before_digest", "bbr_receipt_ref", "owned_dropin_ref", "ownership_receipt_ref", "owned_dropin_absent_before_create", "descriptor_relative_nofollow", "exclusive_create", "dropin_readback_matches", "owned_dropin_path_bound_to_approved_runtime_ref", "receipt_binds_owned_path_and_dropin_digest"]) {
  if (!bbrApplyRequired.includes(field)) throw new Error(`bbr_apply missing required create-only field: ${field}`);
}
for (const schema of [ACTIVE_CHECKPOINT_ZERO_COMMIT_PROOF_SCHEMA, ACTIVE_CHECKPOINT_OWNED_GRAPH_PROOF_SCHEMA]) {
  if (schema.additionalProperties !== false || JSON.stringify(schema.required) !== JSON.stringify(ACTIVE_CHECKPOINT_RECOVERY_PROOF_SCHEMA.required)) {
    throw new Error("active checkpoint reconciliation proof specialization is not closed");
  }
}
const TOOLS_BY_NAME = Object.freeze(Object.fromEntries(TOOL_LIST.map((tool) => [tool.name, tool])));

const R = (field, kind, producer, producerField, owner, consumers) => Object.freeze({
  field, kind, producer, producerField, owner, consumers: Object.freeze([...consumers]),
});
const REF_PRODUCERS = Object.freeze([
  R("run_id", "run", "run_begin", "run_ref", "run", ["run_status", "reconcile_status", "plan_compile", "plan_authorize", "evidence_list", "completion_evaluate", "run_close", "rollback_run", "origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory", "old_line_verify", "xui_install", "xui_create_inbound", "xui_profile_publish", "xui_profile_inspect", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "origin_verify", "cf_node_record_apply", "cf_proxy_enable", "cdn_verify", "traffic_verify", "logs_correlate", "bbr_inventory", "bbr_apply", "bbr_verify", "bbr_rollback"]),
  R("cursor", "nullable_runtime", "evidence_list", "next_cursor", "run", ["evidence_list"]),
  R("origin_target_ref", "target", "onboarding", null, "onboarding", ["run_begin"]),
  R("cloudflare_target_ref", "target", "onboarding", null, "onboarding", ["run_begin"]),
  R("node_hostname_ref", "runtime", "onboarding", null, "onboarding", ["run_begin"]),
  R("protected_line_ref", "nullable_runtime", "onboarding", null, "onboarding", ["run_begin"]),
  R("protected_line_runtime_secret_ref", "nullable_secret", "onboarding", null, "onboarding", ["run_begin"]),
  R("output_dir_ref", "runtime", "onboarding", null, "onboarding", ["run_begin"]),
  R("ssh_identity_secret_ref", "secret", "onboarding", null, "onboarding", ["run_begin"]),
  R("cf_audit_secret_ref", "secret", "onboarding", null, "onboarding", ["run_begin"]),
  R("cf_node_dns_secret_ref", "nullable_secret", "onboarding", null, "onboarding", ["run_begin"]),
  R("cf_origin_ca_secret_ref", "nullable_secret", "onboarding", null, "onboarding", ["run_begin"]),
  R("existing_xui_admin_secret_ref", "nullable_secret", "onboarding", null, "onboarding", ["run_begin"]),
  R("plan_ref", "plan", "plan_compile", "plan_ref", "plan", ["plan_authorize", "rollback_run", "xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "bbr_apply", "bbr_rollback"]),
  R("operation_ref", "operation", "plan_compile", "operation_refs", "plan", ["xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "bbr_apply", "bbr_rollback"]),
  R("approval_challenge_ref", "runtime", "plan_compile", "approval_challenge_ref", "plan", ["plan_authorize"]),
  R("approval_ref", "approval", "plan_authorize", "approval_ref", "plan", ["rollback_run", "xui_install", "xui_create_inbound", "xui_profile_publish", "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply", "cf_node_record_apply", "cf_proxy_enable", "bbr_apply", "bbr_rollback"]),
  R("profile_ref", "profile", "xui_profile_publish", "profile_ref", "run", ["xui_profile_inspect", "traffic_verify"]),
  R("client_profile_secret_ref", "secret", "xui_profile_publish", "client_profile_secret_ref", "run", ["traffic_verify"]),
  R("client_runtime_ref", "runtime", "client_inventory", "client_runtime_refs", "onboarding", ["traffic_verify"]),
  R("probe_destination_ref", "runtime", "client_inventory", "probe_destination_refs", "onboarding", ["old_line_verify", "cdn_verify", "traffic_verify", "bbr_verify"]),
  R("probe_ref", "probe", "traffic_verify", "probe_ref", "run", ["logs_correlate"]),
  R("correlation_window_ref", "runtime", "traffic_verify", "correlation_window_ref", "run", ["logs_correlate"]),
  R("bbr_change_ref", "change", "bbr_apply", "change_ref", "run", ["bbr_verify"]),
]);

const F = (role, provenance, producer, plaintextOwner, consumers, disposition) => Object.freeze({
  role, provenance, producer, plaintextOwner,
  consumers: Object.freeze([...consumers]), mcpBytes: false, disposition,
});
const CREDENTIAL_BYTE_FLOWS = Object.freeze([
  F("ssh-origin-identity", "imported", "onboarding Keychain import", "fixed SSH helper process", ["closed PRIVILEGED_HELPER_OPERATIONS rows"], "NEVER_DELETE_OR_REVOKE"),
  F("xui-panel-admin", "imported", "onboarding Keychain import", "broker fixed XUI adapter", ["xui.inventory_existing_fixed.v1", "xui.inbound_create_generate_store_client.v1", "xui.logs_counter_read_fixed.v1", "xui.reconcile_change_readback_fixed.v1"], "NEVER_DELETE_OR_REVOKE"),
  F("xui-panel-admin", "same-run-generated", "xui.install_generate_store_admin_secret", "broker fixed XUI adapter", ["xui.inventory_owned_fixed.v1", "xui.inbound_create_generate_store_client.v1", "xui.logs_counter_read_fixed.v1", "xui.reconcile_change_readback_fixed.v1", "xui.revoke_same_run_panel_admin.v1"], "DELETE_ONLY_AFTER_DEPENDENT_INVERSES_AND_SAME_RUN_OWNERSHIP_MATCH"),
  F("xui-client-credential", "same-run-generated", "xui.inbound_create_generate_store_client.v1", "broker fixed XUI adapter", ["xui.profile_publish_derive_store.v1", "xui.revoke_same_run_client_secret.v1"], "REVOKE_ONLY_AFTER_PROFILE_COMPENSATION_AND_SAME_RUN_INBOUND_OWNERSHIP_MATCH"),
  F("client-profile-runtime", "same-run-generated", "xui.profile_publish_derive_store.v1", "broker and allowlisted client runtime", ["xui.profile_inspect_projection.v1", "artifact.render_0600", "client.authenticated_egress_probe_fixed.v1", "artifact.reconcile_owned_fixed.v1", "artifact.revoke_same_run_runtime_secrets.v1", "traffic_verify"], "DELETE_AFTER_ARTIFACT_DELETE_OR_CHANGED_ARTIFACT_RESIDUAL_DISPOSITION; RETAIN_RESIDUAL_FOR_UNPROVABLE_COPIES"),
  F("protected-line-runtime", "imported", "onboarding Keychain import", "protected-line broker and fixed probe runtime", ["protected_line.runtime_probe_fixed.v1"], "NEVER_DELETE_OR_REVOKE"),
  F("cf-audit", "imported", "onboarding Keychain import", "broker Cloudflare adapter", ["cf.dns_read"], "NEVER_DELETE_OR_REVOKE"),
  F("cf-node-dns", "imported", "onboarding Keychain import", "broker Cloudflare adapter", ["cf.dns_create_owned", "cf.dns_proxy_owned", "cf.dns_delete_owned"], "NEVER_DELETE_OR_REVOKE"),
  F("cf-origin-ca", "imported", "onboarding Keychain import", "broker Cloudflare adapter", ["cf.origin_ca_issue_store_private_key", "cf.origin_ca_list_reconcile_fixed.v1"], "NEVER_DELETE_OR_REVOKE"),
  F("origin-ca-private-key", "same-run-generated", "cf.origin_ca_issue_store_private_key", "broker then same-run dedicated origin service slot", ["certificate_deploy", "certificate.revoke_same_run_private_key.v1"], "DELETE_WHEN_NO_SLOT_RECEIPT_OR_AFTER_SAME_RUN_SLOT_NODE_DELETE; RETAIN_REMOTE_PUBLIC_ISSUANCE_METADATA_RESIDUAL"),
]);

module.exports = Object.freeze({
  FROZEN_TOOL_NAMES, CORE_V1_TOOL_NAMES,
  S, ERROR_CODES,
  LEASE_POLICIES, EVIDENCE_TTLS,
  RUN_MODE_POLICY, OUTPUT_STATUS_POLICY, MUTATION_FAILURE_RESOLVER, RECONCILIATION_OUTCOME_RESOLVER, RECONCILIATION_OBSERVER_BY_TOOL, PLAN_OPERATION_RESOLVER, ACTIVE_NODE_EVIDENCE_REFRESH_CHECKPOINT, ACTIVE_CURSOR_WRITE_EXPIRY_RESOLVER,
  GENERATED_SECRET_POLICY, LOW_ENTROPY_BINDING_POLICY,
  XUI_INBOUND_POLICY, NGINX_ROUTE_POLICY, CLIENT_PROFILE_POLICY, BBR_TARGET_POLICY,
  XUI_INVENTORY_OBSERVATION_CASES,
  PRIVILEGED_HELPER_OPERATIONS, BROKER_OPERATIONS,
  XUI_INSTALL_POLICY, DOMAIN_IDENTITY_BINDING_POLICY,
  CORE_ROLLBACK_POLICY, NO_CLOBBER_POLICY,
  AUTHENTICATED_E2E_POLICY, MAIN_ROLLBACK_BBR_GATE, BBR_ROLLBACK_MAIN_GATE,
  BBR_ROLLBACK_AUTHORIZATION_SOURCE_SET, RECONCILED_BBR_APPLY_CHANGE_RECEIPT_SCHEMA,
  RECONCILED_BBR_APPLY_CHANGE_RECEIPT_POLICY,
  BBR_APPLY_BASELINE_RECEIPT_BINDING_POLICY,
  BBR_ROLLBACK_ATOMIC_STAGES, BBR_ROLLBACK_ATOMIC_STAGE_IDS,
  BBR_ROLLBACK_FINALIZATION_TRANSACTION, BBR_SAFETY_POLICY,
  REF_PRODUCERS, CREDENTIAL_BYTE_FLOWS,
  TOOLS, TOOL_LIST, TOOLS_BY_NAME,
});

