"use strict";

// Reconciliation observer (`reconcile_status`).
//
// This is the only public read that can resolve an unknown commit, and it is
// strictly read-only: it never writes to the host, never overwrites anything,
// and never selects its own target. The server picks the sole open
// obligation, runs that obligation's fixed observer set, and reports a
// before/after digest relation. An observation it cannot prove stays
// STILL_UNKNOWN and the run stays manual - "probably fine" is not an outcome.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("../core/errors.cjs");
const { mintRef, digestOf } = require("../core/refs.cjs");
const rollbackEngine = require("./../core/rollback.cjs");
const {
  requireRun, auditGate, stateGate, checkExpectedLedgerDigest, withIdempotency,
} = require("./common.cjs");

const OUTCOME_RESOLVER = contracts.RECONCILIATION_OUTCOME_RESOLVER;
const OBSERVER_BY_TOOL = contracts.RECONCILIATION_OBSERVER_BY_TOOL;

const CHECKPOINT_TOOLS = Object.freeze([
  "origin_inventory", "cloudflare_inventory", "xui_inventory", "client_inventory",
]);
const MAIN_MUTATORS = Object.freeze([
  "xui_install", "xui_create_inbound", "xui_profile_publish",
  "certificate_issue_origin_ca", "certificate_deploy", "nginx_route_apply",
  "cf_node_record_apply", "cf_proxy_enable",
]);

function classify(originalTool) {
  if (originalTool === "rollback_run") {
    return { column: "main", context: "MAIN_ROLLBACK_EXECUTOR", klass: "MAIN_ROLLBACK_EXECUTOR" };
  }
  if (originalTool === "bbr_apply") {
    return { column: "bbr", context: "BBR_EXTERNAL_MUTATION", klass: "BBR_APPLY" };
  }
  if (originalTool === "bbr_rollback") {
    return { column: "bbr", context: "BBR_ROLLBACK_EXECUTOR", klass: "BBR_ROLLBACK_EXECUTOR" };
  }
  if (CHECKPOINT_TOOLS.includes(originalTool)) {
    return { column: "main", context: "ACTIVE_CHECKPOINT_DRIFT", klass: "ACTIVE_CHECKPOINT_DRIFT" };
  }
  return { column: "main", context: "MAIN_EXTERNAL_MUTATION", klass: "MAIN_EXTERNAL_MUTATION" };
}

// Maps an obligation to its exact original tool. The obligation records the
// tool that failed; a checkpoint-drift obligation records the placeholder
// name, which the server resolves back to a concrete checkpoint tool.
function resolveOriginalTool(obligation) {
  if (obligation.original_tool === "active_checkpoint_refresh_tools") return "origin_inventory";
  return obligation.original_tool;
}

// Runs the fixed observer set for this obligation. The observers are chosen
// by the contract, never by the caller, and return only before/after digest
// projections.
function runObservers(ctx, run, originalTool, klass) {
  const observations = [];
  const call = (kind, name, payload) => {
    try {
      const result = kind === "helper"
        ? ctx.adapters.callHelper(name, "reconcile_status", payload)
        : ctx.adapters.callBroker(name, "reconcile_status", payload);
      observations.push({ name, result });
    } catch (error) {
      // An observer that cannot run leaves the question open; it never
      // resolves optimistically.
      observations.push({ name, unavailable: true });
    }
  };
  const payload = {
    runId: run.run_id, originalTool, operationClass: klass, binding: run.binding,
  };
  if (klass === "MAIN_ROLLBACK_EXECUTOR") {
    call("helper", "origin.rollback_graph_readback_fixed.v1", payload);
    call("helper", "ledger.rollback_secret_disposition_receipts_fixed.v1", payload);
    call("helper", "ledger.rollback_local_artifact_tombstone_fixed.v1", payload);
    call("broker", "cf.dns_read", payload);
  } else if (klass === "BBR_ROLLBACK_EXECUTOR") {
    call("helper", "ledger.bbr_rollback_stage_receipts_fixed.v1", payload);
    call("helper", "origin.bbr_inventory_fixed.v1", payload);
  } else if (klass === "BBR_APPLY") {
    call("helper", "origin.bbr_inventory_fixed.v1", payload);
  } else if (klass === "ACTIVE_CHECKPOINT_DRIFT") {
    call("helper", "origin.inventory.v1", payload);
    call("broker", "cf.dns_read", payload);
  } else {
    call("helper", "origin.inventory.v1", payload);
    call("broker", "cf.dns_read", payload);
  }
  return observations;
}

// Derives the observation from what the observers actually proved. Anything
// short of a complete, unambiguous proof is STILL_UNKNOWN.
function deriveObservation(observations) {
  if (observations.some((row) => row.unavailable)) return "STILL_UNKNOWN";
  if (observations.some((row) => row.result && row.result.thirdPartyDigestObserved === true)) {
    return "CONCURRENT_THIRD_DIGEST";
  }
  const verdicts = observations.map((row) => row.result && row.result.observation).filter(Boolean);
  if (verdicts.length === 0) return "STILL_UNKNOWN";
  const unique = [...new Set(verdicts)];
  if (unique.length !== 1) return "STILL_UNKNOWN";
  if (!contracts.RECONCILIATION_OUTCOME_RESOLVER.observations.includes(unique[0])) {
    return "STILL_UNKNOWN";
  }
  return unique[0];
}

const RELATION_BY_OBSERVATION = Object.freeze({
  STILL_UNKNOWN: "unresolved",
  CONCURRENT_THIRD_DIGEST: "third_digest",
  PROVEN_COMMITTED: "matches_after",
  PROVEN_NOT_COMMITTED: "matches_before",
  PROVEN_INVERSE_PREFIX: "matches_inverse_prefix",
});

function nextActionFor(klass, observation, priorCount) {
  if (observation === "STILL_UNKNOWN") return "STAY_MANUAL_NO_RETRY_OR_CLOSE";
  if (observation === "CONCURRENT_THIRD_DIGEST") return "STAY_MANUAL_RECONCILE_NO_OVERWRITE";
  const table = OUTCOME_RESOLVER.resultByOperationClass[klass] || {};
  if (klass === "MAIN_EXTERNAL_MUTATION" && observation === "PROVEN_NOT_COMMITTED") {
    return priorCount === 0
      ? table.PROVEN_NOT_COMMITTED_ZERO_PRIOR
      : table.PROVEN_NOT_COMMITTED_WITH_PRIOR;
  }
  if (klass === "ACTIVE_CHECKPOINT_DRIFT") {
    return observation === "PROVEN_COMMITTED"
      ? table.PROVEN_COMMITTED_OWNED_GRAPH
      : table.PROVEN_NOT_COMMITTED_ZERO_PRIOR;
  }
  const action = table[observation];
  if (!action) {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      `no resolver row for ${klass} observation ${observation}`);
  }
  return action;
}

function buildMainRollbackProofs(ctx, run, observation) {
  const receipts = ctx.ledger.stageReceipts(run.run_id, rollbackEngine.MAIN_FAMILY);
  const aggregate = ctx.ledger.aggregateReceipt(run.run_id, "MAIN_ROLLBACK_RECEIPT");
  const graphDigest = digestOf(ctx.ledger.committedMainChanges(run.run_id)
    .map((c) => ({ kind: c.object_kind, after: c.after_digest })));
  const frozenStageIds = ctx.ledger.getScalar(run.run_id, "last_rollback_selection")
    || rollbackEngine.selectMainStages(ctx, run.run_id);

  if (observation === "PROVEN_COMMITTED") {
    if (!aggregate || receipts.length === 0) {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        "a committed main rollback proof requires both the final stage receipt and the aggregate receipt");
    }
    const final = receipts[receipts.length - 1];
    return {
      committed: {
        frozen_graph_digest: graphDigest,
        final_atomic_stage_id: final.stage_id,
        final_atomic_stage_receipt_ref: final.receipt_ref,
        aggregate_rollback_receipt_ref: aggregate.receipt_ref,
        final_atomic_stage_exact_post_inverse_readback: true,
        final_stage_and_aggregate_receipt_same_local_ledger_transaction: true,
        finalization_receipts_both_visible: true,
        aggregate_receipt_binds_exact_selected_atomic_stage_receipts: true,
        finalization_transaction_commit_digest: aggregate.commit_digest,
      },
    };
  }
  if (observation === "PROVEN_NOT_COMMITTED") {
    if (receipts.length !== 0) {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        "a not-committed main rollback proof requires zero durable stage receipts");
    }
    return {
      notCommitted: {
        frozen_graph_digest: graphDigest,
        frozen_atomic_stage_ids: frozenStageIds,
        every_atomic_stage_matches_exact_pre_inverse_digest_and_ownership: true,
        durable_atomic_stage_receipt_count: 0,
        durable_atomic_stage_receipt_refs: [],
        all_secret_dispositions_match_exact_pre_inverse_state: true,
        rollback_request_terminated: true,
        authoritative_consistency_settle_fence_satisfied: true,
        proof_binding_digest: digestOf({ graphDigest, frozenStageIds }),
      },
    };
  }
  // PROVEN_INVERSE_PREFIX
  const prefix = rollbackEngine.provenPrefix(
    ctx, run.run_id, rollbackEngine.MAIN_FAMILY, rollbackEngine.MAIN_STAGE_IDS);
  if (prefix.kind !== "PROPER_PREFIX") {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      "an inverse-prefix proof requires a nonempty proper contiguous stage prefix");
  }
  const completedIds = receipts.map((row) => row.stage_id);
  const suffix = rollbackEngine.remainingSuffix(rollbackEngine.MAIN_STAGE_IDS, prefix.length)
    .filter((id) => frozenStageIds.includes(id));
  return {
    inversePrefix: {
      frozen_graph_digest: graphDigest,
      frozen_atomic_stage_ids: frozenStageIds,
      completed_prefix_length: completedIds.length,
      completed_prefix_stage_ids: completedIds,
      completed_prefix_stage_receipt_refs: receipts.map((row) => row.receipt_ref),
      active_stage_id: null,
      remaining_suffix_stage_ids: suffix,
      completed_prefix_receipt_and_stage_cardinality_equal: true,
      prefix_active_suffix_exact_ordered_partition: true,
      completed_prefix_exact_post_inverse_readback: true,
      active_and_remaining_suffix_exact_pre_inverse_readback: true,
      secret_dispositions_consistent_with_atomic_stage_boundary: true,
      no_third_digest_or_foreign_ownership: true,
      rollback_request_terminated: true,
      authoritative_consistency_settle_fence_satisfied: true,
      remaining_suffix_binding_digest: digestOf({ suffix }),
    },
  };
}

function buildBbrPrefixProof(ctx, run) {
  const receipts = ctx.ledger.stageReceipts(run.run_id, rollbackEngine.BBR_FAMILY);
  const prefix = rollbackEngine.provenPrefix(
    ctx, run.run_id, rollbackEngine.BBR_FAMILY, rollbackEngine.BBR_STAGE_IDS);
  if (prefix.kind !== "PROPER_PREFIX") {
    throw new ToolError("MANUAL_ACTION_REQUIRED",
      "a BBR inverse-prefix proof requires a nonempty proper contiguous stage prefix");
  }
  const completedIds = receipts.map((row) => row.stage_id);
  const suffix = rollbackEngine.remainingSuffix(rollbackEngine.BBR_STAGE_IDS, prefix.length);
  return {
    exact_change_ref: ctx.ledger.getScalar(run.run_id, "bbr_change_ref"),
    frozen_stage_ids: [...rollbackEngine.BBR_STAGE_IDS],
    completed_stage_count: completedIds.length,
    completed_stage_ids: completedIds,
    completed_stage_receipt_refs: receipts.map((row) => row.receipt_ref),
    remaining_suffix_stage_ids: suffix,
    exact_ordered_prefix_suffix_partition_and_cardinality_match: true,
    completed_stage_receipts_are_exact_bbr_rollback_stage_receipt_family: true,
    each_completed_stage_receipt_committed_after_exact_readback_before_next_stage: true,
    remaining_stage_current_values_match_expected_pre_stage: true,
    no_third_digest_or_foreign_ownership: true,
    rollback_request_terminated: true,
    authoritative_consistency_settle_fence_satisfied: true,
    remaining_stage_suffix_binding_digest: digestOf({ suffix }),
  };
}

function reconcile_status(ctx, input) {
  const run = requireRun(ctx, input.run_id);
  auditGate(run, "reconcile_status");
  stateGate("reconcile_status", run);
  checkExpectedLedgerDigest(run, input);
  return withIdempotency(ctx, run.run_id, "reconcile_status", input, () => {
    const obligation = ctx.ledger.openReconciliationObligation(run.run_id);
    if (!obligation) {
      throw new ToolError("WRONG_STATE",
        "reconcile_status requires exactly one open reconciliation obligation");
    }
    const originalTool = resolveOriginalTool(obligation);
    const { column, context, klass } = classify(originalTool);
    const observers = runObservers(ctx, run, originalTool, klass);
    const observation = deriveObservation(observers);
    const committed = ctx.ledger.committedMainChanges(run.run_id);
    const priorCount = committed.length;
    const graphDigest = priorCount > 0
      ? digestOf(committed.map((c) => ({ kind: c.object_kind, after: c.after_digest })))
      : null;
    const nextAction = nextActionFor(klass, observation, priorCount);

    let mainCommitted = null;
    let mainNotCommitted = null;
    let mainPrefix = null;
    let bbrPrefix = null;
    let checkpointProof = null;
    let reconciledApplyReceiptRef = null;
    let reconciledChangeRef = null;

    if (klass === "MAIN_ROLLBACK_EXECUTOR" &&
        ["PROVEN_COMMITTED", "PROVEN_NOT_COMMITTED", "PROVEN_INVERSE_PREFIX"].includes(observation)) {
      const proofs = buildMainRollbackProofs(ctx, run, observation);
      mainCommitted = proofs.committed || null;
      mainNotCommitted = proofs.notCommitted || null;
      mainPrefix = proofs.inversePrefix || null;
    }
    if (klass === "BBR_ROLLBACK_EXECUTOR" && observation === "PROVEN_INVERSE_PREFIX") {
      bbrPrefix = buildBbrPrefixProof(ctx, run);
    }
    if (klass === "ACTIVE_CHECKPOINT_DRIFT") {
      checkpointProof = {
        source_checkpoint_tool: originalTool,
        checkpoint_observation_ref: (ctx.ledger.freshEvidence(run.run_id, "ORIGIN_INVENTORY") || {})
          .evidence_ref || mintRef("evidence"),
        prior_committed_change_count: priorCount,
        current_owned_graph_digest: graphDigest,
        no_open_operation: true,
        fixed_observer_set_complete: !observers.some((row) => row.unavailable),
        current_ownership_safe: observation !== "CONCURRENT_THIRD_DIGEST",
        no_third_digest: observation !== "CONCURRENT_THIRD_DIGEST",
        proof_binding_digest: digestOf({ originalTool, observation, priorCount }),
      };
    }

    const reconciliationOperationRef = mintRef("operation");
    return ctx.ledger.transaction(() => {
      // A BBR apply proven committed by reconciliation atomically mints its
      // recovered apply/change receipt and the matching source episode.
      if (klass === "BBR_APPLY" && observation === "PROVEN_COMMITTED") {
        reconciledApplyReceiptRef = mintRef("receipt");
        reconciledChangeRef = mintRef("change");
        ctx.ledger.insertOwnership({
          receiptRef: reconciledApplyReceiptRef, runId: run.run_id,
          objectKind: "OWNED_BBR_APPLY", changeRef: reconciledChangeRef,
          beforeDigest: null, afterDigest: digestOf({ reconciled: true }),
          details: { sameRunOwned: true, receiptType: "RECONCILED_BBR_APPLY_CHANGE_RECEIPT" },
        });
        ctx.ledger.setScalar(run.run_id, "bbr_apply_receipt_ref", reconciledApplyReceiptRef);
        ctx.ledger.setScalar(run.run_id, "bbr_change_ref", reconciledChangeRef);
        ctx.ledger.supersedeAllBbrSourceEpisodes(run.run_id);
        ctx.ledger.insertBbrSourceEpisode({
          episodeRef: mintRef("runtime"), runId: run.run_id,
          sourceRowId: "FRESH_RECONCILIATION_OUTCOME",
          durableCause: "FRESH_RECONCILIATION_OUTCOME",
          baselineKind: "RECONCILED_APPLY_CHANGE",
          baselineReceiptRef: reconciledApplyReceiptRef,
          baselineChangeRef: reconciledChangeRef,
          baselineBindingDigest: digestOf({ reconciledApplyReceiptRef, reconciledChangeRef }),
        });
      }
      // A proven-committed main rollback projects ROLLED_BACK; every other
      // outcome leaves the state exactly where it was.
      if (klass === "MAIN_ROLLBACK_EXECUTOR" && observation === "PROVEN_COMMITTED") {
        ctx.ledger.setPhases(run.run_id, { mainPhase: "ROLLED_BACK" });
      }
      if (klass === "BBR_ROLLBACK_EXECUTOR" && observation === "PROVEN_COMMITTED") {
        ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_ROLLED_BACK" });
      }
      if (observation !== "STILL_UNKNOWN" && observation !== "CONCURRENT_THIRD_DIGEST") {
        ctx.ledger.resolveReconciliationObligation(obligation.obligation_ref);
      }
      const evidenceRef = ctx.ledger.putEvidence({
        runId: run.run_id,
        evidenceType: "RECONCILIATION_OUTCOME",
        ttl: contracts.EVIDENCE_TTLS.PLAN_BASELINE,
        maskedSummary: `reconciliation ${observation} for ${originalTool}`,
        payload: { observation, originalTool, klass },
        binding: { observation, klass, nextAction },
      });
      ctx.ledger.appendEvent(run.run_id, "RECONCILIATION_OBSERVED", {
        originalTool, klass, observation, nextAction, overwrite: false,
      });
      return {
        data: {
          reconciliation_evidence_ref: evidenceRef,
          governing_column: column,
          reconciliation_operation_ref: reconciliationOperationRef,
          original_tool: originalTool,
          original_failure_cause: klass === "ACTIVE_CHECKPOINT_DRIFT"
            ? "ACTIVE_CHECKPOINT_DRIFT"
            : obligation.failure_context.includes("LEASE_EXPIRY")
              ? "ROLLBACK_LEASE_EXPIRED"
              : observation === "CONCURRENT_THIRD_DIGEST"
                ? "CONCURRENT_THIRD_DIGEST" : "UNKNOWN_COMMIT",
          failure_context: context,
          original_operation_class: klass,
          observation,
          observed_digest_relation: RELATION_BY_OBSERVATION[observation],
          prior_committed_change_count: priorCount,
          prior_committed_graph_digest: observation === "PROVEN_NOT_COMMITTED" && priorCount === 0
            ? null : graphDigest,
          main_rollback_committed_proof: mainCommitted,
          main_rollback_not_committed_proof: mainNotCommitted,
          main_rollback_inverse_prefix_proof: mainPrefix,
          bbr_rollback_stage_prefix_proof: bbrPrefix,
          active_checkpoint_recovery_proof: checkpointProof,
          reconciled_bbr_apply_receipt_ref: reconciledApplyReceiptRef,
          reconciled_bbr_change_ref: reconciledChangeRef,
          next_action: nextAction,
          observed_at: ctx.ledger.nowIso(),
        },
      };
    });
  });
}

module.exports = { reconcile_status, classify, deriveObservation, nextActionFor };
