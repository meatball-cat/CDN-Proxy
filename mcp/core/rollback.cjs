"use strict";

// Rollback stage engine.
//
// Main rollback expands eight dependency-reverse logical graph nodes into the
// frozen eleven ordered atomic stages; the BBR branch has its own frozen four.
// Both share the same discipline:
//
//   * a stage runs only if this run owns that resource and the resource's
//     current bytes still equal the ownership receipt - a third-party digest
//     stops the rollback and goes to manual rather than clobbering;
//   * each stage commits a durable receipt after its own readback and before
//     the next stage starts, so a crash exposes only a contiguous prefix;
//   * the final stage receipt and the aggregate receipt commit in one local
//     ledger transaction with both-or-neither visibility;
//   * a proven prefix is resumed from its exact remaining suffix, and a
//     completed stage is never replayed.
//
// Imported (onboarding) secrets are structurally invisible to disposal: only
// same-run generated material can ever be revoked.

const contracts = require("../../contract/mcp/schemas/contracts.cjs");
const { ToolError } = require("./errors.cjs");
const { mintRef, digestOf } = require("./refs.cjs");

const MAIN_STAGES = contracts.PLAN_OPERATION_RESOLVER.scopes.MAIN_ROLLBACK.atomicStages;
const MAIN_STAGE_IDS = contracts.PLAN_OPERATION_RESOLVER.scopes.MAIN_ROLLBACK.atomicStageIds;
const MAIN_FINALIZATION = contracts.PLAN_OPERATION_RESOLVER.scopes.MAIN_ROLLBACK.finalizationTransaction;
const BBR_STAGES = contracts.BBR_ROLLBACK_ATOMIC_STAGES;
const BBR_STAGE_IDS = contracts.BBR_ROLLBACK_ATOMIC_STAGE_IDS;
const BBR_FINALIZATION = contracts.BBR_ROLLBACK_FINALIZATION_TRANSACTION;
const LEASE_EXPIRY = contracts.PLAN_OPERATION_RESOLVER.rollbackLeaseExpiryResolver;

const MAIN_FAMILY = "MAIN_ROLLBACK_STAGE_RECEIPT";
const BBR_FAMILY = "BBR_ROLLBACK_STAGE_RECEIPT";

// What each atomic stage reverses, and how the server proves this run owns it.
// `ownershipKind` names an ownership receipt; `secretRole` names same-run
// generated credential material. Exactly one of the two is set per stage.
const MAIN_STAGE_SUBJECT = Object.freeze({
  rb01_cf_proxy_restore: { ownershipKind: "OWNED_CF_PROXY" },
  rb02_cf_record_delete: { ownershipKind: "OWNED_CF_RECORD" },
  rb03_nginx_route_delete: { ownershipKind: "OWNED_NGINX_ROUTE" },
  rb04_certificate_slots_delete: { ownershipKind: "OWNED_CERTIFICATE_SLOTS" },
  rb05_origin_ca_private_key_dispose: { secretRole: "origin-ca-private-key" },
  rb06_client_artifact_dispose: { ownershipKind: "OWNED_CLIENT_ARTIFACT" },
  rb07_profile_runtime_secret_dispose: { secretRole: "client-profile-runtime" },
  rb08_xui_inbound_remove: { ownershipKind: "OWNED_XUI_INBOUND_RESOURCE" },
  rb09_xui_client_secret_revoke: { secretRole: "xui-client-credential" },
  rb10_xui_install_uninstall: { ownershipKind: "OWNED_XUI_INSTALLATION" },
  rb11_xui_panel_admin_revoke: { secretRole: "xui-panel-admin" },
});

function operationKind(operationName) {
  if (contracts.PRIVILEGED_HELPER_OPERATIONS[operationName]) return "helper";
  if (contracts.BROKER_OPERATIONS[operationName]) return "broker";
  throw new ToolError("INTERNAL_ERROR", `unknown inverse operation ${operationName}`);
}

// --- stage selection ------------------------------------------------------

// The frozen selection for this run: every atomic stage whose subject this
// run actually owns, in the contract's exact order. Server-derived from the
// immutable ledger; the caller selects nothing.
function selectMainStages(ctx, runId) {
  return MAIN_STAGES.filter((stage) => {
    const subject = MAIN_STAGE_SUBJECT[stage.stageId];
    if (subject.ownershipKind) {
      return ctx.ledger.latestOwnership(runId, subject.ownershipKind) !== null;
    }
    // Imported credentials are never disposable: only same-run generated
    // material with a current disposition qualifies.
    return ctx.ledger.currentSameRunSecret(runId, subject.secretRole) !== null;
  }).map((stage) => stage.stageId);
}

function selectionDigest(stageIds) {
  return digestOf({ selection: stageIds });
}

// A durable stage-receipt prefix must be an exact, contiguous prefix of the
// frozen ordered stage list. Anything else - a gap, a wrong order, a stage
// outside the list - is not a resumable prefix and goes to manual.
function provenPrefix(ctx, runId, family, orderedStageIds) {
  const receipts = ctx.ledger.stageReceipts(runId, family);
  const observed = receipts.map((row) => row.stage_id);
  if (observed.length === 0) return { kind: "ZERO", length: 0, receipts };
  for (let i = 0; i < observed.length; i += 1) {
    if (observed[i] !== orderedStageIds[i]) {
      return { kind: "NON_CONTIGUOUS", length: i, receipts, observed };
    }
  }
  if (observed.length === orderedStageIds.length) {
    return { kind: "COMPLETE", length: observed.length, receipts };
  }
  return { kind: "PROPER_PREFIX", length: observed.length, receipts };
}

function remainingSuffix(orderedStageIds, prefixLength) {
  return orderedStageIds.slice(prefixLength);
}

// --- lease expiry ---------------------------------------------------------

// Main zero-dispatch expiry mints a durable admission receipt and returns the
// run to ROLLBACK_REQUIRED for a fresh full-graph plan. It creates no
// reconciliation evidence: nothing was dispatched, so nothing is unknown.
function resolveMainRollbackLeaseExpiry(ctx, run, plan) {
  const orderedStageIds = ctx.ledger.getScalar(run.run_id, `stages:${plan.plan_ref}`) || [];
  const prefix = provenPrefix(ctx, run.run_id, MAIN_FAMILY, orderedStageIds);
  const openDispatch = ctx.ledger.getScalar(run.run_id, "open_rollback_dispatch");
  if (prefix.length === 0 && prefix.kind !== "NON_CONTIGUOUS" && !openDispatch) {
    const row = LEASE_EXPIRY.rows.MAIN_ZERO_INVERSE_BEFORE_DISPATCH;
    const receiptRef = mintRef("receipt");
    ctx.ledger.transaction(() => {
      ctx.ledger.invalidateCurrentPlan(run.run_id);
      ctx.ledger.insertAdmissionReceipt({
        receiptRef, runId: run.run_id, receiptType: row.admissionReceipt,
        bindingDigest: digestOf({ planRef: plan.plan_ref, zeroStageReceipts: true }),
      });
      ctx.ledger.appendEvent(run.run_id, "MAIN_ROLLBACK_ZERO_DISPATCH_LEASE_EXPIRY", {
        admissionReceipt: row.admissionReceipt, receiptRef,
        invalidates: row.invalidates, reconciliationEvidenceRequired: false,
      });
      ctx.ledger.setPhases(run.run_id, { mainPhase: row.destination });
    });
    throw new ToolError("APPROVAL_STALE",
      "rollback lease expired with zero dispatched inverses; old authority revoked, a durable admission receipt permits a fresh full-graph rollback plan");
  }
  const row = LEASE_EXPIRY.rows.MAIN_PREFIX_STARTED;
  ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    ctx.ledger.insertReconciliationObligation({
      obligationRef: mintRef("runtime"), runId: run.run_id,
      originalTool: "rollback_run", failureContext: "ROLLBACK_LEASE_EXPIRY_AFTER_PREFIX",
    });
    ctx.ledger.appendEvent(run.run_id, "MAIN_ROLLBACK_PREFIX_LEASE_EXPIRY", {
      prefixLength: prefix.length, next: row.next,
    });
    ctx.ledger.setPhases(run.run_id, { mainPhase: row.destination });
  });
  throw new ToolError("MANUAL_ACTION_REQUIRED",
    "rollback lease expired after a dispatched stage prefix; reconcile the proven prefix before any remaining suffix");
}

// BBR zero-stage expiry atomically supersedes the prior source episode,
// inherits its exact one baseline binding, records its own durable cause, and
// creates a new unconsumed episode. It never reuses the main admission
// receipt and never creates reconciliation evidence.
function resolveBbrRollbackLeaseExpiry(ctx, run, plan) {
  const prefix = provenPrefix(ctx, run.run_id, BBR_FAMILY, BBR_STAGE_IDS);
  const openDispatch = ctx.ledger.getScalar(run.run_id, "open_bbr_rollback_dispatch");
  if (prefix.length === 0 && prefix.kind !== "NON_CONTIGUOUS" && !openDispatch) {
    const row = LEASE_EXPIRY.rows.BBR_ZERO_STAGE_BEFORE_DISPATCH;
    const episodes = ctx.ledger.currentBbrSourceEpisodes(run.run_id);
    if (episodes.length !== 1) {
      throw new ToolError("MANUAL_ACTION_REQUIRED",
        "BBR zero-stage expiry requires exactly one current source obligation episode");
    }
    const prior = episodes[0];
    ctx.ledger.transaction(() => {
      ctx.ledger.invalidateCurrentPlan(run.run_id);
      ctx.ledger.consumeBbrSourceEpisode(prior.episode_ref, "consumed");
      ctx.ledger.insertBbrSourceEpisode({
        episodeRef: mintRef("runtime"),
        runId: run.run_id,
        sourceRowId: "BBR_ZERO_STAGE_BEFORE_DISPATCH",
        durableCause: row.cause,
        // Exactly one baseline binding, inherited field for field.
        baselineKind: prior.baseline_kind,
        baselineReceiptRef: prior.baseline_receipt_ref,
        baselineChangeRef: prior.baseline_change_ref,
        baselineBindingDigest: prior.baseline_binding_digest,
      });
      ctx.ledger.appendEvent(run.run_id, "BBR_ROLLBACK_ZERO_STAGE_LEASE_EXPIRY", {
        cause: row.cause,
        consumedEpisodeRef: prior.episode_ref,
        inherited: row.inheritsFromConsumedSourceEpisode,
        mainRollbackAdmissionReceiptAllowed: false,
        reconciliationEvidenceRequired: false,
      });
      ctx.ledger.setPhases(run.run_id, { bbrPhase: row.destination });
    });
    throw new ToolError("APPROVAL_STALE",
      "BBR rollback lease expired with zero stage receipts; the prior source episode was superseded and its exact baseline inherited for a fresh plan");
  }
  const row = LEASE_EXPIRY.rows.BBR_PREFIX_STARTED;
  ctx.ledger.transaction(() => {
    ctx.ledger.invalidateCurrentPlan(run.run_id);
    ctx.ledger.insertReconciliationObligation({
      obligationRef: mintRef("runtime"), runId: run.run_id,
      originalTool: "bbr_rollback", failureContext: "BBR_ROLLBACK_LEASE_EXPIRY_AFTER_PREFIX",
    });
    ctx.ledger.appendEvent(run.run_id, "BBR_ROLLBACK_PREFIX_LEASE_EXPIRY", {
      prefixLength: prefix.length, next: row.next,
    });
    ctx.ledger.setPhases(run.run_id, { bbrPhase: row.destination });
  });
  throw new ToolError("MANUAL_ACTION_REQUIRED",
    "BBR rollback lease expired after a dispatched stage prefix; reconcile before any remaining stage suffix");
}

// --- stage execution ------------------------------------------------------

// Proves the resource this stage reverses is still exactly what this run
// committed. A changed digest means a third party touched it: stop, do not
// write, and go to manual.
function proveStageSubjectUnchanged(ctx, run, stageId) {
  const subject = MAIN_STAGE_SUBJECT[stageId];
  if (subject.ownershipKind) {
    const receipt = ctx.ledger.latestOwnership(run.run_id, subject.ownershipKind);
    if (!receipt) {
      throw new ToolError("ROLLBACK_UNSAFE",
        `stage ${stageId} has no same-run ownership receipt; refusing to touch an unowned resource`);
    }
    const details = JSON.parse(receipt.details || "{}");
    if (details.sameRunOwned !== true) {
      throw new ToolError("ROLLBACK_UNSAFE",
        `stage ${stageId} subject is not same-run owned`);
    }
    return { receipt, expectedDigest: receipt.after_digest, details };
  }
  const secret = ctx.ledger.currentSameRunSecret(run.run_id, subject.secretRole);
  if (!secret) {
    throw new ToolError("ROLLBACK_UNSAFE",
      `stage ${stageId} has no current same-run generated ${subject.secretRole} to dispose`);
  }
  if (secret.provenance !== "same-run-generated") {
    throw new ToolError("ROLLBACK_UNSAFE",
      `stage ${stageId} refuses to dispose an imported ${subject.secretRole} credential`);
  }
  return { secret, expectedDigest: null };
}

function dispatchStage(ctx, run, stage, payload, callerTool) {
  const kind = operationKind(stage.inverseOperation);
  return kind === "helper"
    ? ctx.adapters.callHelper(stage.inverseOperation, callerTool, payload)
    : ctx.adapters.callBroker(stage.inverseOperation, callerTool, payload);
}

// Executes the selected main atomic stages in order. Stages 1..n-1 each
// commit their durable receipt in their own transaction; the final stage
// commits its receipt together with the aggregate receipt.
function executeMainStages(ctx, run, plan, operation, selectedStageIds) {
  const stageReceiptRefs = [];
  const reversedChangeRefs = [];
  const retainedPairs = [];
  const stageObjects = selectedStageIds.map((stageId) =>
    MAIN_STAGES.find((stage) => stage.stageId === stageId));

  for (let index = 0; index < stageObjects.length; index += 1) {
    const stage = stageObjects[index];
    const subjectProof = proveStageSubjectUnchanged(ctx, run, stage.stageId);
    const isFinal = index === stageObjects.length - 1;

    ctx.ledger.setScalar(run.run_id, "open_rollback_dispatch", stage.stageId);
    let result;
    try {
      result = dispatchStage(ctx, run, stage, {
        runId: run.run_id,
        stageId: stage.stageId,
        graphNode: stage.graphNode,
        ownershipReceiptRef: subjectProof.receipt ? subjectProof.receipt.receipt_ref : null,
        expectedCurrentDigest: subjectProof.expectedDigest,
        secretRef: subjectProof.secret ? subjectProof.secret.secret_ref : null,
        binding: run.binding,
      }, "rollback_run");
    } catch (error) {
      ctx.ledger.setScalar(run.run_id, "open_rollback_dispatch", null);
      throw error;
    }
    ctx.ledger.setScalar(run.run_id, "open_rollback_dispatch", null);

    // A third-party digest means the resource is no longer the one this run
    // created; never overwrite it, never compensate blindly.
    if (result.thirdPartyDigestObserved === true) {
      ctx.ledger.transaction(() => {
        ctx.ledger.insertReconciliationObligation({
          obligationRef: mintRef("runtime"), runId: run.run_id,
          originalTool: "rollback_run", failureContext: `THIRD_DIGEST_AT_${stage.stageId}`,
        });
        ctx.ledger.setPhases(run.run_id, { mainPhase: "MANUAL_ACTION_REQUIRED" });
      });
      throw new ToolError("CONFLICT_DETECTED",
        `stage ${stage.stageId} observed a concurrent third-party digest; no inverse was applied`);
    }
    if (result.readbackVerified !== true) {
      throw new ToolError("ROLLBACK_UNSAFE",
        `stage ${stage.stageId} inverse readback was not verified`);
    }

    const stageReceiptRef = mintRef("receipt");
    const readbackDigest = result.readbackDigest || digestOf(result.observation || {});
    // A resource that could not be erased (a remote public record, a copy we
    // cannot prove destroyed) is retained and disclosed, never silently
    // dropped.
    if (result.retainedResidual) {
      const residualRef = mintRef("evidence");
      const compensationReceiptRef = mintRef("receipt");
      retainedPairs.push({
        stageId: stage.stageId,
        residualRef,
        compensationReceiptRef,
        changeRef: subjectProof.receipt ? subjectProof.receipt.change_ref : mintRef("change"),
      });
      ctx.ledger.insertResidual({
        residualRef, runId: run.run_id,
        kind: result.retainedResidual.kind,
        maskedSummary: result.retainedResidual.maskedSummary,
        bindingDigest: readbackDigest,
      });
    }
    if (subjectProof.secret) {
      ctx.ledger.insertSecretDisposition({
        receiptRef: mintRef("receipt"), runId: run.run_id,
        secretRef: subjectProof.secret.secret_ref,
        role: subjectProof.secret.role,
        disposition: result.retainedResidual ? "revoked_with_residual" : "revoked",
      });
    }
    if (subjectProof.receipt) reversedChangeRefs.push(subjectProof.receipt.change_ref);

    const commitStage = () => ctx.ledger.insertStageReceipt({
      receiptRef: stageReceiptRef, runId: run.run_id, family: MAIN_FAMILY,
      operationRef: operation.operation_ref, stageId: stage.stageId,
      stageIndex: MAIN_STAGE_IDS.indexOf(stage.stageId),
      readbackDigest,
      details: { graphNode: stage.graphNode, inverseOperation: stage.inverseOperation },
    });

    if (!isFinal) {
      // Durable before the next stage starts: a crash here exposes exactly
      // this contiguous prefix and nothing more.
      ctx.ledger.transaction(commitStage);
      stageReceiptRefs.push(stageReceiptRef);
      continue;
    }

    // Finalization: the final stage receipt and the aggregate receipt commit
    // together, both-or-neither. A crash before this commit leaves neither.
    const aggregateRef = mintRef("receipt");
    stageReceiptRefs.push(stageReceiptRef);
    const finalDigest = digestOf({ stageReceiptRefs, readbackDigest });
    const commitDigest = digestOf({
      trigger: MAIN_FINALIZATION.trigger,
      selection: selectedStageIds,
      stageReceiptRefs,
      finalDigest,
    });
    ctx.ledger.transaction(() => {
      commitStage();
      ctx.ledger.insertAggregateReceipt({
        receiptRef: aggregateRef, runId: run.run_id,
        receiptType: "MAIN_ROLLBACK_RECEIPT",
        operationRef: operation.operation_ref,
        selectionDigest: selectionDigest(selectedStageIds),
        stageReceiptRefs, commitDigest, finalDigest,
        details: { retainedPairs, reversedChangeRefs },
      });
      ctx.ledger.appendEvent(run.run_id, "MAIN_ROLLBACK_FINALIZED", {
        aggregateRef, stageCount: stageReceiptRefs.length,
        atomicity: MAIN_FINALIZATION.atomicity,
      });
    });
    return {
      aggregateRef, stageReceiptRefs, reversedChangeRefs, retainedPairs,
      finalDigest, commitDigest, finalStageId: stage.stageId,
      finalStageReceiptRef: stageReceiptRef, readbackDigest,
    };
  }
  throw new ToolError("ROLLBACK_UNSAFE", "no atomic stage was selected for this rollback");
}

// Executes the frozen four BBR inverse stages. Each of stages 1-3 commits its
// receipt after its own exact readback and before the next stage; stage 4's
// receipt commits with the aggregate.
function executeBbrStages(ctx, run, plan, operation, selectedStageIds) {
  const priorValues = ctx.ledger.getScalar(run.run_id, "bbr_prior_values");
  const applyReceiptRef = ctx.ledger.getScalar(run.run_id, "bbr_apply_receipt_ref");
  if (!priorValues || !applyReceiptRef) {
    throw new ToolError("ROLLBACK_UNSAFE",
      "BBR rollback requires the recorded prior values and the apply receipt");
  }
  const stageReceiptRefs = [];
  const stageObjects = selectedStageIds.map((stageId) =>
    BBR_STAGES.find((stage) => stage.stageId === stageId));

  for (let index = 0; index < stageObjects.length; index += 1) {
    const stage = stageObjects[index];
    const isFinal = index === stageObjects.length - 1;
    ctx.ledger.setScalar(run.run_id, "open_bbr_rollback_dispatch", stage.stageId);
    let result;
    try {
      result = ctx.adapters.callHelper(stage.helperOperation, "bbr_rollback", {
        runId: run.run_id,
        stageId: stage.stageId,
        orderedAction: stage.orderedAction,
        expectedReadback: stage.readback,
        ownedDropinDigest: ctx.ledger.getScalar(run.run_id, "bbr_dropin_digest"),
        recordedPriorDigest: priorValues.digest,
        recordedPriorValues: { qdisc: priorValues.qdisc, congestionControl: priorValues.congestionControl },
      });
    } catch (error) {
      ctx.ledger.setScalar(run.run_id, "open_bbr_rollback_dispatch", null);
      throw error;
    }
    ctx.ledger.setScalar(run.run_id, "open_bbr_rollback_dispatch", null);

    if (result.thirdPartyDigestObserved === true) {
      ctx.ledger.transaction(() => {
        ctx.ledger.insertReconciliationObligation({
          obligationRef: mintRef("runtime"), runId: run.run_id,
          originalTool: "bbr_rollback", failureContext: `THIRD_DIGEST_AT_${stage.stageId}`,
        });
        ctx.ledger.setPhases(run.run_id, { bbrPhase: "BBR_MANUAL_ACTION_REQUIRED" });
      });
      throw new ToolError("CONFLICT_DETECTED",
        `BBR stage ${stage.stageId} observed a concurrent third-party digest; no inverse was applied`);
    }
    if (result.readbackVerified !== true) {
      throw new ToolError("ROLLBACK_UNSAFE",
        `BBR stage ${stage.stageId} readback (${stage.readback}) was not verified`);
    }

    const stageReceiptRef = mintRef("receipt");
    const readbackDigest = result.readbackDigest || digestOf(result.observation || {});
    const commitStage = () => ctx.ledger.insertStageReceipt({
      receiptRef: stageReceiptRef, runId: run.run_id, family: BBR_FAMILY,
      operationRef: operation.operation_ref, stageId: stage.stageId,
      stageIndex: BBR_STAGE_IDS.indexOf(stage.stageId),
      readbackDigest, details: { orderedAction: stage.orderedAction, readback: stage.readback },
    });

    if (!isFinal) {
      ctx.ledger.transaction(commitStage);
      stageReceiptRefs.push(stageReceiptRef);
      continue;
    }
    const aggregateRef = mintRef("receipt");
    stageReceiptRefs.push(stageReceiptRef);
    const finalDigest = digestOf({ stageReceiptRefs, priorValuesDigest: priorValues.digest });
    const commitDigest = digestOf({
      trigger: BBR_FINALIZATION.trigger, selection: selectedStageIds, stageReceiptRefs, finalDigest,
    });
    ctx.ledger.transaction(() => {
      commitStage();
      ctx.ledger.insertAggregateReceipt({
        receiptRef: aggregateRef, runId: run.run_id,
        receiptType: "BBR_ROLLBACK_RECEIPT",
        operationRef: operation.operation_ref,
        selectionDigest: selectionDigest(selectedStageIds),
        stageReceiptRefs, commitDigest, finalDigest,
        details: { applyReceiptRef, priorValuesDigest: priorValues.digest },
      });
      ctx.ledger.appendEvent(run.run_id, "BBR_ROLLBACK_FINALIZED", {
        aggregateRef, stageCount: stageReceiptRefs.length, atomicity: BBR_FINALIZATION.atomicity,
      });
    });
    return {
      aggregateRef, stageReceiptRefs, finalDigest, commitDigest,
      finalStageId: stage.stageId, finalStageReceiptRef: stageReceiptRef,
      priorValuesDigest: priorValues.digest,
    };
  }
  throw new ToolError("ROLLBACK_UNSAFE", "no BBR stage was selected for this rollback");
}

module.exports = {
  MAIN_STAGES, MAIN_STAGE_IDS, MAIN_STAGE_SUBJECT, MAIN_FAMILY,
  BBR_STAGES, BBR_STAGE_IDS, BBR_FAMILY,
  MAIN_FINALIZATION, BBR_FINALIZATION,
  selectMainStages, selectionDigest, provenPrefix, remainingSuffix,
  resolveMainRollbackLeaseExpiry, resolveBbrRollbackLeaseExpiry,
  proveStageSubjectUnchanged, executeMainStages, executeBbrStages,
  operationKind,
};
