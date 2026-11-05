// The original native stdio owner is the only issuer of this local UNKNOWN
// continuation. Process death does not supply a result or prove remote effect.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from '../kernel/broker-ambiguity.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { InvocationJournalEntry, Run } from '../kernel/types.js';
import type { ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { ResolveToolInput } from '../model/attempt.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { planContinuationCommit } from './continuation-commit.js';
import { KernelStorageError } from './errors.js';
import type { NativeMcpStdioRunOwner, RunMcpStdioLaunchBinding } from './mcp-stdio-broker-native.js';
import { readMcpStdioRunCustody } from './mcp-stdio-execution.js';
import { assertInstalledMcpStdioRunJoined } from './mcp-stdio-native-binding.js';
import { prepareMcpServerTerminal } from './mcp-server-retirement.js';
import { prepareValidatedInvocationSettlement } from './reducers/invocation.js';
import { readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readToolCut } from './tool-cut.js';
import { retainMcpSettlementPreparation } from './mcp-settlement-preparation.js';

export function beginMcpStdioUnknown(driver: SqliteDriver, artifacts: ArtifactCatalog, context: StateOwnerContext,
  native: NativeMcpStdioRunOwner, launch: RunMcpStdioLaunchBinding, prepared: InvocationJournalEntry, claim: InvocationJournalEntry,
  resolveToolInput: ResolveToolInput) {
  const initializeSettlement = retainMcpSettlementPreparation(initialize);
  let selected: Awaited<ReturnType<typeof readToolCut>>;
  let settlement: ReturnType<typeof prepareValidatedInvocationSettlement>;
  let currentRun: Run;
  const custody = readMcpStdioRunCustody(native, launch), binding = custody.call;
  if (!custody.joined || custody.resultReceived || !binding || binding.opId !== claim.opId || binding.dispatchId !== claim.dispatchId ||
      binding.dispatchJournalSeq !== claim.seq || binding.instanceIdentityRef !== claim.evidenceRef || binding.instanceIdentityDigest !== claim.evidenceDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio UNKNOWN has no exact original joined uncertain effect owner');
  assertInstalledMcpStdioRunJoined(native, custody.joined, launch);
  function validate(connection: SqliteConnection, run: Run) {
    assertActiveStateOwner(connection, context); assertInstalledMcpStdioRunJoined(native, custody.joined!, launch);
    requireEqual(readInvocationAttempt(connection, claim.runId, claim.opId, claim.attempt), [prepared, claim], 'MCP stdio original UNKNOWN permanent claim');
    requireEqual(readInvocationJournal(connection, run.id), selected.journal, 'MCP stdio UNKNOWN original whole journal');
    requireEqual(run, currentRun, 'MCP stdio UNKNOWN asynchronously verified current Stop cut');
    if (run.frontierRef !== selected.run.frontierRef || run.latestCheckpointId !== selected.run.latestCheckpointId ||
        run.activeWorkerLaunchId !== selected.run.activeWorkerLaunchId || run.leaseEpoch !== claim.leaseEpoch)
      throw new KernelStorageError('LEASE_FENCED', 'MCP stdio UNKNOWN lost its original owning tool frontier and lease');
  }
  async function initialize() {
    selected = await readToolCut(driver, artifacts, claim.runId, resolveToolInput); currentRun = selected.run;
    const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef), target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
    const active = assertActiveStateOwner(driver, context);
    if (prepared.opKind !== 'mcp' || claim.opKind !== 'mcp' || !['manual', 'retry', 'reconcile'].includes(prepared.replayClass) ||
        claim.replayClass !== prepared.replayClass || target.execution.kind !== 'mcp' ||
        claim.stateOwnerEpoch !== active.ownerEpoch || claim.supervisorInstanceId !== active.supervisorInstanceId ||
        selected.batch.itemId !== request.batchItemId || selected.call.callId !== request.callId || selected.frontier.nextCallIndex !== request.callIndex ||
        request.frontierRef !== selected.run.frontierRef || binding!.requestRef !== prepared.requestRef || binding!.targetRef !== prepared.target)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio UNKNOWN cannot substitute another original Run/tool/native owner');
    const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
    const core: BrokerInvocationAmbiguityEvidenceV1 = { schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1',
      runId: claim.runId, frontierRef: request.frontierRef, frontierDigest: request.frontierRef, opId: claim.opId, opKind: 'mcp', attempt: claim.attempt,
      dispatchId: claim.dispatchId!, dispatchJournalSeq: claim.seq, operationRequestRef: prepared.requestRef, operationRequestDigest: request.requestDigest,
      operationTargetRef: prepared.target, operationTargetDigest: target.targetDigest, claimingSupervisorInstanceId: active.supervisorInstanceId,
      claimingStateOwnerEpoch: active.ownerEpoch, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
      observedAt: sampleCanonicalNow(), ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: claim.brokerFenceTokenDigest!,
      failureCode: 'response_stream_interrupted', durableTerminalResultAbsent: true, evidenceDigest: '' };
    core.evidenceDigest = digestOmitting(core, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(core);
    const initial = await artifacts.publishCanonical(core, core.format);
    settlement = prepareValidatedInvocationSettlement(driver, artifacts, context, { runId: claim.runId, opId: claim.opId,
      attempt: claim.attempt, expectedRunRevision: selected.run.revision }, { phase: 'unknown', evidenceRef: initial.ref, evidenceDigest: core.evidenceDigest },
    async ({ settlement: effect }) => {
      const value = { ...core, observedAt: effect.settledAt, evidenceDigest: '' }; value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
      decodeBrokerInvocationAmbiguity(value);
      const evidence = await artifacts.publishCanonical(value, value.format);
      const local = await prepareMcpServerTerminal(driver, context, binding!.instanceIdentityRef, effect, 'owning_call_unknown');
      // Appending an excluded local retirement audit does not advance the
      // owning call, create a ToolResult, or decide its remote ambiguity.
      const graph = await planContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
        items: [local.stopped], frontier: selected.frontier, workspaceStateRef: selected.checkpoint.workspaceStateRef,
        checkpointId: identityHash('cliq-mcp-stdio-unknown-checkpoint-v1', claim.runId, claim.opId, claim.attempt, claim.dispatchId) }).publish();
      return { metadata: [inspectorArtifact, evidence, ...local.metadata, ...graph.metadata],
        unknownEvidence: { evidenceRef: evidence.ref, evidenceDigest: value.evidenceDigest }, validate,
        commit(connection, run, entry, committedAt) { local.commit(connection, entry, committedAt); graph.commit(connection, run, local.journalSeq, committedAt); } };
    }, validate);
  }
  return Object.freeze({ async finish(): Promise<Run> {
    await initializeSettlement();
    const cut = await readToolCut(driver, artifacts, claim.runId, resolveToolInput);
    const stable = ({ revision: _revision, updatedAt: _updated, stopIntentRef: _stop, cancelRequested: _cancel, parentCancellationRef: _parent, ...rest }: Run) => rest;
    const { run: _oldRun, ...oldCut } = selected, { run: _newRun, ...newCut } = cut;
    if (canonicalSha256(oldCut) !== canonicalSha256(newCut) || canonicalSha256(stable(cut.run)) !== canonicalSha256(stable(selected.run)) ||
        cut.run.revision < selected.run.revision || cut.run.updatedAt < selected.run.updatedAt ||
        cut.run.revision !== selected.run.revision && !cut.run.stopIntentRef || selected.run.cancelRequested && !cut.run.cancelRequested)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio uncertain completion cannot adopt another original call or continuation');
    currentRun = cut.run;
    try { return (await settlement.settle(currentRun.revision)).run; }
    catch (error) { settlement.acceptRevisionConflict(error, readRun(driver, claim.runId).revision); throw error; }
  } });
}
