// Positive local launch failure before the ordinary effect claim. The effect
// preparation and its original call deadline remain unchanged for selection.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { mcpServerFailedLaunchData } from './mcp-server-terminal-data.js';
import { publishOriginalMcpStdioRetirement } from './mcp-stdio-resource-closure.js';
import type { NativeMcpStdioRunOwner, RunMcpStdioLaunchBinding } from './mcp-stdio-broker-native.js';
import { assertInstalledMcpStdioRunJoined } from './mcp-stdio-native-binding.js';
import { readMcpStdioSetupFailureState, acknowledgeMcpStdioSetupFailure } from './mcp-stdio-execution.js';
import type { HeldRunMcpStdioInput } from './native-owner.js';
import type { InstalledMcpStdioRunScope } from '../sandbox/mcp-stdio-native.js';
import { appendInvocationJournalEntry, nextJournalSequence, readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { retainMcpSettlementPreparation } from './mcp-settlement-preparation.js';

export function beginMcpStdioLaunchFailure(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: Readonly<{
  native: NativeMcpStdioRunOwner; binding: RunMcpStdioLaunchBinding; scope: InstalledMcpStdioRunScope; input: HeldRunMcpStdioInput;
  prepared: InvocationJournalEntry; claim?: InvocationJournalEntry; toolPrepared: InvocationJournalEntry;
  reason: 'transport_failure' | 'manifest_mismatch' | 'cancel' | 'deadline';
}>) {
  const prepared = retainMcpSettlementPreparation(prepare);
  const originalEntries = input.claim ? [input.prepared, input.claim] : [input.prepared];
  let committed = false, acknowledged = false;
  async function prepare() {
    const custody = readMcpStdioSetupFailureState(input.native, input.binding);
    if (custody?.setupComplete || custody?.resultReceived) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP initialized or received lifecycle requires its original instance-specific terminal owner');
    const actual = await publishOriginalMcpStdioRetirement(driver, artifacts, owner, input.native, input.binding, input.scope, input.input);
    if (!custody && actual.joined.ownerJoined.completedStages.length !== 0)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP local failure cannot erase an original started protocol owner');
    if (actual.original.joined.effectReleased || input.binding.runId !== input.prepared.runId || input.binding.launchOpId !== input.prepared.opId ||
        input.claim && (input.claim.phase !== 'dispatch_claimed' || input.claim.seq !== input.binding.dispatchJournalSeq || input.prepared.evidenceRef !== input.claim.evidenceRef) ||
        !input.claim && (actual.evidence.kind !== 'containment_plan_quiescent' || actual.original.joined.spawnAttempted || actual.original.joined.execReleased) ||
        readInvocationAttempt(driver, input.prepared.runId, input.toolPrepared.opId, input.toolPrepared.attempt).length !== 1 ||
        readInvocationJournal(driver, input.prepared.runId).some(entry => entry.opId === input.toolPrepared.opId && entry.attempt === input.toolPrepared.attempt && entry.phase === 'dispatch_claimed'))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP setup failure cannot replace an ordinary permanent effect claim');
    const run = readRun(driver, input.prepared.runId), settledAt = sampleCanonicalNow(), terminalSeq = nextJournalSequence(driver, run.id);
    const failureCore = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-failure-v1' as const, runId: run.id,
      launchOpId: input.prepared.opId, attempt: input.prepared.attempt, preparedJournalSeq: input.prepared.seq,
      ...(input.claim ? { claimedJournalSeq: input.claim.seq } : { claimStatus: 'not_claimed' as const }),
      targetRef: input.prepared.target, requestRef: input.prepared.requestRef, grantRef: input.prepared.grantRef!, dispatchId: input.binding.dispatchId,
      sandboxLaunchSpecRef: input.binding.sandboxLaunchSpecRef, nativeClosure: actual.nativeClosure, stoppedAt: actual.observedAt,
      instance: 'not_initialized' as const, reason: input.reason,
      ...(actual.evidence.kind === 'containment_all_descendants_dead' ? { closure: 'containment_dead' as const,
        processContainmentRef: actual.containmentRef!, containmentDeathEvidenceRef: actual.evidenceRef }
        : { closure: 'plan_quiescent' as const, noSpawnEvidenceRef: actual.evidenceRef }) };
    const local = mcpServerFailedLaunchData({ failure: { ...failureCore, failureDigest: canonicalSha256(failureCore) },
      prepared: input.prepared, claim: input.claim, run, terminalSeq, settledAt });
    const failureArtifact = await artifacts.publishBytes(local.failurePlan.bytes, local.failurePlan.mediaType, local.failurePlan.schemaKind);
    const settlementArtifact = await artifacts.publishBytes(local.settlementPlan.bytes, local.settlementPlan.mediaType, local.settlementPlan.schemaKind);
    return { actual, run, settledAt, terminalSeq, failureArtifact, settlement: local.settlement, terminal: local.terminal, settlementArtifact };
  }
  return Object.freeze({ async finish() {
    const fixed = await prepared();
    let clock: ReturnType<typeof advanceTimeFence> | undefined;
    if (!committed) driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); input.scope.assertJoined(fixed.actual.joined.joined);
      assertInstalledMcpStdioRunJoined(input.native, fixed.actual.joined.ownerJoined, input.binding);
      requireEqual(readInvocationAttempt(connection, input.prepared.runId, input.prepared.opId, input.prepared.attempt), originalEntries, 'MCP exact original failed local launch');
      requireEqual(readInvocationAttempt(connection, input.toolPrepared.runId, input.toolPrepared.opId, input.toolPrepared.attempt), [input.toolPrepared], 'MCP original unclaimed ordinary effect preparation');
      if (readInvocationJournal(connection, input.prepared.runId).some(entry => entry.opId === input.toolPrepared.opId && entry.attempt === input.toolPrepared.attempt && entry.phase === 'dispatch_claimed'))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP local launch failure cannot erase an earlier owning effect claim');
      const run = readRun(connection, fixed.run.id), now = sampleCanonicalNow();
      clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
      const stable = ({ revision: _revision, updatedAt: _updated, stopIntentRef: _stop, cancelRequested: _cancel, parentCancellationRef: _parent, ...rest }: typeof run) => rest;
      requireEqual(stable(run), stable(fixed.run), 'MCP failed local lifecycle immutable Run cut');
      if (now < fixed.settledAt || fixed.settledAt < fixed.actual.observedAt || nextJournalSequence(connection, run.id) !== fixed.terminalSeq ||
          run.revision < fixed.run.revision || run.revision !== fixed.run.revision && !run.stopIntentRef)
        throw new KernelStorageError('REVISION_CONFLICT', 'MCP local failure lost its original terminal clock or Journal sequence');
      for (const artifact of [...fixed.actual.metadata, fixed.failureArtifact, fixed.settlementArtifact]) insertArtifactMetadata(connection, artifact, now);
      appendInvocationJournalEntry(connection, fixed.terminal);
      const changed = connection.prepare('UPDATE runs SET budget_consumed_json=?,budget_reserved_json=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?')
        .run(JSON.stringify(fixed.settlement.budgetConsumedAfter), JSON.stringify(fixed.settlement.budgetReservedAfter), now, run.id, BigInt(run.revision));
      if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'MCP failed server original settlement CAS changed');
      appendRunStateEvent(connection, readRun(connection, run.id), now);
    });
    if (!committed) { requireHealthyFence(clock); committed = true; }
    if (!acknowledged) { acknowledgeMcpStdioSetupFailure(input.native, fixed.actual.joined.ownerJoined, input.binding); acknowledged = true; }
    input.input.close(); return readRun(driver, input.prepared.runId);
  } });
}
