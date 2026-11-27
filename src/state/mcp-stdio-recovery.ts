// Successor cleanup of the exact original server domain. The current checker
// cannot recreate its old owner, recipe, receipt, mutex, response or deadline.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from '../kernel/broker-ambiguity.js';
import { decodeBrokerProcessDomainDeath, type BrokerProcessDomainDeathEvidenceV1 } from '../kernel/broker-process-domain-death.js';
import type { ContinuationItem, ProcessContainment, ProcessContainmentDeathEvidenceV1, InvocationJournalEntry } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { openInstalledLinuxWorkerLauncher, type LinuxWorkerController } from '../sandbox/linux-worker.js';
import { retireInstalledRetainedMcpStdioRun, readInstalledMcpStdioRunCleanup } from '../sandbox/mcp-stdio-native.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { KernelStorageError, ResourceRetirementError, joinResourceOperations } from './errors.js';
import { withHeldInstalledRuntime, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { readMcpOriginalClaim } from './mcp-execution.js';
import { readMcpServerLaunchContext, readMcpServerNativeResources } from './mcp-server-history.js';
import { mcpServerTerminalData } from './mcp-server-terminal-data.js';
import { openRetainedRunMcpStdioInput, type HeldRunMcpStdioInput, type RunMcpStdioInputBinding } from './native-owner.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { appendInvocationJournalEntry, nextJournalSequence, readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { settleValidatedInvocation } from './reducers/invocation.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { settleMcpStdioServerWithoutEffect } from './mcp-stdio-unclaimed-recovery.js';
import type { SqliteDriver } from './sqlite-driver.js';

type Checker = { close(): Promise<void> };
const checkers = new WeakMap<SqliteDriver, Set<Checker>>();
export async function closeMcpStdioRecoveries(driver: SqliteDriver): Promise<void> {
  const results = await Promise.allSettled([...(checkers.get(driver) ?? [])].map(value => value.close()));
  const failed = results.find(value => value.status === 'rejected');
  if (failed?.status === 'rejected') throw failed.reason instanceof ResourceRetirementError ? failed.reason :
    new ResourceRetirementError('MCP stdio current checkers did not completely join', failed.reason);
}
export async function recoverMcpStdioClaimedAfterProcessDeath(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, input: Readonly<{ runId: string; expectedRunRevision: number }>, signal?: AbortSignal) {
  return recoverMcpStdioAfterProcessDeath('claimed_effect', driver, artifacts, owner, selected, anchor, input, signal);
}
export async function recoverMcpStdioUnclaimedAfterProcessDeath(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, input: Readonly<{ runId: string; expectedRunRevision: number }>, signal?: AbortSignal) {
  // Scheduling only. The complete immutable semantic/physical cut below,
  // never this membership query, authorizes any cleanup or settlement.
  const pending = driver.prepare(`SELECT 1 AS pending FROM run_journal j WHERE j.run_id=? AND j.op_kind='mcp-server'
    AND j.phase IN ('prepared','dispatch_claimed') AND NOT EXISTS (SELECT 1 FROM run_journal n
      WHERE n.run_id=j.run_id AND n.op_id=j.op_id AND n.attempt=j.attempt AND n.seq>j.seq) LIMIT 1`).get(input.runId);
  if (!pending) return undefined;
  return recoverMcpStdioAfterProcessDeath('unclaimed_effect', driver, artifacts, owner, selected, anchor, input, signal);
}
function retainedInput(context: Awaited<ReturnType<typeof readMcpServerLaunchContext>>, prepared: InvocationJournalEntry): RunMcpStdioInputBinding {
  const p = context.preparation;
  return { runId: context.run.id, principalId: context.principalId, launchOpId: prepared.opId,
    batchItemId: context.request.batchItemId, callId: context.request.callId, workerLaunchId: p.workerLaunchId, supervisorInstanceId: p.supervisorInstanceId,
    nonce: p.nonce, registryRef: context.registry.ref, manifestDigest: context.registry.registry.manifestDigest,
    toolRequestRef: context.request.toolRequestRef, toolRequestDigest: context.tool.requestDigest, requestRef: prepared.requestRef, requestDigest: context.request.requestDigest,
    targetRef: prepared.target, targetDigest: context.target.targetDigest, grantRef: p.grantRef, grantDigest: context.permission.grant.grantDigest,
    plannedContainmentRef: p.plannedContainmentRef, plannedContainmentDigest: p.plannedContainmentDigest, sandboxLaunchSpecRef: p.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: p.sandboxLaunchSpecDigest, attempt: prepared.attempt, lifecycleSeq: context.request.lifecycleSeq,
    callIndex: context.request.callIndex, leaseEpoch: p.leaseEpoch, stateOwnerEpoch: p.stateOwnerEpoch,
    callDeadlineMs: p.callDeadlineMs, launchDeadlineMs: p.launchDeadlineMs, originalSupervisorPid: p.originalSupervisor.pid,
    originalSupervisorStartToken: p.originalSupervisor.processStartToken };
}
async function recoverMcpStdioAfterProcessDeath(mode: 'claimed_effect' | 'unclaimed_effect', driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, input: Readonly<{ runId: string; expectedRunRevision: number }>, signal?: AbortSignal) {
  const cancellation = new AbortController(), combined = signal ? AbortSignal.any([signal, cancellation.signal]) : cancellation.signal;
  const reads = artifacts.withReadSignal(combined);
  let launcher: Awaited<ReturnType<typeof openInstalledLinuxWorkerLauncher>> | undefined, controller: LinuxWorkerController | undefined;
  let openingController: Promise<LinuxWorkerController> | undefined, physical: HeldRunMcpStdioInput | undefined;
  let work!: Promise<Awaited<ReturnType<typeof execute>>>, closing: Promise<void> | undefined;
  const checker: Checker = { close: () => closing ??= (async () => {
    cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP stdio current checker is closing'));
    const revocation = (async () => { const held = controller ?? await openingController; await held?.close(); })();
    const results = await Promise.allSettled([work, revocation]);
    const failed = results.find(value => value.status === 'rejected'); if (failed?.status === 'rejected') throw failed.reason;
  })() };
  let held = checkers.get(driver); if (!held) checkers.set(driver, held = new Set()); held.add(checker);
  async function performCleanup(inputBinding: RunMcpStdioInputBinding, active: ReturnType<typeof assertActiveStateOwner>) {
    physical = openRetainedRunMcpStdioInput(owner.filesystem, inputBinding);
    launcher = await openInstalledLinuxWorkerLauncher(selected, anchor, { signal: combined });
    openingController = launcher.startController({ signal: combined }); controller = await openingController;
    const receipt = await retireInstalledRetainedMcpStdioRun({ selected, anchor, controller, lock: owner.filesystem, input: physical,
      inputBinding, checker: { supervisorInstanceId: active.supervisorInstanceId, stateOwnerEpoch: active.ownerEpoch }, signal: combined });
    return { receipt, actual: readInstalledMcpStdioRunCleanup(receipt, physical), physical };
  }
  async function execute() {
    let failure: unknown;
    try {
      const cut = immutableSnapshot(await readRecoveryClosure(driver, reads, input.runId)), run = cut.run;
      if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'MCP stdio successor original Run cut changed');
      if (mode === 'unclaimed_effect') {
        const candidates = cut.journal.filter(entry => entry.opKind === 'mcp-server' && entry.phase === 'prepared' &&
          ['prepared', 'dispatch_claimed'].includes(readInvocationAttempt(driver, run.id, entry.opId, entry.attempt).at(-1)!.phase));
        if (!candidates.length) return undefined;
        if (candidates.length !== 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor has multiple unresolved original server domains');
        const prepared = candidates[0]!, rows = readInvocationAttempt(driver, run.id, prepared.opId, prepared.attempt);
        const claim = rows[1];
        if (rows.length !== (claim ? 2 : 1) || claim && claim.phase !== 'dispatch_claimed')
          throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor lost its exact original prepared/optional-claim server chain');
        const assembly = await readCanonicalArtifact<import('../kernel/types.js').RunAssemblyV1>(reads, cut.runSpec.assemblyRef);
        const context = await readMcpServerLaunchContext(driver, reads, run, cut.runSpec, assembly, prepared), active = assertActiveStateOwner(driver, owner);
        if (context.preparation.supervisorInstanceId === active.supervisorInstanceId && context.preparation.stateOwnerEpoch === active.ownerEpoch) return undefined;
        const history = await readRetainedStateOwnerHistory(driver, reads, active.ownerEpoch);
        const original = history.entries.find(entry => entry.owner.ownerEpoch === context.preparation.stateOwnerEpoch), inspecting = history.entries.find(entry => entry.owner.ownerEpoch === active.ownerEpoch);
        if (!original || !inspecting || active.ownerEpoch <= original.owner.ownerEpoch || original.owner.supervisorInstanceId !== context.preparation.supervisorInstanceId ||
            original.process.pid !== context.preparation.originalSupervisor.pid || original.process.processStartToken !== context.preparation.originalSupervisor.processStartToken)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP unclaimed server successor has no strictly newer original creator provenance');
        const tool = context.owningPrepared;
        if (cut.journal.some(entry => entry.opId === tool.opId && entry.attempt === tool.attempt && entry.phase === 'dispatch_claimed')) return undefined;
        requireEqual(readInvocationAttempt(driver, run.id, tool.opId, tool.attempt), [tool], 'MCP successor original ordinary effect remains prepared and unclaimed');
        await withHeldInstalledRuntime(selected, async runtime => {
          await runtime.revalidate(combined); const process = await (await runtime.loadStateOwner()).observeCurrentProcess();
          if (process.pid !== inspecting.process.pid || process.processStartToken !== inspecting.process.processStartToken ||
              runtime.bundleDigest !== active.runtimeBundleRef || runtime.bundle.manifestDigest !== active.runtimeBundleManifestDigest)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP unclaimed server checker is not its real current signed process');
        }, combined);
        owner.filesystem.observePriorProcessDeath(original.process.pid, original.process.processStartToken);
        const closed = await performCleanup(retainedInput(context, prepared), active);
        return await settleMcpStdioServerWithoutEffect({ driver, artifacts, reads, owner, cut, context, prepared, claim, tool,
          history, original, receipt: closed.receipt, actual: closed.actual, physical: closed.physical });
      }
      const claims = cut.journal.filter(entry => entry.opKind === 'mcp' && entry.phase === 'dispatch_claimed' &&
        readInvocationAttempt(driver, run.id, entry.opId, entry.attempt).at(-1)?.phase === 'dispatch_claimed');
      if (claims.length !== 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio successor requires one exact unsettled effect claim');
      const claim = claims[0]!, rows = readInvocationAttempt(driver, run.id, claim.opId, claim.attempt), prepared = rows[0]!;
      const assembly = await readCanonicalArtifact<import('../kernel/types.js').RunAssemblyV1>(reads, cut.runSpec.assemblyRef);
      const active = assertActiveStateOwner(driver, owner), original = await readMcpOriginalClaim(driver, reads, { prepared, claim, assembly, throughEpoch: active.ownerEpoch });
      const instance = original.stdioInstance;
      if (!instance || active.ownerEpoch <= original.claiming.owner.ownerEpoch || active.supervisorInstanceId === claim.supervisorInstanceId)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio cleanup cannot adopt a still-current original native creator');
      await withHeldInstalledRuntime(selected, async runtime => {
        await runtime.revalidate(combined);
        const current = original.history.entries.find(value => value.owner.ownerEpoch === active.ownerEpoch), process = await (await runtime.loadStateOwner()).observeCurrentProcess();
        if (!current || process.pid !== current.process.pid || process.processStartToken !== current.process.processStartToken ||
            runtime.bundleDigest !== active.runtimeBundleRef || runtime.bundle.manifestDigest !== active.runtimeBundleManifestDigest)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio checker is not its actual current signed StateOwner process');
      }, combined);
      owner.filesystem.observePriorProcessDeath(original.claiming.process.pid, original.claiming.process.processStartToken);
      const serverRows = readInvocationAttempt(driver, run.id, instance.launchOpId, instance.launchAttempt), serverPrepared = serverRows[0]!, serverClaim = serverRows[1];
      if (serverRows.length !== 2 || !serverClaim || serverClaim.phase !== 'dispatch_claimed' || serverClaim.dispatchId !== instance.launchDispatchId)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio successor lost its exact original server claim');
      const context = await readMcpServerLaunchContext(driver, reads, run, cut.runSpec, assembly, serverPrepared), p = context.preparation;
      if (context.request.toolRequestRef !== prepared.requestRef || p.originalSupervisor.pid !== original.claiming.process.pid ||
          p.originalSupervisor.processStartToken !== original.claiming.process.processStartToken || instance.sandboxLaunchSpecRef !== p.sandboxLaunchSpecRef)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor cleanup substitutes its original native prepared input');
      const closed = await performCleanup(retainedInput(context, serverPrepared), active), receipt = closed.receipt;
      const actual = closed.actual, cleanup = actual.observation, observedAt = new Date(cleanup.observedAtMs).toISOString();
      // The old bytes stay unchanged. Only the separate current checker can
      // say what it actually killed, joined, drained and retired today.
      const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
      const containment = await readCanonicalArtifact<ProcessContainment>(reads, instance.processContainmentRef);
      if (containment.backend.kind !== 'linux') throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original stdio domain is not Linux');
      const deathCore = { schemaVersion: 1 as const, kind: 'containment_all_descendants_dead' as const, containmentRef: instance.processContainmentRef,
        planRef: p.plannedContainmentRef, sandboxLaunchSpecRef: p.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: p.sandboxLaunchSpecDigest,
        owner: containment.owner, launchNonceDigest: containment.launchNonceDigest, inspectorSupervisorInstanceId: active.supervisorInstanceId,
        inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, backend: { ...containment.backend,
          cgroupPopulated: 0 as const, namespaceInitDeadAndReaped: true as const, remainingTrackedDescendants: 0 as const }, observedAt };
      const death: ProcessContainmentDeathEvidenceV1 = { ...deathCore, evidenceDigest: canonicalSha256(deathCore) };
      const [raw, projection, cleanupRaw, cleanupProjection, deathArtifact] = await joinResourceOperations([
        artifacts.publishBytes(actual.lifecycleSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-native-lifecycle-bytes-v1'),
        artifacts.publishCanonical((await import('./native-owner.js')).decodeMcpStdioLifecycleData(actual.lifecycleSnapshot), 'cliq-mcp-stdio-native-lifecycle-v1'),
        artifacts.publishBytes(actual.cleanupSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-native-cleanup-bytes-v1'),
        artifacts.publishCanonical(cleanup, cleanup.format), artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1')]);
      const nativeClosure = { kind: 'linux_successor_cleanup' as const, lifecycleRawRef: raw.ref, lifecycleProjectionRef: projection.ref,
        cleanupRawRef: cleanupRaw.ref, cleanupProjectionRef: cleanupProjection.ref };
      const resources = await readMcpServerNativeResources(driver, reads, context, serverPrepared, serverClaim, { nativeClosure,
        processContainmentRef: instance.processContainmentRef, deathEvidenceRef: deathArtifact.ref });
      const processDeath: BrokerProcessDomainDeathEvidenceV1 = { schemaVersion: 1, format: 'cliq-broker-process-domain-death-evidence-v1', runId: run.id,
        opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId!, dispatchJournalSeq: claim.seq, operationRequestRef: prepared.requestRef,
        operationTargetDigest: original.target.targetDigest, operationGrantRef: prepared.grantRef!, claimingSupervisorInstanceId: claim.supervisorInstanceId!,
        claimingStateOwnerEpoch: claim.stateOwnerEpoch!, claimingProcessIdentityRef: original.claiming.owner.processIdentityRef,
        claimingProcessIdentityDigest: original.claiming.owner.processIdentityDigest, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
        inspectorStateOwnerEpoch: active.ownerEpoch, brokerFenceTokenDigest: claim.brokerFenceTokenDigest!, authorityDomain: 'linux_installed_native_creator_process_v1',
        processObservation: 'absent_or_start_token_mismatch', observedAt, evidenceDigest: '' };
      processDeath.evidenceDigest = digestOmitting(processDeath, 'evidenceDigest'); decodeBrokerProcessDomainDeath(processDeath);
      const processDeathArtifact = await artifacts.publishCanonical(processDeath, processDeath.format);
      const core: BrokerInvocationAmbiguityEvidenceV1 = { schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1', runId: run.id,
        frontierRef: original.request.frontierRef, frontierDigest: original.request.frontierRef, opId: claim.opId, opKind: 'mcp', attempt: claim.attempt,
        dispatchId: claim.dispatchId!, dispatchJournalSeq: claim.seq, operationRequestRef: prepared.requestRef, operationRequestDigest: original.request.requestDigest,
        operationTargetRef: prepared.target, operationTargetDigest: original.target.targetDigest, claimingSupervisorInstanceId: claim.supervisorInstanceId!,
        claimingStateOwnerEpoch: claim.stateOwnerEpoch!, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
        observedAt, ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: claim.brokerFenceTokenDigest!, failureCode: 'response_stream_interrupted',
        durableTerminalResultAbsent: true, creatorProcessDeathEvidenceRef: processDeathArtifact.ref, creatorProcessDeathEvidenceDigest: processDeath.evidenceDigest, evidenceDigest: '' };
      core.evidenceDigest = digestOmitting(core, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(core);
      const ambiguity = await artifacts.publishCanonical(core, core.format);
      const contextManifest = decodeContextManifest(await readCanonicalArtifact(reads, cut.latestCheckpoint.contextManifestRef));
      const items = await reads.mapReads(cut.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) }));
      const frontier = await readCanonicalArtifact<import('../kernel/types.js').RunFrontier>(reads, original.request.frontierRef);
      let fresh: number | undefined;
      return await settleValidatedInvocation(driver, artifacts, owner, { ...input, opId: claim.opId, attempt: claim.attempt },
        { phase: 'unknown', evidenceRef: ambiguity.ref, evidenceDigest: core.evidenceDigest }, async ({ settlement: effect }) => {
          const value = { ...core, observedAt: effect.settledAt, evidenceDigest: '' }; value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(value);
          const evidence = await artifacts.publishCanonical(value, value.format), local = mcpServerTerminalData({ effect, prepared: serverPrepared,
            claim: serverClaim, instance, instanceRef: claim.evidenceRef!, deathRef: deathArtifact.ref, observedAt, nativeClosure, disposition: 'owning_call_unknown' });
          const localMetadata = await artifacts.mapReads([local.settlementPlan, local.terminalPlan], plan => artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
          const graph = await planContinuationCommit(artifacts, { context: contextManifest, existingItems: items, items: [local.stopped], frontier,
            checkpointId: identityHash('cliq-mcp-stdio-unknown-checkpoint-v1', run.id, claim.opId, claim.attempt, claim.dispatchId),
            workspaceStateRef: cut.latestCheckpoint.workspaceStateRef }).publish();
          return { metadata: [raw, projection, cleanupRaw, cleanupProjection, deathArtifact, inspectorArtifact, processDeathArtifact, evidence, ...localMetadata, ...graph.metadata],
            unknownEvidence: { evidenceRef: evidence.ref, evidenceDigest: value.evidenceDigest },
            reobserve(connection) { assertActiveStateOwner(connection, owner); readInstalledMcpStdioRunCleanup(receipt, physical!);
              fresh = owner.filesystem.observePriorProcessDeath(original.claiming.process.pid, original.claiming.process.processStartToken); },
            validate(connection, current, now) {
              resources.assertUnchanged(connection); original.history.assertUnchanged(connection); readInstalledMcpStdioRunCleanup(receipt, physical!);
              requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP successor exact original full unsettled Journal');
              requireEqual(readRun(connection, run.id), run, 'MCP successor exact original Run/Stop cut');
              if (current.frontierRef !== original.request.frontierRef || fresh === undefined || fresh < Date.parse(observedAt) || fresh > Date.parse(now) ||
                  Date.parse(now) - Date.parse(observedAt) > 5_000) throw new KernelStorageError('LEASE_FENCED', 'MCP current cleanup is not fresh at its exact original UNKNOWN commit');
            }, commit(connection, current, entry, now) {
              if (nextJournalSequence(connection, run.id) !== local.terminalSeq || entry.seq !== effect.terminalJournalSeq || now < effect.settledAt)
                throw new KernelStorageError('REVISION_CONFLICT', 'MCP successor dual terminal sequence changed');
              appendInvocationJournalEntry(connection, { ...serverClaim, seq: local.terminalSeq, phase: 'failed', budgetDelta: serverPrepared.budgetDelta,
                errorRef: local.terminalPlan.ref, budgetSettlementRef: local.settlementPlan.ref, timestamp: effect.settledAt });
              const after = readRun(connection, run.id); requireEqual(after.budgetConsumed, local.settlement.budgetConsumedBefore, 'MCP successor after-effect consumed budget');
              requireEqual(after.budgetReserved, local.settlement.budgetReservedBefore, 'MCP successor after-effect reserved budget');
              connection.prepare('UPDATE runs SET budget_consumed_json=?,budget_reserved_json=? WHERE id=?')
                .run(JSON.stringify(local.settlement.budgetConsumedAfter), JSON.stringify(local.settlement.budgetReservedAfter), run.id);
              graph.commit(connection, current, local.terminalSeq, now);
            } };
        });
    } catch (error) { failure = error; throw error; }
    finally {
      const failures: unknown[] = [];
      try { const held = controller ?? await openingController; await held?.close(); } catch (error) { failures.push(error); }
      try { await launcher?.close(); } catch (error) { failures.push(error); }
      if (failures.length) throw new ResourceRetirementError('MCP stdio current checker did not join its actual controller/launcher',
        new AggregateError([...(failure === undefined ? [] : [failure]), ...failures]));
      physical?.close(); held!.delete(checker);
    }
  }
  work = Promise.resolve().then(execute);
  return work;
}
