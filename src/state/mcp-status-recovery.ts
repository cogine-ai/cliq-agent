// Strict successor cleanup of one original purpose3 birth. This receiver
// never reconstructs the dead broker, its mutex, payload or status response.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpInvocationWait, mcpUnresolvedProbeState } from '../kernel/mcp-status.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1, Run } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { openInstalledLinuxWorkerLauncher, type LinuxWorkerController } from '../sandbox/linux-worker.js';
import { retireInstalledRetainedMcpStdioRecovery, readInstalledMcpStdioRecoveryCleanup, type InstalledMcpStdioRecoveryCleanup } from '../sandbox/mcp-stdio-native.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError, joinResourceOperations } from './errors.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime, type HeldInstalledAnchor } from './installed-runtime.js';
import { openRetainedRecoveryMcpStdioInput, decodeMcpStdioRecoveryLifecycleData, type HeldRecoveryMcpStdioInput } from './native-owner.js';
import { readMcpStatusRetirementHistory } from './mcp-status-native-history.js';
import { readMcpStatusProbeEvidence } from './mcp-status-history.js';
import { readMcpStatusProbePreparation } from './mcp-status-preparation.js';
import { decodeMcpStatusRetirement, decodeMcpStatusProbeClosure, decodeMcpStatusProbeWrapper } from './mcp-status-proof.js';
import { validateMcpInvocationWait } from './mcp-status-state.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export function prepareMcpStatusSuccessorRecovery(input: Readonly<{ driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext;
  selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor; runId: string; expectedRunRevision: number; signal: AbortSignal }>) {
  const { driver, artifacts, owner } = input, cancellation = new AbortController(), signal = AbortSignal.any([input.signal, cancellation.signal]);
  const reads = artifacts.withReadSignal(signal);
  let launcher: Awaited<ReturnType<typeof openInstalledLinuxWorkerLauncher>> | undefined, controller: LinuxWorkerController | undefined;
  let openingController: Promise<LinuxWorkerController> | undefined, physical: HeldRecoveryMcpStdioInput | undefined;
  let receipt: InstalledMcpStdioRecoveryCleanup | undefined;
  let original: Awaited<ReturnType<typeof readMcpStatusProbePreparation>> | undefined;
  let publication: Promise<Run> | undefined, closing: Promise<void> | undefined, committed: Run | undefined;
  let source: Awaited<ReturnType<typeof validateMcpInvocationWait>>['source'] | undefined;
  const closeInput = () => {
    try { physical?.close(); }
    catch (error) { throw new ResourceRetirementError('MCP status successor did not close its original retained input descriptor', error); }
  };
  const cancel = () => {
    cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP status original successor checker is closing'));
    void (async () => { const current = controller ?? await openingController; await current?.close(); })().catch(() => {});
  };
  const complete = () => publication ??= (async () => {
    if (committed) { closeInput(); return readRun(driver, committed.id); }
    if (!receipt || !physical || !original || !source) fail('MCP status successor has no genuine complete original retained-birth cleanup');
    const heldReceipt = receipt, heldInput = physical, originalProbe = original;
    const actual = readInstalledMcpStdioRecoveryCleanup(receipt, physical), cleanup = actual.observation;
    const active = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(active);
    const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format), metadata: PublishedArtifact[] = [inspectorArtifact];
    const lifecycle = decodeMcpStdioRecoveryLifecycleData(actual.lifecycleSnapshot), plan = original.plan;
    if (plan.backend.kind !== 'linux' || lifecycle.binding.kind !== 'recovery') fail('MCP status successor changed its original Linux readonly purpose');
    const unavailable = lifecycle.joined.responseRefused;
    if (unavailable && (lifecycle.progressKind !== 9 || !lifecycle.joined.execReleased || !lifecycle.joined.deathJoined ||
        !lifecycle.joined.ownerDrained || !lifecycle.joined.outputCustodyRetired || !lifecycle.containment))
      fail('MCP successor cannot audit a refused response without its original complete disposed-output progress');
    const observedAt = new Date(cleanup.observedAtMs).toISOString(), common = { schemaVersion: 1 as const,
      planRef: original.preparation.plannedContainmentRef, sandboxLaunchSpecRef: original.preparation.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: original.preparation.sandboxLaunchSpecDigest, owner: plan.owner, launchNonceDigest: plan.launchNonceDigest,
      inspectorSupervisorInstanceId: active.supervisorInstanceId, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt };
    let containmentRef: string | undefined, evidence: ProcessContainmentDeathEvidenceV1 | ProcessContainmentNoSpawnEvidenceV1;
    if (lifecycle.containment) {
      const birth = lifecycle.containment;
      const backend = { kind: 'linux' as const, cgroupPath: plan.backend.cgroupPath, cgroupId: birth.cgroupId, pidNamespaceId: birth.pidNamespaceId,
        pidNamespaceReservationId: plan.backend.pidNamespaceReservationId, namespaceInitStartToken: birth.namespaceInitStartToken,
        subreaperStartToken: plan.backend.subreaperStartToken };
      const containment: ProcessContainment = { schemaVersion: 1, planRef: original.preparation.plannedContainmentRef,
        sandboxLaunchSpecRef: original.preparation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: original.preparation.sandboxLaunchSpecDigest,
        owner: plan.owner, filesystemBinding: plan.filesystemBinding, launchNonceDigest: plan.launchNonceDigest,
        backend, createdAt: new Date(birth.observedAtMs).toISOString() };
      const artifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1'); metadata.push(artifact); containmentRef = artifact.ref;
      const core = { ...common, kind: 'containment_all_descendants_dead' as const, containmentRef,
        backend: { ...backend,
          cgroupPopulated: 0 as const, namespaceInitDeadAndReaped: true as const, remainingTrackedDescendants: 0 as const } };
      evidence = { ...core, evidenceDigest: canonicalSha256(core) };
    } else {
      const core = { ...common, kind: 'containment_plan_quiescent' as const, backend: { kind: 'linux' as const,
        cgroupPath: plan.backend.cgroupPath, cgroupObservation: { kind: 'empty' as const, cgroupId: cleanup.retirement.cgroupId, populated: 0 as const },
        pidNamespaceObservation: { kind: 'never_created' as const, pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
        subreaperStartToken: plan.backend.subreaperStartToken, matchingLaunchNonceProcessCount: 0 as const } };
      evidence = { ...core, evidenceDigest: canonicalSha256(core) };
    }
    const [raw, projection, cleanupRaw, cleanupProjection, evidenceArtifact] = await joinResourceOperations([
      artifacts.publishBytes(actual.lifecycleSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-recovery-native-lifecycle-bytes-v1'),
      artifacts.publishCanonical(lifecycle, lifecycle.format),
      artifacts.publishBytes(actual.cleanupSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-recovery-native-cleanup-bytes-v1'),
      artifacts.publishCanonical(cleanup, cleanup.format), artifacts.publishCanonical(evidence,
        evidence.kind === 'containment_all_descendants_dead' ? 'cliq-process-containment-death-evidence-v1' : 'cliq-process-containment-no-spawn-evidence-v1')]);
    metadata.push(raw, projection, cleanupRaw, cleanupProjection, evidenceArtifact);
    const core = { schemaVersion: 1 as const, format: 'cliq-mcp-stdio-recovery-retirement-v1' as const, binding: original.binding,
      ...(containmentRef ? { processContainmentRef: containmentRef } : {}), retirementEvidenceRef: evidenceArtifact.ref, observedAt,
      nativeClosure: { kind: unavailable ? 'linux_successor_response_unavailable_cleanup' : 'linux_successor_cleanup',
        lifecycleRawRef: raw.ref, lifecycleProjectionRef: projection.ref,
        cleanupRawRef: cleanupRaw.ref, cleanupProjectionRef: cleanupProjection.ref },
      creatorProcessDomain: { authorityDomain: 'linux_installed_native_creator_process_v1' as const,
        processObservation: 'absent_or_start_token_mismatch' as const, creatorSupervisorInstanceId: original.original.owner.supervisorInstanceId,
        creatorStateOwnerEpoch: original.original.owner.ownerEpoch, creatorProcessIdentityRef: original.original.owner.processIdentityRef,
        creatorProcessIdentityDigest: original.original.owner.processIdentityDigest, inspectorStateOwnerEpoch: active.ownerEpoch, observedAt } };
    const retirement = decodeMcpStatusRetirement({ ...core, retirementDigest: canonicalSha256(core) });
    const retirementArtifact = await artifacts.publishCanonical(retirement, retirement.format); metadata.push(retirementArtifact);
    const proof = await readMcpStatusRetirementHistory(driver, artifacts, original, retirementArtifact.ref, retirement.retirementDigest);
    const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, artifacts, input.runId);
    const selected = await validateMcpInvocationWait(driver, artifacts, cut), state = selected.wait.probeState;
    if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || state.dispatch.subjectKind !== 'mcp_recovery' ||
        selected.run.waitingOnRef !== original.binding.waitingSubjectRef || state.dispatch.dispatchDigest !== original.binding.probeDispatchDigest)
      fail('MCP status successor cannot close a different or newer original nonce');
    const dispatch = state.dispatch, closedAt = sampleCanonicalNow();
    if (closedAt < dispatch.probeDeadlineAt || closedAt < proof.value.observedAt || closedAt < selected.run.updatedAt)
      fail('MCP successor cannot shorten the original thirty second probe or regress its current Run');
    const closureCore = { schemaVersion: 1 as const, format: 'cliq-reconciliation-probe-timeout-closure-v1' as const, runId: input.runId,
      waitingSubjectRef: selected.run.waitingOnRef!, probeKind: dispatch.probeKind, probeOrdinal: dispatch.probeOrdinal,
      probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, probeDeadlineAt: dispatch.probeDeadlineAt,
      inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, closedAt, subjectKind: 'mcp_recovery' as const,
      brokerDispatchId: dispatch.brokerDispatchId, brokerTargetDigest: dispatch.brokerTargetDigest, brokerFenceTokenDigest: dispatch.brokerFenceTokenDigest,
      noActiveReleaseForNonce: true as const, retirementRef: retirementArtifact.ref, retirementDigest: retirement.retirementDigest };
    const closure = decodeMcpStatusProbeClosure({ ...closureCore, closureDigest: canonicalSha256(closureCore) });
    const closureArtifact = await artifacts.publishCanonical(closure, closure.format); metadata.push(closureArtifact);
    const wrapperCore = { schemaVersion: 1 as const, format: 'cliq-reconciliation-probe-evidence-v1' as const, runId: input.runId,
      waitingSubjectRef: selected.run.waitingOnRef!, waitingSubjectDigest: selected.run.waitingOnRef!, probeKind: dispatch.probeKind,
      probeOrdinal: dispatch.probeOrdinal, probeNonceDigest: dispatch.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest,
      probeStartedAt: dispatch.probeStartedAt, probeDeadlineAt: dispatch.probeDeadlineAt, inspectorIdentityRef: inspectorArtifact.ref,
      inspectorIdentityDigest: inspector.identityDigest, observedAt: closedAt, outcome: 'probe_timeout' as const,
      timeoutReason: 'no_authoritative_observation_before_deadline' as const, timeoutClosureRef: closureArtifact.ref, timeoutClosureDigest: closure.closureDigest };
    const wrapper = decodeMcpStatusProbeWrapper({ ...wrapperCore, evidenceDigest: canonicalSha256(wrapperCore) });
    const wrapperArtifact = await artifacts.publishCanonical(wrapper, wrapper.format); metadata.push(wrapperArtifact);
    await readMcpStatusProbeEvidence(driver, artifacts, selected.source, wrapperArtifact.ref, wrapper.evidenceDigest);
    const nextWait = decodeMcpInvocationWait({ ...selected.wait, probeState: mcpUnresolvedProbeState(selected.wait, wrapperArtifact.ref, wrapper.evidenceDigest, closedAt, 'timeout') });
    const nextArtifact = await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1'); metadata.push(nextArtifact);
    let outcome: TimeFenceAdvance | undefined;
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); readInstalledMcpStdioRecoveryCleanup(heldReceipt, heldInput);
      requireEqual(readRun(connection, input.runId), cut.run, 'MCP successor original current Run nonce');
      requireEqual(readInvocationJournal(connection, input.runId), cut.journal, 'MCP successor unchanged original full-once effect Journal');
      selected.source.registry.assertUnchanged(connection); selected.source.original.history.assertUnchanged(connection); proof.history.assertUnchanged(connection);
      const fresh = owner.filesystem.observePriorProcessDeath(originalProbe.original.process.pid, originalProbe.original.process.processStartToken), now = sampleCanonicalNow();
      outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
      if (now < closedAt || fresh < Date.parse(proof.value.observedAt) || fresh > Date.parse(now) || Date.parse(now) - Date.parse(closedAt) > 5_000)
        throw new KernelStorageError('LEASE_FENCED', 'MCP successor death observation is not fresh at the original nonce close transaction');
      for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
      connection.prepare('UPDATE runs SET waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?').run(nextArtifact.ref, now, input.runId);
      committed = readRun(connection, input.runId); appendRunStateEvent(connection, committed, now);
    });
    requireHealthyFence(outcome); if (!committed) fail('MCP successor nonce closure did not commit');
    closeInput(); return immutableSnapshot(committed);
  })().finally(() => { publication = undefined; });
  const work = Promise.resolve().then(async () => {
    try {
      signal.throwIfAborted(); const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, reads, input.runId);
      if (cut.run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'MCP successor original revision changed');
      const selected = await validateMcpInvocationWait(driver, reads, cut), state = selected.wait.probeState;
      if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || state.dispatch.subjectKind !== 'mcp_recovery') fail('MCP successor requires its exact old in-flight readonly probe');
      original = await readMcpStatusProbePreparation(driver, reads, selected.wait, selected.source); source = selected.source;
      const active = assertActiveStateOwner(driver, owner);
      if (active.ownerEpoch <= original.original.owner.ownerEpoch || active.supervisorInstanceId === original.original.owner.supervisorInstanceId)
        fail('MCP successor cannot close a still-current original creator process domain');
      if (sampleCanonicalNow() < state.dispatch.probeDeadlineAt)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP successor original probe deadline has not elapsed');
      const history = await readRetainedStateOwnerHistory(driver, reads, active.ownerEpoch), current = history.entries.find(entry => entry.owner.ownerEpoch === active.ownerEpoch);
      if (!current) fail('MCP successor lost its real current StateOwner provenance');
      await withHeldInstalledRuntime(input.selected, async installed => {
        await installed.revalidate(signal); const process = await (await installed.loadStateOwner()).observeCurrentProcess();
        if (process.pid !== current.process.pid || process.processStartToken !== current.process.processStartToken || installed.bundleDigest !== active.runtimeBundleRef ||
            installed.bundle.manifestDigest !== active.runtimeBundleManifestDigest) fail('MCP successor checker is not its actual current signed process');
      }, signal);
      owner.filesystem.observePriorProcessDeath(original.original.process.pid, original.original.process.processStartToken);
      physical = openRetainedRecoveryMcpStdioInput(owner.filesystem, original.inputBinding);
      launcher = await openInstalledLinuxWorkerLauncher(input.selected, input.anchor, { signal }); signal.throwIfAborted();
      openingController = launcher.startController({ signal }); controller = await openingController; signal.throwIfAborted();
      receipt = await retireInstalledRetainedMcpStdioRecovery({ selected: input.selected, anchor: input.anchor, controller, lock: owner.filesystem,
        input: physical, inputBinding: original.inputBinding, checker: { supervisorInstanceId: active.supervisorInstanceId, stateOwnerEpoch: active.ownerEpoch }, signal });
      return await complete();
    } finally {
      const results = await Promise.allSettled([(async () => { const current = controller ?? await openingController; await current?.close(); })(),
        (async () => { await launcher?.close(); })()]);
      const failed = results.find(result => result.status === 'rejected');
      if (failed?.status === 'rejected') throw new ResourceRetirementError('MCP successor current checker did not completely join', failed.reason);
      if (!receipt) closeInput();
    }
  });
  return Object.freeze({ result: () => work, resumeResult: complete, cancel, hasRetirement: () => receipt !== undefined,
    assertJoined() { if (!receipt || !physical) fail('MCP successor has no positive original actual cleanup'); return readInstalledMcpStdioRecoveryCleanup(receipt, physical); },
    close: () => closing ??= (async () => {
      cancel(); const results = await Promise.allSettled([work, (async () => { const current = controller ?? await openingController; await current?.close(); })()]);
      const failure = results.find(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError);
      if (failure?.status === 'rejected') throw failure.reason;
      if (receipt && physical) readInstalledMcpStdioRecoveryCleanup(receipt, physical);
    })() });
}
