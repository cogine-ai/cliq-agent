// Exact terminal acknowledgement of one original uncertain invocation. No
// retry, probe, result synthesis, budget change or second terminal writer.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeManualAbandonAttestation, decodeManualInvocationWait, decodeToolAbandonedItem, type ManualInvocationWaitV1, type ManualAbandonAttestationV1 } from '../kernel/mcp.js';
import { decodeBrokerInvocationAmbiguity } from '../kernel/broker-ambiguity.js';
import { decodeBrokerProcessDomainDeath, type BrokerProcessDomainDeathEvidenceV1 } from '../kernel/broker-process-domain-death.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText, controlWireInteger } from '../kernel/control-wire-data.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { decodeInstalledControlRequest, decodeInstalledControlResponse, type RunReconcileRequestV1 } from '../kernel/control-wire.js';
import type { InvocationJournalEntry, RecoveryClosureV1, Run, TerminalDetail, ToolBatchItem, RunFrontier } from '../kernel/types.js';
import type { ToolRequestV1, ToolTargetV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { exactKeys, requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { toolOperationId } from '../policy/tool-policy.js';
import { recordAgentStopPredecessor, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow, advanceTimeFence } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, readHistoricalControlChannel, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeBudgetSettlement, decodeLocalSocketPeerObservation, decodePlatformProcessIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { assertInstalledMcpBrokerProcess, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { MCP_HTTP_BROKER_ENTRY_ID, MCP_HTTP_BROKER_RELATIVE_PATH } from './mcp-broker-native.js';
import { MCP_STDIO_BROKER_ENTRY_ID, MCP_STDIO_BROKER_RELATIVE_PATH } from './mcp-stdio-broker-native.js';
import { readMcpManualDispatchOwner, assertMcpRunQuiescence, readMcpNoReleaseHistory, readMcpAmbiguityHistory } from './mcp-execution.js';
import { readMcpRegistryClosure } from './mcp-registration.js';
import { readMcpServerClosedAttempt, validateMcpServerHistory } from './mcp-server-history.js';
import { resumeOwnedMcpServerManualTerminal } from './mcp-server-retirement.js';
import { stateRootIdentityForLock } from './native-owner.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readRun, readSessionPrincipalId, readControlRequest, ZERO_BUDGET, readCheckpoint } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';
import { appendRunStateEvent } from './reducers/invocation.js';
const same = (a: unknown, b: unknown) => canonicalSha256(a) === canonicalSha256(b);
function invalid(message = 'manual acknowledgement does not close its exact original invocation'): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message);
}
type Subject = ManualInvocationWaitV1['subject'];
type ManualHistoryCut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal' | 'items'>;
async function frame(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: ManualHistoryCut, subject: Subject) {
  const { run, runSpec: spec } = cut, entries = cut.journal.filter(row => row.opId === subject.opId && row.attempt === subject.attempt);
  const [prepared, claim, unknown] = entries;
  if (!prepared || !claim || !unknown || ![3, 4].includes(entries.length) || prepared.phase !== 'prepared' || claim.phase !== 'dispatch_claimed' ||
    unknown.phase !== 'unknown' || entries.length === 4 && entries[3]!.phase !== 'abandoned' ||
    entries.some(row => row.runId !== run.id || row.opKind !== subject.opKind || row.replayClass !== 'manual') ||
    cut.journal.some(row => row.opId === subject.opId && row.attempt !== subject.attempt &&
      ['dispatch_claimed', 'unknown', 'completed', 'abandoned'].includes(row.phase)) || !prepared.grantRef || !unknown.budgetSettlementRef ||
    !unknown.evidenceRef || !unknown.evidenceDigest || !claim.dispatchId || !claim.brokerFenceTokenDigest || claim.sandboxLaunchSpecRef !== undefined) {
    invalid();
  }
  for (const row of [claim, unknown, ...entries.slice(3)]) {
    for (const key of ['requestRef', 'target', 'grantRef', 'leaseEpoch'] as const) {
      if (row[key] !== prepared[key]) {
        invalid();
      }
    }
  }
  for (const row of [unknown, ...entries.slice(3)]) {
    for (const key of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest'] as const) {
      if (row[key] !== claim[key]) {
        invalid();
      }
    }
  }
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef), target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, prepared.grantRef);
  if (spec.operation !== 'agent' || request.format !== 'cliq-tool-request-v1' || request.runId !== run.id || request.assemblyRef !== spec.assemblyRef ||
    request.opId !== prepared.opId || request.opId !== toolOperationId(run.id, request.batchItemId, request.callId) ||
    request.requestDigest !== digestOmitting(request, 'requestDigest') || target.targetDigest !== digestOmitting(target, 'targetDigest') ||
    request.targetRef !== prepared.target || request.targetDigest !== target.targetDigest || grant.grantDigest !== digestOmitting(grant, 'grantDigest') ||
    grant.runId !== run.id || grant.opId !== subject.opId || grant.requestRef !== prepared.requestRef || grant.requestDigest !== request.requestDigest ||
    grant.targetRef !== prepared.target || grant.targetDigest !== target.targetDigest || grant.frontierRef !== request.frontierRef ||
    grant.subject.replayClass !== 'manual' || grant.subject.batchItemId !== request.batchItemId || grant.subject.callId !== request.callId ||
    grant.subject.callIndex !== request.callIndex || grant.subject.toolName !== request.toolName || grant.subject.toolContractDigest !== target.toolContractDigest ||
    grant.maxDispatchedAttempts !== 1 || grant.issuedAt > claim.timestamp || claim.timestamp >= grant.expiresAt || claim.timestamp >= run.deadlineAt || unknown.timestamp < claim.timestamp) {
    invalid();
  }
  const batchRow = cut.items.find(item => item.itemId === request.batchItemId);
  if (!batchRow) {
    invalid();
  }
  const batch = await readCanonicalArtifact<ToolBatchItem>(artifacts, batchRow.payloadRef), call = batch.calls?.[request.callIndex];
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, request.frontierRef);
  if (batch.kind !== 'assistant_tool_batch' || batch.runId !== run.id || batch.itemId !== request.batchItemId || !call || call.callId !== request.callId ||
    call.toolName !== request.toolName || call.inputRef !== request.inputRef || call.inputDigest !== request.inputDigest || frontier.kind !== 'tool' ||
    frontier.batchItemId !== batch.itemId || frontier.nextCallIndex !== request.callIndex || !same(frontier.orderedCallIds, batch.calls.map(call => call.callId))) {
    invalid();
  }
  const ambiguity = decodeBrokerInvocationAmbiguity(await readCanonicalArtifact(artifacts, unknown.evidenceRef));
  if (ambiguity.evidenceDigest !== unknown.evidenceDigest || ambiguity.runId !== run.id || ambiguity.opId !== subject.opId || ambiguity.opKind !== subject.opKind ||
    ambiguity.attempt !== subject.attempt || ambiguity.frontierRef !== request.frontierRef || ambiguity.dispatchId !== claim.dispatchId ||
    ambiguity.dispatchJournalSeq !== claim.seq || ambiguity.operationRequestRef !== prepared.requestRef || ambiguity.operationRequestDigest !== request.requestDigest ||
    ambiguity.operationTargetRef !== prepared.target || ambiguity.operationTargetDigest !== target.targetDigest || ambiguity.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
    ambiguity.claimingStateOwnerEpoch !== claim.stateOwnerEpoch || ambiguity.claimingSupervisorInstanceId !== claim.supervisorInstanceId || ambiguity.observedAt !== unknown.timestamp) {
    invalid();
  }
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef));
  if (settlement.runId !== run.id || settlement.opId !== subject.opId || settlement.attempt !== subject.attempt ||
    settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== unknown.seq || settlement.terminalPhase !== 'unknown' ||
    settlement.settledAt !== unknown.timestamp || !same(settlement.reserved, prepared.budgetDelta) || !same(settlement.consumed, prepared.budgetDelta) ||
    !same(settlement.released, prepared.budgetDelta) || !same(unknown.budgetDelta, prepared.budgetDelta)) {
    invalid();
  }
  const principalId = readSessionPrincipalId(driver, run.sessionId);
  if (grant.principalId !== principalId) {
    invalid();
  }
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  if (subject.opKind !== 'mcp' || target.execution.kind !== 'mcp' || assembly.runtime.sandboxBackend !== 'linux_namespace') {
    invalid('manual closure for this tool transport is not implemented');
  }
  const registry = await readMcpRegistryClosure(driver, artifacts, target.execution.registryRevisionRef, principalId);
  if (!assembly.mcpServers.some(server => server.registryRevisionRef === registry.ref &&
    server.manifestDigest === registry.registry.manifestDigest) || target.execution.registryManifestDigest !== registry.registry.manifestDigest) {
    invalid();
  }
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  const stdio = registry.registry.transport.kind === 'stdio';
  const images = bundle.entries.filter(entry => entry.entryId === (stdio ? MCP_STDIO_BROKER_ENTRY_ID : MCP_HTTP_BROKER_ENTRY_ID));
  if (bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest || images.length !== 1 || images[0]!.role !== 'platform_helper' ||
    images[0]!.version !== '1' || images[0]!.executable !== true || images[0]!.relativePath !== (stdio ? MCP_STDIO_BROKER_RELATIVE_PATH : MCP_HTTP_BROKER_RELATIVE_PATH)) {
    invalid();
  }
  const originalOwners = await readRetainedStateOwnerHistory(driver, artifacts, claim.stateOwnerEpoch!), claiming = originalOwners.entries.find(entry => entry.owner.ownerEpoch === claim.stateOwnerEpoch);
  if (!claiming || claiming.owner.supervisorInstanceId !== claim.supervisorInstanceId || claiming.owner.acquiredAt > claim.timestamp ||
    claiming.owner.runtimeBundleRef !== assembly.runtime.runtimeBundleRef || claiming.owner.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
    claiming.process.platform !== 'linux' || claiming.owner.state === 'terminal' &&
      claiming.owner.releasedAt < (ambiguity.creatorProcessDeathEvidenceRef ? claim.timestamp : unknown.timestamp)) {
    invalid();
  }
  await readMcpAmbiguityHistory(driver, artifacts, { prepared, claim, unknown, assembly });
  return {
    prepared,
    claim,
    unknown,
    entries,
    request,
    target,
    grant,
    ambiguity,
    assembly,
    principalId,
    stdio
  };
}
/** Uses the caller's actual selected recovery cut; never recursively reads it. */
export async function validateManualInvocationWait(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  const { run } = cut;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef || !run.frontierRef) {
    invalid();
  }
  const wait = decodeManualInvocationWait(await readCanonicalArtifact(artifacts, run.waitingOnRef));
  if (wait.runId !== run.id || wait.frontierRef !== run.frontierRef || wait.createdFromRevision >= run.revision || wait.createdAt > run.updatedAt ||
    run.activeWorkerLaunchId || cut.workerLaunches.length || !same(run.budgetReserved, ZERO_BUDGET) || cut.workspaceGenerations.some(row => !['sealed', 'retired'].includes(row.phase))) {
    invalid();
  }
  const original = await frame(driver, artifacts, cut, wait.subject);
  if (original.entries.length !== 3 || original.request.frontierRef !== wait.frontierRef || original.unknown.timestamp > wait.createdAt ||
    cut.latestCheckpoint.journalSeq !== cut.journal.length || cut.latestCheckpoint.runItemSeq !== cut.items.length ||
    cut.latestCheckpoint.createdAt > wait.createdAt || cut.latestCheckpoint.basedOnRunRevision > wait.createdFromRevision) {
    invalid();
  }
  assertRetiredGenerationCut(driver, run, cut.workspaceGenerations);
  return {
    wait,
    ...original
  };
}
export async function prepareManualInvocationWait(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  runId: string;
  opId: string;
  attempt: number;
  expectedRunRevision: number;
}) {
  const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, artifacts, input.runId), { run } = cut;
  if (run.revision !== input.expectedRunRevision) {
    throw new KernelStorageError('REVISION_CONFLICT', 'manual wait Run revision changed');
  }
  if (run.activeWorkerLaunchId || cut.workerLaunches.length || !run.frontierRef || run.nextStep !== 'tool' || run.status !== 'queued' ||
    run.waitingOnRef || run.waitingReason || !same(run.budgetReserved, ZERO_BUDGET) || cut.latestCheckpoint.journalSeq !== cut.journal.length || cut.latestCheckpoint.runItemSeq !== cut.items.length) {
    invalid();
  }
  assertRetiredGenerationCut(driver, run, cut.workspaceGenerations);
  const original = await frame(driver, artifacts, cut, {
    kind: 'invocation',
    recovery: 'manual',
    opKind: 'mcp',
    opId: input.opId,
    attempt: input.attempt
  });
  if (original.entries.length !== 3 || original.request.frontierRef !== run.frontierRef) {
    invalid();
  }
  const createdAt = sampleCanonicalNow(), wait: ManualInvocationWaitV1 = {
    schemaVersion: 1,
    kind: 'reconciliation',
    runId: run.id,
    createdFromRevision: run.revision,
    createdAt,
    frontierRef: run.frontierRef,
    subject: {
      kind: 'invocation',
      recovery: 'manual',
      opKind: 'mcp',
      opId: input.opId,
      attempt: input.attempt
    },
    probeState: {
      phase: 'manual_only',
      automaticProbeCount: 0,
      userProbeCount: 0
    }
  };
  const artifact = await artifacts.publishCanonical(wait, 'cliq-waiting-subject-v1');
  let updated!: Run;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    if (!same(readRun(connection, run.id), run) || !same(readInvocationJournal(connection, run.id), cut.journal)) {
      invalid();
    }
    const committedAt = sampleCanonicalNow();
    if (committedAt < createdAt || advanceTimeFence(connection, owner.ownerEpoch, committedAt) !== 'healthy') {
      invalid('manual wait canonical time is not healthy');
    }
    insertArtifactMetadata(connection, artifact, committedAt);
    connection.prepare("UPDATE runs SET status='waiting',waiting_reason='reconciliation',waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?")
      .run(artifact.ref, committedAt, run.id);
    updated = readRun(connection, run.id);
    appendRunStateEvent(connection, updated, committedAt);
  });
  return {
    run: immutableSnapshot(updated),
    wait
  };
}
type Physical = {
  schemaVersion: 1;
  format: 'cliq-manual-dispatch-closure-v1';
  runId: string;
  opId: string;
  attempt: number;
  dispatchId: string;
  dispatchJournalSeq: number;
  brokerFenceTokenDigest: string;
  unknownJournalSeq: number;
  inspectorIdentityRef: string;
  inspectorIdentityDigest: string;
  inspectorStateOwnerEpoch: number;
  observedAt: string;
  evidenceDigest: string;
} & ({
  kind: 'original_native_joined';
  joined: unknown;
} | {
  kind: 'broker_process_domain_dead';
  deathEvidenceRef: string;
  deathEvidenceDigest: string;
});
/** Closed historical data only. A parsed joined projection never creates a
 * current native owner, release fence, cleanup permission or process proof. */
export function decodeManualDispatchClosureData(value: unknown): Physical {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'manual dispatch closure');
  const base = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq',
    'brokerFenceTokenDigest', 'unknownJournalSeq', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'inspectorStateOwnerEpoch', 'observedAt',
    'evidenceDigest', 'kind'], ['joined', 'deathEvidenceRef', 'deathEvidenceDigest']);
  if (base.schemaVersion !== 1 || base.format !== 'cliq-manual-dispatch-closure-v1' || base.evidenceDigest !== digestOmitting(base, 'evidenceDigest'))
    throw new TypeError('manual dispatch closure changes its exact closed format or digest');
  for (const key of ['runId', 'opId', 'dispatchId']) controlWireText(base[key]);
  for (const key of ['brokerFenceTokenDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest']) controlWireRef(base[key]);
  controlWireInteger(base.attempt); for (const key of ['dispatchJournalSeq', 'unknownJournalSeq', 'inspectorStateOwnerEpoch']) controlWireInteger(base[key], 1);
  parseCanonicalTime(base.observedAt as string);
  if (base.kind === 'broker_process_domain_dead') {
    if (base.joined !== undefined) throw new TypeError('manual process death cannot borrow an original native join');
    controlWireRef(base.deathEvidenceRef); controlWireRef(base.deathEvidenceDigest);
  } else if (base.kind === 'original_native_joined') {
    if (base.deathEvidenceRef !== undefined || base.deathEvidenceDigest !== undefined) throw new TypeError('manual original join cannot borrow a successor death');
    const joined = controlWireRecord(base.joined, ['kind', 'purpose', 'setupReleased', 'effectReleased', 'completedStages', 'tokenRevoked',
      'matchingActiveReleaseCount', 'tasksJoined'], ['brokerFenceTokenDigest', 'networkStarted', 'requestStarted', 'networkJoined',
      'releaseFenceTokenDigest', 'execReleased', 'processJoined', 'pipesJoined', 'outputCustodyRetired']);
    if (joined.purpose !== 'run' || joined.tokenRevoked !== true || joined.matchingActiveReleaseCount !== 0 || joined.tasksJoined !== true ||
        typeof joined.setupReleased !== 'boolean' || typeof joined.effectReleased !== 'boolean' || !Array.isArray(joined.completedStages) || joined.completedStages.length > 4 ||
        !same(joined.completedStages, ['initialize', 'initialized', 'tools_list', 'tools_call'].slice(0, joined.completedStages.length)))
      throw new TypeError('manual original join has no exact finite revoked local projection');
    if (joined.kind === 'mcp_http_owner_joined') {
      controlWireRecord(base.joined, ['kind', 'purpose', 'brokerFenceTokenDigest', 'networkStarted', 'requestStarted', 'setupReleased', 'effectReleased',
        'completedStages', 'tokenRevoked', 'matchingActiveReleaseCount', 'networkJoined', 'tasksJoined']);
      if (joined.brokerFenceTokenDigest !== base.brokerFenceTokenDigest || joined.networkJoined !== true ||
          typeof joined.networkStarted !== 'boolean' || typeof joined.requestStarted !== 'boolean' || joined.effectReleased && !joined.setupReleased || joined.requestStarted && !joined.networkStarted)
        throw new TypeError('manual original HTTP projection changes its local release domain');
    } else if (joined.kind === 'mcp_stdio_owner_joined') {
      controlWireRecord(base.joined, ['kind', 'purpose', 'releaseFenceTokenDigest', 'execReleased', 'setupReleased', 'effectReleased', 'completedStages',
        'tokenRevoked', 'matchingActiveReleaseCount', 'processJoined', 'pipesJoined', 'tasksJoined', 'outputCustodyRetired']);
      if (joined.releaseFenceTokenDigest !== base.brokerFenceTokenDigest || joined.execReleased !== true || joined.setupReleased !== true ||
          joined.processJoined !== true || joined.pipesJoined !== true || joined.outputCustodyRetired !== true)
        throw new TypeError('manual original stdio projection changes its process/pipe release domain');
    } else throw new TypeError('unsupported manual native join purpose');
  } else throw new TypeError('unsupported manual closure kind');
  return immutableSnapshot(base) as Physical;
}
declare const manualPlanBrand: unique symbol;
export type ManualInvocationFinalization = Readonly<{
  readonly [manualPlanBrand]: true;
}>;
type Mutation = {
  request: RunReconcileRequestV1;
  identity: AuthenticatedControlIdentity;
};
type Plan = {
  driver: SqliteDriver;
  owner: StateOwnerContext;
  cut: RecoveryClosureV1;
  mutation: Mutation;
  original: Awaited<ReturnType<typeof validateManualInvocationWait>>;
  physical: Physical;
  physicalRef: string;
  metadata: PublishedArtifact[];
  reobserve(connection: SqliteConnection): void;
  validate(connection: SqliteConnection, at: string): void;
  release(): void;
};
const plans = new WeakMap<ManualInvocationFinalization, Plan>();
export async function prepareManualInvocationFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: Mutation & {
  installedRuntime: HeldInstalledRuntime;
}): Promise<ManualInvocationFinalization> {
  const decoded = decodeInstalledControlRequest(input.request);
  if (decoded.method !== 'run.reconcile' || decoded.resolution.kind !== 'abandon_run' || decoded.resolution.acknowledgeExactRisk !== true) {
    throw new KernelStorageError('INVALID_REQUEST', 'manual abandonment requires exact risk acknowledgement');
  }
  await validateControlChannelClosure(artifacts, owner, input.identity);
  assertCurrentControlFrame(owner, input.identity);
  const cut = immutableSnapshot(await (await import('./recovery-closure.js')).readRecoveryClosure(driver, artifacts, decoded.runId));
  if (readSessionPrincipalId(driver, cut.run.sessionId) !== input.identity.principalId) {
    throw new KernelStorageError('NOT_FOUND', 'manual Run is unavailable');
  }
  if (cut.run.revision !== decoded.expectedRevision) {
    throw new KernelStorageError('REVISION_CONFLICT', 'manual Run revision changed');
  }
  if (cut.run.waitingOnRef !== decoded.waitingOnRef) {
    throw new KernelStorageError('INVALID_REQUEST', 'manual wait differs');
  }
  const original = await validateManualInvocationWait(driver, artifacts, cut), active = assertActiveStateOwner(driver, owner);
  assertInstalledMcpBrokerProcess();
  const history = await readRetainedStateOwnerHistory(driver, artifacts, active.ownerEpoch), claiming = history.entries.find(row => row.owner.ownerEpoch === original.claim.stateOwnerEpoch);
  if (!claiming || claiming.owner.supervisorInstanceId !== original.claim.supervisorInstanceId || claiming.owner.runtimeBundleRef !== original.assembly.runtime.runtimeBundleRef ||
    claiming.owner.runtimeBundleManifestDigest !== original.assembly.runtime.runtimeBundleManifestDigest || claiming.process.platform !== 'linux') {
    invalid();
  }
  if (!original.ambiguity.creatorProcessDeathEvidenceRef) {
    await readSupervisorInspector(artifacts, claiming.owner, original.assembly, original.ambiguity);
  }
  const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format), metadata = [inspectorArtifact];
  const retained = readMcpManualDispatchOwner(original.claim);
  let fresh = 0;
  let death: BrokerProcessDomainDeathEvidenceV1 | undefined;
  let observedAt = sampleCanonicalNow();
  let kind: Pick<Physical, 'kind'> & Record<string, unknown>;
  if (retained) {
    if (active.ownerEpoch !== original.claim.stateOwnerEpoch || active.supervisorInstanceId !== original.claim.supervisorInstanceId) {
      invalid();
    }
    retained.assertJoined();
    kind = {
      kind: 'original_native_joined',
      joined: retained.joined
    };
  }
  else {
    if (active.ownerEpoch <= claiming.owner.ownerEpoch) {
      invalid('original MCP owner or newer original-process death proof is required');
    }
    await withHeldInstalledRuntime(input.installedRuntime, async (installed) => {
      const root = stateRootIdentityForLock(owner.filesystem), inspection = history.entries.find(row => row.owner.ownerEpoch === active.ownerEpoch);
      if (!inspection || !same(inspection.owner, active) || !same(root, history.rootIdentity) || installed.bundleDigest !== active.runtimeBundleRef ||
        root.canonicalAbsolutePath !== installed.stateRoot.canonicalPath || root.deviceId !== installed.stateRoot.deviceId || root.directoryFileId !== installed.stateRoot.fileId) {
        invalid();
      }
      await installed.revalidate();
      const process = await (await installed.loadStateOwner()).observeCurrentProcess();
      if (process.pid !== inspection.process.pid || process.processStartToken !== inspection.process.processStartToken || process.executableImageDigest !== active.supervisorExecutableDigest) {
        invalid();
      }
    });
    const at = new Date(owner.filesystem.observePriorProcessDeath(claiming.process.pid, claiming.process.processStartToken)).toISOString();
    death = {
      schemaVersion: 1,
      format: 'cliq-broker-process-domain-death-evidence-v1',
      runId: cut.run.id,
      opId: original.claim.opId,
      attempt: original.claim.attempt,
      dispatchId: original.claim.dispatchId!,
      dispatchJournalSeq: original.claim.seq,
      operationRequestRef: original.prepared.requestRef,
      operationTargetDigest: original.target.targetDigest,
      operationGrantRef: original.prepared.grantRef!,
      claimingSupervisorInstanceId: claiming.owner.supervisorInstanceId,
      claimingStateOwnerEpoch: claiming.owner.ownerEpoch,
      claimingProcessIdentityRef: claiming.owner.processIdentityRef,
      claimingProcessIdentityDigest: claiming.owner.processIdentityDigest,
      inspectorIdentityRef: inspectorArtifact.ref,
      inspectorIdentityDigest: inspector.identityDigest,
      inspectorStateOwnerEpoch: active.ownerEpoch,
      brokerFenceTokenDigest: original.claim.brokerFenceTokenDigest!,
      authorityDomain: 'linux_installed_native_creator_process_v1',
      processObservation: 'absent_or_start_token_mismatch',
      observedAt: at,
      evidenceDigest: ''
    };
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
    decodeBrokerProcessDomainDeath(death);
    const published = await artifacts.publishCanonical(death, death.format);
    metadata.push(published);
    kind = {
      kind: 'broker_process_domain_dead',
      deathEvidenceRef: published.ref,
      deathEvidenceDigest: death.evidenceDigest
    };
  }
  observedAt = sampleCanonicalNow();
  const physical = {
    schemaVersion: 1,
    format: 'cliq-manual-dispatch-closure-v1',
    runId: cut.run.id,
    opId: original.claim.opId,
    attempt: original.claim.attempt,
    dispatchId: original.claim.dispatchId!,
    dispatchJournalSeq: original.claim.seq,
    brokerFenceTokenDigest: original.claim.brokerFenceTokenDigest!,
    unknownJournalSeq: original.unknown.seq,
    inspectorIdentityRef: inspectorArtifact.ref,
    inspectorIdentityDigest: inspector.identityDigest,
    inspectorStateOwnerEpoch: active.ownerEpoch,
    observedAt,
    evidenceDigest: '',
    ...kind
  } as Physical;
  physical.evidenceDigest = digestOmitting(physical, 'evidenceDigest');
  decodeManualDispatchClosureData(physical);
  const closure = await artifacts.publishCanonical(physical, physical.format);
  metadata.push(closure);
  const handle = Object.freeze({}) as ManualInvocationFinalization;
  plans.set(handle, {
    driver,
    owner,
    cut,
    mutation: {
      request: decoded,
      identity: immutableSnapshot(input.identity)
    },
    original,
    physical,
    physicalRef: closure.ref,
    metadata,
    reobserve(connection) {
      assertActiveStateOwner(connection, owner);
      assertCurrentControlFrame(owner, input.identity);
      assertMcpRunQuiescence(cut.run.id);
      if (retained) {
        retained.assertJoined();
      }
      else
        fresh = owner.filesystem.observePriorProcessDeath(claiming.process.pid, claiming.process.processStartToken);
    },
    validate(connection, at) {
      history.assertUnchanged(connection);
      assertCurrentControlFrame(owner, input.identity);
      if (!same(readRun(connection, cut.run.id), cut.run) || !same(readInvocationJournal(connection, cut.run.id), cut.journal) ||
        parseCanonicalTime(at) < parseCanonicalTime(observedAt) || parseCanonicalTime(at) - parseCanonicalTime(observedAt) > 5000 ||
        death && (fresh < parseCanonicalTime(death.observedAt) || fresh > parseCanonicalTime(at) ||
          parseCanonicalTime(at) - parseCanonicalTime(death.observedAt) > 5000)) {
        invalid();
      }
      if (retained) {
        retained.assertJoined();
      }
    },
    release() {
      retained?.release();
    }
  });
  return handle;
}
export function readManualInvocationFinalization(driver: SqliteDriver, owner: StateOwnerContext, value: ManualInvocationFinalization, runId: string) {
  const plan = plans.get(value);
  if (!plan || plan.driver !== driver || plan.owner !== owner || plan.cut.run.id !== runId) {
    invalid('manual terminal plan lacks its original owner');
  }
  return plan;
}
export function stageManualInvocationFinalization(plan: Plan, now: string, journalSeq: number) {
  const { run } = plan.cut, { request, identity } = plan.mutation, o = plan.original;
  const attestation = {
    schemaVersion: 1,
    format: 'cliq-manual-abandon-attestation-v1',
    principalId: identity.principalId,
    channelIdentityRef: identity.channelIdentityRef,
    channelIdentityDigest: identity.channelIdentityDigest,
    requestId: request.requestId,
    requestDigest: request.requestDigest,
    runId: run.id,
    waitingSubjectRef: request.waitingOnRef,
    frontierRef: o.wait.frontierRef,
    opId: o.claim.opId,
    attempt: o.claim.attempt,
    unknownJournalSeq: o.unknown.seq,
    operationRequestRef: o.prepared.requestRef,
    operationRequestDigest: o.request.requestDigest,
    targetRef: o.prepared.target,
    targetDigest: o.target.targetDigest,
    ambiguityEvidenceRef: o.unknown.evidenceRef!,
    ambiguityEvidenceDigest: o.unknown.evidenceDigest!,
    acknowledgedRisk: 'effect_may_have_occurred_result_will_not_be_used_and_run_will_stop',
    createdAt: now,
    attestationDigest: ''
  } satisfies ManualAbandonAttestationV1;
  attestation.attestationDigest = digestOmitting(attestation, 'attestationDigest');
  decodeManualAbandonAttestation(attestation);
  const artifact = planCanonicalArtifact(attestation, attestation.format), intent = recordAgentStopPredecessor({
    schemaVersion: 1,
    runId: run.id,
    createdAt: now,
    origin: 'manual_abandon',
    targetStatus: 'cancelled',
    reason: 'cancelled_by_user',
    requestId: request.requestId,
    principalId: identity.principalId,
    opId: o.claim.opId,
    attempt: o.claim.attempt,
    attestationRef: artifact.ref
  }, undefined, plan.cut.latestCheckpoint.id, run.revision, plan.cut.journal.length);
  const { evidenceRef: _e, evidenceDigest: _d, ...prior } = o.unknown;
  const abandoned: InvocationJournalEntry = {
    ...prior,
    seq: journalSeq,
    phase: 'abandoned',
    attestationRef: artifact.ref,
    budgetDelta: {
      ...ZERO_BUDGET
    },
    timestamp: now
  };
  const item = decodeToolAbandonedItem({
    schemaVersion: 1,
    kind: 'tool_abandoned',
    itemId: identityHash('cliq-tool-abandoned-item-v1', run.id, o.request.batchItemId, o.request.callId),
    runId: run.id,
    batchItemId: o.request.batchItemId,
    callId: o.request.callId,
    index: o.request.callIndex,
    opId: o.claim.opId,
    attempt: o.claim.attempt,
    abandonedJournalSeq: journalSeq,
    attestationRef: artifact.ref,
    createdAt: now
  });
  return {
    attestation,
    artifact,
    intent,
    abandoned,
    item,
    detail: {
      opId: o.claim.opId,
      attempt: o.claim.attempt,
      abandonedJournalSeq: journalSeq,
      attestationRef: artifact.ref,
      dispatchFenceOrDeathEvidenceRef: plan.physicalRef,
      toolAbandonedItemRef: canonicalSha256(item)
    }
  };
}
export async function replayManualReconciliation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: Mutation) {
  await validateControlChannelClosure(artifacts, owner, input.identity);
  assertCurrentControlFrame(owner, input.identity);
  const row = readControlRequest(driver, input.identity.principalId, 'run.reconcile', input.request.requestId);
  if (!row) {
    return undefined;
  }
  if (row.requestDigest !== input.request.requestDigest) {
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'manual request id differs');
  }
  const response = decodeInstalledControlResponse(await readCanonicalArtifact(artifacts, row.responseRef), input.request);
  if (!response.ok || response.result.method !== 'run.reconcile' || response.result.resolution.kind !== 'abandoned_run') {
    invalid();
  }
  const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, artifacts, input.request.runId);
  const closed = await validateManualAbandonmentHistory(driver, artifacts, cut);
  if (!closed) invalid('manual first response has no exact original durable abandonment');
  assertCurrentControlFrame(owner, input.identity);
  const claim = cut.journal.find(entry => entry.opId === closed.opId && entry.attempt === closed.attempt && entry.phase === 'dispatch_claimed');
  if (!claim) invalid('manual first response lost its exact original permanent claim');
  resumeOwnedMcpServerManualTerminal(driver, owner, claim);
  return {
    run: cut.run,
    response
  };
}
/** Full retained data audit over an already selected cut; never resource truth. */
export async function validateManualAbandonmentHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: ManualHistoryCut, detail?: TerminalDetail) {
  const abandoned = cut.journal.filter(row => row.phase === 'abandoned' && row.replayClass === 'manual');
  const markers = (await artifacts.mapReads(cut.items, entry => readCanonicalArtifact<{
    kind?: string;
  }>(artifacts, entry.payloadRef)))
    .filter(item => item.kind === 'tool_abandoned');
  if (!abandoned.length) {
    if (detail?.abandonedManualInvocation || markers.length) {
      invalid();
    }
    return undefined;
  }
  if (markers.length !== 1) {
    invalid();
  }
  if (abandoned.length !== 1 || !['cancelled', 'failed'].includes(cut.run.status) || !cut.run.terminalDetailRef) {
    invalid();
  }
  const row = abandoned[0]!, attestation = decodeManualAbandonAttestation(await readCanonicalArtifact(artifacts, row.attestationRef!));
  const wait = decodeManualInvocationWait(await readCanonicalArtifact(artifacts, attestation.waitingSubjectRef));
  const original = await frame(driver, artifacts, cut, wait.subject), terminal = detail ?? await readCanonicalArtifact<TerminalDetail>(artifacts, cut.run.terminalDetailRef);
  const marker = terminal.abandonedManualInvocation;
  if (wait.runId !== cut.run.id || wait.frontierRef !== original.request.frontierRef || wait.createdFromRevision >= cut.run.revision - 1 ||
    wait.createdAt < original.unknown.timestamp || wait.createdAt > attestation.createdAt ||
    !marker || marker.opId !== row.opId || marker.attempt !== row.attempt || marker.abandonedJournalSeq !== row.seq || marker.attestationRef !== row.attestationRef ||
    row.budgetSettlementRef !== original.unknown.budgetSettlementRef || !same(row.budgetDelta, ZERO_BUDGET) || row.timestamp !== terminal.createdAt || attestation.createdAt !== terminal.createdAt ||
    attestation.runId !== cut.run.id || attestation.frontierRef !== wait.frontierRef || attestation.opId !== row.opId || attestation.attempt !== row.attempt || attestation.unknownJournalSeq !== original.unknown.seq ||
    attestation.operationRequestRef !== original.prepared.requestRef || attestation.operationRequestDigest !== original.request.requestDigest || attestation.targetRef !== original.prepared.target ||
    attestation.targetDigest !== original.target.targetDigest || attestation.ambiguityEvidenceRef !== original.unknown.evidenceRef || attestation.ambiguityEvidenceDigest !== original.unknown.evidenceDigest) {
    invalid();
  }
  const item = decodeToolAbandonedItem(await readCanonicalArtifact(artifacts, marker.toolAbandonedItemRef));
  if (item.runId !== cut.run.id || item.opId !== row.opId || item.attempt !== row.attempt || item.abandonedJournalSeq !== row.seq || item.attestationRef !== row.attestationRef ||
    item.batchItemId !== original.request.batchItemId || item.callId !== original.request.callId || item.index !== original.request.callIndex ||
    !cut.items.some(entry => entry.payloadRef === marker.toolAbandonedItemRef && entry.itemId === item.itemId) || item.createdAt !== terminal.createdAt) {
    invalid();
  }
  const physical = decodeManualDispatchClosureData(await readCanonicalArtifact(artifacts, marker.dispatchFenceOrDeathEvidenceRef));
  if (!exactKeys(physical, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq', 'brokerFenceTokenDigest', 'unknownJournalSeq',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'inspectorStateOwnerEpoch', 'observedAt', 'evidenceDigest', 'kind',
    ...(physical.kind === 'original_native_joined' ? ['joined'] : ['deathEvidenceRef', 'deathEvidenceDigest'])]) || physical.schemaVersion !== 1 || physical.format !== 'cliq-manual-dispatch-closure-v1' || physical.evidenceDigest !== digestOmitting(physical, 'evidenceDigest') || physical.runId !== cut.run.id ||
    physical.opId !== row.opId || physical.attempt !== row.attempt || physical.dispatchId !== original.claim.dispatchId || physical.dispatchJournalSeq !== original.claim.seq ||
    physical.brokerFenceTokenDigest !== original.claim.brokerFenceTokenDigest || physical.unknownJournalSeq !== original.unknown.seq ||
    physical.observedAt < original.unknown.timestamp || physical.observedAt > terminal.createdAt ||
    parseCanonicalTime(cut.run.updatedAt) - parseCanonicalTime(physical.observedAt) > 5000) {
    invalid();
  }
  const history = await readRetainedStateOwnerHistory(driver, artifacts, physical.inspectorStateOwnerEpoch), inspecting = history.entries.find(entry => entry.owner.ownerEpoch === physical.inspectorStateOwnerEpoch);
  const claiming = history.entries.find(entry => entry.owner.ownerEpoch === original.claim.stateOwnerEpoch);
  if (!inspecting || !claiming) {
    invalid();
  }
  await readSupervisorInspector(artifacts, inspecting.owner, {
    runtime: {
      runtimeBundleRef: inspecting.owner.runtimeBundleRef,
      runtimeBundleManifestDigest: inspecting.owner.runtimeBundleManifestDigest
    }
  }, physical);
  let originalDeath: BrokerProcessDomainDeathEvidenceV1 | undefined;
  if (physical.kind === 'original_native_joined') {
    if (original.stdio) {
      const joined = physical.joined as import('./mcp-stdio-broker-native.js').NativeMcpStdioRunJoined;
      if (!exactKeys(joined, ['kind', 'purpose', 'releaseFenceTokenDigest', 'execReleased', 'setupReleased', 'effectReleased', 'completedStages',
        'tokenRevoked', 'matchingActiveReleaseCount', 'processJoined', 'pipesJoined', 'tasksJoined', 'outputCustodyRetired']) ||
          inspecting.owner.ownerEpoch !== claiming.owner.ownerEpoch || joined.kind !== 'mcp_stdio_owner_joined' || joined.purpose !== 'run' ||
          joined.releaseFenceTokenDigest !== row.brokerFenceTokenDigest || joined.tokenRevoked !== true || joined.matchingActiveReleaseCount !== 0 ||
          joined.processJoined !== true || joined.pipesJoined !== true || joined.tasksJoined !== true || joined.outputCustodyRetired !== true ||
          joined.execReleased !== true || joined.setupReleased !== true || typeof joined.effectReleased !== 'boolean' || !Array.isArray(joined.completedStages) ||
          !same(joined.completedStages, ['initialize', 'initialized', 'tools_list', 'tools_call'].slice(0, joined.completedStages.length)) || joined.completedStages.length > 4)
        invalid('MCP stdio manual closure changes its original joined local release domain');
    } else {
    const joined = physical.joined as import('./mcp-broker-native.js').NativeMcpRunJoined;
    if (!exactKeys(joined, ['kind', 'purpose', 'brokerFenceTokenDigest', 'networkStarted', 'requestStarted', 'setupReleased', 'effectReleased', 'completedStages', 'tokenRevoked',
      'matchingActiveReleaseCount', 'networkJoined', 'tasksJoined']) || inspecting.owner.ownerEpoch !== claiming.owner.ownerEpoch || joined.kind !== 'mcp_http_owner_joined' || joined.purpose !== 'run' || joined.brokerFenceTokenDigest !== row.brokerFenceTokenDigest ||
      joined.tokenRevoked !== true || joined.matchingActiveReleaseCount !== 0 || joined.networkJoined !== true || joined.tasksJoined !== true ||
      ['networkStarted', 'requestStarted', 'setupReleased', 'effectReleased'].some(key => typeof (joined as unknown as Record<string, unknown>)[key] !== 'boolean') ||
      !Array.isArray(joined.completedStages) || joined.completedStages.length > 4 || !same(joined.completedStages, ['initialize', 'initialized', 'tools_list', 'tools_call'].slice(0, joined.completedStages.length)) ||
      joined.effectReleased && !joined.setupReleased || joined.requestStarted && !joined.networkStarted) {
      invalid();
    }
    }
  }
  else if (physical.kind === 'broker_process_domain_dead') {
    const death = decodeBrokerProcessDomainDeath(await readCanonicalArtifact(artifacts, physical.deathEvidenceRef));
    originalDeath = death;
    if (death.evidenceDigest !== physical.deathEvidenceDigest || death.runId !== cut.run.id || death.opId !== row.opId || death.attempt !== row.attempt || death.dispatchId !== original.claim.dispatchId ||
      death.dispatchJournalSeq !== original.claim.seq || death.operationRequestRef !== original.prepared.requestRef || death.operationGrantRef !== original.prepared.grantRef ||
      death.operationTargetDigest !== original.target.targetDigest || death.brokerFenceTokenDigest !== original.claim.brokerFenceTokenDigest ||
      death.claimingStateOwnerEpoch !== claiming.owner.ownerEpoch || death.claimingSupervisorInstanceId !== claiming.owner.supervisorInstanceId ||
      death.claimingProcessIdentityRef !== claiming.owner.processIdentityRef || death.claimingProcessIdentityDigest !== claiming.owner.processIdentityDigest ||
      death.inspectorStateOwnerEpoch !== inspecting.owner.ownerEpoch || death.inspectorIdentityRef !== physical.inspectorIdentityRef ||
      death.inspectorIdentityDigest !== physical.inspectorIdentityDigest || death.observedAt < original.unknown.timestamp ||
      death.observedAt > physical.observedAt) {
      invalid();
    }
  }
  else
    invalid();
  const control = readControlRequest(driver, attestation.principalId, 'run.reconcile', attestation.requestId);
  if (!control || control.requestDigest !== attestation.requestDigest || control.committedAt < cut.run.updatedAt ||
    parseCanonicalTime(control.committedAt) - parseCanonicalTime(physical.observedAt) > 5000 ||
    originalDeath && parseCanonicalTime(control.committedAt) - parseCanonicalTime(originalDeath.observedAt) > 5000 ||
    control.channelIdentityRef !== attestation.channelIdentityRef || control.channelIdentityDigest !== attestation.channelIdentityDigest) {
    invalid();
  }
  const request = {
    protocolVersion: 1 as const,
    method: 'run.reconcile' as const,
    requestId: attestation.requestId,
    requestDigest: attestation.requestDigest,
    runId: cut.run.id,
    expectedRevision: cut.run.revision - 1,
    waitingOnRef: attestation.waitingSubjectRef,
    resolution: {
      kind: 'abandon_run' as const,
      acknowledgeExactRisk: true as const
    }
  };
  decodeInstalledControlRequest(request);
  const response = decodeInstalledControlResponse(await readCanonicalArtifact(artifacts, control.responseRef), request);
  if (!response.ok || response.result.method !== 'run.reconcile' || response.result.resolution.kind !== 'abandoned_run' || response.result.resolution.attestationRef !== row.attestationRef ||
    response.result.resolution.terminalDetailRef !== cut.run.terminalDetailRef || !same(response.result.snapshot.run, cut.run)) {
    invalid();
  }
  const intent = await readCanonicalArtifact<AgentStopIntent>(artifacts, cut.run.stopIntentRef!);
  if (intent.origin === 'manual_abandon') {
    if (intent.requestId !== attestation.requestId || intent.principalId !== attestation.principalId || intent.opId !== row.opId || intent.attempt !== row.attempt ||
      intent.attestationRef !== row.attestationRef || intent.createdAt !== attestation.createdAt || intent.registeredRunRevision !== request.expectedRevision ||
      intent.registeredJournalSeq === undefined || intent.registeredJournalSeq < original.unknown.seq || !intent.registeredCheckpointId) {
      invalid();
    }
    const before = readCheckpoint(driver, intent.registeredCheckpointId), after = readCheckpoint(driver, cut.run.latestCheckpointId), markerRow = cut.items.find(item => item.payloadRef === marker.toolAbandonedItemRef)!;
    if (before.runId !== cut.run.id || before.journalSeq !== intent.registeredJournalSeq || before.runItemSeq !== markerRow.itemSeq - 1 ||
      before.workspaceStateRef !== after.workspaceStateRef || before.createdAt > attestation.createdAt || before.basedOnRunRevision > wait.createdFromRevision) {
      invalid();
    }
  }
  const channel = await readHistoricalControlChannel(driver, artifacts, {
    principalId: attestation.principalId,
    channelIdentityRef: control.channelIdentityRef,
    channelIdentityDigest: control.channelIdentityDigest
  });
  // The channel schema records the authenticated client, not a server PID.
  // Bind its observation/opening and this commit to the one retained inspector
  // owner interval. A client PID must never masquerade as the Supervisor PID.
  if (channel.channel.openedAt < inspecting.owner.acquiredAt || channel.channel.openedAt > physical.observedAt ||
    attestation.createdAt < inspecting.owner.acquiredAt || channel.channel.openedAt > attestation.createdAt || attestation.createdAt > control.committedAt ||
    inspecting.owner.state === 'terminal' && inspecting.owner.releasedAt < control.committedAt) {
    invalid();
  }
  if (channel.channel.transport.kind === 'uds_peer') {
    const peer = decodeLocalSocketPeerObservation(await readCanonicalArtifact(artifacts, channel.channel.transport.peerObservationRef));
    if (peer.observedAt < inspecting.owner.acquiredAt || peer.observedAt > channel.channel.openedAt) {
      invalid();
    }
  } else {
    const process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, channel.channel.transport.processIdentityRef));
    if (process.pid !== inspecting.process.pid || process.processStartToken !== inspecting.process.processStartToken ||
      process.executableImageDigest !== inspecting.owner.supervisorExecutableDigest || process.observedAt < inspecting.owner.acquiredAt) {
      invalid();
    }
  }
  if (attestation.principalId !== original.principalId) {
    invalid();
  }
  return marker;
}
export async function validateMcpStopComposition(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, manual?: Plan,
  retryClosure?: import('./mcp-retry-admission.js').McpRetryTerminalClosure) {
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, cut.runSpec.assemblyRef));
  const noRelease = new Set<number>();
  let closedRetry: TerminalDetail['abandonedRetryInvocations'] = [];
  if (retryClosure) {
    (await import('./mcp-retry-admission.js')).assertMcpRetryTerminalClosure(driver, artifacts, retryClosure, cut);
    closedRetry = retryClosure.abandonedRetryInvocations;
  } else if (['failed', 'cancelled'].includes(cut.run.status) && cut.run.terminalDetailRef) {
    const detail = await readCanonicalArtifact<TerminalDetail>(artifacts, cut.run.terminalDetailRef);
    closedRetry = await (await import('./mcp-retry-admission.js')).validateMcpRetryTerminalHistory(driver, artifacts, cut, detail);
  }
  if (cut.journal.some(row => row.opKind === 'mcp-server')) {
    const items = new Map((await artifacts.mapReads(cut.items, async row =>
      readCanonicalArtifact<import('../kernel/types.js').ContinuationItem>(artifacts, row.payloadRef))).map(item => [item.itemId, item]));
    await validateMcpServerHistory(driver, artifacts, cut.run, cut.runSpec, assembly, items, cut.journal);
    // A generic undispatched Stop refund cannot close a local reservation:
    // even an unclaimed launch owns real pipes, an input and a scope. Only
    // its exact original typed physical retirement may enter terminal Stop.
    for (const prepared of cut.journal.filter(row => row.opKind === 'mcp-server' && row.phase === 'prepared')) {
      const entries = cut.journal.filter(row => row.opId === prepared.opId && row.attempt === prepared.attempt);
      const closed = await readMcpServerClosedAttempt(driver, artifacts, cut.run, cut.runSpec, assembly, prepared, entries);
      noRelease.add(closed.terminal.seq);
    }
  }
  if (!assembly.mcpServers.length && cut.journal.some(row => row.opKind === 'mcp')) {
    invalid('MCP history has no original registered composition');
  }
  for (const server of assembly.mcpServers) {
    const registry = await readMcpRegistryClosure(driver, artifacts, server.registryRevisionRef, readSessionPrincipalId(driver, cut.run.sessionId));
    if (server.manifestDigest !== registry.registry.manifestDigest) {
      invalid();
    }
  }
  for (const row of cut.journal.filter(row => row.opKind === 'mcp')) {
    const final = cut.journal.filter(entry => entry.opId === row.opId && entry.attempt === row.attempt).at(-1)!;
    if (final.phase === 'unknown' && manual?.original.unknown.seq !== final.seq &&
        !closedRetry.some(entry => final.replayClass === 'retry' && entry.opId === final.opId && entry.attempt === final.attempt &&
          entry.unknownJournalSeq === final.seq && entry.budgetSettlementRef === final.budgetSettlementRef) || final.phase === 'dispatch_claimed') {
      invalid();
    }
    if (final.phase === 'failed' && !noRelease.has(final.seq)) {
      const entries = cut.journal.filter(entry => entry.opId === row.opId && entry.attempt === row.attempt), claim = entries.find(entry => entry.phase === 'dispatch_claimed');
      if (claim) {
        await readMcpNoReleaseHistory(driver, artifacts, {
          prepared: entries[0]!,
          claim,
          failed: final,
          assembly
        });
        noRelease.add(final.seq);
      }
    }
  }
  assertMcpRunQuiescence(cut.run.id);
  return noRelease;
}
