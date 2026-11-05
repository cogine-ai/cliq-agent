// The original external UNKNOWN stays UNKNOWN/full once. This owner closes
// only its old local dispatch before a separately permitted new attempt.
import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import { decodeBrokerProcessDomainDeath, type BrokerProcessDomainDeathEvidenceV1 } from '../kernel/broker-process-domain-death.js';
import { decodeMcpRetryDispatchClosure, decodeMcpJoinedDispatchData, mcpRetryState, type McpRetryDispatchClosureV1 } from '../kernel/mcp-retry.js';
import type { InvocationJournalEntry, RunAssemblyV1, Run, RecoveryClosureV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readMcpAmbiguityHistory, readMcpManualDispatchOwner, readMcpOriginalClaim } from './mcp-execution.js';
import { countMcpServerLaunchClaims, decodeMcpServerLaunchRequest, decodeMcpServerLaunchPreparation } from '../kernel/mcp-server-authorization.js';
import { readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { supervisorInspectorIdentity, readSupervisorInspector } from './supervisor-inspector.js';
import { assertInstalledMcpBrokerProcess, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { stateRootIdentityForLock } from './native-owner.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { ToolCut } from './tool-cut.js';

type UnknownHistory = Awaited<ReturnType<typeof readMcpAmbiguityHistory>>;
type OriginalRows = Readonly<{
  prepared: InvocationJournalEntry & { grantRef: string };
  claim: InvocationJournalEntry & { dispatchId: string; supervisorInstanceId: string; stateOwnerEpoch: number; brokerFenceTokenDigest: string;
    evidenceRef: string; evidenceDigest: string };
  unknown: InvocationJournalEntry & { evidenceRef: string; evidenceDigest: string; budgetSettlementRef: string };
}>;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function originalRows(journal: readonly InvocationJournalEntry[], opId: string, attempt: number): OriginalRows {
  const entries = journal.filter(entry => entry.opId === opId && entry.attempt === attempt), [prepared, claim, unknown] = entries;
  if (entries.length !== 3 || prepared?.phase !== 'prepared' || claim?.phase !== 'dispatch_claimed' || unknown?.phase !== 'unknown' ||
      prepared.opKind !== 'mcp' || prepared.replayClass !== 'retry' || !prepared.grantRef || !claim.dispatchId || !claim.supervisorInstanceId ||
      !claim.stateOwnerEpoch || !claim.brokerFenceTokenDigest || !claim.evidenceRef || !claim.evidenceDigest ||
      !unknown.evidenceRef || !unknown.evidenceDigest || !unknown.budgetSettlementRef)
    invalid('MCP retry needs its one exact original wholly settled UNKNOWN');
  return { prepared: { ...prepared, grantRef: prepared.grantRef }, claim: { ...claim, dispatchId: claim.dispatchId,
    supervisorInstanceId: claim.supervisorInstanceId, stateOwnerEpoch: claim.stateOwnerEpoch, brokerFenceTokenDigest: claim.brokerFenceTokenDigest,
    evidenceRef: claim.evidenceRef, evidenceDigest: claim.evidenceDigest },
    unknown: { ...unknown, evidenceRef: unknown.evidenceRef, evidenceDigest: unknown.evidenceDigest, budgetSettlementRef: unknown.budgetSettlementRef } };
}
function originalDeadline(original: UnknownHistory): number {
  const value = original.stdioClosed?.context.preparation.callDeadlineMs ?? original.httpRetryIdentity?.binding.deadlineMs;
  if (!Number.isSafeInteger(value) || value === undefined || value <= 0) invalid('MCP retry lost its original durable actual call deadline');
  return value;
}
function assertOriginalClosure(data: McpRetryDispatchClosureV1, rows: OriginalRows, original: UnknownHistory): void {
  const { prepared, claim, unknown } = rows;
  if (data.runId !== claim.runId || data.opId !== claim.opId || data.attempt !== claim.attempt || data.nextAttempt !== claim.attempt + 1 ||
      data.preparedJournalSeq !== prepared.seq || data.dispatchId !== claim.dispatchId || data.dispatchJournalSeq !== claim.seq ||
      data.unknownJournalSeq !== unknown.seq || data.requestRef !== prepared.requestRef || data.requestDigest !== original.request.requestDigest ||
      data.targetRef !== prepared.target || data.targetDigest !== original.target.targetDigest || data.grantRef !== prepared.grantRef ||
      data.grantDigest !== original.grant.grantDigest || data.registryRef !== original.registry.ref || data.manifestDigest !== original.registry.registry.manifestDigest ||
      data.toolContractDigest !== original.toolContract.toolContractDigest || data.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
      data.unknownEvidenceRef !== unknown.evidenceRef || data.unknownEvidenceDigest !== unknown.evidenceDigest || data.budgetSettlementRef !== unknown.budgetSettlementRef ||
      data.originalClaimIdentity.ref !== claim.evidenceRef || data.originalClaimIdentity.digest !== claim.evidenceDigest ||
      (data.originalClaimIdentity.kind === 'stdio_instance') !== Boolean(original.stdioInstance) ||
      data.claimingSupervisorInstanceId !== claim.supervisorInstanceId || data.claimingStateOwnerEpoch !== claim.stateOwnerEpoch ||
      data.callDeadlineMs > originalDeadline(original) || data.observedAt < unknown.timestamp)
    invalid('MCP retry dispatch closure changes the original UNKNOWN/request/grant/registry/token/deadline');
  if (data.kind === 'original_native_joined' && Boolean(original.stdioInstance) !== (data.joined.kind === 'mcp_stdio_owner_joined'))
    invalid('MCP retry joined receipt substitutes its original transport');
  if (data.kind === 'original_native_joined' && original.stdioClosed && data.joined.kind === 'mcp_stdio_owner_joined') {
    const raw = original.stdioClosed.resources.lifecycle.joined;
    if (data.joined.execReleased !== raw.execReleased || data.joined.effectReleased !== raw.effectReleased || !raw.deathJoined || !raw.outputCustodyRetired || raw.responseRefused)
      invalid('MCP retry joined stdio receipt differs from its complete original raw lifecycle');
  }
}
/** Historical data only, used by full tool recovery and retention. It cannot
 * reconstruct an old FD, fence, owner, or fresh death observation. */
export async function readMcpRetryPreparationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, assembly: RunAssemblyV1,
  next: InvocationJournalEntry, rows: OriginalRows) {
  if (next.opKind !== 'mcp' || next.replayClass !== 'retry' || next.phase !== 'prepared' || next.attempt !== rows.unknown.attempt + 1 ||
      !next.evidenceRef || !next.evidenceDigest || next.requestRef !== rows.prepared.requestRef || next.target !== rows.prepared.target)
    invalid('MCP retry preparation has no exact previous original UNKNOWN dispatch closure');
  return readMcpRetryDispatchClosureHistory(driver, artifacts, assembly, next.evidenceRef, next.evidenceDigest, rows, next.timestamp, true);
}
async function readMcpRetryDispatchClosureHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, assembly: RunAssemblyV1,
  ref: string, digest: string, rows: OriginalRows, committedAt: string, beforeDeadline: boolean) {
  const data = decodeMcpRetryDispatchClosure(await readCanonicalArtifact(artifacts, ref));
  const original = await readMcpAmbiguityHistory(driver, artifacts, { ...rows, assembly });
  assertOriginalClosure(data, rows, original);
  if (data.evidenceDigest !== digest || data.observedAt > committedAt ||
      Date.parse(committedAt) - Date.parse(data.observedAt) > 5_000 || beforeDeadline && Date.parse(committedAt) >= data.callDeadlineMs)
    invalid('MCP retry prepared transaction was outside its true original closure/deadline interval');
  const history = await readRetainedStateOwnerHistory(driver, artifacts, data.inspectorStateOwnerEpoch);
  const inspecting = history.entries.find(entry => entry.owner.ownerEpoch === data.inspectorStateOwnerEpoch);
  if (!inspecting || inspecting.owner.acquiredAt > data.observedAt ||
      inspecting.owner.state === 'terminal' && inspecting.owner.releasedAt < committedAt)
    invalid('MCP retry original inspector is outside its exact owner lifetime');
  await readSupervisorInspector(artifacts, inspecting.owner, { runtime: { runtimeBundleRef: inspecting.owner.runtimeBundleRef,
    runtimeBundleManifestDigest: inspecting.owner.runtimeBundleManifestDigest } }, data);
  if (data.kind === 'original_native_joined') {
    if (data.inspectorStateOwnerEpoch !== rows.claim.stateOwnerEpoch || inspecting.owner.supervisorInstanceId !== rows.claim.supervisorInstanceId)
      invalid('MCP retry same-owner native receipt substitutes its original creator');
  } else {
    const death = decodeBrokerProcessDomainDeath(await readCanonicalArtifact(artifacts, data.deathEvidenceRef));
    assertDeath(death, data, rows, original);
    if (death.evidenceDigest !== data.deathEvidenceDigest || death.observedAt > data.observedAt ||
        Date.parse(committedAt) - Date.parse(death.observedAt) > 5_000) invalid('MCP retry successor death was not fresh at actual preparation');
  }
  return { data, original, history };
}
function assertDeath(death: BrokerProcessDomainDeathEvidenceV1, data: McpRetryDispatchClosureV1, rows: OriginalRows, original: UnknownHistory): void {
  if (death.runId !== data.runId || death.opId !== data.opId || death.attempt !== data.attempt || death.dispatchId !== data.dispatchId ||
      death.dispatchJournalSeq !== data.dispatchJournalSeq || death.operationRequestRef !== rows.prepared.requestRef ||
      death.operationTargetDigest !== original.target.targetDigest || death.operationGrantRef !== rows.prepared.grantRef ||
      death.claimingSupervisorInstanceId !== rows.claim.supervisorInstanceId || death.claimingStateOwnerEpoch !== rows.claim.stateOwnerEpoch ||
      death.claimingProcessIdentityRef !== original.claiming.owner.processIdentityRef || death.claimingProcessIdentityDigest !== original.claiming.owner.processIdentityDigest ||
      death.inspectorIdentityRef !== data.inspectorIdentityRef || death.inspectorIdentityDigest !== data.inspectorIdentityDigest ||
      death.inspectorStateOwnerEpoch !== data.inspectorStateOwnerEpoch || death.brokerFenceTokenDigest !== rows.claim.brokerFenceTokenDigest ||
      death.observedAt < rows.unknown.timestamp) invalid('MCP retry death evidence substitutes the actual original native creator domain');
}

/** Exhaust the original operation history before permitting recovery to treat
 * an older UNKNOWN as locally fenced. No CAS record creates a native handle.
 * The earliest actual bound native deadline survives every later attempt. */
export async function readMcpRetryJournalHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, assembly: RunAssemblyV1,
  journal: readonly InvocationJournalEntry[], opId: string, now: string) {
  const entries = journal.filter(entry => entry.opId === opId), preparations = entries.filter(entry => entry.phase === 'prepared');
  const first = preparations[0];
  if (!first || first.opKind !== 'mcp' || first.replayClass !== 'retry') invalid('MCP retry history has no exact original preparation');
  const request = await readCanonicalArtifact<import('../kernel/tool-authorization.js').ToolRequestV1>(artifacts, first.requestRef);
  const policy = assembly.retry.tools.find(tool => tool.toolName === request.toolName);
  if (!policy || policy.replayClass !== 'retry') invalid('MCP retry history has no exact frozen literal retry policy');
  let deadline: number | undefined;
  let frozenRegistry: Readonly<{ ref: string; registry: import('../kernel/mcp.js').McpRegistryRevisionV1 }> | undefined;
  const closures: Array<Awaited<ReturnType<typeof readMcpRetryPreparationHistory>>> = [];
  for (const prepared of preparations) {
    const current = entries.filter(entry => entry.attempt === prepared.attempt), claim = current.find(entry => entry.phase === 'dispatch_claimed');
    const prior = entries.filter(entry => entry.attempt === prepared.attempt - 1).at(-1);
    if (prior?.phase === 'unknown') {
      const history = await readMcpRetryPreparationHistory(driver, artifacts, assembly, prepared, originalRows(journal, opId, prepared.attempt - 1));
      if (deadline === undefined || history.data.callDeadlineMs > deadline) invalid('MCP retry preparation extends the earliest original native call deadline');
      deadline = Math.min(deadline, history.data.callDeadlineMs); closures.push(history);
    } else if (prepared.evidenceRef || prepared.evidenceDigest) invalid('MCP retry preparation borrows a dispatch closure without its preceding UNKNOWN');
    if (!claim) continue;
    const terminal = current.at(-1);
    const original = terminal?.phase === 'failed'
      ? (await (await import('./mcp-execution.js')).readMcpNoReleaseHistory(driver, artifacts, { prepared, claim, failed: terminal, assembly })).originalClaim
      : await readMcpOriginalClaim(driver, artifacts, { prepared, claim, assembly, throughEpoch: claim.stateOwnerEpoch! });
    frozenRegistry ??= original.registry;
    let actual = original.httpRetryIdentity?.binding.deadlineMs;
    if (original.stdioInstance) {
      const instance = original.stdioInstance, launch = readInvocationAttempt(driver, claim.runId, instance.launchOpId, instance.launchAttempt)[0];
      if (!launch?.evidenceRef || !launch.evidenceDigest) invalid('MCP retry original stdio call has no first resource preparation');
      const preparation = decodeMcpServerLaunchPreparation(await readCanonicalArtifact(artifacts, launch.evidenceRef));
      if (preparation.preparationDigest !== launch.evidenceDigest || preparation.toolRequestRef !== prepared.requestRef ||
          preparation.toolRequestDigest !== original.request.requestDigest) invalid('MCP retry original stdio deadline changes its owning effect request');
      actual = preparation.callDeadlineMs;
    }
    if (actual === undefined || !Number.isSafeInteger(actual) || actual <= 0 || deadline !== undefined && actual > deadline)
      invalid('MCP retry claim lacks or extends its earliest actual native deadline');
    deadline = Math.min(deadline ?? actual, actual);
  }
  // A first unclaimed preparation cannot authorize a retry. The maximum here
  // merely lets the pure planner report that pending data before any native
  // deadline exists; callers require the actual deadline for all dispatches.
  const state = mcpRetryState(policy, entries, now, deadline ?? Number.MAX_SAFE_INTEGER);
  let launchCapacity: Readonly<{ used: number; limit: number; exhausted: boolean }> | undefined;
  if (frozenRegistry?.registry.transport.kind === 'stdio') {
    const requests = new Map<string, ReturnType<typeof decodeMcpServerLaunchRequest>>();
    for (const prepared of journal.filter(entry => entry.opKind === 'mcp-server' && entry.phase === 'prepared'))
      requests.set(prepared.requestRef, decodeMcpServerLaunchRequest(await readCanonicalArtifact(artifacts, prepared.requestRef)));
    const used = countMcpServerLaunchClaims(journal, requests, { runId: request.runId, batchItemId: request.batchItemId,
      callId: request.callId, callIndex: request.callIndex, registryRevisionRef: frozenRegistry.ref,
      registryManifestDigest: frozenRegistry.registry.manifestDigest });
    const limit = frozenRegistry.registry.lifecycle.maxLaunchesPerCall;
    if (used > limit) invalid('MCP retry history already exceeds its original independent server launch capacity');
    launchCapacity = { used, limit, exhausted: used === limit };
  }
  return { entries, preparations, policy, deadline, state, closures, launchCapacity, sampledAt: now };
}
declare const admissionBrand: unique symbol;
export type McpRetryAdmission = Readonly<{ readonly [admissionBrand]: true }>;
type RetryClosureCut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal'>;
type Plan = Readonly<{ driver: SqliteDriver; owner: StateOwnerContext; cut: RetryClosureCut; rows: OriginalRows;
  reference: Readonly<{ ref: string; digest: string }>; data: McpRetryDispatchClosureV1; metadata: readonly PublishedArtifact[];
  reobserve(connection: SqliteConnection): void;
  assertCurrent(connection: SqliteConnection, run: Run, attempt: number, now: string): void;
  retained: ReturnType<typeof readMcpManualDispatchOwner> }>;
const admissions = new WeakMap<McpRetryAdmission, Plan>();
export function mcpRetryAdmissionData(driver: SqliteDriver, owner: StateOwnerContext, admission: McpRetryAdmission): Plan {
  const value = admissions.get(admission);
  if (!value || value.driver !== driver || value.owner !== owner) invalid('foreign MCP retry preparation owner');
  return value;
}
export async function acknowledgeMcpRetryAdmission(driver: SqliteDriver, owner: StateOwnerContext, admission: McpRetryAdmission): Promise<void> {
  const plan = mcpRetryAdmissionData(driver, owner, admission);
  const prepared = readInvocationAttempt(driver, plan.cut.run.id, plan.rows.claim.opId, plan.data.nextAttempt)[0];
  if (!prepared || prepared.phase !== 'prepared' || prepared.evidenceRef !== plan.reference.ref || prepared.evidenceDigest !== plan.reference.digest)
    invalid('MCP retry original local domain cannot leave before its exact committed new preparation');
  await plan.retained?.releaseRetry(plan.reference.ref); admissions.delete(admission);
}
/** The producer already owns the current original prepared call. This read
 * only tightens its native ceiling; it never invents a missing first claim. */
export async function readMcpRetryPreparedDeadline(driver: SqliteDriver, artifacts: ArtifactCatalog,
  prepared: InvocationJournalEntry): Promise<number | undefined> {
  if (prepared.opKind !== 'mcp' || prepared.replayClass !== 'retry') return undefined;
  const run = (await import('./rows.js')).readRun(driver, prepared.runId);
  const spec = await readCanonicalArtifact<import('../kernel/types.js').RunSpec>(artifacts, run.specRef);
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  const journal = readInvocationJournal(driver, run.id);
  requireEqual(journal.find(entry => entry.seq === prepared.seq), prepared, 'MCP retry actual original prepared deadline owner');
  return (await readMcpRetryJournalHistory(driver, artifacts, assembly, journal, prepared.opId, sampleCanonicalNow())).deadline;
}
/** Call only after the old worker/generation has actually retired and the
 * current worker, if any, is freshly restored from the original Checkpoint.
 * This inspection performs no MCP request, model call, or new authority. */
async function prepareOriginalMcpRetryClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  installedRuntime: HeldInstalledRuntime, cutValue: RetryClosureCut, opId: string, attempt: number, mode: 'retry' | 'terminal' | 'proposal',
  signal?: AbortSignal): Promise<Plan> {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  const cut = immutableSnapshot(cutValue), assembly = await readCanonicalArtifact<RunAssemblyV1>(reads, cut.runSpec.assemblyRef);
  const entries = cut.journal.filter(entry => entry.opId === opId), highest = entries.filter(entry => entry.phase === 'prepared').at(-1);
  if (!highest || mode === 'retry' && highest.attempt !== attempt) invalid('MCP retry has no original prepared invocation');
  const rows = originalRows(cut.journal, opId, attempt), original = await readMcpAmbiguityHistory(driver, reads, { ...rows, assembly });
  // readToolCut has already validated the original physical retirement
  // evidence. A matching row alone is not a substitute for that full read.
  const oldWorkers = readWorkerLaunchesForRun(driver, cut.run.id).filter(launch => launch.leaseEpoch === rows.claim.leaseEpoch);
  if (oldWorkers.length !== 1 || oldWorkers[0]!.phase !== 'retired' || !oldWorkers[0]!.retiredAt ||
      !oldWorkers[0]!.retirementEvidenceRef || oldWorkers[0]!.retiredAt < rows.claim.timestamp ||
      oldWorkers[0]!.launchId === cut.run.activeWorkerLaunchId)
    invalid('MCP retry cannot overtake its original claimed worker physical retirement');
  if (original.toolContract.recovery.kind !== 'retry' || mode === 'retry' && (original.request.frontierRef !== cut.run.frontierRef ||
      cut.run.stopIntentRef || cut.run.cancelRequested || !['queued', 'running'].includes(cut.run.status)) ||
      mode !== 'retry' && (mode === 'terminal' && !cut.run.stopIntentRef || cut.run.activeWorkerLaunchId || cut.run.status !== 'queued'))
    invalid('MCP retry lost its sole original productive or worker-free terminal cut');
  const progress = await readMcpRetryJournalHistory(driver, reads, assembly, cut.journal, opId, sampleCanonicalNow());
  if (progress.deadline === undefined) invalid('MCP retry closure lost its original actual native deadline');
  const callDeadlineMs = Math.min(originalDeadline(original), progress.deadline), state = progress.state;
  if (mode === 'retry' && (state.kind !== 'ready' || state.nextAttempt !== highest.attempt + 1 || progress.launchCapacity?.exhausted))
    invalid('MCP retry has no literal capacity/backoff/original-deadline admission');
  assertInstalledMcpBrokerProcess(); const active = assertActiveStateOwner(driver, owner);
  const history = await readRetainedStateOwnerHistory(driver, reads, active.ownerEpoch);
  const inspecting = history.entries.find(entry => entry.owner.ownerEpoch === active.ownerEpoch);
  if (!inspecting) invalid('MCP retry has no original current StateOwner process history');
  const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const metadata: PublishedArtifact[] = [inspectorArtifact], retained = readMcpManualDispatchOwner(rows.claim);
  let death: BrokerProcessDomainDeathEvidenceV1 | undefined;
  let branch: Pick<McpRetryDispatchClosureV1, 'kind'> & Record<string, unknown>;
  if (retained) {
    if (active.ownerEpoch !== rows.claim.stateOwnerEpoch || active.supervisorInstanceId !== rows.claim.supervisorInstanceId)
      invalid('MCP retry cannot adopt an old process native handle');
    retained.assertJoined(); branch = { kind: 'original_native_joined', joined: decodeMcpJoinedDispatchData(retained.joined) };
  } else {
    if (active.ownerEpoch <= original.claiming.owner.ownerEpoch) invalid('MCP retry requires original native custody or a strict successor-domain death');
    await withHeldInstalledRuntime(installedRuntime, async installed => {
      const root = stateRootIdentityForLock(owner.filesystem);
      requireEqual(root, history.rootIdentity, 'MCP retry actual held StateRoot');
      if (canonicalSha256(inspecting.owner) !== canonicalSha256(active) || installed.bundleDigest !== active.runtimeBundleRef ||
          root.canonicalAbsolutePath !== installed.stateRoot.canonicalPath || root.deviceId !== installed.stateRoot.deviceId || root.directoryFileId !== installed.stateRoot.fileId)
        invalid('MCP retry successor is not the actual original held installed image/root');
      await installed.revalidate(signal); const process = await (await installed.loadStateOwner(signal)).observeCurrentProcess();
      if (process.pid !== inspecting.process.pid || process.processStartToken !== inspecting.process.processStartToken || process.executableImageDigest !== active.supervisorExecutableDigest)
        invalid('MCP retry successor process differs from its actual signed StateOwner');
    }, signal);
    const observedAt = new Date(owner.filesystem.observePriorProcessDeath(original.claiming.process.pid, original.claiming.process.processStartToken)).toISOString();
    const core = { schemaVersion: 1 as const, format: 'cliq-broker-process-domain-death-evidence-v1' as const, runId: rows.claim.runId, opId,
      attempt: rows.claim.attempt, dispatchId: rows.claim.dispatchId, dispatchJournalSeq: rows.claim.seq, operationRequestRef: rows.prepared.requestRef,
      operationTargetDigest: original.target.targetDigest, operationGrantRef: rows.prepared.grantRef,
      claimingSupervisorInstanceId: rows.claim.supervisorInstanceId, claimingStateOwnerEpoch: rows.claim.stateOwnerEpoch,
      claimingProcessIdentityRef: original.claiming.owner.processIdentityRef, claimingProcessIdentityDigest: original.claiming.owner.processIdentityDigest,
      inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, inspectorStateOwnerEpoch: active.ownerEpoch,
      brokerFenceTokenDigest: rows.claim.brokerFenceTokenDigest, authorityDomain: 'linux_installed_native_creator_process_v1' as const,
      processObservation: 'absent_or_start_token_mismatch' as const, observedAt };
    death = decodeBrokerProcessDomainDeath({ ...core, evidenceDigest: canonicalSha256(core) });
    const artifact = await artifacts.publishCanonical(death, death.format); metadata.push(artifact);
    branch = { kind: 'broker_process_domain_dead', deathEvidenceRef: artifact.ref, deathEvidenceDigest: death.evidenceDigest };
  }
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-retry-dispatch-closure-v1' as const, runId: rows.claim.runId, opId,
    attempt: rows.claim.attempt, nextAttempt: rows.claim.attempt + 1, preparedJournalSeq: rows.prepared.seq, dispatchId: rows.claim.dispatchId,
    dispatchJournalSeq: rows.claim.seq, unknownJournalSeq: rows.unknown.seq, requestRef: rows.prepared.requestRef, requestDigest: original.request.requestDigest,
    targetRef: rows.prepared.target, targetDigest: original.target.targetDigest, grantRef: rows.prepared.grantRef, grantDigest: original.grant.grantDigest,
    registryRef: original.registry.ref, manifestDigest: original.registry.registry.manifestDigest, toolContractDigest: original.toolContract.toolContractDigest,
    brokerFenceTokenDigest: rows.claim.brokerFenceTokenDigest, unknownEvidenceRef: rows.unknown.evidenceRef, unknownEvidenceDigest: rows.unknown.evidenceDigest,
    budgetSettlementRef: rows.unknown.budgetSettlementRef, claimingSupervisorInstanceId: rows.claim.supervisorInstanceId,
    originalClaimIdentity: { kind: original.stdioInstance ? 'stdio_instance' : 'http_retry_binding', ref: rows.claim.evidenceRef, digest: rows.claim.evidenceDigest },
    claimingStateOwnerEpoch: rows.claim.stateOwnerEpoch, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    inspectorStateOwnerEpoch: active.ownerEpoch, callDeadlineMs, observedAt: sampleCanonicalNow(), ...branch };
  const data = decodeMcpRetryDispatchClosure({ ...core, evidenceDigest: canonicalSha256(core) }); assertOriginalClosure(data, rows, original);
  const artifact = await artifacts.publishCanonical(data, data.format); metadata.push(artifact);
  reads.assertReadActive();
  let freshDeath: number | undefined;
  return { driver, owner, cut, rows, reference: { ref: artifact.ref, digest: data.evidenceDigest }, data, metadata, retained,
    reobserve(connection) {
      assertActiveStateOwner(connection, owner); history.assertUnchanged(connection);
      if (retained) retained.assertJoined();
      else freshDeath = owner.filesystem.observePriorProcessDeath(original.claiming.process.pid, original.claiming.process.processStartToken);
    },
    assertCurrent(connection, run, attempt, now) {
      const current = assertActiveStateOwner(connection, owner); history.assertUnchanged(connection);
      requireEqual(run, cut.run, 'MCP retry exact whole original Run cut');
      requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP retry exact whole original Journal');
      requireEqual(readWorkerLaunchesForRun(connection, run.id).filter(launch => launch.leaseEpoch === rows.claim.leaseEpoch), oldWorkers,
        'MCP retry original physically retired worker');
      requireEqual(readInvocationAttempt(connection, run.id, opId, rows.claim.attempt), [rows.prepared, rows.claim, rows.unknown], 'MCP retry original wholly settled UNKNOWN');
      if (current.ownerEpoch !== active.ownerEpoch || current.supervisorInstanceId !== active.supervisorInstanceId || attempt !== data.nextAttempt ||
          now < data.observedAt || Date.parse(now) - Date.parse(data.observedAt) > 5_000 ||
          mode === 'retry' && (Date.parse(now) >= data.callDeadlineMs || run.stopIntentRef || run.cancelRequested))
        invalid('MCP retry physical closure/current original owner/deadline changed at preparation');
      if (retained) retained.assertJoined();
      else {
        if (!death || now < death.observedAt || Date.parse(now) - Date.parse(death.observedAt) > 5_000) invalid('MCP retry lacks its actual fresh successor death');
        if (freshDeath === undefined || freshDeath < Date.parse(death.observedAt) || freshDeath > parseCanonicalTime(now))
          invalid('MCP retry original creator-domain death is no longer fresh');
      }
    } };
}

export async function prepareMcpRetryAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  installedRuntime: HeldInstalledRuntime, cut: ToolCut, opId: string, signal?: AbortSignal): Promise<McpRetryAdmission> {
  const highest = cut.journal.filter(entry => entry.opId === opId && entry.phase === 'prepared').at(-1);
  if (!highest) invalid('MCP retry lost its actual highest prepared invocation');
  const plan = await prepareOriginalMcpRetryClosure(driver, artifacts, owner, installedRuntime, cut, opId, highest.attempt, 'retry', signal);
  const request = await readCanonicalArtifact<import('../kernel/tool-authorization.js').ToolRequestV1>(signal ? artifacts.withReadSignal(signal) : artifacts, plan.rows.prepared.requestRef);
  if (plan.rows.prepared.runId !== cut.run.id || plan.data.requestRef !== canonicalSha256(request) ||
      request.batchItemId !== cut.batch.itemId || request.callId !== cut.call.callId || request.callIndex !== cut.frontier.nextCallIndex)
    invalid('MCP retry changed its actual current ordered call');
  const admission = Object.freeze({}) as McpRetryAdmission; admissions.set(admission, plan); return admission;
}

type Abandonments = import('../kernel/types.js').TerminalDetail['abandonedRetryInvocations'];
function unusedMcpRetryUnknowns(journal: readonly InvocationJournalEntry[]) {
  const latest = new Map<string, InvocationJournalEntry>();
  for (const entry of journal) latest.set(`${entry.opId}\0${entry.attempt}`, entry);
  return [...latest.values()].filter(entry => entry.opKind === 'mcp' && entry.replayClass === 'retry' && entry.phase === 'unknown')
    .sort((a, b) => a.seq - b.seq);
}
export type McpRetryTerminalClosure = Readonly<{
  metadata: readonly PublishedArtifact[]; abandonedRetryInvocations: Abandonments;
  reobserve(connection: SqliteConnection): void;
  validate(connection: SqliteConnection, run: Run, committedAt: string): void;
  acknowledge(): Promise<void>;
}>;
const terminalClosures = new WeakMap<McpRetryTerminalClosure, Readonly<{ driver: SqliteDriver; artifacts: ArtifactCatalog; cut: RecoveryClosureV1 }>>();
export function assertMcpRetryTerminalClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, value: McpRetryTerminalClosure, cut: RecoveryClosureV1): void {
  const original = terminalClosures.get(value);
  if (!original || original.driver !== driver || original.artifacts !== artifacts) invalid('foreign MCP retry terminal closure');
  requireEqual(original.cut, cut, 'MCP retry terminal complete original recovery cut');
}
/** Same original Journal lifecycle. An earlier retry preparation may already
 * prove its irreversible closure; a still-last UNKNOWN requires a fresh
 * original native join or strictly newer creator-process-domain death. */
export async function prepareMcpRetryTerminalClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  installedRuntime: HeldInstalledRuntime | undefined, cutValue: RecoveryClosureV1, proposal = false, signal?: AbortSignal): Promise<McpRetryTerminalClosure> {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts; reads.assertReadActive();
  const cut = immutableSnapshot(cutValue), unknowns = unusedMcpRetryUnknowns(cut.journal), plans: Plan[] = [];
  const metadata: PublishedArtifact[] = [], abandonedRetryInvocations: Abandonments = [];
  if (unknowns.length && (!installedRuntime || cut.run.activeWorkerLaunchId || cut.run.status !== 'queued'))
    invalid('MCP terminal ambiguity needs its actual installed worker-free original closure');
  const active = assertActiveStateOwner(driver, owner);
  const assembly = unknowns.length ? await readCanonicalArtifact<RunAssemblyV1>(reads, cut.runSpec.assemblyRef) : undefined;
  for (const unknown of unknowns) {
    const rows = originalRows(cut.journal, unknown.opId, unknown.attempt);
    const next = cut.journal.find(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt + 1 && entry.phase === 'prepared');
    let reference: string;
    if (next) {
      await readMcpRetryPreparationHistory(driver, reads, assembly!, next, rows);
      reference = next.evidenceRef!;
    } else {
      const plan = await prepareOriginalMcpRetryClosure(driver, artifacts, owner, installedRuntime!, cut, unknown.opId, unknown.attempt,
        proposal ? 'proposal' : 'terminal', signal);
      plans.push(plan); metadata.push(...plan.metadata); reference = plan.reference.ref;
    }
    abandonedRetryInvocations.push({ opId: unknown.opId, attempt: unknown.attempt, unknownJournalSeq: unknown.seq,
      budgetSettlementRef: rows.unknown.budgetSettlementRef, dispatchFenceOrDeathEvidenceRef: reference });
  }
  const result: McpRetryTerminalClosure = Object.freeze({ metadata, abandonedRetryInvocations,
    reobserve(connection) {
      requireEqual(assertActiveStateOwner(connection, owner), active, 'MCP terminal exact original owner');
      for (const plan of plans) plan.reobserve(connection);
    },
    validate(connection, run, committedAt) {
      requireEqual(assertActiveStateOwner(connection, owner), active, 'MCP terminal exact original owner');
      requireEqual(run, cut.run, 'MCP terminal complete original Run cut');
      requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP terminal complete original Journal cut');
      for (const plan of plans) plan.assertCurrent(connection, run, plan.data.nextAttempt, committedAt);
    },
    async acknowledge() {
      if (!unknowns.length) return;
      const run = (await import('./rows.js')).readRun(driver, cut.run.id);
      if (!['failed', 'cancelled'].includes(run.status) || !run.terminalDetailRef) invalid('MCP retry local domain cannot leave before its actual terminal transaction');
      const detail = await readCanonicalArtifact<import('../kernel/types.js').TerminalDetail>(artifacts, run.terminalDetailRef);
      for (const entry of abandonedRetryInvocations) if (detail.abandonedRetryInvocations.filter(actual => canonicalSha256(actual) === canonicalSha256(entry)).length !== 1)
        invalid('MCP retry local domain has no identical actual terminal dispatch closure');
      const failures: unknown[] = [];
      for (const unknown of unknowns) {
        const rows = originalRows(cut.journal, unknown.opId, unknown.attempt), retained = readMcpManualDispatchOwner(rows.claim);
        if (!retained) continue; // No old FD/native handle is reconstructed.
        try { await retained.releaseRetry(abandonedRetryInvocations.find(entry => entry.unknownJournalSeq === unknown.seq)!.dispatchFenceOrDeathEvidenceRef); }
        catch (error) { failures.push(error); }
      }
      if (failures.length) throw new ResourceRetirementError('MCP retry original closed domains did not complete their exact terminal acknowledgement', new AggregateError(failures));
    } });
  terminalClosures.set(result, { driver, artifacts, cut }); return result;
}

/** Historical data only. It never adopts the original handle or supplies a
 * current release/death observation. */
export async function validateMcpRetryTerminalHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  detail: import('../kernel/types.js').TerminalDetail): Promise<Abandonments> {
  const unknowns = unusedMcpRetryUnknowns(cut.journal);
  const selected = detail.abandonedRetryInvocations.filter(entry => unknowns.some(unknown => unknown.seq === entry.unknownJournalSeq));
  if (selected.length !== unknowns.length) invalid('MCP terminal history lost an exact unused original retry UNKNOWN');
  if (!unknowns.length) return [];
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, cut.runSpec.assemblyRef);
  for (const unknown of unknowns) {
    const matches = selected.filter(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt &&
      entry.unknownJournalSeq === unknown.seq && entry.budgetSettlementRef === unknown.budgetSettlementRef), match = matches[0];
    if (matches.length !== 1 || !match) invalid('MCP terminal history substitutes its original once-settled UNKNOWN');
    const rows = originalRows(cut.journal, unknown.opId, unknown.attempt);
    const next = cut.journal.find(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt + 1 && entry.phase === 'prepared');
    if (next) {
      if (match.dispatchFenceOrDeathEvidenceRef !== next.evidenceRef) invalid('MCP terminal history replaces the already original prepared closure');
      await readMcpRetryPreparationHistory(driver, artifacts, assembly, next, rows);
    } else {
      const data = decodeMcpRetryDispatchClosure(await readCanonicalArtifact(artifacts, match.dispatchFenceOrDeathEvidenceRef));
      await readMcpRetryDispatchClosureHistory(driver, artifacts, assembly, match.dispatchFenceOrDeathEvidenceRef,
        data.evidenceDigest, rows, detail.createdAt, false);
    }
  }
  return selected;
}
