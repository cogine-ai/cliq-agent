// One original instance and its actual native local retirement. This owner is
// the sole friend of the ordinary effect's atomic terminal writer; CAS data
// cannot recreate it and local death never supplies an effect outcome.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { sha256Bytes, identityHash } from '../kernel/identity.js';
import { decodeMcpServerInstanceIdentity, type McpServerInstanceIdentityV1 } from '../kernel/mcp-stdio.js';
import { decodeMcpRetryDispatchClosure } from '../kernel/mcp-retry.js';
import type { McpRegistryRevisionV1 } from '../kernel/mcp.js';
import { decodeMcpServerLaunchFailure, decodeMcpServerFailedStoppedItem } from '../kernel/mcp-server-authorization.js';
import type { InvocationJournalEntry, BudgetSettlementV1, ProcessContainment, ProcessContainmentPlanV1, ProcessContainmentDeathEvidenceV1, SandboxLaunchSpecV1 } from '../kernel/types.js';
import type { PublishedArtifact, ArtifactCatalog } from './artifacts.js';
import { insertArtifactMetadata } from './artifacts.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { mcpServerTerminalData, isMcpLocalStopAdvance } from './mcp-server-terminal-data.js';
import { addBudget, subtractBudget } from './invariants.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeAgentStop } from '../runtime/stop.js';
import { readToolCut } from './tool-cut.js';
import type { ResolveToolInput } from '../model/attempt.js';
import { readInvocationJournal } from './repositories/journal.js';
import type { NativeMcpStdioRunOwner, RunMcpStdioLaunchBinding } from './mcp-stdio-broker-native.js';
import { assertInstalledMcpStdioRunOwner, assertInstalledMcpStdioRunJoined } from './mcp-stdio-native-binding.js';
import type { HeldRunMcpStdioInput } from './native-owner.js';
import { readInstalledMcpStdioRunReady, readInstalledMcpStdioRunJoined, type InstalledMcpStdioRunScope } from '../sandbox/mcp-stdio-native.js';
import { readMcpStdioRunSetup, readMcpStdioRunCustody, recordMcpStdioRunJoined, acknowledgeMcpStdioRun, closeMcpStdioManualTerminalFence,
  closeMcpStdioReconcileWaitFence } from './mcp-stdio-execution.js';
import { appendInvocationJournalEntry, nextJournalSequence, readInvocationAttempt } from './repositories/journal.js';
import { readRun } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { requireHealthyFence, appendRunStateEvent } from './reducers/invocation.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { retainMcpSettlementPreparation, retainMcpTerminalAcknowledgement } from './mcp-settlement-preparation.js';

type Domain = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; native: NativeMcpStdioRunOwner;
  scope: InstalledMcpStdioRunScope; input: HeldRunMcpStdioInput; launch: RunMcpStdioLaunchBinding;
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; instance: McpServerInstanceIdentityV1; instanceRef: string;
  containment: ProcessContainment; containmentRef: string; plan: ProcessContainmentPlanV1; spec: SandboxLaunchSpecV1;
  identityPlans: readonly PlannedArtifact[]; published: boolean;
  acknowledgePhysical(): void;
  retirement?: Promise<Retirement>; retired?: Retirement;
  terminal?: Readonly<{ terminalRef: string; settlementRef: string; stoppedItemId: string; disposition: 'completed' | 'owning_call_unknown' | 'owning_call_not_dispatched' }> };
type Retirement = { joined: ReturnType<typeof readInstalledMcpStdioRunJoined>; death: ProcessContainmentDeathEvidenceV1;
  deathRef: string; nativeClosure: Readonly<{ kind: 'linux_original_join'; lifecycleRawRef: string; lifecycleProjectionRef: string }>;
  metadata: PublishedArtifact[] };
const instances = new Map<string, Domain>();
const BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
async function publishIdentity(domain: Domain) {
  const metadata: PublishedArtifact[] = [];
  // The fixed two objects are joined before publication can reject. A failed
  // write never leaves an unobserved sibling producer behind the Stop path.
  for (const plan of domain.identityPlans) metadata.push(await domain.artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
  return metadata;
}
export function beginMcpServerUndispatchedClosure(driver: SqliteDriver, owner: StateOwnerContext, instanceRef: string,
  toolPrepared: InvocationJournalEntry, resolveToolInput: ResolveToolInput) {
  const domain = instances.get(instanceRef);
  if (!domain || domain.driver !== driver || domain.owner !== owner || domain.launch.toolRequestRef !== toolPrepared.requestRef ||
      domain.launch.leaseEpoch !== toolPrepared.leaseEpoch || domain.prepared.seq <= toolPrepared.seq)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP undispatched local closure has no original initialized native domain');
  let prepared = retainMcpSettlementPreparation(prepare), committed = false, acknowledged = false;
  async function prepare() {
    const actual = await retirement(domain!), custody = readMcpStdioRunCustody(domain!.native, domain!.launch);
    if (!custody.setupComplete || custody.resultReceived || !custody.joined || custody.joined.effectReleased)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP initialized local closure cannot replace any original released effect or result');
    if (domain!.instance.initializedAt > actual.death.observedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP initialized identity is outside its actual original process lifetime');
    const identityMetadata = await publishIdentity(domain!);
    const selected = await readToolCut(driver, domain!.artifacts, domain!.launch.runId, resolveToolInput);
    requireEqual(readInvocationAttempt(driver, selected.run.id, toolPrepared.opId, toolPrepared.attempt), [toolPrepared], 'MCP exact original never-claimed effect preparation');
    if (selected.journal.some(entry => entry.opId === toolPrepared.opId && entry.attempt === toolPrepared.attempt && entry.phase === 'dispatch_claimed') ||
        selected.batch.itemId !== domain!.instance.batchItemId || selected.call.callId !== domain!.instance.callId || selected.frontier.nextCallIndex !== domain!.instance.callIndex)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP initialized local closure lost the whole original never-claimed owning call');
    const now = sampleCanonicalNow();
    let reason: 'cancel' | 'deadline', cause: Readonly<{ kind: 'stop_intent'; stopIntentRef: string }> | Readonly<{ kind: 'original_call_deadline'; deadlineMs: number }>;
    if (selected.run.stopIntentRef) {
      const stop = decodeAgentStop(await readCanonicalArtifact(domain!.artifacts, selected.run.stopIntentRef), selected.run);
      if (stop.createdAt > now) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP undispatched Stop is outside its actual original clock');
      reason = stop.origin === 'deadline' ? 'deadline' : 'cancel'; cause = { kind: 'stop_intent', stopIntentRef: selected.run.stopIntentRef };
    } else {
      if (Date.parse(now) < domain!.launch.callDeadlineMs) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original initialized local closure requires actual Stop or its immutable call expiry');
      reason = 'deadline'; cause = { kind: 'original_call_deadline', deadlineMs: domain!.launch.callDeadlineMs };
    }
    const terminalSeq = nextJournalSequence(driver, selected.run.id), stoppedItemId = identityHash('cliq-mcp-server-stopped-item-v1', selected.run.id,
      domain!.prepared.opId, domain!.prepared.attempt, domain!.claim.dispatchId);
    const core = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-failure-v1' as const, runId: selected.run.id,
      launchOpId: domain!.prepared.opId, attempt: domain!.prepared.attempt, preparedJournalSeq: domain!.prepared.seq, claimedJournalSeq: domain!.claim.seq,
      targetRef: domain!.prepared.target, requestRef: domain!.prepared.requestRef, grantRef: domain!.prepared.grantRef!, dispatchId: domain!.claim.dispatchId!,
      sandboxLaunchSpecRef: domain!.launch.sandboxLaunchSpecRef, nativeClosure: actual.nativeClosure, stoppedAt: actual.death.observedAt,
      instance: 'initialized' as const, instanceIdentityRef: instanceRef, instanceIdentityDigest: domain!.instance.identityDigest,
      closure: 'containment_dead' as const, processContainmentRef: domain!.containmentRef, containmentDeathEvidenceRef: actual.deathRef,
      disposition: 'owning_call_not_dispatched' as const, reason, owningCallClosureCause: cause, stoppedItemId };
    const failure = decodeMcpServerLaunchFailure({ ...core, failureDigest: canonicalSha256(core) });
    const failureArtifact = await domain!.artifacts.publishCanonical(failure, failure.format);
    const budgetCore = { schemaVersion: 1 as const, format: 'cliq-budget-settlement-v1' as const, runId: selected.run.id,
      opId: domain!.prepared.opId, attempt: domain!.prepared.attempt, preparedJournalSeq: domain!.prepared.seq, terminalJournalSeq: terminalSeq,
      terminalPhase: 'failed' as const, reserved: domain!.prepared.budgetDelta, consumed: BUDGET, released: domain!.prepared.budgetDelta,
      budgetConsumedBefore: selected.run.budgetConsumed, budgetConsumedAfter: addBudget(selected.run.budgetConsumed, BUDGET, 'MCP initialized undispatched local launch charge'),
      budgetReservedBefore: selected.run.budgetReserved, budgetReservedAfter: subtractBudget(selected.run.budgetReserved, domain!.prepared.budgetDelta, 'MCP initialized undispatched launch reservation'), settledAt: now };
    const settlement: BudgetSettlementV1 = { ...budgetCore, settlementDigest: canonicalSha256(budgetCore) }, settlementArtifact = await domain!.artifacts.publishCanonical(settlement, settlement.format);
    const stopped = decodeMcpServerFailedStoppedItem({ schemaVersion: 1, kind: 'mcp_server_stopped', disposition: 'owning_call_not_dispatched', itemId: stoppedItemId,
      runId: selected.run.id, batchItemId: domain!.instance.batchItemId, callId: domain!.instance.callId, callIndex: domain!.instance.callIndex,
      serverManifestRef: domain!.instance.registryRevisionRef, lifecycleSeq: domain!.instance.lifecycleSeq, launchOpId: domain!.prepared.opId,
      instanceIdentityRef: instanceRef, instanceIdentityDigest: domain!.instance.identityDigest, launchFailureRef: failureArtifact.ref,
      launchFailureDigest: failure.failureDigest, cause: reason, containmentEvidenceRef: actual.deathRef, createdAt: actual.death.observedAt });
    const graph = await planContinuationCommit(domain!.artifacts, { context: selected.context, existingItems: selected.items, items: [stopped], frontier: selected.frontier,
      checkpointId: identityHash('cliq-mcp-stdio-undispatched-checkpoint-v1', selected.run.id, domain!.prepared.opId, domain!.prepared.attempt),
      workspaceStateRef: selected.checkpoint.workspaceStateRef }).publish();
    return { selected, actual, identityMetadata, cause, failureArtifact, settlement, settlementArtifact, terminalSeq, stoppedItemId, graph };
  }
  return Object.freeze({ async finish() {
    const plan = await prepared(); let clock: ReturnType<typeof advanceTimeFence> | undefined;
    if (!committed) try { driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); domain!.scope.assertJoined(plan.actual.joined.joined);
      assertInstalledMcpStdioRunJoined(domain!.native, plan.actual.joined.ownerJoined, domain!.launch);
      requireEqual(readInvocationJournal(connection, domain!.launch.runId), plan.selected.journal, 'MCP initialized undispatched original whole Journal');
      requireEqual(readInvocationAttempt(connection, domain!.launch.runId, toolPrepared.opId, toolPrepared.attempt), [toolPrepared], 'MCP original effect still never claimed');
      const run = readRun(connection, domain!.launch.runId), now = sampleCanonicalNow(); clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
      requireEqual(run, plan.selected.run, 'MCP initialized undispatched original Run/Stop cut');
      if (nextJournalSequence(connection, run.id) !== plan.terminalSeq || now < plan.settlement.settledAt || plan.settlement.settledAt < plan.actual.death.observedAt ||
          plan.selected.journal.some(entry => entry.opId === toolPrepared.opId && entry.attempt === toolPrepared.attempt && entry.phase === 'dispatch_claimed') ||
          (plan.cause.kind === 'stop_intent' ? run.stopIntentRef !== plan.cause.stopIntentRef : Date.parse(now) < domain!.launch.callDeadlineMs))
        throw new KernelStorageError('LEASE_FENCED', 'MCP initialized undispatched local closure lost its exact Stop/expiry or whole-call no-claim cut');
      for (const artifact of [...plan.actual.metadata, ...plan.identityMetadata, plan.failureArtifact, plan.settlementArtifact, ...plan.graph.metadata]) insertArtifactMetadata(connection, artifact, now);
      appendInvocationJournalEntry(connection, { ...domain!.claim, seq: plan.terminalSeq, phase: 'failed', budgetDelta: BUDGET,
        errorRef: plan.failureArtifact.ref, budgetSettlementRef: plan.settlementArtifact.ref, timestamp: plan.settlement.settledAt });
      const changed = connection.prepare('UPDATE runs SET budget_consumed_json=?,budget_reserved_json=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?')
        .run(JSON.stringify(plan.settlement.budgetConsumedAfter), JSON.stringify(plan.settlement.budgetReservedAfter), now, run.id, BigInt(run.revision));
      if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'MCP initialized undispatched local settlement lost its original budget CAS');
      plan.graph.commit(connection, run, plan.terminalSeq, now);
      appendRunStateEvent(connection, readRun(connection, run.id), now);
    }); requireHealthyFence(clock);
      committed = true;
      domain!.terminal = { terminalRef: plan.failureArtifact.ref, settlementRef: plan.settlementArtifact.ref, stoppedItemId: plan.stoppedItemId,
        disposition: 'owning_call_not_dispatched' };
    } catch (error) {
      // Only a genuine newer Stop over the same entire untouched Journal can
      // invalidate uncommitted staging. It cannot adopt a committed terminal,
      // changed budgets, another call or any effect claim. The next explicit
      // finish reuses the original native join and prepares this actual Stop.
      const journal = readInvocationJournal(driver, domain!.launch.runId), current = readRun(driver, domain!.launch.runId);
      if (isMcpLocalStopAdvance(plan.selected.run, current) && canonicalSha256(journal) === canonicalSha256(plan.selected.journal) &&
          !journal.some(entry => entry.opId === toolPrepared.opId && entry.attempt === toolPrepared.attempt && entry.phase === 'dispatch_claimed'))
        prepared = retainMcpSettlementPreparation(prepare);
      throw error;
    }
    if (!acknowledged) { acknowledgeMcpServerTerminal(driver, owner, instanceRef); acknowledged = true; }
    return readRun(driver, domain!.launch.runId);
  } });
}
type InstanceInput = Readonly<{
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; native: NativeMcpStdioRunOwner;
  scope: InstalledMcpStdioRunScope; input: HeldRunMcpStdioInput; binding: RunMcpStdioLaunchBinding;
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; assertLaunchRelease(): void;
  plan: ProcessContainmentPlanV1; spec: SandboxLaunchSpecV1; registry: McpRegistryRevisionV1;
}>;
/** Retains the original completed negotiation synchronously, before storage.
 * This identity has no effect-admission authority until its original live
 * publication transaction succeeds. A failed publication can subsequently be
 * closed only with the same original physical owner and actual join. */
export function retainMcpServerInitializedInstance(input: InstanceInput) {
  const { driver, artifacts, owner, native, scope, binding, prepared, claim } = input;
  assertInstalledMcpStdioRunOwner(native, binding);
  const setup = readMcpStdioRunSetup(native, binding), ready = readInstalledMcpStdioRunReady(scope, input.input);
  const { plan, spec, registry } = input;
  if (plan.backend.kind !== 'linux' || plan.owner.kind !== 'run_invocation' || plan.planDigest !== binding.plannedContainmentDigest ||
      spec.launchSpecDigest !== binding.sandboxLaunchSpecDigest || plan.owner.opId !== prepared.opId || plan.owner.attempt !== prepared.attempt ||
      plan.owner.dispatchId !== claim.dispatchId || ready.cgroupPopulated !== 1 || ready.namespaceInitDeadAndReaped !== 0 ||
      canonicalSha256(plan) !== binding.plannedContainmentRef || canonicalSha256(spec) !== binding.sandboxLaunchSpecRef ||
      canonicalSha256(registry) !== binding.registryRef || registry.transport.kind !== 'stdio' || registry.manifestDigest !== binding.manifestDigest ||
      setup.initializedAt < claim.timestamp || ready.observedAtMs < Date.parse(claim.timestamp) || ready.observedAtMs > Date.parse(setup.initializedAt))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original initialized instance has no exact same-scope native READY/plan/spec');
  const containment: ProcessContainment = { schemaVersion: 1, planRef: binding.plannedContainmentRef, sandboxLaunchSpecRef: binding.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: binding.sandboxLaunchSpecDigest, owner: plan.owner, filesystemBinding: plan.filesystemBinding, launchNonceDigest: plan.launchNonceDigest,
    backend: { kind: 'linux', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId, pidNamespaceId: ready.pidNamespaceId,
      cgroupPath: plan.backend.cgroupPath, cgroupId: ready.cgroupId, namespaceInitStartToken: ready.namespaceInitStartToken,
      subreaperStartToken: plan.backend.subreaperStartToken }, createdAt: new Date(ready.observedAtMs).toISOString() };
  const containmentArtifact = planCanonicalArtifact(containment, 'cliq-process-containment-v1'), initializedAt = setup.initializedAt;
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-server-instance-identity-v1' as const, runId: binding.runId,
    batchItemId: binding.batchItemId, callId: binding.callId, callIndex: binding.callIndex, registrationId: registry.registrationId,
    registryRevisionRef: binding.registryRef, registryManifestDigest: binding.manifestDigest, lifecycleSeq: binding.lifecycleSeq,
    launchOpId: binding.launchOpId, launchAttempt: binding.attempt, launchDispatchId: binding.dispatchId, sandboxLaunchSpecRef: binding.sandboxLaunchSpecRef,
    processContainmentRef: containmentArtifact.ref, initializeDigest: setup.initializeDigest, capabilityDigest: setup.capabilityDigest,
    probedToolsListDigest: setup.probedToolsListDigest, instanceNonceDigest: sha256Bytes(Buffer.from(binding.nonce)), initializedAt };
  const instance = decodeMcpServerInstanceIdentity({ ...core, identityDigest: canonicalSha256(core) });
  const artifact = planCanonicalArtifact(instance, instance.format), prior = instances.get(artifact.ref);
  if (prior) {
    if (prior.driver !== driver || prior.owner !== owner || prior.native !== native || prior.scope !== scope || prior.input !== input.input)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original instance already has a different retained physical owner');
    requireEqual(prior.launch, binding, 'MCP retained original initialized launch');
    requireEqual(prior.instance, instance, 'MCP retained original initialized negotiation');
  } else {
    const domain: Domain = { driver, artifacts, owner, native, scope, input: input.input, launch: immutableSnapshot(binding), prepared, claim,
      instance, instanceRef: artifact.ref, containment, containmentRef: containmentArtifact.ref, plan, spec,
      identityPlans: [containmentArtifact, artifact], published: false,
      acknowledgePhysical: retainMcpTerminalAcknowledgement(() => acknowledgeMcpStdioRun(native), () => input.input.close()) };
    instances.set(artifact.ref, domain);
  }
  return Object.freeze({ ref: artifact.ref, instance, containmentRef: containmentArtifact.ref });
}
export async function publishMcpServerInstance(input: InstanceInput) {
  const identity = retainMcpServerInitializedInstance(input), domain = instances.get(identity.ref)!;
  const { driver, owner, native, scope, binding, prepared, claim } = input;
  const metadata = await publishIdentity(domain);
  input.assertLaunchRelease();
  let clock: ReturnType<typeof advanceTimeFence> | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner); input.input.assertHeld(); const now = sampleCanonicalNow(); clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
    requireEqual(readInvocationAttempt(connection, binding.runId, binding.launchOpId, binding.attempt), [prepared, claim], 'MCP initialized exact original server claim');
    assertInstalledMcpStdioRunOwner(native, binding); readInstalledMcpStdioRunReady(scope, input.input);
    if (now < identity.instance.initializedAt || Date.parse(now) >= binding.launchDeadlineMs)
      throw new KernelStorageError('LEASE_FENCED', 'MCP initialized instance extends its original launch lease/deadline');
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, identity.instance.initializedAt);
  }); requireHealthyFence(clock);
  domain.published = true; return identity;
}
export function assertOwnedMcpServerInstance(driver: SqliteDriver, owner: StateOwnerContext, native: NativeMcpStdioRunOwner,
  reference: string, digest: string, launch: RunMcpStdioLaunchBinding) {
  const domain = instances.get(reference);
  if (!domain || !domain.published || domain.driver !== driver || domain.owner !== owner || domain.native !== native || domain.instance.identityDigest !== digest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP effect has no original native owned initialized instance');
  requireEqual(domain.launch, launch, 'MCP effect original initialized native launch'); assertInstalledMcpStdioRunOwner(native, launch);
  readInstalledMcpStdioRunReady(domain.scope, domain.input);
}
async function retirement(domain: Domain): Promise<Retirement> {
  if (domain.retired) return domain.retired;
  if (domain.retirement) return domain.retirement;
  const task = (async () => {
    const { artifacts, scope, native, launch } = domain, joined = readInstalledMcpStdioRunJoined(scope, domain.input);
    assertInstalledMcpStdioRunJoined(native, joined.ownerJoined, launch); scope.assertJoined(joined.joined); recordMcpStdioRunJoined(native, joined.ownerJoined, launch);
    const physical = joined.joined.observation, original = joined.originalLifecycle;
    if (!original.retirement || !original.containment || !original.joined.deathJoined || !original.joined.outputCustodyRetired ||
        original.joined.responseRefused || !original.joined.ownerDrained ||
        physical.cgroupPopulated !== 0 || physical.namespaceInitDeadAndReaped !== 1 || physical.remainingTrackedDescendants !== 0)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP server local retirement has no actual complete descendant/pipe/FD join');
    requireEqual(physical, original.retirement, 'MCP server current original scope and immutable final retirement');
    const inspector = supervisorInspectorIdentity(assertActiveStateOwner(domain.driver, domain.owner)), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
    const backend = domain.containment.backend;
    if (backend.kind !== 'linux') throw new TypeError('MCP stdio original instance is not its actual Linux domain');
    const deathCore = { schemaVersion: 1 as const, kind: 'containment_all_descendants_dead' as const, containmentRef: domain.containmentRef,
      planRef: launch.plannedContainmentRef, sandboxLaunchSpecRef: launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: launch.sandboxLaunchSpecDigest,
      owner: domain.plan.owner, launchNonceDigest: domain.plan.launchNonceDigest, inspectorSupervisorInstanceId: domain.owner.supervisorInstanceId,
      inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, backend: { ...backend, cgroupPopulated: 0 as const,
        namespaceInitDeadAndReaped: true as const, remainingTrackedDescendants: 0 as const }, observedAt: new Date(physical.observedAtMs).toISOString() };
    const death: ProcessContainmentDeathEvidenceV1 = { ...deathCore, evidenceDigest: canonicalSha256(deathCore) };
    const deathArtifact = await artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
    const raw = await artifacts.publishBytes(joined.lifecycleSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-native-lifecycle-bytes-v1');
    const projection = await artifacts.publishCanonical(original, original.format);
    return domain.retired = { joined, death, deathRef: deathArtifact.ref, nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: raw.ref,
      lifecycleProjectionRef: projection.ref }, metadata: [inspectorArtifact, deathArtifact, raw, projection] };
  })();
  domain.retirement = task;
  try { return await task; } finally { if (domain.retirement === task) domain.retirement = undefined; }
}
/** The effect's original settlement supplies the exact N; this writer stages
 * the launch at N+1 and commits only inside that same original transaction. */
export async function prepareMcpServerTerminal(driver: SqliteDriver, owner: StateOwnerContext, instanceRef: string,
  effect: BudgetSettlementV1, disposition: 'completed' | 'owning_call_unknown') {
  const domain = instances.get(instanceRef);
  if (!domain || domain.driver !== driver || domain.owner !== owner) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP terminal writer lost its original physical instance');
  const actual = await retirement(domain), custody = readMcpStdioRunCustody(domain.native, domain.launch), binding = custody.call;
  if (!binding || binding.instanceIdentityRef !== instanceRef || !custody.joined || effect.runId !== domain.launch.runId || effect.opId !== binding.opId || effect.attempt !== binding.attempt ||
      effect.terminalPhase !== (disposition === 'completed' ? 'completed' : 'unknown') || custody.resultReceived !== (disposition === 'completed'))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP local terminal writer cannot change the original known/UNKNOWN effect disposition');
  const stoppedAt = actual.death.observedAt;
  const { settlement, settlementPlan, terminalPlan, terminalSeq, stoppedItemId, stopped } = mcpServerTerminalData({ effect,
    prepared: domain.prepared, claim: domain.claim, instance: domain.instance, instanceRef, deathRef: actual.deathRef,
    observedAt: stoppedAt, nativeClosure: actual.nativeClosure, disposition });
  const terminalOwner = { terminalRef: terminalPlan.ref, settlementRef: settlementPlan.ref, stoppedItemId, disposition };
  if (domain.terminal) requireEqual(domain.terminal, terminalOwner, 'MCP original local terminal publication owner');
  else domain.terminal = terminalOwner;
  const published = await domain.artifacts.mapReads([settlementPlan, terminalPlan], plan => domain.artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
  function commit(connection: SqliteConnection, effectEntry: InvocationJournalEntry, committedAt: string) {
    assertActiveStateOwner(connection, owner); domain!.scope.assertJoined(actual.joined.joined);
    assertInstalledMcpStdioRunJoined(domain!.native, actual.joined.ownerJoined, domain!.launch);
    requireEqual(readInvocationAttempt(connection, effect.runId, domain!.prepared.opId, domain!.prepared.attempt), [domain!.prepared, domain!.claim], 'MCP original local server terminal claim');
    if (nextJournalSequence(connection, effect.runId) !== terminalSeq || effectEntry.seq !== effect.terminalJournalSeq || effectEntry.opId !== binding!.opId ||
        effectEntry.phase !== effect.terminalPhase || committedAt < effect.settledAt || effect.settledAt < stoppedAt)
      throw new KernelStorageError('REVISION_CONFLICT', 'MCP separate server terminal lost its exact same-transaction effect/clock order');
    const run = readRun(connection, effect.runId);
    requireEqual(run.budgetConsumed, settlement.budgetConsumedBefore, 'MCP server exact after-effect consumed budget');
    requireEqual(run.budgetReserved, settlement.budgetReservedBefore, 'MCP server exact after-effect reserved budget');
    const entry: InvocationJournalEntry = { ...domain!.claim, seq: terminalSeq, phase: settlement.terminalPhase,
      budgetDelta: BUDGET, budgetSettlementRef: settlementPlan.ref, timestamp: settlement.settledAt,
      ...(disposition === 'completed' ? { resultRef: instanceRef, receiptRef: terminalPlan.ref } : { errorRef: terminalPlan.ref }) };
    appendInvocationJournalEntry(connection, entry);
    const changed = connection.prepare('UPDATE runs SET budget_consumed_json=?,budget_reserved_json=? WHERE id=? AND revision=? AND budget_consumed_json=? AND budget_reserved_json=?')
      .run(JSON.stringify(settlement.budgetConsumedAfter), JSON.stringify(settlement.budgetReservedAfter), run.id, BigInt(run.revision),
        JSON.stringify(run.budgetConsumed), JSON.stringify(run.budgetReserved));
    if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'MCP separate launch settlement budget CAS changed');
  }
  return { stopped, journalSeq: terminalSeq, settlement, terminalRef: terminalPlan.ref, metadata: [...actual.metadata, ...published], commit };
}
export function acknowledgeMcpServerTerminal(driver: SqliteDriver, owner: StateOwnerContext, instanceRef: string) {
  const domain = instances.get(instanceRef); if (!domain || domain.driver !== driver || domain.owner !== owner) throw new TypeError('foreign MCP server terminal acknowledgement');
  const rows = readInvocationAttempt(driver, domain.launch.runId, domain.launch.launchOpId, domain.launch.attempt), terminal = rows.at(-1);
  if (rows.length !== 3 || !terminal || !['completed', 'failed'].includes(terminal.phase) || !terminal.budgetSettlementRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original local launch has not durably settled exactly once');
  const item = domain.terminal && driver.prepare('SELECT item_id FROM items WHERE run_id=? AND item_id=?')
    .get<{ item_id: string }>(domain.launch.runId, domain.terminal.stoppedItemId);
  if (!domain.retired || !domain.terminal || !item || terminal.budgetSettlementRef !== domain.terminal.settlementRef ||
      (domain.terminal.disposition === 'completed' ? terminal.phase !== 'completed' || terminal.receiptRef !== domain.terminal.terminalRef
        : terminal.phase !== 'failed' || terminal.errorRef !== domain.terminal.terminalRef))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP terminal acknowledgement has no exact original durable joined writer');
  domain.scope.assertJoined(domain.retired.joined.joined); domain.acknowledgePhysical(); instances.delete(instanceRef);
}
export function acknowledgeMcpServerManualTerminal(native: NativeMcpStdioRunOwner, instanceRef: string) {
  const domain = instances.get(instanceRef), call = domain && readMcpStdioRunCustody(native, domain.launch).call;
  if (!domain || domain.native !== native || !call || domain.terminal?.disposition !== 'owning_call_unknown' ||
      readInvocationAttempt(domain.driver, domain.launch.runId, call.opId, call.attempt).at(-1)?.phase !== 'abandoned')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio local domain can release only after its exact durable manual acknowledgement');
  closeMcpStdioManualTerminalFence(native, instanceRef);
  acknowledgeMcpServerTerminal(domain.driver, domain.owner, instanceRef);
}
/** The same original local instance may leave only after its original UNKNOWN
 * is durably fenced by a new preparation or the unique terminal transaction.
 * This acknowledgement supplies no remote outcome or new execution permit. */
export async function acknowledgeMcpServerRetryClosure(native: NativeMcpStdioRunOwner, instanceRef: string, closureRef: string) {
  const domain = instances.get(instanceRef), call = domain && readMcpStdioRunCustody(native, domain.launch).call;
  if (!domain || domain.native !== native || !call || domain.terminal?.disposition !== 'owning_call_unknown')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP retry lost its original fully retired uncertain local instance');
  const rows = readInvocationAttempt(domain.driver, domain.launch.runId, call.opId, call.attempt), [prepared, claim, unknown] = rows;
  if (rows.length !== 3 || prepared?.replayClass !== 'retry' || prepared.phase !== 'prepared' || claim?.phase !== 'dispatch_claimed' ||
      unknown?.phase !== 'unknown' || claim.evidenceRef !== instanceRef || claim.evidenceDigest !== call.instanceIdentityDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP retry acknowledgement changes its exact once-settled original UNKNOWN');
  const proof = decodeMcpRetryDispatchClosure(await readCanonicalArtifact(domain.artifacts, closureRef));
  if (proof.runId !== prepared.runId || proof.opId !== prepared.opId || proof.attempt !== prepared.attempt ||
      proof.preparedJournalSeq !== prepared.seq || proof.dispatchId !== claim.dispatchId || proof.dispatchJournalSeq !== claim.seq ||
      proof.unknownJournalSeq !== unknown.seq || proof.budgetSettlementRef !== unknown.budgetSettlementRef ||
      proof.unknownEvidenceRef !== unknown.evidenceRef || proof.unknownEvidenceDigest !== unknown.evidenceDigest ||
      proof.brokerFenceTokenDigest !== call.releaseFenceTokenDigest || proof.originalClaimIdentity.kind !== 'stdio_instance' ||
      proof.originalClaimIdentity.ref !== instanceRef || proof.originalClaimIdentity.digest !== call.instanceIdentityDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP retry acknowledgement substitutes its original dispatch closure');
  const next = readInvocationJournal(domain.driver, prepared.runId).find(entry => entry.opId === prepared.opId &&
    entry.attempt === prepared.attempt + 1 && entry.phase === 'prepared');
  const run = readRun(domain.driver, prepared.runId);
  const terminal = ['failed', 'cancelled'].includes(run.status) && run.terminalDetailRef
    ? await readCanonicalArtifact<import('../kernel/types.js').TerminalDetail>(domain.artifacts, run.terminalDetailRef) : undefined;
  if (next ? next.evidenceRef !== closureRef || next.evidenceDigest !== proof.evidenceDigest
    : !terminal || terminal.abandonedRetryInvocations.filter(entry => entry.opId === prepared.opId && entry.attempt === prepared.attempt &&
      entry.unknownJournalSeq === unknown.seq && entry.budgetSettlementRef === unknown.budgetSettlementRef &&
      entry.dispatchFenceOrDeathEvidenceRef === closureRef).length !== 1)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP retry local domain has no identical actually committed preparation or terminal closure');
  closeMcpStdioManualTerminalFence(native, instanceRef);
  acknowledgeMcpServerTerminal(domain.driver, domain.owner, instanceRef);
}
/** Resume only the original retained physical acknowledgement, after the
 * authenticated replay reader validated the complete first response/history.
 * No matching domain means this process owns no such outstanding receiver. */
export function resumeOwnedMcpServerManualTerminal(driver: SqliteDriver, owner: StateOwnerContext, claim: InvocationJournalEntry) {
  if (claim.opKind !== 'mcp' || claim.phase !== 'dispatch_claimed' || !claim.evidenceRef) return;
  const domain = instances.get(claim.evidenceRef); if (!domain) return;
  if (domain.driver !== driver || domain.owner !== owner || domain.instance.identityDigest !== claim.evidenceDigest ||
      domain.launch.runId !== claim.runId || domain.launch.supervisorInstanceId !== claim.supervisorInstanceId || domain.launch.stateOwnerEpoch !== claim.stateOwnerEpoch)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP manual replay cannot adopt another original physical domain');
  const call = readMcpStdioRunCustody(domain.native, domain.launch).call;
  if (!call || call.opId !== claim.opId || call.attempt !== claim.attempt || call.dispatchId !== claim.dispatchId || call.dispatchJournalSeq !== claim.seq ||
      call.releaseFenceTokenDigest !== claim.brokerFenceTokenDigest || call.instanceIdentityRef !== claim.evidenceRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP manual replay changes its exact original claimed effect');
  acknowledgeMcpServerManualTerminal(domain.native, claim.evidenceRef);
}
/** The original UNKNOWN is already fully charged and physically retired.
 * A durable exact reconcile wait retains all its source bytes; the separate
 * status query needs no old live native owner. Only that current owning
 * domain may acknowledge its real irreversible fence/join and input close. */
export async function resumeOwnedMcpServerReconcileWait(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runId: string, signal?: AbortSignal): Promise<void> {
  const domains = [...instances.entries()].filter(([, domain]) => domain.launch.runId === runId);
  if (!domains.length) return;
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive(); assertActiveStateOwner(driver, owner);
  const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, reads, runId);
  const { source } = await (await import('./mcp-status-state.js')).validateMcpInvocationWait(driver, reads, cut);
  const selected = domains[0];
  if (domains.length !== 1 || !selected) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP reconcile wait retains competing original local domains');
  const [reference, domain] = selected;
  if (domain.driver !== driver || domain.artifacts !== artifacts || domain.owner !== owner || domain.terminal?.disposition !== 'owning_call_unknown' ||
      source.prepared.replayClass !== 'reconcile' || source.claim.evidenceRef !== reference || source.claim.evidenceDigest !== domain.instance.identityDigest ||
      source.claim.supervisorInstanceId !== owner.supervisorInstanceId || source.claim.stateOwnerEpoch !== owner.ownerEpoch)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP reconcile acknowledgement cannot borrow another purpose, instance or native creator');
  const call = readMcpStdioRunCustody(domain.native, domain.launch).call;
  if (!call || call.opId !== source.claim.opId || call.attempt !== source.claim.attempt || call.dispatchId !== source.claim.dispatchId ||
      call.dispatchJournalSeq !== source.claim.seq || call.instanceIdentityRef !== reference || call.releaseFenceTokenDigest !== source.claim.brokerFenceTokenDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP reconcile acknowledgement changed its exact original permanently claimed effect');
  reads.assertReadActive(); assertActiveStateOwner(driver, owner);
  requireEqual(readRun(driver, runId), cut.run, 'MCP reconcile original durable waiting Run');
  requireEqual(readInvocationJournal(driver, runId), cut.journal, 'MCP reconcile original full-once UNKNOWN history');
  source.registry.assertUnchanged(driver); source.original.history.assertUnchanged(driver);
  closeMcpStdioReconcileWaitFence(domain.native, reference);
  acknowledgeMcpServerTerminal(driver, owner, reference);
}
