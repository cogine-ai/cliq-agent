import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodeDeliveryPlan, type DeliveryCaptureTopologyV1, type DeliveryPlan,
  type PublicationDirectoryIdentityV1 } from '../kernel/publication.js';
import type { ContinuationItem, RunFrontier } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { readDeliveryAuthorization } from './delivery-approval.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, loadNativeStateOwner, stateRootIdentityForLock,
  type HeldStateOwnerLock, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from './native-owner.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { assertDeliveryExecution, assertDeliveryPublicationExecution,
  type DeliveryPublicationTask, type RunExecutionWorkerIdentity } from './run-execution.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, assertFenceHealthy, type StateOwnerContext } from './state-owner.js';

type PhysicalIdentity = HeldWorkspaceRoot['identity'] & { mode: number };
type ArenaParent = { kind: 'present'; identity: PhysicalIdentity } | { kind: 'absent'; runtimeIdentity: PhysicalIdentity };
const MAX_INVENTORY = 100_000;
const parentPath = (value: string) => value.slice(0, Math.max(0, value.lastIndexOf('/')));
function refuse(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Actual readonly mechanism only, not approval, a publication claim or live
 * preflight authority. Production creates it internally after full admission;
 * a caller cannot supply this observation to mint a release token. */
export async function inspectPublicationPlan(lock: HeldStateOwnerLock, root: HeldWorkspaceRoot,
  planInput: DeliveryPlan, topologyInput: DeliveryCaptureTopologyV1, signal?: AbortSignal) {
  // Brand checks precede every property read from either supplied handle.
  assertHeldWorkspaceRoot(root);
  const stateRoot = stateRootIdentityForLock(lock);
  const plan = decodeDeliveryPlan(planInput), topology = decodeDeliveryCaptureTopology(topologyInput);
  if (plan.captureTopologyDigest !== topology.topologyDigest || plan.capturedWorkspaceRef !== topology.capturedWorkspaceRef)
    refuse('publication preflight has a foreign captured topology');
  const resources: Array<{ close(): void }> = [], cursors: HeldWorkspaceCursor[] = [], entries: HeldWorkspaceEntry[] = [];
  let closed = false, retirement: ResourceRetirementError | undefined;
  const identity = (value: HeldWorkspaceRoot | HeldWorkspaceEntry): PhysicalIdentity => Object.freeze({ ...value.identity, mode: value.mode });
  const raw = (value: PublicationDirectoryIdentityV1): PhysicalIdentity => ({ deviceId: value.deviceId,
    fileId: value.fileId, ownerUid: value.ownerUid, mode: value.mode });
  function checkRoot() {
    assertHeldWorkspaceRoot(root); lock.assertHeld();
    requireEqual(identity(root), raw(topology.rootIdentity), 'publication original root identity and raw mode');
    if (root.identity.deviceId !== stateRoot.deviceId || lock.runtime.deviceId !== stateRoot.deviceId)
      refuse('publication preflight requires the actual StateRoot and workspace on one filesystem');
  }
  function close(cause?: unknown) {
    if (retirement) throw retirement;
    if (closed) return;
    const failures: unknown[] = [];
    for (const resource of [...resources].reverse()) try { resource.close(); } catch (error) { failures.push(error); }
    if (failures.length) {
      retirement = new ResourceRetirementError('publication preflight descriptors did not retire',
        new AggregateError(cause === undefined ? failures : [cause, ...failures]));
      throw retirement;
    }
    closed = true;
  }
  const keepCursor = (value: HeldWorkspaceCursor) => { resources.push(value); cursors.push(value); return value; };
  const keepEntry = (value: HeldWorkspaceEntry) => { resources.push(value); entries.push(value); return value; };
  const discard = (value: { close(): void }) => {
    try { value.close(); }
    catch (error) { throw new ResourceRetirementError('publication unselected metadata descriptor did not retire', error); }
  };
  let arenaParent: ArenaParent, inventory = 0;
  try {
    signal?.throwIfAborted(); checkRoot();
    // Open only the canonical private runtime already continuously held by
    // this real lock, then independently bind its actual dev/ino/UID/raw mode.
    const native = await loadNativeStateOwner(), runtime = native.openWorkspaceRoot(path.join(stateRoot.canonicalAbsolutePath, 'runtime'));
    resources.push(runtime);
    requireEqual(runtime.identity, lock.runtime, 'publication actual held runtime identity');
    if (runtime.mode !== 0o700) refuse('publication runtime is not private');
    const runtimeCursor = runtime.openSnapshot(); resources.push(runtimeCursor);
    let arenaRoot: HeldWorkspaceRoot | undefined;
    arenaParent = { kind: 'absent', runtimeIdentity: identity(runtime) };
    for (;;) {
      await setImmediate(); signal?.throwIfAborted();
      const entry = runtimeCursor.next(); if (!entry) break;
      if (++inventory > MAX_INVENTORY) { discard(entry); refuse('publication metadata inventory exceeds the source limit'); }
      if (entry.path !== 'publications') { discard(entry); continue; }
      resources.push(entry);
      if (entry.kind !== 'directory' || entry.mode !== 0o700 || entry.identity.ownerUid !== stateRoot.ownerUid ||
          entry.identity.deviceId !== root.identity.deviceId) refuse('publication actual private arena parent is not on the workspace filesystem');
      arenaParent = { kind: 'present', identity: identity(entry) };
      // A source cursor owns its entries, so it must join before later private
      // arena birth changes directory contents. Retain an independently held
      // fixed-role root instead: its named identity/raw mode remains checked,
      // but its legitimate children are not frozen as user-workspace A.
      arenaRoot = native.openWorkspaceRoot(path.join(stateRoot.canonicalAbsolutePath, 'runtime', 'publications'));
      resources.push(arenaRoot); entry.assertPathHeld();
      requireEqual(identity(arenaRoot), arenaParent.identity, 'publication original private arena parent identity');
    }
    runtimeCursor.assertComplete(); discard(runtimeCursor);
    const directories = new Map(topology.directories.map(value => [value.path, value]));
    const operations = new Map(plan.forwardOperations.map(operation => [operation.path, operation]));
    const creators = new Map(plan.forwardOperations.filter(operation => operation.desired.kind === 'directory' && operation.expected.kind !== 'directory')
      .map(operation => [operation.path, operation]));
    const needed = new Set<string>(), neededParents = new Set<string>(), virtual = new Set<string>();
    for (const operation of plan.forwardOperations) {
      const parent = parentPath(operation.path), creator = creators.get(parent);
      if (operation.parent.kind === 'planned_directory') {
        if (!creator || creator.index >= operation.index || creator.operationId !== operation.parent.createdByOperationId || operation.expected.kind !== 'absent')
          refuse('publication virtual parent is not its original preceding directory creator');
      } else {
        const expected = parent ? directories.get(parent) : topology.rootIdentity;
        if (!expected || expected.identityDigest !== operation.parent.expectedIdentityDigest || creator)
          refuse('publication existing parent differs from its original captured identity');
      }
      let virtualAncestor = false;
      for (let prefix = parent; prefix; prefix = parentPath(prefix)) if (creators.has(prefix)) virtualAncestor = true;
      if (virtualAncestor) { virtual.add(operation.path); continue; }
      needed.add(operation.path);
      for (let prefix = parent; prefix; prefix = parentPath(prefix)) { needed.add(prefix); neededParents.add(prefix); }
    }
    inventory = 0;
    const observed = new Set<string>(), stack = [keepCursor(root.openSnapshot())];
    while (stack.length) {
      await setImmediate(); signal?.throwIfAborted();
      const cursor = stack[stack.length - 1]!, entry = cursor.next();
      if (!entry) { cursor.assertComplete(); stack.pop(); continue; }
      if (++inventory > MAX_INVENTORY) { discard(entry); refuse('publication metadata inventory exceeds the source limit'); }
      if (!needed.has(entry.path)) { discard(entry); continue; }
      keepEntry(entry); observed.add(entry.path);
      if (entry.identity.deviceId !== root.identity.deviceId) refuse('publication existing path crosses the original workspace device');
      const operation = operations.get(entry.path), captured = directories.get(entry.path);
      if (operation?.expected.kind === 'absent') refuse('publication originally absent path is now occupied');
      if (operation && (entry.kind !== operation.expected.kind ||
          operation.expected.kind !== 'symlink' && entry.mode !== operation.expected.mode))
        refuse('publication existing entry type or raw mode changed');
      if (entry.kind === 'file' && operation && entry.linkCount !== 1)
        refuse('publication whole plan contains a multiply-linked old regular file');
      if (entry.kind === 'directory') {
        if (!captured) refuse('publication existing directory has no original captured identity');
        requireEqual(identity(entry), raw(captured), 'publication captured parent directory identity');
        if (neededParents.has(entry.path)) stack.push(keepCursor(entry.openDirectory()));
      } else if (neededParents.has(entry.path))
        refuse('publication existing ancestor is not a directory');
    }
    for (const name of needed) if (!observed.has(name) && operations.get(name)?.expected.kind !== 'absent')
      refuse('publication required original parent or leaf is absent');
    const assertHeld = () => {
      if (retirement) throw retirement;
      if (closed) refuse('publication preflight is closed');
      signal?.throwIfAborted(); checkRoot();
      assertHeldWorkspaceRoot(runtime);
      requireEqual(identity(runtime), { ...lock.runtime, mode: 0o700 }, 'publication original private runtime identity');
      if (arenaRoot && arenaParent.kind === 'present') {
        assertHeldWorkspaceRoot(arenaRoot);
        requireEqual(identity(arenaRoot), arenaParent.identity, 'publication original private arena parent identity');
      }
      for (const cursor of cursors) cursor.assertComplete();
      for (const entry of entries) entry.assertHeld();
    };
    assertHeld();
    return Object.freeze({ arenaParent: Object.freeze(arenaParent), observedPaths: observed.size, virtualPaths: virtual.size,
      assertHeld, close: () => close() });
  } catch (error) { close(error); throw error; }
}

const preflightBrand: unique symbol = Symbol('PublicationPreflight');
export type PublicationPreflight = Readonly<{ readonly [preflightBrand]: true; close(): void }>;
type PhysicalInspection = Awaited<ReturnType<typeof inspectPublicationPlan>>;
type PreflightProjection = Readonly<{
  runId: string; plan: DeliveryPlan; planRef: string; frontierRef: string; leaseEpoch: number;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; worker: RunExecutionWorkerIdentity;
  observedAt: string; arenaParent: ArenaParent;
}>;
type PreflightBinding = { driver: SqliteDriver; owner: StateOwnerContext; projection: PreflightProjection; assertCurrent(): void };
const preflights = new WeakMap<object, PreflightBinding>();

const sessionIdentity = (session: ReturnType<typeof readSession>) => ({ id: session.id,
  workspaceIdentityRef: session.workspaceIdentityRef, createdAt: session.createdAt,
  ...(session.parentSessionId === undefined ? {} : { parentSessionId: session.parentSessionId, forkedThroughItemSeq: session.forkedThroughItemSeq }) });
function publicationCut(connection: SqliteConnection, runId: string) {
  const run = readRun(connection, runId);
  return { run, journal: readInvocationJournal(connection, runId), checkpoint: readCheckpoint(connection, run.latestCheckpointId),
    items: connection.prepare('SELECT item_id,session_id,run_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; session_id: string | null; run_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
      .map(row => ({ ...row, item_seq: Number(row.item_seq) })),
    launches: readWorkerLaunchesForRun(connection, runId), generations: readWorkspaceGenerationsForRun(connection, runId),
    session: sessionIdentity(readSession(connection, run.sessionId)), principalId: readSessionPrincipalId(connection, run.sessionId) };
}

/** One initial publish cut, before its first forward claim or workspace write.
 * This owns readonly observations, not an operation reservation, claim or arm.
 * The first claim transaction must consume the exact same cut; subsequent
 * operations require their genuine completed prefix, not another reading of A. */
export async function preparePublicationPreflight(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { runId: string; expectedRunRevision: number; execution: unknown; worker: RunExecutionWorkerIdentity;
    workspaceRoot: HeldWorkspaceRoot; task?: DeliveryPublicationTask; signal?: AbortSignal }): Promise<PublicationPreflight> {
  // Neither a structural execution callback nor a structural source root can
  // reach SQL/CAS or become a physical publication permit.
  const worker = immutableSnapshot(input.worker), { workspaceRoot: root, execution, signal, runId } = input;
  const task = input.task;
  const assertExecution = () => task === undefined ? assertDeliveryExecution(driver, owner, execution, worker)
    : assertDeliveryPublicationExecution(driver, owner, execution, worker, task);
  assertExecution();
  assertHeldWorkspaceRoot(root);
  if (worker.runId !== runId || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
    throw new TypeError('publication preflight requires its exact Run and revision');
  assertActiveStateOwner(driver, owner); signal?.throwIfAborted();
  const before = driver.readSnapshot(connection => publicationCut(connection, runId)), beforeDigest = canonicalSha256(before);
  if (before.run.revision !== input.expectedRunRevision)
    throw new KernelStorageError('REVISION_CONFLICT', 'publication preflight revision changed');
  let physical: PhysicalInspection | undefined;
  try {
    const cut = await readRecoveryClosure(driver, artifacts, runId);
    if (cut.runSpec.operation !== 'delivery' || cut.run.status !== 'running' || cut.run.nextStep !== 'delivery' ||
        !cut.run.frontierRef || cut.run.activeWorkerLaunchId !== worker.launchId || cut.run.leaseEpoch !== worker.leaseEpoch ||
        cut.run.stopIntentRef || cut.run.cancelRequested || cut.childAllocations.length ||
        cut.journal.some(entry => entry.opKind === 'publish' && entry.phase !== 'prepared'))
      refuse('publication preflight requires the original unstopped initial publish worker and no prior forward claim');
    requireEqual(cut.run, before.run, 'publication preflight original Run');
    requireEqual(cut.journal, before.journal, 'publication preflight original Journal');
    requireEqual(cut.latestCheckpoint, before.checkpoint, 'publication preflight original Checkpoint');
    const decoded = await Promise.all(cut.items.map(async row => ({ ...row,
      item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })));
    requireEqual(before.items, decoded.map(row => ({ item_id: row.itemId, session_id: null, run_id: runId,
      item_seq: row.itemSeq, kind: row.item.kind, payload_ref: row.payloadRef, created_at: row.createdAt })), 'publication preflight original owned items');
    if (decoded.some(({ item }) => item.kind === 'publication_path_progress' || item.kind === 'publication_path_result'))
      refuse('publication preflight cannot reinterpret an already published workspace as captured A');
    // Full R and authorization remain independently checked in this same call.
    // A future validated-cut deep module may remove duplicate retained work;
    // this must not become a cross-cut cache or weaken either graph today.
    const authorization = await readDeliveryAuthorization(driver, artifacts, cut);
    if (!authorization?.grant || !authorization.grantRef || authorization.decision.decision !== 'allow' ||
        authorization.workspace.kind !== 'live' || authorization.workspace.ownerPrincipalId !== before.principalId)
      refuse('publication preflight has no complete original plan allow');
    const expectedFrontier: RunFrontier = { ...authorization.frontier, phase: 'publish', nextPathOperationIndex: 0 };
    requireEqual(await readCanonicalArtifact(artifacts, cut.run.frontierRef), expectedFrontier, 'publication preflight original initial frontier');
    const plan = authorization.context.plan;
    if (!plan.forwardOperations.length) refuse('no-op delivery cannot acquire publication preflight');
    // A prepared row may precede this check; no later operation may be
    // prepared speculatively before the initial physical plan is accepted.
    const prepared = cut.journal.filter(entry => entry.opKind === 'publish');
    const firstOpId = identityHash('cliq-publication-operation-v1', runId, authorization.context.planRef,
      'forward', '0', plan.forwardOperations[0]!.operationId);
    if (prepared.length > 1 || prepared[0] && prepared[0].opId !== firstOpId)
      refuse('publication initial preflight has speculative path preparations');
    const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(artifacts, plan.captureTopologyRef));
    if (topology.workspaceIdentityRef !== authorization.context.workspaceIdentityRef ||
        topology.workspaceIdentityDigest !== authorization.context.workspaceIdentityDigest ||
        heldWorkspaceRootPath(root) !== authorization.workspace.canonicalRootPath)
      refuse('publication preflight root or topology differs from the original approved target');
    requireEqual(root.identity, authorization.workspace.rootIdentity, 'publication original approved root');
    const source = authorization.verified.admission.source;
    const sourceDigest = canonicalSha256({ run: source.run, session: sessionIdentity(source.session), principalId: before.principalId });
    const assertCut = () => {
      assertActiveStateOwner(driver, owner);
      if (canonicalSha256(publicationCut(driver, runId)) !== beforeDigest ||
          canonicalSha256({ run: readRun(driver, source.run.id), session: sessionIdentity(readSession(driver, source.session.id)),
            principalId: readSessionPrincipalId(driver, source.session.id) }) !== sourceDigest ||
          driver.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(runId, runId) ||
          driver.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(runId))
        throw new KernelStorageError('REVISION_CONFLICT', 'publication preflight original cut changed');
      assertExecution();
    };
    assertCut();
    physical = await inspectPublicationPlan(owner.filesystem, root, plan, topology, signal);
    assertCut();
    const observedAt = sampleCanonicalNow(), observedMs = parseCanonicalTime(observedAt);
    const projection: PreflightProjection = immutableSnapshot({ runId, plan, planRef: authorization.context.planRef,
      frontierRef: cut.run.frontierRef, leaseEpoch: cut.run.leaseEpoch, workspaceIdentityRef: authorization.context.workspaceIdentityRef,
      workspaceIdentityDigest: authorization.context.workspaceIdentityDigest, worker, observedAt, arenaParent: physical.arenaParent });
    const held = physical;
    const assertCurrent = () => {
      // Preserve a sticky descriptor-retirement failure over cancellation or
      // a later SQL conflict; neither can turn an uncertain join into success.
      held.assertHeld(); signal?.throwIfAborted(); assertCut();
      const fence = assertFenceHealthy(readTimeFence(driver)), now = sampleCanonicalNow(), nowMs = parseCanonicalTime(now);
      if (fence.stateOwnerEpoch !== owner.ownerEpoch || now < fence.lastAcceptedAt || nowMs < observedMs ||
          nowMs - observedMs > 5_000 || now < authorization.grant!.issuedAt || now >= cut.run.deadlineAt || now >= authorization.grant!.expiresAt)
        throw new KernelStorageError('LEASE_FENCED', 'publication preflight is no longer fresh within its original lifetime');
    };
    assertCurrent();
    const value = Object.freeze({ [preflightBrand]: true as const, close: () => held.close() });
    preflights.set(value, { driver, owner, projection, assertCurrent });
    return value;
  } catch (error) {
    try { physical?.close(); } catch (retirement) {
      throw new ResourceRetirementError('publication preflight did not join after refusal', new AggregateError([error, retirement]));
    }
    throw error;
  }
}

/** Friend for the original Store only. Data, another Store's observation or a
 * closed/stale preflight cannot authorize the first publication claim. */
export function assertPublicationPreflight(driver: SqliteDriver, owner: StateOwnerContext, value: unknown): PreflightProjection {
  const binding = value !== null && typeof value === 'object' ? preflights.get(value) : undefined;
  if (!binding || binding.driver !== driver || binding.owner !== owner)
    throw new TypeError('publication requires its genuine same-owner publication preflight');
  binding.assertCurrent();
  return binding.projection;
}
