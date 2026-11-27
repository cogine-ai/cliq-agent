// The original StateOwner writes these two existing tables. The row reader
// compares the indexed projection to the complete canonical retained data.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, digestOmitting } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeLocalInferenceCycle, decodeLocalInferenceLaunch, localInferenceParticipantKey,
  LOCAL_INFERENCE_PARTICIPANTS, LOCAL_INFERENCE_RETRY_MS, type LocalInferenceActivationCycleV1,
  type LocalInferenceActivationParticipantV1, type LocalInferenceServiceLaunchV1 } from '../kernel/local-inference.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { insertArtifactMetadata, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type Cycle = LocalInferenceActivationCycleV1;
type Launch = LocalInferenceServiceLaunchV1;
type CycleRow = { activation_cycle_id: string; owner_principal_id: string; service_id: string; cycle_ordinal: bigint | number; phase: string; row_json: string };
type LaunchRow = { launch_id: string; activation_cycle_id: string; owner_principal_id: string; service_id: string; phase: string; retired_at: string | null; row_json: string };
const CYCLES = 'SELECT activation_cycle_id,owner_principal_id,service_id,cycle_ordinal,phase,row_json FROM local_inference_activation_cycles';
const LAUNCHES = 'SELECT launch_id,activation_cycle_id,owner_principal_id,service_id,phase,retired_at,row_json FROM local_inference_launches';
const json = (value: unknown) => canonicalJsonBytes(value).toString('utf8');
const isCyclePending = (cycle: Cycle) => cycle.phase === 'starting_launch' || cycle.phase === 'retry_wait';
function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

function readCycleRow(row: CycleRow): Cycle {
  const cycle = decodeLocalInferenceCycle(parseJsonStrict(row.row_json));
  if (row.row_json !== json(cycle) || row.activation_cycle_id !== cycle.activationCycleId ||
      row.owner_principal_id !== cycle.ownerPrincipalId || row.service_id !== cycle.serviceId ||
      Number(row.cycle_ordinal) !== cycle.cycleOrdinal || row.phase !== cycle.phase)
    mismatch('local inference cycle SQL projection differs from its complete canonical row');
  return cycle;
}
function readLaunchRow(row: LaunchRow): Launch {
  const launch = decodeLocalInferenceLaunch(parseJsonStrict(row.row_json));
  if (row.row_json !== json(launch) || row.launch_id !== launch.launchId || row.activation_cycle_id !== launch.activationCycleId ||
      row.owner_principal_id !== launch.ownerPrincipalId || row.service_id !== launch.serviceId || row.phase !== launch.phase ||
      row.retired_at !== (launch.phase === 'retired' ? launch.retiredAt : null))
    mismatch('local inference launch SQL projection differs from its complete canonical row');
  return launch;
}
export function readLocalInferenceCycle(connection: SqliteConnection, id: string): Cycle | undefined {
  const row = connection.prepare(CYCLES + ' WHERE activation_cycle_id=?').get<CycleRow>(id);
  return row && readCycleRow(row);
}
export function readLocalInferenceLaunch(connection: SqliteConnection, id: string): Launch | undefined {
  const row = connection.prepare(LAUNCHES + ' WHERE launch_id=?').get<LaunchRow>(id);
  return row && readLaunchRow(row);
}
export function readLocalInferenceCurrent(connection: SqliteConnection, owner: string, service: string): Readonly<{ latest?: Cycle; launch?: Launch }> {
  let latest: Cycle | undefined;
  for (const row of connection.prepare(CYCLES + ' WHERE owner_principal_id=? AND service_id=? ORDER BY cycle_ordinal').iterate<CycleRow>(owner, service)) {
    const cycle = readCycleRow(row);
    if (cycle.cycleOrdinal !== (latest?.cycleOrdinal ?? 0) + 1 || latest && isCyclePending(latest))
      mismatch('local inference cycle ordinals are not a contiguous terminal prefix');
    latest = cycle;
  }
  let launch: Launch | undefined;
  for (const row of connection.prepare(LAUNCHES + ' WHERE owner_principal_id=? AND service_id=?')
    .iterate<LaunchRow>(owner, service)) {
    const candidate = readLaunchRow(row);
    if (candidate.phase === 'retired') continue;
    if (launch) mismatch('local inference service has more than one unretired launch');
    launch = candidate;
    if (!latest || launch.activationCycleId !== latest.activationCycleId || latest.launchIds.at(-1) !== launch.launchId)
      mismatch('unretired local inference launch is outside its one owning cycle');
  }
  return { ...(latest ? { latest } : {}), ...(launch ? { launch } : {}) };
}
export function findLocalInferenceSubmission(connection: SqliteConnection, owner: string, requestId: string, requestDigest: string): Cycle | undefined {
  let found: Cycle | undefined;
  for (const row of connection.prepare(CYCLES + ' WHERE owner_principal_id=?').iterate<CycleRow>(owner)) {
    const cycle = readCycleRow(row);
    const participant = cycle.participants.find(item => item.kind === 'run_submission' && item.requestId === requestId);
    if (!participant || participant.kind !== 'run_submission') continue;
    if (participant.requestDigest !== requestDigest)
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'local inference request id already belongs to different original bytes');
    if (found) mismatch('local inference request is retained by more than one cycle');
    found = cycle;
  }
  return found;
}
export function readUnclosedLocalInference(connection: SqliteConnection): Readonly<{ cycles: readonly Cycle[]; launches: readonly Launch[] }> {
  const cycles: Cycle[] = [], launches: Launch[] = [];
  for (const row of connection.prepare(CYCLES + ' ORDER BY owner_principal_id,service_id,cycle_ordinal').iterate<CycleRow>()) {
    const cycle = readCycleRow(row);
    if (isCyclePending(cycle)) cycles.push(cycle);
  }
  for (const row of connection.prepare(LAUNCHES + ' ORDER BY owner_principal_id,service_id').iterate<LaunchRow>()) {
    const launch = readLaunchRow(row);
    if (launch.phase !== 'retired') launches.push(launch);
  }
  return { cycles, launches };
}

export function localCycleData(value: Omit<Cycle, 'cycleDigest'> | Record<string, unknown>): Cycle {
  const data = { ...value, cycleDigest: '' };
  return decodeLocalInferenceCycle({ ...data, cycleDigest: digestOmitting(data, 'cycleDigest') });
}
function cycleIdentity(cycle: Cycle) {
  const { schemaVersion, activationCycleId, ownerPrincipalId, serviceId, serviceSpecRef, serviceSpecDigest,
    localModelRegistrationRef, localModelRegistrationDigest, cycleOrdinal, createdAt } = cycle;
  return { schemaVersion, activationCycleId, ownerPrincipalId, serviceId, serviceSpecRef, serviceSpecDigest,
    localModelRegistrationRef, localModelRegistrationDigest, cycleOrdinal, createdAt };
}
function launchIdentity(launch: Launch) {
  const { schemaVersion, launchId, activationCycleId, activationAttempt, activationNonceDigest, ownerPrincipalId, serviceId,
    serviceSpecRef, serviceSpecDigest, supervisorInstanceId, containmentPlanRef, sandboxLaunchSpecRef, nativeInputRef, createdAt, activationDeadlineAt } = launch;
  return { schemaVersion, launchId, activationCycleId, activationAttempt, activationNonceDigest, ownerPrincipalId, serviceId,
    serviceSpecRef, serviceSpecDigest, supervisorInstanceId, containmentPlanRef, sandboxLaunchSpecRef, nativeInputRef, createdAt, activationDeadlineAt };
}
function writeCycle(connection: SqliteConnection, previous: Cycle | undefined, next: Cycle, now: string): void {
  const retained = readLocalInferenceCycle(connection, next.activationCycleId);
  requireEqual(retained ?? null, previous ?? null, 'original local inference cycle compare-and-swap');
  if (next.createdAt > now || next.participants.some(item => item.joinedAt > now))
    mismatch('local inference cycle has a future participant or creation time');
  if (!previous) {
    const current = readLocalInferenceCurrent(connection, next.ownerPrincipalId, next.serviceId);
    if (current.launch || current.latest && isCyclePending(current.latest) ||
        next.cycleOrdinal !== (current.latest?.cycleOrdinal ?? 0) + 1 || next.phase !== 'starting_launch' ||
        next.activationAttempt !== 1 || next.rowVersion !== 1)
      mismatch('new local inference cycle cannot overtake original activation or retirement');
    const result = connection.prepare('INSERT INTO local_inference_activation_cycles VALUES (?,?,?,?,?,?)')
      .run(next.activationCycleId, next.ownerPrincipalId, next.serviceId, next.cycleOrdinal, next.phase, json(next));
    if (result.changes !== 1n) mismatch('new local inference cycle did not create exactly one row');
    return;
  }
  if (!isCyclePending(previous) || next.rowVersion !== previous.rowVersion + 1 ||
      canonicalSha256(cycleIdentity(next)) !== canonicalSha256(cycleIdentity(previous)))
    mismatch('local inference cycle changed immutable identity or terminal state');
  requireEqual(next.participants.slice(0, previous.participants.length), previous.participants, 'original local inference participant prefix');
  requireEqual(next.launchIds.slice(0, previous.launchIds.length), previous.launchIds, 'original local inference launch prefix');
  if (next.phase === previous.phase) {
    const { participants: _before, rowVersion: _version, cycleDigest: _digest, ...before } = previous;
    const { participants: _after, rowVersion: _nextVersion, cycleDigest: _nextDigest, ...after } = next;
    if (next.participants.length !== previous.participants.length + 1) mismatch('local inference participant append is not singular');
    requireEqual(after, before, 'local inference participant append must retain its lifecycle fields');
  } else {
    if (next.participants.length !== previous.participants.length) mismatch('local inference lifecycle transition changed participants');
    if (next.phase === 'retry_wait') {
      const original = readLocalInferenceLaunch(connection, previous.launchIds[0]!);
      if (previous.phase !== 'starting_launch' || previous.activationAttempt !== 1 || !original || original.phase !== 'retired' ||
          next.retryNotBeforeAt !== addCanonicalDuration(original.retiredAt, LOCAL_INFERENCE_RETRY_MS))
        mismatch('local inference retry requires its exact positive first retirement and fixed delay');
    } else if (next.phase === 'starting_launch') {
      if (previous.phase !== 'retry_wait' || next.activationAttempt !== 2 || now < previous.retryNotBeforeAt)
        mismatch('local inference second attempt is not yet eligible');
    } else if (next.phase === 'active') {
      const active = readLocalInferenceLaunch(connection, next.currentLaunchId);
      if (previous.phase !== 'starting_launch' || next.activationAttempt !== previous.activationAttempt || !active || active.phase !== 'active' ||
          active.boundaryEvidenceRef !== next.boundaryEvidenceRef || next.finishedAt > now || active.leaseExpiresAt <= now)
        mismatch('local inference cycle cannot complete without its exact fresh active launch');
    } else {
      const attempt = readLocalInferenceLaunch(connection, previous.launchIds.at(-1)!);
      if (next.phase !== 'failed' || previous.phase !== 'starting_launch' || next.activationAttempt !== previous.activationAttempt ||
          next.finishedAt > now || previous.activationAttempt === 1 && attempt?.phase === 'retired')
        mismatch('local inference cycle failure differs from its original attempt or omits a required retry');
    }
  }
  const result = connection.prepare('UPDATE local_inference_activation_cycles SET phase=?,row_json=? WHERE activation_cycle_id=? AND row_json=?')
    .run(next.phase, json(next), next.activationCycleId, json(previous));
  if (result.changes !== 1n) mismatch('local inference cycle CAS changed no original row');
}
function writeLaunch(connection: SqliteConnection, previous: Launch | undefined, next: Launch, now: string): void {
  requireEqual(readLocalInferenceLaunch(connection, next.launchId) ?? null, previous ?? null, 'original local inference launch compare-and-swap');
  const cycle = readLocalInferenceCycle(connection, next.activationCycleId);
  if (!cycle || cycle.launchIds[next.activationAttempt - 1] !== next.launchId || cycle.ownerPrincipalId !== next.ownerPrincipalId ||
      cycle.serviceId !== next.serviceId || cycle.serviceSpecRef !== next.serviceSpecRef || cycle.serviceSpecDigest !== next.serviceSpecDigest || next.createdAt > now)
    mismatch('local inference launch lacks its exact owning cycle and source');
  if (!previous) {
    if (next.phase !== 'reserved' || cycle.phase !== 'starting_launch' || cycle.currentLaunchId !== next.launchId ||
        readLocalInferenceCurrent(connection, next.ownerPrincipalId, next.serviceId).launch || next.activationDeadlineAt <= now)
      mismatch('local inference launch reservation overtakes original containment or deadline');
    const result = connection.prepare('INSERT INTO local_inference_launches VALUES (?,?,?,?,?,NULL,?)')
      .run(next.launchId, next.activationCycleId, next.ownerPrincipalId, next.serviceId, next.phase, json(next));
    if (result.changes !== 1n) mismatch('local inference reservation did not create exactly one row');
    return;
  }
  requireEqual(launchIdentity(next), launchIdentity(previous), 'local inference launch immutable source');
  if (next.phase === 'active' && previous.phase === 'active') {
    const { leaseExpiresAt: _beforeTime, leaseVersion: _beforeLease, ...before } = previous;
    const { leaseExpiresAt: _afterTime, leaseVersion: _afterLease, ...after } = next;
    requireEqual(before, after, 'local inference heartbeat changes only its original lease fields');
    if (next.leaseVersion !== previous.leaseVersion + 1 || previous.leaseExpiresAt <= now || next.leaseExpiresAt <= previous.leaseExpiresAt)
      mismatch('local inference heartbeat cannot revive an expired lease');
  } else {
    if (next.rowVersion !== previous.rowVersion + 1) mismatch('local inference launch transition skipped its row version');
    if (next.phase === 'preactivated') {
      if (previous.phase !== 'reserved' || now >= next.activationDeadlineAt) mismatch('local inference preactivation lacks its live original reservation');
    } else if (next.phase === 'active') {
      if (previous.phase !== 'preactivated' || next.processContainmentRef !== previous.processContainmentRef ||
          next.leaseVersion !== 1 || next.leaseExpiresAt <= now || now >= next.activationDeadlineAt)
        mismatch('local inference activation lacks its original blocked containment and deadline');
    } else if (next.phase === 'revoking') {
      if (previous.phase !== 'active' || next.processContainmentRef !== previous.processContainmentRef ||
          next.boundaryEvidenceRef !== previous.boundaryEvidenceRef || next.leaseVersion !== previous.leaseVersion)
        mismatch('local inference revocation changed its original launch evidence');
    } else if (next.phase === 'retired') {
      if (next.retiredAt > now || next.leaseVersion !== previous.leaseVersion ||
          (next.retirementKind === 'no_spawn' ? previous.phase !== 'reserved' :
            previous.phase !== 'preactivated' && previous.phase !== 'revoking' || next.processContainmentRef !== previous.processContainmentRef ||
            next.boundaryEvidenceRef !== ('boundaryEvidenceRef' in previous ? previous.boundaryEvidenceRef : undefined) ||
            previous.phase === 'revoking' && next.quiesceId !== previous.quiesceId))
        mismatch('local inference retirement changed original containment, phase or lease');
    } else mismatch('local inference launch phase transition is unavailable');
  }
  const result = connection.prepare('UPDATE local_inference_launches SET phase=?,retired_at=?,row_json=? WHERE launch_id=? AND row_json=?')
    .run(next.phase, next.phase === 'retired' ? next.retiredAt : null, json(next), next.launchId, json(previous));
  if (result.changes !== 1n) mismatch('local inference launch CAS changed no original row');
}

type RowChange<T> = Readonly<{ previous?: T; next: T }>;
/** Called only by the installed local lifecycle producer. A terminal cycle
 * change owns the same synchronous transaction as its participant finalizer. */
export function commitLocalInferenceCut(driver: SqliteDriver, owner: StateOwnerContext, cut: Readonly<{
  cycle?: RowChange<Cycle>; launch?: RowChange<Launch>; metadata?: readonly PublishedArtifact[];
  assert?: (connection: SqliteConnection, now: string) => void;
  finalizeParticipants?: (connection: SqliteConnection, now: string) => void;
}>): void {
  const cycle = cut.cycle && { ...cut.cycle, next: decodeLocalInferenceCycle(cut.cycle.next) };
  const launch = cut.launch && { ...cut.launch, next: decodeLocalInferenceLaunch(cut.launch.next) };
  const terminal = cycle?.next.phase === 'active' || cycle?.next.phase === 'failed';
  if (terminal !== (cut.finalizeParticipants !== undefined)) throw new TypeError('local inference terminal cycle and participant finalizer must share one cut');
  let fence: TimeFenceAdvance | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow(); fence = advanceTimeFence(connection, owner.ownerEpoch, now);
    if (fence !== 'healthy') return;
    cut.assert?.(connection, now);
    for (const artifact of cut.metadata ?? []) insertArtifactMetadata(connection, artifact, now);
    if (launch?.previous) writeLaunch(connection, launch.previous, launch.next, now);
    if (cycle) writeCycle(connection, cycle.previous, cycle.next, now);
    if (launch && !launch.previous) writeLaunch(connection, undefined, launch.next, now);
    cut.finalizeParticipants?.(connection, now);
  });
  if (fence !== 'healthy') throw new KernelStorageError('LEASE_FENCED', 'local inference canonical time fence refused the commit');
}

export function appendLocalInferenceParticipant(cycle: Cycle, participant: LocalInferenceActivationParticipantV1): Cycle {
  if (!isCyclePending(cycle)) mismatch('local inference cycle already completed');
  const original = cycle.participants.find(item => localInferenceParticipantKey(item) === localInferenceParticipantKey(participant));
  if (original) {
    const { joinedAt: _old, ...retained } = original, { joinedAt: _new, ...candidate } = participant;
    requireEqual(retained, candidate, 'original local inference participant replay');
    return cycle;
  }
  if (cycle.participants.length >= LOCAL_INFERENCE_PARTICIPANTS)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'local inference participant capacity is exhausted');
  return localCycleData({ ...cycle, participants: [...cycle.participants, participant], rowVersion: cycle.rowVersion + 1 });
}
