// Test-only read diagnostic. Neither a SQLite row nor this projection creates
// StateOwner, worker, renewal or native containment authority.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, type BigIntStats } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, encodeCanonicalTime, identityHash, normalizeBoundedText, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { BoundWorkerLaunch, WorkspaceGenerationStateV1 } from '../../../src/kernel/types.js';
import { decodeWorkerIdentity, decodeWorkspaceGenerationSnapshotEvidence } from '../../../src/state/decoders.js';
import { decodeWorkerLaunch, decodeWorkspaceGenerationState } from '../../../src/state/invariants.js';
import { decodePublicationArenaBirth, decodePublicationPathProgressItem } from '../../../src/kernel/publication.js';
import { journalEntryFromRow, type JournalSqlRow } from '../../../src/state/repositories/journal.js';
import type { PublicationGenerationResourcesV1 } from '../../../src/kernel/publication.js';
import type { VerifierParentDomainDispatchClosureV1 } from '../../../src/state/verifier-unknown-retirement.js';
import { decodeVerifierParentDomainDispatchClosure as decodeVerifierParentEvidence } from '../../../src/state/verifier-unknown-retirement.js';

export type InstalledWorkerLeaseExpected = { uid: number; runId: string; launchId: string; leaseEpoch: number;
  runRevision: number; supervisorInstanceId: string; deadlineAt: string };
export type InstalledWorkerLeaseInspection = Readonly<{ diagnosticOnly: true; databaseIdentity: string;
  launchInvariantDigest: string; leaseVersion: number; leaseExpiresAt: string; observedAt: string }>;
export type InstalledWorkerIdentityInspection = Readonly<{ diagnosticOnly: true; databaseIdentity: string;
  launchIdentityDigest: string; runId: string; launchId: string; supervisorInstanceId: string; leaseEpoch: number;
  workerIdentityDigest: string; workspaceGenerationRef: string; processContainmentRef: string;
  generationId: string; generationIdentityDigest: string; pid: number; processStartToken: string;
  executableDigest: string; activatedAt: string; observedAt: string }>;
export type InstalledWorkerRetirementInspection = InstalledWorkerIdentityInspection & Readonly<{
  phase: 'retired'; generationWriteState: 'sealed'; generationPhase: 'sealed'; retiredAt: string;
  retirementEvidenceRef: string; snapshotEvidenceRef: string; snapshotEvidenceDigest: string; deathObservedAt: string }>;
export type InstalledWorkerRetirementBinding = Readonly<Pick<InstalledWorkerRetirementInspection,
  'launchId' | 'supervisorInstanceId' | 'leaseEpoch' | 'workspaceGenerationRef' | 'snapshotEvidenceRef' | 'snapshotEvidenceDigest' | 'retiredAt'>>;
const identityFields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink'] as const;
const refused = 'installed worker lease inspection refused';
const MAX_ENUMERATED_WORKER_LAUNCHES = 16;
function requireValue(value: unknown): asserts value { if (!value) throw new Error(refused); }
function identity(value: BigIntStats) {
  return Object.fromEntries(identityFields.map(field => [field, value[field].toString()]));
}

const objectFields = [...identityFields, 'size', 'mtimeNs', 'ctimeNs'] as const;
const sameMetadata = (left: BigIntStats, right: BigIntStats, fields: readonly (typeof objectFields)[number][] = identityFields) =>
  fields.every(field => left[field] === right[field]);
const boundedString = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 256;
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);

/** Held, bounded canonical objects are data only, never native capabilities. */
function readWorkerDiagnostic<T>(stateRoot: string, uid: number,
  read: (database: DatabaseSync, databaseIdentity: string, readCas: (ref: string) => unknown) => T): T {
  requireValue(Number.isSafeInteger(uid) && uid > 0);
  const filename = path.join(stateRoot, KERNEL_DATABASE_FILENAME), casPath = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
  const root = lstatSync(stateRoot, { bigint: true }), file = lstatSync(filename, { bigint: true });
  const cas = lstatSync(casPath, { bigint: true });
  for (const directory of [root, cas]) requireValue(directory.isDirectory() && !directory.isSymbolicLink() &&
    directory.uid === BigInt(uid) && (directory.mode & 0o7777n) === 0o700n);
  requireValue(file.isFile() && !file.isSymbolicLink() && file.uid === BigInt(uid) && file.nlink === 1n && (file.mode & 0o7777n) === 0o600n);
  const databaseIdentity = canonicalSha256({ root: identity(root), file: identity(file) });
  const held: number[] = [];
  let database: DatabaseSync | undefined;
  const stable = () => {
    requireValue(sameMetadata(root, lstatSync(stateRoot, { bigint: true })) && sameMetadata(root, fstatSync(held[0]!, { bigint: true })));
    requireValue(sameMetadata(cas, lstatSync(casPath, { bigint: true })) && sameMetadata(cas, fstatSync(held[1]!, { bigint: true })));
    requireValue(sameMetadata(file, lstatSync(filename, { bigint: true })));
  };
  try {
    for (const directory of [stateRoot, casPath]) held.push(openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    stable();
    database = new DatabaseSync(filename, { readOnly: true, allowExtension: false });
    database.exec('PRAGMA busy_timeout=1000');
    requireValue(database.prepare('PRAGMA user_version').get()?.user_version === KERNEL_STATE_SCHEMA_VERSION);
    const readCas = (ref: string) => {
      requireValue(digest(ref)); stable();
      const objectPath = path.join(casPath, ref), fd = openSync(objectPath, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
      try {
        const before = fstatSync(fd, { bigint: true });
        requireValue(before.isFile() && before.uid === BigInt(uid) && before.nlink === 1n &&
          (before.mode & 0o7777n) === 0o400n && before.size > 0n && before.size <= 65536n &&
          sameMetadata(before, lstatSync(objectPath, { bigint: true }), objectFields));
        const bytes = Buffer.alloc(Number(before.size) + 1);
        let used = 0;
        while (used < bytes.length) {
          const count = readSync(fd, bytes, used, bytes.length - used, used);
          if (!count) break;
          used += count;
        }
        requireValue(BigInt(used) === before.size && sameMetadata(before, fstatSync(fd, { bigint: true }), objectFields) &&
          sameMetadata(before, lstatSync(objectPath, { bigint: true }), objectFields));
        const retained = bytes.subarray(0, used), value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(retained));
        requireValue(canonicalSha256(value) === ref && canonicalJsonBytes(value).equals(retained)); stable();
        return value;
      } finally { closeSync(fd); }
    };
    const value = read(database, databaseIdentity, readCas); stable();
    return value;
  } finally {
    try { database?.close(); } finally { for (const fd of held.reverse()) closeSync(fd); }
  }
}

/** One actual readonly SQL cut, used only to arm the external crash actor or
 * record the first post-kill cut. A missing claim is not a missing resource. */
export function inspectInstalledPublicationClaim(stateRoot: string, uid: number, runId: string) {
  requireValue(boundedString(runId));
  return readWorkerDiagnostic(stateRoot, uid, (database, databaseIdentity, readCas) => {
    database.exec('BEGIN');
    const rows = database.prepare(`SELECT run_id,seq,op_id,op_kind,attempt,phase,
      CASE WHEN typeof(entry_json)='text' AND length(CAST(entry_json AS BLOB)) BETWEEN 1 AND 65536
      THEN entry_json ELSE NULL END AS entry_json FROM run_journal WHERE run_id=? ORDER BY seq LIMIT 5`).all(runId);
    requireValue(rows.length <= 4 && rows.every(row => typeof row.entry_json === 'string'));
    const journal = rows.map(row => journalEntryFromRow(row as JournalSqlRow));
    journal.forEach((row, index) => requireValue(row.runId === runId && row.seq === index + 1 && row.opKind === 'publish'));
    const claims = journal.filter(row => row.phase === 'dispatch_claimed');
    requireValue(claims.length <= 1);
    if (!claims.length) { database.exec('COMMIT'); return undefined; }
    const claim = claims[0]!;
    requireValue(claim.attempt === 0 && claim.evidenceRef && claim.evidenceDigest && claim.dispatchId && claim.stateOwnerEpoch);
    const birth = decodePublicationArenaBirth(readCas(claim.evidenceRef));
    requireValue(birth.deliveryRunId === runId && birth.opId === claim.opId && birth.dispatchId === claim.dispatchId &&
      birth.birthDigest === claim.evidenceDigest && birth.sequence === 'forward' && birth.attempt === 0);
    const items = database.prepare(`SELECT item_id,item_seq,payload_ref,kind,created_at FROM items WHERE run_id=? ORDER BY item_seq LIMIT 17`).all(runId);
    requireValue(items.length <= 16);
    const progress = items.filter(row => row.kind === 'publication_path_progress').map(row => {
      requireValue(typeof row.payload_ref === 'string'); const item = decodePublicationPathProgressItem(readCas(row.payload_ref));
      requireValue(item.runId === runId && item.itemId === row.item_id && item.createdAt === row.created_at); return { row, item };
    });
    const originalReceiptCommitted = journal.some(row => row.phase === 'completed' || row.phase === 'failed') ||
      progress.some(value => value.item.state === 'received_handoff');
    const result = Object.freeze({ diagnosticOnly: true, databaseIdentity, sqlCutDigest: canonicalSha256({ journal, items }),
      birth, claim, originalReceiptCommitted, journal, progress });
    database.exec('COMMIT'); return result;
  });
}

/** Strict recovery branch only. Retained data cannot replace the owning
 * campaign's independent observation of the actual PID/start lifetime. */
type RecoveredWorkerExpected = {
  runId: string; supervisorInstanceId: string; leaseEpoch: number;
  inspectorIdentityRef: string; inspectorIdentityDigest: string;
  resources: Extract<PublicationGenerationResourcesV1, { kind: 'genuinely_retired_from_verified_checkpoint' }>;
};
export type InstalledVerifierParentRetirementBinding = Omit<RecoveredWorkerExpected, 'resources'> & {
  evidence: VerifierParentDomainDispatchClosureV1;
};

export function inspectInstalledRecoveredWorkerRetirement(stateRoot: string, uid: number, expected: RecoveredWorkerExpected) {
  const { graph: _graph, ...projection } = inspectRecoveredWorkerRetirement(stateRoot, uid, expected);
  return Object.freeze(projection);
}

/** Same strict recovery reader, not a publication receipt or a child death.
 * Its actual worker lifetime still needs the campaign's independent /proc cut. */
export function inspectInstalledVerifierParentRetirement(stateRoot: string, uid: number, expected: InstalledVerifierParentRetirementBinding) {
  closedRecord(expected, ['runId', 'supervisorInstanceId', 'leaseEpoch', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidence']);
  const evidence = decodeVerifierParentEvidence(expected.evidence), closure = evidence.closure;
  requireValue(evidence.runId === expected.runId && closure.claimingSupervisorInstanceId === expected.supervisorInstanceId &&
    closure.leaseEpoch === expected.leaseEpoch);
  return inspectRecoveredWorkerRetirement(stateRoot, uid, {
    runId: expected.runId, supervisorInstanceId: expected.supervisorInstanceId, leaseEpoch: expected.leaseEpoch,
    inspectorIdentityRef: expected.inspectorIdentityRef, inspectorIdentityDigest: expected.inspectorIdentityDigest,
    resources: { kind: 'verifier_parent_domain', workerLaunchId: closure.workerLaunchId, generationRef: closure.generationRef,
      quarantineEvidenceRef: closure.quarantineEvidenceRef, retirementEvidenceRef: closure.retirementEvidenceRef },
  }, evidence);
}

function inspectRecoveredWorkerRetirement(stateRoot: string, uid: number, expected: Omit<RecoveredWorkerExpected, 'resources'> & {
  resources: RecoveredWorkerExpected['resources'] | { kind: 'verifier_parent_domain'; workerLaunchId: string; generationRef: string;
    quarantineEvidenceRef: string; retirementEvidenceRef: string };
}, verifierEvidence?: VerifierParentDomainDispatchClosureV1) {
  const closedValue = (value: object, keys: readonly string[]) => { closedRecord(value, keys); };
  try {
    closedRecord(expected, ['runId', 'supervisorInstanceId', 'leaseEpoch', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'resources']);
    closedRecord(expected.resources, ['kind', 'workerLaunchId', 'generationRef',
      ...(expected.resources.kind === 'verifier_parent_domain' ? [] : ['sourceCheckpointId']), 'quarantineEvidenceRef', 'retirementEvidenceRef']);
    requireValue(boundedString(expected.runId) && boundedString(expected.supervisorInstanceId) && Number.isSafeInteger(expected.leaseEpoch) && expected.leaseEpoch > 0 &&
      digest(expected.inspectorIdentityRef) && digest(expected.inspectorIdentityDigest));
    const resources = expected.resources;
    requireValue((resources.kind === 'genuinely_retired_from_verified_checkpoint' && !verifierEvidence && boundedString(resources.sourceCheckpointId) ||
      resources.kind === 'verifier_parent_domain' && verifierEvidence) && boundedString(resources.workerLaunchId) &&
      [resources.generationRef, resources.quarantineEvidenceRef, resources.retirementEvidenceRef].every(digest));
    return readWorkerDiagnostic(stateRoot, uid, (database, databaseIdentity, readCas) => {
      database.exec('BEGIN');
      const { row, launch, generation } = readWorkerRows(database, expected.runId, resources.workerLaunchId);
      requireValue(launch.phase === 'retired' && launch.generationWriteState === 'fenced_reconciling' && launch.retiredAt && launch.retirementEvidenceRef &&
        launch.supervisorInstanceId === expected.supervisorInstanceId && launch.leaseEpoch === expected.leaseEpoch &&
        generation.phase === 'retired' && generation.generationRef === resources.generationRef &&
        (resources.kind === 'verifier_parent_domain' || generation.sourceCheckpointId === resources.sourceCheckpointId) && generation.retirementEvidenceRef === resources.retirementEvidenceRef &&
        row.active_worker_launch_id === null);
      requireValue(!database.prepare("SELECT 1 FROM worker_launches WHERE phase!='retired' AND json_extract(row_json,'$.workspaceGenerationRef')=? LIMIT 1")
        .get(generation.generationRef));
      const read = (ref: string): Record<string, any> => {
        const value = readCas(ref); requireValue(value && typeof value === 'object' && !Array.isArray(value)); return value as Record<string, any>;
      };
      const evidence = (ref: string, expectedDigest?: string) => {
        const value = read(ref); requireValue(value.schemaVersion === 1 && value.evidenceDigest === digestOmitting(value, 'evidenceDigest') &&
          (expectedDigest === undefined || value.evidenceDigest === expectedDigest)); parseCanonicalTime(value.observedAt); return value;
      };
      const retired = evidence(resources.retirementEvidenceRef, generation.retirementEvidenceDigest);
      closedValue(retired, ['schemaVersion', 'format', 'runId', 'generationRef', 'generationIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest',
        'observedAt', 'evidenceDigest', 'fromPhase', 'quarantineEvidenceRef', 'quarantineEvidenceDigest', 'sourceQuarantinedRowVersion',
        'activeRunPointerCount', 'nonretiredWorkerLaunchCount', 'liveContainmentCount', 'activeMountCount', 'releasableBrokerClaimCount']);
      // prepareWorkerRecoveryTerminalPlan observes retirement before its sole
      // terminal transaction retires all three rows. Ordinary recovery still
      // requires an already-retired launch; only the exact verifier closure
      // may use the fresh, atomic terminal commit branch.
      const atomicVerifierCommit = verifierEvidence !== undefined && retired.observedAt < launch.retiredAt;
      if (atomicVerifierCommit) {
        const commits = database.prepare('SELECT updated_at FROM runs WHERE id=? LIMIT 2').all(expected.runId);
        requireValue(commits.length === 1 && commits[0]!.updated_at === launch.retiredAt && row.lease_epoch === launch.leaseEpoch &&
          launch.retiredAt === generation.updatedAt &&
          parseCanonicalTime(generation.updatedAt) - parseCanonicalTime(retired.observedAt) <= 5000);
      }
      requireValue(retired.format === 'cliq-workspace-generation-retirement-evidence-v1' && retired.fromPhase === 'quarantined' &&
        retired.runId === expected.runId && retired.generationRef === generation.generationRef && retired.generationIdentityDigest === generation.generationIdentityDigest &&
        retired.quarantineEvidenceRef === resources.quarantineEvidenceRef && retired.sourceQuarantinedRowVersion === generation.rowVersion - 1 &&
        (atomicVerifierCommit || retired.observedAt >= launch.retiredAt) && retired.observedAt <= generation.updatedAt &&
        ['activeRunPointerCount', 'nonretiredWorkerLaunchCount', 'liveContainmentCount', 'activeMountCount', 'releasableBrokerClaimCount'].every(key => retired[key] === 0));
      const quarantine = evidence(resources.quarantineEvidenceRef, retired.quarantineEvidenceDigest);
      closedValue(quarantine, ['schemaVersion', 'format', 'runId', 'generationRef', 'generationIdentityDigest', 'sourceRowVersion', 'observedState',
        'inspectorIdentityRef', 'inspectorIdentityDigest', 'quarantineCanonicalRootRelativePath', 'quarantineDeviceId', 'quarantineFileId',
        'originalLocatorAbsent', 'renameNoReplace', 'directoryFsyncComplete', 'observedAt', 'evidenceDigest', 'reason', 'fromPhase',
        'workerRecoveryEvidenceRef', 'workerRecoveryEvidenceDigest']);
      requireValue(quarantine.format === 'cliq-workspace-generation-quarantine-evidence-v1' && quarantine.reason === 'worker_recovery' &&
        quarantine.fromPhase === 'fenced_reconciling' && quarantine.runId === expected.runId && quarantine.generationRef === generation.generationRef &&
        quarantine.generationIdentityDigest === generation.generationIdentityDigest && quarantine.originalLocatorAbsent === true &&
        quarantine.renameNoReplace === true && quarantine.directoryFsyncComplete === true &&
        quarantine.quarantineCanonicalRootRelativePath === `quarantine/workspace-generations/${identityHash(generation.generationId, String(quarantine.sourceRowVersion))}` &&
        /^(0|[1-9][0-9]*)$/u.test(quarantine.quarantineDeviceId) && /^(0|[1-9][0-9]*)$/u.test(quarantine.quarantineFileId));
      const recovery = evidence(quarantine.workerRecoveryEvidenceRef, quarantine.workerRecoveryEvidenceDigest);
      closedValue(recovery, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'oldWorkerLaunchId', 'oldLeaseEpoch', 'oldWorkerIdentityDigest',
        'processContainmentRef', 'containmentDeathEvidenceRef', 'containmentDeathEvidenceDigest', 'workspaceGenerationRef', 'generationTreeDigest',
        'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'generationDisposition']);
      requireValue(recovery.format === 'cliq-worker-recovery-evidence-v1' && recovery.generationDisposition === 'quarantined' &&
        recovery.runId === expected.runId && recovery.oldWorkerLaunchId === launch.launchId && recovery.oldLeaseEpoch === launch.leaseEpoch &&
        recovery.oldWorkerIdentityDigest === launch.workerIdentityDigest && recovery.processContainmentRef === launch.processContainmentRef &&
        recovery.workspaceGenerationRef === generation.generationRef && recovery.generationTreeDigest === generation.lastVerifiedTreeDigest &&
        recovery.observedAt <= quarantine.observedAt && quarantine.observedAt <= launch.retiredAt);
      const wrapper = evidence(launch.retirementEvidenceRef), death = evidence(recovery.containmentDeathEvidenceRef, recovery.containmentDeathEvidenceDigest);
      closedValue(wrapper, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'waitingSubjectDigest', 'probeKind', 'probeOrdinal', 'probeNonceDigest',
        'probeDispatchDigest', 'probeStartedAt', 'probeDeadlineAt', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest',
        'outcome', 'subjectEvidenceKind', 'subjectEvidenceRef', 'subjectEvidenceDigest']);
      requireValue(wrapper.format === 'cliq-reconciliation-probe-evidence-v1' && wrapper.runId === expected.runId &&
        wrapper.outcome === 'subject_observation' && wrapper.subjectEvidenceKind === 'worker_recovery' &&
        wrapper.subjectEvidenceRef === quarantine.workerRecoveryEvidenceRef && wrapper.subjectEvidenceDigest === recovery.evidenceDigest &&
        wrapper.waitingSubjectRef === recovery.waitingSubjectRef && wrapper.waitingSubjectDigest === recovery.waitingSubjectRef &&
        wrapper.observedAt === recovery.observedAt);
      const wait = read(recovery.waitingSubjectRef), dispatch = wait.probeState?.dispatch;
      closedValue(wait, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject', 'probeState']);
      closedValue(wait.subject, ['kind', 'oldWorkerLaunchId', 'oldLeaseEpoch', 'oldWorkerIdentity', 'processContainmentRef', 'workspaceGenerationRef', 'openInvocationRefs']);
      closedValue(wait.probeState, ['phase', 'automaticProbeCount', 'userProbeCount', 'dispatch']);
      closedValue(dispatch, ['schemaVersion', 'format', 'runId', 'reconciliationSubjectDigest', 'probeKind', 'probeOrdinal', 'probeNonceDigest',
        'probeStartedAt', 'probeDeadlineAt', 'owningSupervisorInstanceId', 'dispatchDigest', 'subjectKind', 'inspectorTaskId', 'inspectionTargetDigest']);
      requireValue(digest(wait.frontierRef) && Number.isSafeInteger(wait.createdFromRevision) && wait.createdFromRevision > 0 &&
        parseCanonicalTime(wait.createdAt) <= parseCanonicalTime(dispatch.probeStartedAt) &&
        dispatch.schemaVersion === 1 && dispatch.format === 'cliq-reconciliation-probe-dispatch-v1' &&
        dispatch.reconciliationSubjectDigest === canonicalSha256(wait.subject) && digest(dispatch.probeNonceDigest) &&
        dispatch.inspectorTaskId === identityHash(expected.runId, canonicalSha256(wait.subject), 'automatic', dispatch.probeOrdinal, dispatch.probeNonceDigest) &&
        dispatch.owningSupervisorInstanceId === death.inspectorSupervisorInstanceId);
      requireValue(Array.isArray(wait.subject.openInvocationRefs) && wait.subject.openInvocationRefs.length <= 16);
      let priorSeq = 0;
      for (const ref of wait.subject.openInvocationRefs) {
        requireValue(digest(ref)); const witness = read(ref);
        const journal = database.prepare(`SELECT run_id,seq,op_id,op_kind,attempt,phase,
          CASE WHEN typeof(entry_json)='text' AND length(CAST(entry_json AS BLOB)) BETWEEN 1 AND 65536
          THEN entry_json ELSE NULL END AS entry_json FROM run_journal WHERE run_id=? AND seq=? LIMIT 2`).all(expected.runId, witness.seq);
        requireValue(journal.length === 1 && typeof journal[0]!.entry_json === 'string');
        const actual = journalEntryFromRow(journal[0] as JournalSqlRow);
        requireValue(actual.phase === 'prepared' && actual.seq > priorSeq && actual.timestamp <= dispatch.probeStartedAt && canonicalSha256(actual) === ref);
        priorSeq = actual.seq;
      }
      requireValue(wait.schemaVersion === 1 && wait.kind === 'reconciliation' && wait.runId === expected.runId &&
        wait.subject?.kind === 'worker_death' && wait.subject.oldWorkerLaunchId === launch.launchId &&
        wait.subject.oldLeaseEpoch === launch.leaseEpoch && wait.subject.oldWorkerIdentity === launch.workerIdentityDigest &&
        wait.subject.processContainmentRef === launch.processContainmentRef && wait.subject.workspaceGenerationRef === generation.generationRef &&
        wait.probeState?.phase === 'automatic_in_flight' && wait.probeState.userProbeCount === 0 &&
        dispatch?.subjectKind === 'worker_recovery' && dispatch.dispatchDigest === digestOmitting(dispatch, 'dispatchDigest') &&
        dispatch.runId === expected.runId && dispatch.probeKind === 'automatic' && dispatch.probeOrdinal === wait.probeState.automaticProbeCount &&
        dispatch.probeOrdinal >= 1 && dispatch.probeOrdinal <= 8 && dispatch.probeDeadlineAt === new Date(parseCanonicalTime(dispatch.probeStartedAt) + 30000).toISOString() &&
        wrapper.probeKind === 'automatic' && wrapper.probeOrdinal === dispatch.probeOrdinal && wrapper.probeNonceDigest === dispatch.probeNonceDigest &&
        wrapper.probeDispatchDigest === dispatch.dispatchDigest && wrapper.probeStartedAt === dispatch.probeStartedAt && wrapper.probeDeadlineAt === dispatch.probeDeadlineAt &&
        death.observedAt >= dispatch.probeStartedAt && death.observedAt <= recovery.observedAt && recovery.observedAt <= dispatch.probeDeadlineAt &&
        quarantine.observedAt < dispatch.probeDeadlineAt && (!atomicVerifierCommit || launch.retiredAt < dispatch.probeDeadlineAt));
      const anchor = decodeWorkspaceGenerationState(readCas(dispatch.inspectionTargetDigest)); requireValue(anchor.phase === 'fenced_reconciling');
      requireValue(anchor.generationRef === generation.generationRef && anchor.generationIdentityDigest === generation.generationIdentityDigest &&
        anchor.activeWorkerLaunchId === launch.launchId && anchor.leaseEpoch === launch.leaseEpoch &&
        anchor.sourceCheckpointId === generation.sourceCheckpointId && anchor.sourceWorkspaceStateRef === generation.sourceWorkspaceStateRef &&
        quarantine.sourceRowVersion === anchor.rowVersion + 1);
      const containment = read(launch.processContainmentRef!);
      closedValue(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner', 'launchNonceDigest',
        'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']);
      requireValue(death.kind === 'containment_all_descendants_dead' && death.containmentRef === launch.processContainmentRef &&
        death.planRef === launch.containmentPlanRef && death.sandboxLaunchSpecRef === launch.sandboxLaunchSpecRef &&
        death.launchNonceDigest === launch.spawnNonceDigest && death.sandboxLaunchSpecDigest === containment.sandboxLaunchSpecDigest &&
        canonicalSha256(death.owner) === canonicalSha256({ kind: 'worker_activation', runId: expected.runId,
          intendedLeaseEpoch: expected.leaseEpoch, workerLaunchId: launch.launchId }) &&
        canonicalSha256(containment.owner) === canonicalSha256(death.owner) &&
        canonicalSha256(containment.filesystemBinding) === canonicalSha256({ kind: 'run-generation', generationRef: generation.generationRef }));
      requireValue(death.backend?.kind === 'linux' && canonicalSha256(death.backend) === canonicalSha256({ ...containment.backend,
        cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }));
      for (const fact of [retired, quarantine, recovery, death, wrapper]) requireValue(fact.inspectorIdentityRef === expected.inspectorIdentityRef &&
        fact.inspectorIdentityDigest === expected.inspectorIdentityDigest);
      if (verifierEvidence) {
        const closure = verifierEvidence.closure;
        requireValue(closure.parentContainmentRef === launch.processContainmentRef && closure.parentDeathEvidenceRef === recovery.containmentDeathEvidenceRef &&
          closure.parentDeathEvidenceDigest === death.evidenceDigest && closure.quarantineEvidenceDigest === quarantine.evidenceDigest &&
          closure.retirementEvidenceDigest === retired.evidenceDigest && verifierEvidence.observedAt === retired.observedAt &&
          quarantine.observedState.kind === 'complete_tree' && quarantine.observedState.treeDigest === generation.lastVerifiedTreeDigest);
        requireValue(row.status === 'cancelled' && row.cancel_requested === 1 && digest(row.stop_intent_ref));
      }
      const current = workerProjection(databaseIdentity, launch, generation, readCas);
      database.exec('COMMIT');
      return Object.freeze({ ...current, generationPhase: 'retired' as const, generationWriteState: 'fenced_reconciling' as const,
        retiredAt: launch.retiredAt, retirementEvidenceRef: resources.retirementEvidenceRef,
        quarantineEvidenceRef: resources.quarantineEvidenceRef, containmentDeathEvidenceRef: recovery.containmentDeathEvidenceRef,
        deathObservedAt: death.observedAt as string, quarantinePath: quarantine.quarantineCanonicalRootRelativePath as string,
        graph: { launch, generation, retired, quarantine, recovery, death, containment, runRow: row } });
    });
  } catch { throw new Error('installed recovered worker retirement inspection refused'); }
}

function readWorkerRows(database: DatabaseSync, runId: string, launchId: string) {
  const rows = database.prepare(`SELECT r.id AS run_id, r.active_worker_launch_id, r.status, r.lease_epoch,
    r.revision, r.cancel_requested, r.stop_intent_ref, r.deadline_at,
    w.launch_id, w.run_id AS worker_run_id, w.phase AS worker_phase, w.retired_at,
    CASE WHEN typeof(w.row_json) = 'text' AND length(CAST(w.row_json AS BLOB)) BETWEEN 1 AND 65536
      THEN w.row_json ELSE NULL END AS worker_json,
    g.generation_id, g.run_id AS generation_run_id, g.phase AS generation_phase, g.row_version,
    CASE WHEN typeof(g.row_json) = 'text' AND length(CAST(g.row_json AS BLOB)) BETWEEN 1 AND 65536
      THEN g.row_json ELSE NULL END AS generation_json
    FROM runs r JOIN worker_launches w ON w.run_id = r.id
    JOIN workspace_generations g ON g.run_id = w.run_id AND
      json_extract(CASE WHEN typeof(g.row_json) = 'text' AND length(CAST(g.row_json AS BLOB)) BETWEEN 1 AND 65536
        THEN g.row_json ELSE NULL END, '$.generationRef') =
      json_extract(CASE WHEN typeof(w.row_json) = 'text' AND length(CAST(w.row_json AS BLOB)) BETWEEN 1 AND 65536
        THEN w.row_json ELSE NULL END, '$.workspaceGenerationRef')
    WHERE r.id = ? AND w.launch_id = ? LIMIT 2`).all(runId, launchId);
  requireValue(rows.length === 1);
  const row = rows[0]!;
  requireValue(typeof row.worker_json === 'string' && typeof row.generation_json === 'string');
  const launch = decodeWorkerLaunch(parseJsonStrict(row.worker_json));
  const generation = decodeWorkspaceGenerationState(parseJsonStrict(row.generation_json));
  requireValue(launch.retirementKind !== 'preparation' && launch.phase !== 'preparing' &&
    row.run_id === runId && row.worker_run_id === runId && row.generation_run_id === runId &&
    row.launch_id === launchId && launch.launchId === launchId && launch.runId === runId &&
    row.worker_phase === launch.phase && row.retired_at === (launch.retiredAt ?? null) &&
    row.generation_id === generation.generationId && generation.runId === runId && row.generation_phase === generation.phase &&
    row.row_version === generation.rowVersion && generation.generationRef === launch.workspaceGenerationRef);
  return { row, launch: launch as BoundWorkerLaunch, generation };
}

function workerProjection(databaseIdentity: string, launch: BoundWorkerLaunch, generation: WorkspaceGenerationStateV1,
  readCas: (ref: string) => unknown): InstalledWorkerIdentityInspection {
  requireValue(launch.workerIdentityDigest && launch.processContainmentRef && launch.leaseEpoch && launch.activatedAt);
  const worker = decodeWorkerIdentity(readCas(launch.workerIdentityDigest));
  requireValue(worker.launchId === launch.launchId && worker.supervisorInstanceId === launch.supervisorInstanceId &&
    worker.intendedLeaseEpoch === launch.leaseEpoch && worker.processContainmentRef === launch.processContainmentRef &&
    worker.spawnNonceDigest === launch.spawnNonceDigest && worker.activationNonceDigest === launch.activationNonceDigest &&
    /^linux-proc-start-ticks:(?:0|[1-9][0-9]*)$/u.test(worker.processStartToken));
  const { phase: _phase, generationWriteState: _writeState, leaseVersion: _version, leaseExpiresAt: _expiry,
    quiesceId: _quiesce, retiredAt: _retiredAt, retirementEvidenceRef: _retirement, ...launchIdentity } = launch;
  const source = { generationId: generation.generationId, generationRef: generation.generationRef,
    generationIdentityDigest: generation.generationIdentityDigest, sourceCheckpointId: generation.sourceCheckpointId,
    sourceWorkspaceStateRef: generation.sourceWorkspaceStateRef, sourceWorkspaceStateDigest: generation.sourceWorkspaceStateDigest };
  return Object.freeze({ diagnosticOnly: true, databaseIdentity, launchIdentityDigest: canonicalSha256({ launchIdentity, source }),
    runId: launch.runId, launchId: launch.launchId, supervisorInstanceId: launch.supervisorInstanceId, leaseEpoch: launch.leaseEpoch,
    workerIdentityDigest: launch.workerIdentityDigest, workspaceGenerationRef: launch.workspaceGenerationRef,
    processContainmentRef: launch.processContainmentRef, generationId: generation.generationId,
    generationIdentityDigest: generation.generationIdentityDigest, pid: worker.pid, processStartToken: worker.processStartToken,
    executableDigest: worker.executableDigest, activatedAt: launch.activatedAt, observedAt: encodeCanonicalTime(Date.now()) });
}

/** Captures data for an independent /proc observation before releasing the
 * already owned response. No process observation or execution authority here. */
export function inspectInstalledWorkerIdentity(stateRoot: string,
  expected: InstalledWorkerLeaseExpected): InstalledWorkerIdentityInspection {
  try {
    requireValue(Object.keys(expected).sort().join(',') === 'deadlineAt,launchId,leaseEpoch,runId,runRevision,supervisorInstanceId,uid');
    for (const value of [expected.leaseEpoch, expected.runRevision]) requireValue(Number.isSafeInteger(value) && value > 0);
    for (const value of [expected.runId, expected.launchId, expected.supervisorInstanceId]) requireValue(boundedString(value));
    parseCanonicalTime(expected.deadlineAt);
    return readWorkerDiagnostic(stateRoot, expected.uid, (database, databaseIdentity, readCas) => {
      const { row, launch, generation } = readWorkerRows(database, expected.runId, expected.launchId);
      const now = encodeCanonicalTime(Date.now());
      requireValue(row.active_worker_launch_id === expected.launchId && row.status === 'running' &&
        row.lease_epoch === expected.leaseEpoch && row.revision === expected.runRevision && row.cancel_requested === 0 &&
        row.stop_intent_ref === null && row.deadline_at === expected.deadlineAt && launch.phase === 'activated' &&
        launch.generationWriteState === 'active' && launch.supervisorInstanceId === expected.supervisorInstanceId &&
        launch.leaseEpoch === expected.leaseEpoch && launch.leaseExpiresAt && launch.leaseExpiresAt > now &&
        launch.leaseExpiresAt <= expected.deadlineAt && generation.phase === 'active' &&
        generation.activeWorkerLaunchId === launch.launchId && generation.leaseEpoch === launch.leaseEpoch);
      return workerProjection(databaseIdentity, launch, generation, readCas);
    });
  } catch { throw new Error('installed worker identity inspection refused'); }
}

const projectionKeys = ['diagnosticOnly', 'databaseIdentity', 'launchIdentityDigest', 'runId', 'launchId', 'supervisorInstanceId',
  'leaseEpoch', 'workerIdentityDigest', 'workspaceGenerationRef', 'processContainmentRef', 'generationId', 'generationIdentityDigest',
  'pid', 'processStartToken', 'executableDigest', 'activatedAt', 'observedAt'];
function closedRecord(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

/** The exact original normal seal, not a recovery/preparation/GC validator.
 * This only checks retained declarations. Independent observation of the
 * captured PID/start lifetime is required; all-descendant death is not proved. */
export function inspectInstalledWorkerRetirement(stateRoot: string, uid: number,
  original: InstalledWorkerIdentityInspection): InstalledWorkerRetirementInspection {
  try {
    closedRecord(original, projectionKeys);
    requireValue(original.diagnosticOnly === true);
    for (const value of [original.databaseIdentity, original.launchIdentityDigest, original.workerIdentityDigest,
      original.workspaceGenerationRef, original.processContainmentRef, original.generationIdentityDigest, original.executableDigest]) requireValue(digest(value));
    for (const value of [original.runId, original.launchId, original.supervisorInstanceId, original.generationId]) requireValue(boundedString(value));
    for (const value of [original.leaseEpoch, original.pid]) requireValue(Number.isSafeInteger(value) && value > 0);
    requireValue(/^linux-proc-start-ticks:(?:0|[1-9][0-9]*)$/u.test(original.processStartToken));
    parseCanonicalTime(original.activatedAt); parseCanonicalTime(original.observedAt);
    return readRetiredWorkerHistory(stateRoot, uid, original, original);
  } catch { throw new Error('installed worker retirement inspection refused'); }
}

/** Retained data only, for an exact launch selected by its original invocation.
 * Unlike the live-identity API, this makes no claim to have observed the worker
 * before retirement. Full Run recovery and independent death checks remain the
 * owning campaign's responsibility; a missing row is never proof of retirement. */
export function inspectInstalledWorkerRetirementHistory(stateRoot: string, uid: number,
  expected: Readonly<{ runId: string; launchId: string; retirement?: InstalledWorkerRetirementBinding }>): InstalledWorkerRetirementInspection {
  try {
    const bound = Object.hasOwn(expected, 'retirement');
    closedRecord(expected, bound ? ['runId', 'launchId', 'retirement'] : ['runId', 'launchId']);
    requireValue(boundedString(expected.runId) && boundedString(expected.launchId));
    const observed = readRetiredWorkerHistory(stateRoot, uid, expected);
    if (bound) {
      const keys = ['launchId', 'supervisorInstanceId', 'leaseEpoch', 'workspaceGenerationRef',
        'snapshotEvidenceRef', 'snapshotEvidenceDigest', 'retiredAt'] as const;
      closedRecord(expected.retirement, keys);
      requireValue(keys.every(key => expected.retirement![key] === observed[key]));
    }
    return observed;
  } catch { throw new Error('installed worker retirement history inspection refused'); }
}

/** Original identifiers only, not worker/retirement evidence. A known empty
 * Run is distinguished from a missing Run; every returned launch still needs
 * the complete retained seal reader and independent process checks. Sixteen
 * is this fixed campaign diagnostic's bound, not a production Run limit. */
export function inspectInstalledWorkerLaunchIds(stateRoot: string, uid: number, runId: string): Readonly<{
  diagnosticOnly: true; databaseIdentity: string; runId: string; launchIds: readonly string[];
}> {
  try {
    requireValue(typeof runId === 'string' && normalizeBoundedText(runId, 1, 128) === runId);
    return readWorkerDiagnostic(stateRoot, uid, (database, databaseIdentity) => {
      const rows = database.prepare(`SELECT r.id AS run_id,
        CASE WHEN typeof(w.launch_id)='text' AND length(CAST(w.launch_id AS BLOB)) BETWEEN 1 AND 128
          THEN w.launch_id ELSE NULL END AS launch_id, w.run_id AS worker_run_id
        FROM runs r LEFT JOIN worker_launches w ON w.run_id=r.id
        WHERE r.id=? ORDER BY w.launch_id LIMIT ?`).all(runId, MAX_ENUMERATED_WORKER_LAUNCHES + 1);
      requireValue(rows.length > 0 && rows.length <= MAX_ENUMERATED_WORKER_LAUNCHES);
      const launchIds: string[] = [];
      for (const row of rows) {
        requireValue(row.run_id === runId);
        if (row.launch_id === null) { requireValue(rows.length === 1 && row.worker_run_id === null); continue; }
        if (typeof row.launch_id !== 'string') throw new Error('invalid original worker identifier');
        requireValue(row.worker_run_id === runId &&
          normalizeBoundedText(row.launch_id, 1, 128) === row.launch_id && !launchIds.includes(row.launch_id));
        launchIds.push(row.launch_id);
      }
      return Object.freeze({ diagnosticOnly: true as const, databaseIdentity, runId, launchIds: Object.freeze(launchIds) });
    });
  } catch { throw new Error('installed worker launch enumeration refused'); }
}

function readRetiredWorkerHistory(stateRoot: string, uid: number, expected: Readonly<{ runId: string; launchId: string }>,
  original?: InstalledWorkerIdentityInspection): InstalledWorkerRetirementInspection {
  return readWorkerDiagnostic(stateRoot, uid, (database, databaseIdentity, readCas) => {
    const { launch, generation } = readWorkerRows(database, expected.runId, expected.launchId);
    requireValue(launch.phase === 'retired' && launch.generationWriteState === 'sealed' && launch.retiredAt &&
      launch.retirementEvidenceRef && generation.phase === 'sealed' && generation.updatedAt === launch.retiredAt);
    const current = workerProjection(databaseIdentity, launch, generation, readCas);
    requireValue(launch.retiredAt <= current.observedAt);
    if (original) {
      const { observedAt: _originalTime, ...captured } = original, { observedAt: _observedAt, ...retained } = current;
      requireValue(canonicalSha256(captured) === canonicalSha256(retained) && launch.retiredAt >= original.observedAt);
    }
    const snapshot = decodeWorkspaceGenerationSnapshotEvidence(readCas(generation.snapshotEvidenceRef));
    requireValue(snapshot.purpose === 'sealed_to_checkpoint' && snapshot.runId === current.runId &&
      snapshot.generationRef === current.workspaceGenerationRef && snapshot.generationIdentityDigest === current.generationIdentityDigest &&
      snapshot.evidenceDigest === generation.snapshotEvidenceDigest && snapshot.treeDigest === generation.lastVerifiedTreeDigest &&
      snapshot.observedAt >= current.activatedAt && snapshot.observedAt <= launch.retiredAt);
    const death = readCas(launch.retirementEvidenceRef);
    closedRecord(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest',
      'owner', 'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']);
    requireValue(death.schemaVersion === 1 && death.kind === 'containment_all_descendants_dead' &&
      death.evidenceDigest === digestOmitting(death, 'evidenceDigest') && death.containmentRef === current.processContainmentRef &&
      death.planRef === launch.containmentPlanRef && death.sandboxLaunchSpecRef === launch.sandboxLaunchSpecRef &&
      death.launchNonceDigest === launch.spawnNonceDigest && boundedString(death.inspectorSupervisorInstanceId));
    for (const value of [death.sandboxLaunchSpecDigest, death.inspectorIdentityRef, death.inspectorIdentityDigest, death.evidenceDigest]) requireValue(digest(value));
    closedRecord(death.owner, ['kind', 'runId', 'intendedLeaseEpoch', 'workerLaunchId']);
    requireValue(death.owner.kind === 'worker_activation' && death.owner.runId === current.runId &&
      death.owner.intendedLeaseEpoch === current.leaseEpoch && death.owner.workerLaunchId === current.launchId);
    const identityKeys = ['pidNamespaceReservationId', 'pidNamespaceId', 'cgroupPath', 'cgroupId', 'namespaceInitStartToken', 'subreaperStartToken'];
    closedRecord(death.backend, ['kind', ...identityKeys, 'cgroupPopulated', 'namespaceInitDeadAndReaped', 'remainingTrackedDescendants']);
    const backend = death.backend;
    requireValue(backend.kind === 'linux' && identityKeys.every(key => typeof backend[key] === 'string' &&
      (backend[key] as string).length > 0 && (backend[key] as string).length <= 4096) &&
      backend.cgroupPopulated === 0 && backend.namespaceInitDeadAndReaped === true && backend.remainingTrackedDescendants === 0);
    const containment = readCas(current.processContainmentRef);
    closedRecord(containment, ['schemaVersion', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner',
      'filesystemBinding', 'launchNonceDigest', 'backend', 'createdAt']);
    requireValue(containment.schemaVersion === 1 && containment.planRef === death.planRef &&
      containment.sandboxLaunchSpecRef === death.sandboxLaunchSpecRef && containment.sandboxLaunchSpecDigest === death.sandboxLaunchSpecDigest &&
      containment.launchNonceDigest === death.launchNonceDigest && canonicalSha256(containment.owner) === canonicalSha256(death.owner) &&
      canonicalSha256(containment.filesystemBinding) === canonicalSha256({ kind: 'run-generation', generationRef: current.workspaceGenerationRef }));
    closedRecord(containment.backend, ['kind', ...identityKeys]);
    requireValue(containment.backend.kind === backend.kind && identityKeys.every(key =>
      (containment.backend as Record<string, unknown>)[key] === backend[key]));
    requireValue(typeof containment.createdAt === 'string'); parseCanonicalTime(containment.createdAt);
    requireValue(containment.createdAt <= current.activatedAt);
    requireValue(typeof death.observedAt === 'string'); parseCanonicalTime(death.observedAt);
    requireValue(death.observedAt >= snapshot.observedAt && death.observedAt <= launch.retiredAt);
    return Object.freeze({ ...current, phase: 'retired', generationWriteState: 'sealed', generationPhase: 'sealed',
      retiredAt: launch.retiredAt, retirementEvidenceRef: launch.retirementEvidenceRef,
      snapshotEvidenceRef: generation.snapshotEvidenceRef, snapshotEvidenceDigest: generation.snapshotEvidenceDigest,
      deathObservedAt: death.observedAt });
  });
}

/** A fresh short-lived readonly connection observes one joined SQL cut. */
export function inspectInstalledWorkerLease(stateRoot: string,
  expected: InstalledWorkerLeaseExpected): InstalledWorkerLeaseInspection {
  try {
    requireValue(Object.keys(expected).sort().join(',') ===
      'deadlineAt,launchId,leaseEpoch,runId,runRevision,supervisorInstanceId,uid');
    for (const value of [expected.uid, expected.leaseEpoch, expected.runRevision])
      requireValue(Number.isSafeInteger(value) && value > 0);
    for (const value of [expected.runId, expected.launchId, expected.supervisorInstanceId])
      requireValue(typeof value === 'string' && value.length > 0 && value.length <= 256);
    requireValue(typeof expected.deadlineAt === 'string'); parseCanonicalTime(expected.deadlineAt);
    const filename = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
    const root = lstatSync(stateRoot, { bigint: true }), file = lstatSync(filename, { bigint: true });
    requireValue(root.isDirectory() && !root.isSymbolicLink() && root.uid === BigInt(expected.uid) && (root.mode & 0o7777n) === 0o700n);
    requireValue(file.isFile() && !file.isSymbolicLink() && file.uid === BigInt(expected.uid) && file.nlink === 1n && (file.mode & 0o7777n) === 0o600n);
    const databaseIdentity = canonicalSha256({ root: identity(root), file: identity(file) });
    const database = new DatabaseSync(filename, { readOnly: true, allowExtension: false });
    let launch;
    try {
      // Connection-local waiting only; never changes journal mode or data.
      database.exec('PRAGMA busy_timeout=1000');
      requireValue(database.prepare('PRAGMA user_version').get()?.user_version === KERNEL_STATE_SCHEMA_VERSION);
      const rows = database.prepare(`SELECT r.id AS run_id, r.active_worker_launch_id, r.status, r.lease_epoch,
        r.revision, r.cancel_requested, r.stop_intent_ref, r.deadline_at,
        w.launch_id, w.run_id AS worker_run_id, w.phase, w.retired_at,
        CASE WHEN typeof(w.row_json) = 'text' AND length(CAST(w.row_json AS BLOB)) BETWEEN 1 AND 65536
          THEN w.row_json ELSE NULL END AS row_json
        FROM runs r JOIN worker_launches w ON w.run_id = r.id AND w.launch_id = r.active_worker_launch_id
        WHERE r.id = ? AND w.launch_id = ? LIMIT 2`).all(expected.runId, expected.launchId);
      requireValue(rows.length === 1);
      const row = rows[0]!;
      requireValue(row.run_id === expected.runId && row.worker_run_id === expected.runId &&
        row.launch_id === expected.launchId && row.active_worker_launch_id === expected.launchId && row.status === 'running' &&
        row.lease_epoch === expected.leaseEpoch && row.revision === expected.runRevision && row.cancel_requested === 0 &&
        row.stop_intent_ref === null && row.deadline_at === expected.deadlineAt && row.phase === 'activated' && row.retired_at === null &&
        typeof row.row_json === 'string' && Buffer.byteLength(row.row_json) <= 65536);
      launch = decodeWorkerLaunch(parseJsonStrict(row.row_json));
      requireValue(launch.runId === row.worker_run_id && launch.launchId === row.launch_id && launch.phase === row.phase &&
        launch.generationWriteState === 'active' && launch.supervisorInstanceId === expected.supervisorInstanceId &&
        launch.leaseEpoch === expected.leaseEpoch && launch.retiredAt === undefined);
    } finally { database.close(); }
    requireValue(databaseIdentity === canonicalSha256({ root: identity(lstatSync(stateRoot, { bigint: true })),
      file: identity(lstatSync(filename, { bigint: true })) }));
    const observedAt = encodeCanonicalTime(Date.now());
    requireValue(launch.leaseExpiresAt && launch.leaseExpiresAt > observedAt && launch.leaseExpiresAt <= expected.deadlineAt);
    const { leaseVersion, leaseExpiresAt, ...invariant } = launch;
    return Object.freeze({ diagnosticOnly: true, databaseIdentity, launchInvariantDigest: canonicalSha256(invariant),
      leaseVersion, leaseExpiresAt: leaseExpiresAt!, observedAt });
  } catch { throw new Error(refused); }
}

/** Pure data comparison only; callers must independently observe the same real
 * installed process and worker. Neither supplied timestamps nor hashes attest it. */
export function assertInstalledWorkerLeaseRenewed(before: InstalledWorkerLeaseInspection,
  after: InstalledWorkerLeaseInspection, deadlineAt: string): void {
  try {
    requireValue(typeof deadlineAt === 'string'); parseCanonicalTime(deadlineAt);
    for (const value of [before, after]) {
      requireValue(Object.keys(value).sort().join(',') ===
        'databaseIdentity,diagnosticOnly,launchInvariantDigest,leaseExpiresAt,leaseVersion,observedAt');
      requireValue(value.diagnosticOnly === true && Number.isSafeInteger(value.leaseVersion) && value.leaseVersion > 0);
      for (const hash of [value.databaseIdentity, value.launchInvariantDigest])
        requireValue(typeof hash === 'string' && /^[0-9a-f]{64}$/u.test(hash));
      requireValue(typeof value.leaseExpiresAt === 'string' && typeof value.observedAt === 'string');
      parseCanonicalTime(value.leaseExpiresAt); parseCanonicalTime(value.observedAt);
      requireValue(value.leaseExpiresAt > value.observedAt && value.leaseExpiresAt <= deadlineAt);
    }
    requireValue(before.databaseIdentity === after.databaseIdentity && before.launchInvariantDigest === after.launchInvariantDigest &&
      after.leaseVersion > before.leaseVersion && after.leaseExpiresAt > before.leaseExpiresAt && after.observedAt > before.leaseExpiresAt);
  } catch { throw new Error('installed worker lease renewal diagnostic refused'); }
}
