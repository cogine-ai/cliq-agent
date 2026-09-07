import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import type { InvocationJournalEntry, RecoveryClosureV1, WorkerDeathWait } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeInvocationJournalEntry } from './invariants.js';

/** Immutable witnesses of existing Journal facts, not a second invocation state machine. */
export function openWorkerInvocations(journal: readonly InvocationJournalEntry[]): InvocationJournalEntry[] {
  const latest = new Map<string, InvocationJournalEntry>();
  for (const entry of journal) latest.set(`${entry.opId}\0${entry.attempt}`, entry);
  return journal.filter(entry => entry.phase === 'prepared' &&
    ['prepared', 'dispatch_claimed', 'unknown'].includes(latest.get(`${entry.opId}\0${entry.attempt}`)!.phase));
}

type WorkerCut = Pick<RecoveryClosureV1, 'run' | 'journal' | 'workerLaunches' | 'workspaceGenerations'>;

/** Validate the installed wait from the same SQLite cut as the Run, launch, generation and Journal. */
export async function validateWorkerRecoveryWait(artifacts: ArtifactCatalog, cut: WorkerCut): Promise<void> {
  const { run, workerLaunches: launches, workspaceGenerations: generations } = cut;
  const reconciling = launches.filter(launch => launch.phase === 'reconciling');
  const fenced = generations.filter(generation => generation.phase === 'fenced_reconciling');
  if (run.waitingReason !== 'reconciliation' && reconciling.length === 0 && fenced.length === 0) return;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef ||
      run.activeWorkerLaunchId !== undefined || !run.frontierRef || reconciling.length !== 1 ||
      launches.length !== 1 || fenced.length !== 1) throw new TypeError('worker recovery requires one pointer-free Run, reconciling launch and fenced generation');
  const launch = reconciling[0]!;
  const generation = fenced[0]!;
  if (launch.runId !== run.id || launch.leaseEpoch !== run.leaseEpoch || !launch.workerIdentityDigest ||
      !launch.processContainmentRef || generation.runId !== run.id || generation.activeWorkerLaunchId !== launch.launchId ||
      generation.leaseEpoch !== launch.leaseEpoch || generation.generationRef !== launch.workspaceGenerationRef ||
      launch.generationWriteState !== 'fenced_reconciling' || generation.waitingSubjectRef !== run.waitingOnRef ||
      generation.waitingSubjectDigest !== run.waitingOnRef || generation.quiesceId !== launch.quiesceId) {
    throw new TypeError('worker recovery wait substitutes its retained launch, epoch or generation');
  }
  const wait = await readCanonicalArtifact<WorkerDeathWait>(artifacts, run.waitingOnRef);
  if (!Number.isSafeInteger(wait.createdFromRevision) || wait.createdFromRevision <= launch.plannedRunRevision ||
      wait.createdFromRevision >= run.revision || parseCanonicalTime(wait.createdAt) < parseCanonicalTime(launch.activatedAt!) ||
      wait.createdAt > generation.updatedAt || generation.updatedAt > run.updatedAt) {
    throw new TypeError('worker recovery wait has no prior activated Run cut');
  }
  if (!Array.isArray(wait.subject?.openInvocationRefs)) throw new TypeError('worker recovery has no open invocation identities');
  const witnesses = await Promise.all(wait.subject.openInvocationRefs.map(async ref => {
    const entry = decodeInvocationJournalEntry(await readCanonicalArtifact(artifacts, ref));
    if (entry.phase !== 'prepared' || entry.runId !== run.id || entry.timestamp > generation.updatedAt) {
      throw new TypeError('worker recovery witness is not a prior prepared invocation');
    }
    requireEqual(entry, cut.journal[entry.seq - 1], 'open invocation Journal witness');
    return entry;
  }));
  if (witnesses.some((entry, index) => index > 0 && entry.seq <= witnesses[index - 1]!.seq)) {
    throw new TypeError('worker recovery invocation identities are not unique in Journal order');
  }
  const refs = new Set(wait.subject.openInvocationRefs);
  if (openWorkerInvocations(cut.journal).some(entry => !refs.has(canonicalSha256(entry)))) {
    throw new TypeError('worker recovery wait omits an unresolved invocation');
  }
  const expected: WorkerDeathWait = {
    schemaVersion: 1, kind: 'reconciliation', runId: run.id, createdFromRevision: wait.createdFromRevision,
    createdAt: wait.createdAt, frontierRef: run.frontierRef,
    subject: { kind: 'worker_death', oldWorkerLaunchId: launch.launchId, oldLeaseEpoch: launch.leaseEpoch!,
      oldWorkerIdentity: launch.workerIdentityDigest, processContainmentRef: launch.processContainmentRef,
      workspaceGenerationRef: generation.generationRef, openInvocationRefs: witnesses.map(canonicalSha256) },
    probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: wait.createdAt }
  };
  requireEqual(wait, expected, 'installed worker death wait');
}
