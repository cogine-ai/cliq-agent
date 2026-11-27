// Read-only campaign consumer of the existing UNKNOWN parent-domain contract.
// No child PID, receipt, native handle, dispatch permission or SQL write is made.
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { parseCanonicalTime } from '../../../src/kernel/identity.js';
import type { StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { agentStopDetail, decodeAgentStop, stopCheckpointId } from '../../../src/runtime/stop.js';
import { decodeStateOwnerRecord } from '../../../src/state/decoders.js';
import { validateVerifierUnknownOriginalClaim, decodeVerifierParentDomainDispatchClosure } from '../../../src/state/verifier-unknown-retirement.js';
import type { CandidateSourceReader } from '../../../src/state/result-source.js';
import { assertInstalledVerifierInspectors, type InstalledVerifierProcessIdentity } from './installed-verifier-evidence.js';
import type { InstalledVerifierParentRetirementBinding, inspectInstalledVerifierParentRetirement } from './installed-worker-lease.js';

export type InstalledVerifierParentRetirementIdentity = {
  kind: 'unknown_parent_domain'; opId: string; attempt: number; childIdentityRecorded: false;
  containmentRef: string; deathEvidenceRef: string; namespaceInitStartToken: string; subreaperStartToken: string;
  processes: InstalledVerifierProcessIdentity[]; recovery: InstalledVerifierParentRetirementBinding;
};
const check = (value: unknown): void => { if (!value) throw new Error('installed verifier parent evidence differs'); };
const same = (left: unknown, right: unknown) => check(canonicalSha256(left) === canonicalSha256(right));

/** The strict recovered-row reader is invoked both here and by the independent
 * worker-/proc campaign. An UNKNOWN cannot borrow the sealed-child path. */
export async function assertInstalledVerifierParentRetirement(input: {
  cut: Record<string, any>; spec: any; candidate: any; planRef: string;
  prepared: Record<string, any>; claim: Record<string, any>; terminal: Record<string, any>;
  reader: CandidateSourceReader; readOwnerHistory(): Promise<readonly StateOwnerRecordV1[]>;
  readParentRetirement(binding: InstalledVerifierParentRetirementBinding): ReturnType<typeof inspectInstalledVerifierParentRetirement>;
}) {
  const { cut, prepared, claim, terminal, reader } = input, run = cut.snapshot.run;
  check(run.status === 'cancelled' && run.terminalReason === 'cancelled_by_user' && run.cancelRequested && run.stopIntentRef &&
    run.terminalDetailRef && !run.resultRef && !run.activeWorkerLaunchId && !run.frontierRef && run.nextStep === null &&
    terminal.phase === 'unknown' && terminal.resultRef === undefined && terminal.receiptRef === undefined);
  const stop = decodeAgentStop(await reader.readCanonical(run.stopIntentRef), run);
  check(stop.origin === 'user_cancel');
  const detail: any = await reader.readCanonical(run.terminalDetailRef);
  parseCanonicalTime(detail.createdAt);
  check(Array.isArray(detail.abandonedRetryInvocations) && detail.abandonedRetryInvocations.length === 1);
  same(detail, { ...agentStopDetail(stop, run.stopIntentRef, detail.createdAt), abandonedRetryInvocations: detail.abandonedRetryInvocations });
  const entry = detail.abandonedRetryInvocations[0];
  same(Object.keys(entry).sort(), ['opId', 'attempt', 'unknownJournalSeq', 'budgetSettlementRef', 'dispatchFenceOrDeathEvidenceRef'].sort());
  check(entry.opId === claim.opId && entry.attempt === claim.attempt && entry.unknownJournalSeq === terminal.seq &&
    entry.budgetSettlementRef === terminal.budgetSettlementRef);
  const evidence = decodeVerifierParentDomainDispatchClosure(await reader.readCanonical(entry.dispatchFenceOrDeathEvidenceRef));
  const closure = evidence.closure;
  check(evidence.runId === run.id && evidence.opId === claim.opId && evidence.attempt === claim.attempt && evidence.dispatchId === claim.dispatchId &&
    evidence.unknownJournalSeq === terminal.seq && closure.claimJournalSeq === claim.seq &&
    closure.claimingSupervisorInstanceId === claim.supervisorInstanceId && closure.claimingStateOwnerEpoch === claim.stateOwnerEpoch &&
    closure.requestRef === prepared.requestRef && closure.targetRef === prepared.target && closure.grantRef === prepared.grantRef &&
    closure.sandboxLaunchSpecRef === claim.sandboxLaunchSpecRef && closure.leaseEpoch === claim.leaseEpoch &&
    evidence.observedAt >= terminal.timestamp && evidence.observedAt <= detail.createdAt && detail.createdAt <= run.updatedAt &&
    parseCanonicalTime(run.updatedAt) - parseCanonicalTime(evidence.observedAt) <= 5000);
  const death: any = await reader.readCanonical(closure.parentDeathEvidenceRef);
  const binding: InstalledVerifierParentRetirementBinding = { runId: run.id, supervisorInstanceId: claim.supervisorInstanceId,
    leaseEpoch: claim.leaseEpoch, inspectorIdentityRef: death.inspectorIdentityRef, inspectorIdentityDigest: death.inspectorIdentityDigest, evidence };
  const physical = input.readParentRetirement(binding), { launch, generation } = physical.graph;
  const row = physical.graph.runRow;
  check(row.revision === run.revision && row.lease_epoch === run.leaseEpoch && row.status === run.status &&
    row.cancel_requested === 1 && row.stop_intent_ref === run.stopIntentRef && row.deadline_at === run.deadlineAt);
  check(launch.launchId === closure.workerLaunchId && generation.generationRef === closure.generationRef &&
    generation.retirementEvidenceRef === closure.retirementEvidenceRef && generation.retirementEvidenceDigest === closure.retirementEvidenceDigest);
  const history = await input.readOwnerHistory(); check(Array.isArray(history) && history.length > 0 && history.length <= 1000);
  const owners = history.map(decodeStateOwnerRecord);
  await validateVerifierUnknownOriginalClaim(reader, { run, runSpec: input.spec, journal: cut.journal }, generation, launch,
    owners.find(owner => owner.ownerEpoch === claim.stateOwnerEpoch), { candidate: input.candidate, planRef: input.planRef });
  await assertInstalledVerifierInspectors({ assemblyRef: input.spec.assemblyRef, readCanonical: reader.readCanonical,
    owners, observations: [physical.graph.death], claimingOwnerEpoch: claim.stateOwnerEpoch });
  const cps = cut.checkpoints.filter((cp: any) => cp.id === stopCheckpointId(run.id, run.stopIntentRef)); check(cps.length === 1);
  const checkpoint = cps[0];
  check(checkpoint.id === run.latestCheckpointId && checkpoint.runId === run.id && checkpoint.basedOnRunRevision === run.revision - 1 &&
    checkpoint.createdAt === run.updatedAt && checkpoint.journalSeq === terminal.seq && terminal.seq === cut.journal.length &&
    checkpoint.workspaceStateRef === generation.sourceWorkspaceStateRef && generation.updatedAt === run.updatedAt &&
    physical.retiredAt === run.updatedAt && physical.graph.quarantine.observedState.kind === 'complete_tree' &&
    physical.graph.quarantine.observedState.treeDigest === generation.lastVerifiedTreeDigest);
  const parent = physical.graph.containment;
  const init = /^linux-namespace-init:([1-9][0-9]*):([0-9]+):monitor:([1-9][0-9]*):([0-9]+)$/u.exec(parent.backend.namespaceInitStartToken);
  const subreaper = /^linux-subreaper:([1-9][0-9]*):linux-proc-start-ticks:([0-9]+)$/u.exec(parent.backend.subreaperStartToken);
  check(init && subreaper);
  const processes: InstalledVerifierProcessIdentity[] = [{ role: 'namespace_init', pid: Number(init![1]), startTicks: init![2]! },
    { role: 'monitor', pid: Number(init![3]), startTicks: init![4]! }, { role: 'subreaper', pid: Number(subreaper![1]), startTicks: subreaper![2]! }];
  check(processes.every(process => Number.isSafeInteger(process.pid) && process.pid > 0));
  const identity: InstalledVerifierParentRetirementIdentity = { kind: 'unknown_parent_domain', opId: claim.opId, attempt: claim.attempt,
    childIdentityRecorded: false, containmentRef: closure.parentContainmentRef, deathEvidenceRef: closure.parentDeathEvidenceRef,
    namespaceInitStartToken: parent.backend.namespaceInitStartToken, subreaperStartToken: parent.backend.subreaperStartToken, processes, recovery: binding };
  return { checkpoint, identity };
}
