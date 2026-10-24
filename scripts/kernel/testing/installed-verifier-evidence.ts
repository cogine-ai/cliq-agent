// Shared retained-data evidence only. No StateOwner, native capability, live
// process observation or permission is created by these assertions.
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { Checkpoint, Run, RunSpec, StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { decodeRetainedRunAssembly } from '../../../src/model/run-assembly.js';
import { exactKeys } from '../../../src/policy/runtime-authority.js';
import { decodePlatformProcessIdentity, decodeSourceManifest, decodeStateLockIdentity, decodeStateOwnerAcquisitionEvidence,
  decodeStateOwnerRecord, decodeStateRootIdentity, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { joinResourceOperations } from '../../../src/state/errors.js';
import { decodeBuiltinEditContainmentPlan, decodeVerifierSandboxLaunchSpec } from '../../../src/state/execution-closure.js';
import { decodeGuestToolchainManifest } from '../../../src/state/guest-toolchain.js';
import { validateMatchingWorkerDeath } from '../../../src/state/tool-checkpoint.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierSpec } from '../../../src/state/verifier-artifacts.js';
import { planVerifierRequest } from '../../../src/state/verifier-policy.js';
import { verifierCheckpointId } from '../../../src/state/verifier-recovery.js';
import { supervisorInspectorIdentity } from '../../../src/state/supervisor-inspector.js';

export type InstalledVerifierProcessIdentity = { role: 'namespace_init' | 'monitor' | 'subreaper'; pid: number; startTicks: string };
export type InstalledVerifierRetirementIdentity = { opId: string; attempt: number; containmentRef: string; deathEvidenceRef: string;
  namespaceInitStartToken: string; subreaperStartToken: string; processes: InstalledVerifierProcessIdentity[] };
export type InstalledVerifierRetirementPhase = 'verifier_retirement_request' | 'verifier_retirement_source' | 'verifier_retirement_projection' |
  'verifier_retirement_launch' | 'verifier_retirement_child' | 'verifier_retirement_parent' | 'verifier_retirement_inspector' |
  'verifier_retirement_processes' | 'verifier_retirement_output';
type Reader = (ref: string) => Promise<Buffer>;
const check = (value: unknown): void => { if (!value) throw new Error('installed verifier evidence differs'); };
const same = (left: unknown, right: unknown) => check(canonicalSha256(left) === canonicalSha256(right));
function retained(reader: Reader) {
  const bytes = async (ref: string, maximum = 1_048_576) => {
    check(typeof ref === 'string' && /^[a-f0-9]{64}$/u.test(ref));
    const value = await reader(ref); check(Buffer.isBuffer(value) && value.length <= maximum && sha256Bytes(value) === ref); return value;
  };
  const object = async (ref: string): Promise<any> => {
    const value = await bytes(ref), data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(value));
    check(canonicalJsonBytes(data).equals(value)); return data;
  };
  return { bytes, object };
}

/** The original source assertions, shared with the Delivery verifier. */
export async function readInstalledVerifierInputs(spec: RunSpec, reader: Reader) {
  const { object } = retained(reader), frozen = decodeVerifierSpec(await object(spec.verifierSpecRef));
  const assembly = decodeRetainedRunAssembly(await object(spec.assemblyRef));
  const commands = await joinResourceOperations(frozen.verifiers.map(async entry => decodeVerifierCommand(await object(entry.commandRef))));
  const environments = await joinResourceOperations(frozen.verifiers.map(async entry => decodeVerifierEnvironment(await object(entry.environmentRef))));
  for (const [index, entry] of frozen.verifiers.entries()) {
    const command = commands[index]!, environment = environments[index]!;
    check(command.verifierId === entry.id && command.verifierVersion === entry.version && command.commandDigest === entry.commandDigest &&
      environment.verifierId === entry.id && environment.verifierVersion === entry.version && environment.environmentDigest === entry.environmentDigest &&
      environment.commandRef === entry.commandRef && environment.commandDigest === entry.commandDigest && environment.sourceProjectionRef === spec.sourceProjectionRef &&
      environment.runtimeBundleRef === assembly.runtime.runtimeBundleRef && environment.runtimeBundleManifestDigest === assembly.runtime.runtimeBundleManifestDigest &&
      environment.guestToolchainManifestRef === assembly.runtime.guestToolchainManifestRef && environment.guestToolchainManifestDigest === assembly.runtime.guestToolchainManifestDigest);
    check(command.executable.kind === 'guest_toolchain');
    if (command.executable.kind !== 'guest_toolchain') throw new Error('unsupported installed verifier executable');
    const guest = decodeGuestToolchainManifest(await object(command.executable.guestToolchainManifestRef));
    check(command.executable.guestToolchainManifestRef === environment.guestToolchainManifestRef &&
      command.executable.guestToolchainManifestDigest === guest.manifestDigest && guest.manifestDigest === environment.guestToolchainManifestDigest &&
      command.executable.toolId === guest.node.logicalName && command.executable.executionPath === guest.node.canonicalGuestPath &&
      command.executable.executableDigest === guest.node.digest && command.executable.abiFingerprint === guest.manifestDigest);
  }
  return { frozen, assembly, commands, environments };
}

/** Callers separately validate the complete candidate/context and exact result
 * or Stop item. This function owns the shared claim→native launch→child death→
 * M snapshot→parent death graph; the returned lifetimes still require /proc. */
export async function assertInstalledVerifierRetirement(input: {
  run: Pick<Run, 'id' | 'deadlineAt'>; checkpoints: readonly Checkpoint[];
  prepared: Record<string, any>; claim: Record<string, any>; terminal: Record<string, any>;
  requestContext: any; measurement: Record<string, any>; readRetainedArtifact: Reader;
  readOwnerHistory: () => Promise<readonly StateOwnerRecordV1[]>;
}, observe?: (phase: InstalledVerifierRetirementPhase) => void) {
  const phase = (value: InstalledVerifierRetirementPhase) => { try { observe?.(value); } catch { /* Optional fixed-data diagnosis only. */ } };
  try {
    phase('verifier_retirement_request');
    const { run, prepared, claim, terminal, requestContext, measurement } = input, opId = prepared.opId, attempt = prepared.attempt;
    check(prepared.phase === 'prepared' && claim.phase === 'dispatch_claimed' && ['completed', 'failed'].includes(terminal.phase) &&
      prepared.runId === run.id && claim.runId === run.id && terminal.runId === run.id && prepared.opKind === 'verifier' &&
      claim.opKind === 'verifier' && terminal.opKind === 'verifier' && claim.opId === opId && terminal.opId === opId &&
      claim.attempt === attempt && terminal.attempt === attempt && prepared.seq < claim.seq && claim.seq < terminal.seq && claim.sandboxLaunchSpecRef);
    const { bytes, object } = retained(input.readRetainedArtifact), planned = planVerifierRequest(requestContext);
    same(await object(prepared.requestRef), planned.request); same(await object(prepared.target), planned.target);
    phase('verifier_retirement_source');
    const source = decodeSourceManifest(await object(requestContext.resultSourceRef)), entries = decodeWorkspaceEntries(await object(source.entriesRef));
    check(source.manifestDigest === requestContext.sourceDigest && entries.treeDigest === source.treeDigest);
    phase('verifier_retirement_projection');
    const retirement = await object(measurement.retirementRef);
    check(exactKeys(retirement, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'leaseEpoch', 'containmentRef', 'deathEvidenceRef',
      'checkpointId', 'workspaceStateRef', 'snapshotEvidenceRef', 'parentRetirementEvidenceRef', 'sourceAfterRef', 'sourceAfterDigest', 'evidenceDigest']) &&
      retirement.schemaVersion === 1 && retirement.format === 'cliq-verifier-retirement-v1' && retirement.evidenceDigest === digestOmitting(retirement, 'evidenceDigest') &&
      retirement.runId === run.id && retirement.opId === opId && retirement.attempt === attempt && retirement.dispatchId === claim.dispatchId && retirement.leaseEpoch === claim.leaseEpoch &&
      retirement.checkpointId === verifierCheckpointId(run.id, opId, attempt) && retirement.sourceAfterRef === requestContext.resultSourceRef && retirement.sourceAfterDigest === requestContext.sourceDigest);
    const cps = input.checkpoints.filter(cp => cp.id === retirement.checkpointId); check(cps.length === 1);
    const cp = cps[0]!, snapshot = decodeWorkspaceGenerationSnapshotEvidence(await object(retirement.snapshotEvidenceRef));
    const workspaceState = decodeWorkspaceState(await object(cp.workspaceStateRef));
    check(cp.runId === run.id && cp.journalSeq === terminal.seq && cp.workspaceStateRef === retirement.workspaceStateRef && cp.createdAt >= terminal.timestamp && cp.createdAt < run.deadlineAt &&
      snapshot.purpose === 'sealed_to_checkpoint' && snapshot.checkpointId === cp.id && snapshot.workspaceStateRef === cp.workspaceStateRef && snapshot.runId === run.id &&
      snapshot.workspaceStateDigest === workspaceState.stateDigest && snapshot.entriesRef === workspaceState.entriesRef && workspaceState.entriesRef === source.entriesRef && snapshot.treeDigest === entries.treeDigest &&
      snapshot.observedAt <= cp.createdAt && snapshot.observedAt >= measurement.endedAt);
    phase('verifier_retirement_launch');
    const launch = decodeVerifierSandboxLaunchSpec(await object(claim.sandboxLaunchSpecRef));
    // This existing decoder is the pure closed run_invocation data decoder;
    // its edit-oriented name supplies no native closure or launch authority.
    const childPlan = decodeBuiltinEditContainmentPlan(await object(launch.containmentPlanRef));
    check(launch.requestRef === prepared.requestRef && launch.requestDigest === planned.request.requestDigest && launch.targetRef === prepared.target && launch.targetDigest === planned.target.targetDigest &&
      launch.operationGrantRef === prepared.grantRef && launch.filesystem.kind === 'run_generation' && launch.filesystem.generationRef === snapshot.generationRef &&
      launch.filesystem.sourceProjectionRef === requestContext.environment.sourceProjectionRef && launch.owner.kind === 'run_invocation');
    if (launch.owner.kind !== 'run_invocation') throw new Error('wrong verifier launch owner');
    same(launch.owner, { kind: 'run_invocation', runId: run.id, intendedLeaseEpoch: claim.leaseEpoch, workerLaunchId: launch.owner.workerLaunchId, opId, attempt, dispatchId: claim.dispatchId });
    same(childPlan.owner, launch.owner); same(childPlan.filesystemBinding, { kind: 'run-generation', generationRef: snapshot.generationRef });
    check(childPlan.planDigest === launch.containmentPlanDigest && childPlan.parentContainmentRef === launch.parentWorkerContainmentRef);
    if (childPlan.backend.kind !== 'linux') throw new Error('unsupported verifier containment plan');
    phase('verifier_retirement_child');
    const containment = await object(retirement.containmentRef), death = await object(retirement.deathEvidenceRef), parentDeath = await object(retirement.parentRetirementEvidenceRef);
    check(exactKeys(containment, ['schemaVersion', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner', 'filesystemBinding', 'parentContainmentRef', 'launchNonceDigest', 'backend', 'createdAt']) &&
      containment.schemaVersion === 1 && containment.planRef === launch.containmentPlanRef && containment.sandboxLaunchSpecRef === claim.sandboxLaunchSpecRef && containment.sandboxLaunchSpecDigest === launch.launchSpecDigest &&
      containment.parentContainmentRef === launch.parentWorkerContainmentRef && containment.backend.kind === 'linux');
    check(exactKeys(containment.backend, ['kind', 'pidNamespaceReservationId', 'pidNamespaceId', 'cgroupPath', 'cgroupId', 'namespaceInitStartToken', 'subreaperStartToken']));
    same(containment.owner, launch.owner); same(containment.filesystemBinding, { kind: 'run-generation', generationRef: snapshot.generationRef });
    check(containment.launchNonceDigest === childPlan.launchNonceDigest && containment.createdAt >= childPlan.createdAt &&
      childPlan.createdAt >= prepared.timestamp && childPlan.createdAt <= claim.timestamp && containment.createdAt <= measurement.endedAt &&
      containment.backend.cgroupPath === childPlan.backend.cgroupPath &&
      containment.backend.pidNamespaceReservationId === childPlan.backend.pidNamespaceReservationId &&
      containment.backend.subreaperStartToken === childPlan.backend.subreaperStartToken);
    check(exactKeys(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner', 'launchNonceDigest',
      'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']) &&
      death.schemaVersion === 1 && death.kind === 'containment_all_descendants_dead' && death.evidenceDigest === digestOmitting(death, 'evidenceDigest') &&
      death.containmentRef === retirement.containmentRef && death.planRef === containment.planRef && death.sandboxLaunchSpecRef === containment.sandboxLaunchSpecRef &&
      death.sandboxLaunchSpecDigest === containment.sandboxLaunchSpecDigest && death.launchNonceDigest === containment.launchNonceDigest &&
      death.inspectorSupervisorInstanceId === claim.supervisorInstanceId && death.observedAt >= measurement.endedAt && death.observedAt <= snapshot.observedAt);
    same(death.owner, launch.owner); same(death.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 });
    phase('verifier_retirement_parent');
    check(parentDeath.kind === 'containment_all_descendants_dead' && parentDeath.containmentRef === launch.parentWorkerContainmentRef &&
      parentDeath.evidenceDigest === digestOmitting(parentDeath, 'evidenceDigest') && parentDeath.observedAt >= death.observedAt && parentDeath.observedAt <= cp.createdAt);
    check(parentDeath.schemaVersion === 1 && parentDeath.backend.kind === 'linux' && parentDeath.backend.cgroupPopulated === 0 &&
      parentDeath.backend.namespaceInitDeadAndReaped === true && parentDeath.backend.remainingTrackedDescendants === 0);
    same(parentDeath.owner, { kind: 'worker_activation', runId: run.id, intendedLeaseEpoch: claim.leaseEpoch, workerLaunchId: launch.owner.workerLaunchId });
    validateMatchingWorkerDeath(await object(snapshot.quiescenceEvidenceRef!), parentDeath, 'installed verifier parent retirement');
    phase('verifier_retirement_inspector');
    const assembly = decodeRetainedRunAssembly(await object(requestContext.assemblyRef)), bundle = await object(assembly.runtime.runtimeBundleRef);
    check(bundle.manifestDigest === assembly.runtime.runtimeBundleManifestDigest && Array.isArray(bundle.entries));
    const supervisors = bundle.entries.filter((entry: any) => entry.role === 'supervisor'); check(supervisors.length === 1);
    const values = await input.readOwnerHistory(); check(Array.isArray(values) && values.length > 0 && values.length <= 1000);
    const owners = values.map(value => decodeStateOwnerRecord(value));
    owners.forEach((owner, index) => check(owner.ownerEpoch === index + 1 && (index === owners.length - 1 || owner.state === 'terminal')));
    for (const observation of [death, parentDeath]) {
      const inspector = await object(observation.inspectorIdentityRef), owner = owners.find(value => value.ownerEpoch === inspector.stateOwnerEpoch);
      check(owner); if (!owner) throw new Error('missing original verifier inspector owner');
      same(inspector, supervisorInspectorIdentity(owner));
      check(inspector.identityDigest === observation.inspectorIdentityDigest && owner.supervisorInstanceId === observation.inspectorSupervisorInstanceId &&
        owner.runtimeBundleRef === assembly.runtime.runtimeBundleRef && owner.runtimeBundleManifestDigest === assembly.runtime.runtimeBundleManifestDigest &&
        owner.supervisorEntryId === supervisors[0].entryId && owner.supervisorEntryVersion === supervisors[0].version &&
        owner.supervisorExecutableDigest === supervisors[0].digest && supervisors[0].executable === true && owner.acquiredAt <= observation.observedAt &&
        (owner.state !== 'terminal' || owner.releasedAt >= observation.observedAt));
      if (observation === death) check(owner.ownerEpoch === claim.stateOwnerEpoch && owner.supervisorInstanceId === claim.supervisorInstanceId);
      const process = decodePlatformProcessIdentity(await object(owner.processIdentityRef)), lock = decodeStateLockIdentity(await object(owner.stateLockIdentityRef));
      const root = decodeStateRootIdentity(await object(lock.stateRootIdentityRef)), acquired = decodeStateOwnerAcquisitionEvidence(await object(owner.acquisitionEvidenceRef));
      check(process.identityDigest === owner.processIdentityDigest && process.executableImageDigest === owner.supervisorExecutableDigest &&
        lock.identityDigest === owner.stateLockIdentityDigest && lock.stateRootIdentityDigest === root.identityDigest &&
        process.ownerUid === root.ownerUid && lock.ownerUid === root.ownerUid && lock.deviceId === root.deviceId && acquired.evidenceDigest === owner.acquisitionEvidenceDigest);
      for (const field of ['ownerEpoch', 'supervisorInstanceId', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'processIdentityRef',
        'processIdentityDigest', 'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const) check(acquired[field] === owner[field]);
    }
    phase('verifier_retirement_processes');
    const init = /^linux-namespace-init:([1-9][0-9]*):([0-9]+):monitor:([1-9][0-9]*):([0-9]+)$/u.exec(containment.backend.namespaceInitStartToken);
    const subreaper = /^linux-subreaper:([1-9][0-9]*):linux-proc-start-ticks:([0-9]+)$/u.exec(containment.backend.subreaperStartToken);
    check(init && subreaper);
    const processes: InstalledVerifierProcessIdentity[] = [{ role: 'namespace_init', pid: Number(init![1]), startTicks: init![2]! },
      { role: 'monitor', pid: Number(init![3]), startTicks: init![4]! }, { role: 'subreaper', pid: Number(subreaper![1]), startTicks: subreaper![2]! }];
    check(processes.every(process => Number.isSafeInteger(process.pid) && process.pid > 0));
    const identity: InstalledVerifierRetirementIdentity = { opId, attempt, containmentRef: retirement.containmentRef, deathEvidenceRef: retirement.deathEvidenceRef,
      namespaceInitStartToken: containment.backend.namespaceInitStartToken, subreaperStartToken: containment.backend.subreaperStartToken, processes };
    phase('verifier_retirement_output');
    const limit = requestContext.verifierSpec.verifiers[requestContext.verifierIndex].outputLimitBytes;
    check((await bytes(measurement.stdoutRef, limit)).length + (await bytes(measurement.stderrRef, limit)).length <= limit);
    return { checkpoint: cp, snapshot, workspaceState, launch, identity };
  } catch { throw new Error('installed verifier retirement evidence refused'); }
}
