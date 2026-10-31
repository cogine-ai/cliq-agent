import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { decodeDependencyClaimEvidence } from '../kernel/dependency-claim.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { InvocationJournalEntry, RunAssemblyV1, StateOwnerRecordV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { assertNativeContainmentDeath, captureNativeDependencyResult, type NativeDependencyResult } from '../sandbox/linux-worker.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeBuiltinEditContainmentPlan, decodeBuiltinProcessContainment, decodeDependencySandboxLaunchSpec } from './execution-closure.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

type Termination = { terminationReason: 'exit'; exitCode: number } | { terminationReason: 'signal'; signal: string } |
  { terminationReason: 'spawn_error'; nativeErrorCode: number } | { terminationReason: 'timeout' | 'resource_failure' | 'controller_stop' };
export type DependencyProcessCaptureV1 = { schemaVersion: 1; format: 'cliq-dependency-process-capture-v1';
  runId: string; opId: string; attempt: number; dispatchId: string; leaseEpoch: number; requestRef: string; targetRef: string;
  grantRef: string; sandboxLaunchSpecRef: string; claimEvidenceRef: string; dependencyPlanRef: string;
  startedAt: string; endedAt: string; durationMs: number; stdoutRef: string; stdoutByteCount: number; stderrRef: string; stderrByteCount: number;
  stdoutTruncated: boolean; stderrTruncated: boolean; containmentRef: string; deathEvidenceRef: string; captureDigest: string } & Termination;
const keys = ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'leaseEpoch', 'requestRef', 'targetRef', 'grantRef',
  'sandboxLaunchSpecRef', 'claimEvidenceRef', 'dependencyPlanRef', 'startedAt', 'endedAt', 'durationMs', 'stdoutRef', 'stdoutByteCount',
  'stderrRef', 'stderrByteCount', 'stdoutTruncated', 'stderrTruncated', 'containmentRef', 'deathEvidenceRef', 'captureDigest', 'terminationReason'];
function termination(value: Termination): Termination {
  return value.terminationReason === 'exit' ? { terminationReason: 'exit', exitCode: value.exitCode } :
    value.terminationReason === 'signal' ? { terminationReason: 'signal', signal: value.signal } : value.terminationReason === 'spawn_error'
      ? { terminationReason: 'spawn_error', nativeErrorCode: value.nativeErrorCode } : { terminationReason: value.terminationReason };
}
/** Pure closed retained data, never a native result, permission or death. */
export function decodeDependencyProcessCapture(value: unknown): DependencyProcessCaptureV1 {
  assertControlWireJson(value);
  const reason = value && typeof value === 'object' ? (value as { terminationReason?: unknown }).terminationReason : undefined;
  const data = controlWireRecord(value, keys, reason === 'exit' ? ['exitCode'] : reason === 'signal' ? ['signal'] : reason === 'spawn_error' ? ['nativeErrorCode'] : []);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-process-capture-v1' ||
      !['exit', 'signal', 'spawn_error', 'timeout', 'resource_failure', 'controller_stop'].includes(reason as string))
    throw new TypeError('dependency capture has another purpose or termination');
  for (const key of ['runId', 'opId', 'dispatchId']) controlWireText(data[key], 256);
  for (const key of ['requestRef', 'targetRef', 'grantRef', 'sandboxLaunchSpecRef', 'claimEvidenceRef', 'dependencyPlanRef', 'stdoutRef',
    'stderrRef', 'containmentRef', 'deathEvidenceRef', 'captureDigest']) controlWireRef(data[key]);
  controlWireInteger(data.attempt, 0, 1); controlWireInteger(data.leaseEpoch, 1); controlWireInteger(data.durationMs, 0);
  const stdout = controlWireInteger(data.stdoutByteCount, 0, 67_108_864), stderr = controlWireInteger(data.stderrByteCount, 0, 67_108_864);
  if (stdout + stderr > 67_108_864 || typeof data.stdoutTruncated !== 'boolean' || typeof data.stderrTruncated !== 'boolean')
    throw new TypeError('dependency capture exceeds the combined original output bound');
  const start = parseCanonicalTime(controlWireText(data.startedAt)), end = parseCanonicalTime(controlWireText(data.endedAt));
  if (end < start || data.captureDigest !== digestOmitting(data, 'captureDigest')) throw new TypeError('dependency capture time or complete digest differs');
  if (reason === 'exit') controlWireInteger(data.exitCode, 0, 255);
  if (reason === 'signal' && !/^SIG[A-Z0-9]{1,16}$/u.test(controlWireText(data.signal))) throw new TypeError('dependency signal is invalid');
  if (reason === 'spawn_error') controlWireInteger(data.nativeErrorCode, 1, 2_147_483_647);
  return data as DependencyProcessCaptureV1;
}

/** The original private native bytes are captured synchronously, before the
 * first await. CAS failure retains this same publication and all byte refs. */
export function retainDependencyCapturePublication(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1,
  prepared: InvocationJournalEntry, claim: InvocationJournalEntry, evidenceRef: string,
  spec: ReturnType<typeof decodeDependencySandboxLaunchSpec>, result: NativeDependencyResult) {
  let native: NativeDependencyResult | undefined = captureNativeDependencyResult(result);
  assertControlWireJson({ owner, prepared, claim, evidenceRef, spec });
  owner = immutableSnapshot(owner); prepared = immutableSnapshot(prepared); claim = immutableSnapshot(claim); spec = immutableSnapshot(spec);
  assertNativeContainmentDeath(native.death);
  const containment = native.death.containment, subject = containment.owner;
  if (subject.kind !== 'run_invocation' || subject.runId !== prepared.runId || subject.opId !== prepared.opId || subject.attempt !== prepared.attempt ||
      subject.dispatchId !== claim.dispatchId || subject.intendedLeaseEpoch !== claim.leaseEpoch || claim.sandboxLaunchSpecRef !== undefined ||
      claim.evidenceRef !== evidenceRef || !claim.brokerFenceTokenDigest || prepared.target !== 'builtin:dependency-acquire' ||
      owner.ownerEpoch !== claim.stateOwnerEpoch || owner.supervisorInstanceId !== claim.supervisorInstanceId ||
      containment.sandboxLaunchSpecRef !== canonicalSha256(spec) || containment.sandboxLaunchSpecDigest !== spec.launchSpecDigest ||
      containment.planRef !== spec.containmentPlanRef || native.startedAt < claim.timestamp || native.endedAt < native.startedAt ||
      native.death.observedAt < native.endedAt || containment.backend.kind !== 'linux' ||
      native.stdout.byteLength + native.stderr.byteLength > spec.resources.maxInvocationOutputBytes)
    throw new TypeError('dependency result differs from its original permanent claim, recipe or whole-domain death');
  requireEqual(subject, spec.owner, 'dependency captured original scope owner');
  const backend = containment.backend;
  if (backend.kind !== 'linux') throw new TypeError('dependency capture requires its original Linux scope');
  let outputs: PublishedArtifact[] | undefined;
  let publication: Readonly<{ capture: DependencyProcessCaptureV1; artifact: PublishedArtifact; metadata: readonly PublishedArtifact[] }> | undefined;
  let pending: Promise<NonNullable<typeof publication>> | undefined;
  const publish = (): Promise<NonNullable<typeof publication>> => {
    if (publication) return Promise.resolve(publication);
    if (pending) return pending;
    const work = (async () => {
      const value = native; if (!value) throw new TypeError('dependency original publication data is already released');
      outputs ??= await joinResourceOperations([value.stdout, value.stderr].map(bytes =>
        artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-dependency-process-output-v1')));
      const inspector = supervisorInspectorIdentity(owner), containmentRef = canonicalSha256(containment);
      const death: ProcessContainmentDeathEvidenceV1 = { schemaVersion: 1, kind: 'containment_all_descendants_dead',
        containmentRef, planRef: containment.planRef, sandboxLaunchSpecRef: containment.sandboxLaunchSpecRef,
        sandboxLaunchSpecDigest: containment.sandboxLaunchSpecDigest, owner: containment.owner, launchNonceDigest: containment.launchNonceDigest,
        inspectorSupervisorInstanceId: owner.supervisorInstanceId, inspectorIdentityRef: canonicalSha256(inspector), inspectorIdentityDigest: inspector.identityDigest,
        backend: { ...backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
        observedAt: value.death.observedAt, evidenceDigest: '' };
      death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
      const core = { schemaVersion: 1 as const, format: 'cliq-dependency-process-capture-v1' as const,
        runId: prepared.runId, opId: prepared.opId, attempt: prepared.attempt, dispatchId: claim.dispatchId!, leaseEpoch: claim.leaseEpoch,
        requestRef: prepared.requestRef, targetRef: spec.targetRef, grantRef: prepared.grantRef!, sandboxLaunchSpecRef: canonicalSha256(spec),
        claimEvidenceRef: evidenceRef, dependencyPlanRef: '', startedAt: value.startedAt, endedAt: value.endedAt, durationMs: value.durationMs,
        stdoutRef: outputs[0]!.ref, stdoutByteCount: value.stdout.byteLength, stderrRef: outputs[1]!.ref, stderrByteCount: value.stderr.byteLength,
        stdoutTruncated: value.stdoutTruncated, stderrTruncated: value.stderrTruncated, containmentRef,
        deathEvidenceRef: canonicalSha256(death), ...termination(value), captureDigest: '' };
      const evidence = decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, evidenceRef));
      if (evidence.runId !== claim.runId || evidence.opId !== claim.opId || evidence.attempt !== claim.attempt ||
          evidence.dispatchId !== claim.dispatchId || evidence.evidenceDigest !== claim.evidenceDigest || evidence.sandboxLaunchSpecRef !== core.sandboxLaunchSpecRef ||
          evidence.requestRef !== prepared.requestRef || evidence.targetRef !== spec.targetRef || evidence.grantRef !== prepared.grantRef ||
          evidence.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest) throw new TypeError('dependency capture substitutes its original whole claim evidence');
      core.dependencyPlanRef = evidence.dependencyPlanRef; core.captureDigest = digestOmitting(core, 'captureDigest');
      const capture = decodeDependencyProcessCapture(core);
      const values = [{ value: inspector, schemaKind: inspector.format }, { value: containment, schemaKind: 'cliq-process-containment-v1' },
        { value: death, schemaKind: 'cliq-process-containment-death-evidence-v1' }, { value: capture, schemaKind: capture.format }] as const;
      const quartet = await artifacts.publishCanonicalFour(values);
      if (quartet.some((item, index) => item.ref !== canonicalSha256(values[index]!.value) || item.byteLength !== canonicalJsonBytes(values[index]!.value).length ||
          item.mediaType !== 'application/json' || item.schemaKind !== values[index]!.schemaKind))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency output graph differs from its whole original bytes');
      publication = immutableSnapshot({ capture, artifact: quartet[3]!, metadata: [...outputs, ...quartet] }); return publication;
    })().finally(() => { if (pending === work) pending = undefined; });
    pending = work; return work;
  };
  return Object.freeze({ publish,
    /** Caller uses this only after the unique SQL settlement and actual ACK;
     * no public flag or close can authorize the underlying native ACK. */
    releasePublishedData() {
      if (!publication) throw new TypeError('dependency original capture has not actually completed publication');
      native = undefined;
    }
  });
}

/** Full independent historical capture, with the original broker-fenced
 * evidence supplying its fixed process recipe. No close/path guesses. */
export async function readDependencyProcessCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  captureRef: string; prepared: InvocationJournalEntry; claim: InvocationJournalEntry; assembly: RunAssemblyV1; observedAt: string;
}) {
  assertControlWireJson(input); input = immutableSnapshot(input);
  const { prepared, claim } = input, capture = decodeDependencyProcessCapture(await readCanonicalArtifact(artifacts, input.captureRef));
  parseCanonicalTime(input.observedAt);
  if (!claim.evidenceRef || !claim.evidenceDigest || !claim.brokerFenceTokenDigest || claim.sandboxLaunchSpecRef !== undefined)
    throw new TypeError('dependency capture has no exact broker-only claim');
  const evidence = decodeDependencyClaimEvidence(await readCanonicalArtifact(artifacts, claim.evidenceRef));
  const spec = decodeDependencySandboxLaunchSpec(await readCanonicalArtifact(artifacts, evidence.sandboxLaunchSpecRef));
  if (capture.runId !== prepared.runId || capture.opId !== prepared.opId || capture.attempt !== prepared.attempt ||
      capture.dispatchId !== claim.dispatchId || capture.leaseEpoch !== claim.leaseEpoch || capture.requestRef !== prepared.requestRef ||
      capture.targetRef !== spec.targetRef || capture.grantRef !== prepared.grantRef || capture.claimEvidenceRef !== claim.evidenceRef ||
      capture.dependencyPlanRef !== evidence.dependencyPlanRef || evidence.evidenceDigest !== claim.evidenceDigest ||
      evidence.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest || evidence.runId !== claim.runId || evidence.opId !== claim.opId ||
      evidence.attempt !== claim.attempt || evidence.dispatchId !== claim.dispatchId || evidence.requestRef !== prepared.requestRef ||
      evidence.stateOwnerEpoch !== claim.stateOwnerEpoch || evidence.supervisorInstanceId !== claim.supervisorInstanceId ||
      evidence.leaseEpoch !== claim.leaseEpoch || evidence.grantRef !== prepared.grantRef || evidence.targetRef !== capture.targetRef ||
      evidence.targetDigest !== spec.targetDigest || evidence.requestDigest !== spec.requestDigest || spec.requestRef !== prepared.requestRef ||
      spec.operationGrantRef !== prepared.grantRef || evidence.sandboxLaunchSpecRef !== capture.sandboxLaunchSpecRef ||
      evidence.sandboxLaunchSpecDigest !== spec.launchSpecDigest || capture.startedAt < claim.timestamp || capture.endedAt > input.observedAt ||
      capture.stdoutByteCount + capture.stderrByteCount > spec.resources.maxInvocationOutputBytes)
    throw new TypeError('dependency capture substitutes its complete original claim and resource bound');
  const containment = decodeBuiltinProcessContainment(await readCanonicalArtifact(artifacts, capture.containmentRef), spec.parentWorkerContainmentRef);
  const death = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, capture.deathEvidenceRef);
  assertControlWireJson(death); controlWireRecord(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef',
    'sandboxLaunchSpecDigest', 'owner', 'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest',
    'backend', 'observedAt', 'evidenceDigest']);
  if (death.schemaVersion !== 1 || death.kind !== 'containment_all_descendants_dead' || death.evidenceDigest !== digestOmitting(death, 'evidenceDigest') ||
      death.containmentRef !== capture.containmentRef || death.planRef !== spec.containmentPlanRef || death.sandboxLaunchSpecRef !== capture.sandboxLaunchSpecRef ||
      death.sandboxLaunchSpecDigest !== spec.launchSpecDigest || containment.planRef !== death.planRef ||
      containment.sandboxLaunchSpecRef !== death.sandboxLaunchSpecRef || containment.sandboxLaunchSpecDigest !== death.sandboxLaunchSpecDigest ||
      containment.launchNonceDigest !== death.launchNonceDigest || containment.createdAt < claim.timestamp || containment.createdAt > capture.startedAt ||
      death.observedAt < capture.endedAt || death.observedAt > input.observedAt || containment.backend.kind !== 'linux')
    throw new TypeError('dependency capture has no original complete positive domain death');
  parseCanonicalTime(death.observedAt); requireEqual(containment.owner, spec.owner, 'dependency historical scope owner');
  requireEqual(spec.owner, { kind: 'run_invocation', runId: prepared.runId, intendedLeaseEpoch: claim.leaseEpoch,
    workerLaunchId: evidence.workerLaunchId, opId: prepared.opId, attempt: prepared.attempt, dispatchId: claim.dispatchId }, 'dependency historical claim owner');
  requireEqual(death.owner, spec.owner, 'dependency historical death owner');
  if (spec.filesystem.kind !== 'run_generation') throw new TypeError('dependency capture lost its original generation');
  requireEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: spec.filesystem.generationRef }, 'dependency historical generation');
  requireEqual(death.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, 'dependency historical whole-domain death');
  const plan = decodeBuiltinEditContainmentPlan(await readCanonicalArtifact(artifacts, spec.containmentPlanRef));
  requireEqual(plan.owner, spec.owner, 'dependency original historical plan owner');
  requireEqual(plan.filesystemBinding, containment.filesystemBinding, 'dependency original historical plan generation');
  if (plan.backend.kind !== 'linux' || plan.backend.cgroupPath !== containment.backend.cgroupPath ||
      plan.backend.pidNamespaceReservationId !== containment.backend.pidNamespaceReservationId ||
      plan.backend.subreaperStartToken !== containment.backend.subreaperStartToken || plan.launchNonceDigest !== containment.launchNonceDigest)
    throw new TypeError('dependency capture substitutes its original native reservation');
  const parent = readRequiredWorkerLaunch(driver, spec.owner.workerLaunchId), owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
  if (parent.runId !== prepared.runId || parent.processContainmentRef !== spec.parentWorkerContainmentRef || parent.workspaceGenerationRef !== spec.filesystem.generationRef ||
      parent.leaseEpoch !== claim.leaseEpoch || !owner || owner.supervisorInstanceId !== claim.supervisorInstanceId ||
      death.inspectorSupervisorInstanceId !== owner.supervisorInstanceId || owner.acquiredAt > death.observedAt || owner.state === 'terminal' && owner.releasedAt < death.observedAt)
    throw new TypeError('dependency capture lost its original WorkerLaunch or StateOwner');
  const inspector = await readSupervisorInspector(artifacts, owner, input.assembly, death);
  await artifacts.mapReads([{ ref: capture.stdoutRef, size: capture.stdoutByteCount }, { ref: capture.stderrRef, size: capture.stderrByteCount }], async value => {
    let bytes = 0; for await (const chunk of artifacts.readChunks(value.ref, value.size)) bytes += chunk.length;
    if (bytes !== value.size) throw new TypeError('dependency output stream is incomplete');
  });
  const metadata = (ref: string, value: unknown, schemaKind: string): PublishedArtifact => ({ ref, mediaType: 'application/json', schemaKind, byteLength: canonicalJsonBytes(value).length });
  return { capture, spec, evidence, containment, death, metadata: [
    { ref: capture.stdoutRef, mediaType: 'application/octet-stream', schemaKind: 'cliq-dependency-process-output-v1', byteLength: capture.stdoutByteCount },
    { ref: capture.stderrRef, mediaType: 'application/octet-stream', schemaKind: 'cliq-dependency-process-output-v1', byteLength: capture.stderrByteCount },
    metadata(death.inspectorIdentityRef, inspector, inspector.format), metadata(capture.containmentRef, containment, 'cliq-process-containment-v1'),
    metadata(capture.deathEvidenceRef, death, 'cliq-process-containment-death-evidence-v1'), metadata(input.captureRef, capture, capture.format)] };
}
