import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { InvocationJournalEntry, RunAssemblyV1, StateOwnerRecordV1 } from '../kernel/types.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { compileOutputSchema } from '../tools/input-schema.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { builtinToolInputBytes, decodeBuiltinReadOutput, decodeBuiltinToolInput, isBuiltinScriptTool,
  BUILTIN_SCRIPT_RECIPE, type BuiltinScriptTool, type BuiltinToolInput } from '../sandbox/builtin-tool-data.js';
import { observeNativeBuiltinCaptureDurable, acknowledgeNativeBuiltinToolResult, assertNativeContainmentDeath, captureNativeBuiltinToolResult,
  type LinuxBlockedInvocation, type NativeBuiltinToolResult } from '../sandbox/linux-worker.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeBuiltinProcessContainment, decodeBuiltinScriptSandboxLaunchSpec } from './execution-closure.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import { readPrivateBuiltinClaim } from './private-tool-rollback.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

type Termination = { terminationReason: 'exit'; exitCode: number } | { terminationReason: 'signal'; signal: string }
  | { terminationReason: 'spawn_error'; nativeErrorCode: number }
  | { terminationReason: 'timeout' | 'resource_failure' | 'controller_stop' };
export type BuiltinCaptureModel = Readonly<{ outcome: 'executed'; content: unknown }> |
  Readonly<{ outcome: 'error'; code: 'TOOL_PROTOCOL_ERROR' }>;
/** Inert retained bytes. Only the native result producer may supply live result
 * data; neither this artifact nor its decoder is an execution/death permit. */
export type BuiltinToolCaptureV1 = {
  schemaVersion: 1; format: 'cliq-builtin-tool-capture-v1'; runId: string; opId: string; attempt: number;
  dispatchId: string; leaseEpoch: number; tool: BuiltinScriptTool;
  requestRef: string; targetRef: string; grantRef: string; sandboxLaunchSpecRef: string;
  startedAt: string; endedAt: string; durationMs: number;
  stdoutRef: string; stdoutByteCount: number; stderrRef: string; stderrByteCount: number;
  stdoutTruncated: boolean; stderrTruncated: boolean; containmentRef: string; deathEvidenceRef: string; captureDigest: string;
} & Termination;
const captureKeys = ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'leaseEpoch', 'tool', 'requestRef',
  'targetRef', 'grantRef', 'sandboxLaunchSpecRef', 'startedAt', 'endedAt', 'durationMs', 'terminationReason', 'stdoutRef',
  'stdoutByteCount', 'stderrRef', 'stderrByteCount', 'stdoutTruncated', 'stderrTruncated', 'containmentRef', 'deathEvidenceRef', 'captureDigest'];
function closed(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const properties = Object.getOwnPropertyDescriptors(value);
  return Reflect.ownKeys(properties).length === keys.length && keys.every(key => Object.hasOwn(properties, key) &&
    Object.hasOwn(properties[key]!, 'value') && properties[key]!.enumerable);
}
function integer(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}
export function decodeBuiltinToolCapture(value: unknown): BuiltinToolCaptureV1 {
  // Inspect descriptors before reading even the discriminant.
  if (value === null || typeof value !== 'object' || types.isProxy(value)) throw new TypeError('invalid builtin capture');
  const reason = Object.getOwnPropertyDescriptor(value, 'terminationReason');
  const termination = reason && Object.hasOwn(reason, 'value') ? reason.value : undefined;
  const extra = termination === 'exit' ? ['exitCode'] : termination === 'signal' ? ['signal'] : termination === 'spawn_error' ? ['nativeErrorCode'] : [];
  if (!closed(value, [...captureKeys, ...extra]) || value.schemaVersion !== 1 || value.format !== 'cliq-builtin-tool-capture-v1' ||
      !isBuiltinScriptTool(value.tool) || !integer(value.attempt, 0) || !integer(value.leaseEpoch, 1) ||
      !integer(value.durationMs, 0) || !integer(value.stdoutByteCount, 0, BUILTIN_SCRIPT_RECIPE.maximumOutputBytes) ||
      !integer(value.stderrByteCount, 0, BUILTIN_SCRIPT_RECIPE.maximumOutputBytes) ||
      value.stdoutByteCount + value.stderrByteCount > BUILTIN_SCRIPT_RECIPE.maximumOutputBytes ||
      typeof value.stdoutTruncated !== 'boolean' || typeof value.stderrTruncated !== 'boolean' ||
      typeof termination !== 'string' || !['exit', 'signal', 'spawn_error', 'timeout', 'resource_failure', 'controller_stop'].includes(termination) ||
      termination === 'exit' && !integer(value.exitCode, 0, 255) ||
      termination === 'signal' && (typeof value.signal !== 'string' || !/^SIG[A-Z0-9]{1,16}$/u.test(value.signal)) ||
      termination === 'spawn_error' && !integer(value.nativeErrorCode, 1, 2_147_483_647)) throw new TypeError('invalid closed builtin capture');
  for (const key of ['runId', 'opId', 'dispatchId']) if (typeof value[key] !== 'string' || normalizeBoundedText(value[key], 1, 256) !== value[key])
    throw new TypeError('invalid builtin capture owner');
  for (const key of ['requestRef', 'targetRef', 'grantRef', 'sandboxLaunchSpecRef', 'stdoutRef', 'stderrRef', 'containmentRef', 'deathEvidenceRef', 'captureDigest'])
    assertArtifactRef(value[key] as string);
  if (typeof value.startedAt !== 'string' || typeof value.endedAt !== 'string' ||
      parseCanonicalTime(value.endedAt) < parseCanonicalTime(value.startedAt) || value.captureDigest !== digestOmitting(value, 'captureDigest'))
    throw new TypeError('builtin capture time or digest mismatch');
  return immutableSnapshot(value) as BuiltinToolCaptureV1;
}

const terminationData = (value: Termination): Termination => value.terminationReason === 'exit'
  ? { terminationReason: 'exit', exitCode: value.exitCode } : value.terminationReason === 'signal'
    ? { terminationReason: 'signal', signal: value.signal } : value.terminationReason === 'spawn_error'
      ? { terminationReason: 'spawn_error', nativeErrorCode: value.nativeErrorCode } : { terminationReason: value.terminationReason };

/** Called with the private snapshot captured from the genuine native result
 * before any await. This only persists that result; it cannot dispatch work. */
export function retainBuiltinCapturePublication(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1,
  prepared: InvocationJournalEntry, claim: InvocationJournalEntry, result: NativeBuiltinToolResult, capsule: BuiltinToolInput) {
  // The only input is the genuine original token. Private raw buffers never
  // leave this retained producer or become mutable caller-owned views.
  let native: NativeBuiltinToolResult | undefined = captureNativeBuiltinToolResult(result);
  assertNativeContainmentDeath(native.death);
  const containment = native.death.containment;
  const subject = containment.owner;
  if (subject.kind !== 'run_invocation' || subject.runId !== prepared.runId || subject.opId !== prepared.opId ||
      subject.attempt !== prepared.attempt || subject.dispatchId !== claim.dispatchId || subject.intendedLeaseEpoch !== claim.leaseEpoch ||
      containment.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || prepared.grantRef === undefined ||
      owner.ownerEpoch !== claim.stateOwnerEpoch || owner.supervisorInstanceId !== claim.supervisorInstanceId ||
      native.startedAt < claim.timestamp || native.endedAt < native.startedAt || native.death.observedAt < native.endedAt || containment.backend.kind !== 'linux')
    throw new TypeError('native builtin result differs from its original permanent claim');
  const backend = containment.backend;
  if (backend.kind !== 'linux') throw new TypeError('builtin output requires its real Linux invocation');
  let model: BuiltinCaptureModel;
  try { model = Object.freeze({ outcome: 'executed', content: builtinCaptureModelContent({ ...native,
    stdoutByteCount: native.stdout.byteLength, stderrByteCount: native.stderr.byteLength }, native.stdout, native.stderr, capsule) }); }
  catch { model = Object.freeze({ outcome: 'error', code: 'TOOL_PROTOCOL_ERROR' }); }
  let outputs: PublishedArtifact[] | undefined, captured: PublishedArtifact | undefined;
  const publish = async (): Promise<PublishedArtifact> => {
    if (captured) return captured;
    const original = native;
    if (!original) throw new TypeError('builtin capture has already acknowledged its original bytes');
    outputs ??= await joinResourceOperations([original.stdout, original.stderr].map(bytes =>
      artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-builtin-tool-output-v1')));
    const inspector = supervisorInspectorIdentity(owner), inspectorRef = canonicalSha256(inspector), containmentRef = canonicalSha256(containment);
    const death: ProcessContainmentDeathEvidenceV1 = { schemaVersion: 1, kind: 'containment_all_descendants_dead',
      containmentRef, planRef: containment.planRef, sandboxLaunchSpecRef: containment.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: containment.sandboxLaunchSpecDigest, owner: containment.owner, launchNonceDigest: containment.launchNonceDigest,
      inspectorSupervisorInstanceId: owner.supervisorInstanceId, inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest,
      backend: { ...backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
      observedAt: original.death.observedAt, evidenceDigest: '' };
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
    const deathRef = canonicalSha256(death);
    const capture: BuiltinToolCaptureV1 = { schemaVersion: 1, format: 'cliq-builtin-tool-capture-v1', runId: prepared.runId,
      opId: prepared.opId, attempt: prepared.attempt, dispatchId: claim.dispatchId!, leaseEpoch: claim.leaseEpoch, tool: original.tool,
      requestRef: prepared.requestRef, targetRef: prepared.target, grantRef: prepared.grantRef!, sandboxLaunchSpecRef: claim.sandboxLaunchSpecRef!,
      startedAt: original.startedAt, endedAt: original.endedAt, durationMs: original.durationMs, ...terminationData(original),
      stdoutRef: outputs[0]!.ref, stdoutByteCount: original.stdout.byteLength, stderrRef: outputs[1]!.ref, stderrByteCount: original.stderr.byteLength,
      stdoutTruncated: original.stdoutTruncated, stderrTruncated: original.stderrTruncated,
      containmentRef, deathEvidenceRef: deathRef, captureDigest: '' };
    capture.captureDigest = digestOmitting(capture, 'captureDigest'); decodeBuiltinToolCapture(capture);
    // This exact four-object graph has no intermediate authority, clock or
    // SQL effect. Every original raw output is already durable and joined.
    // The existing CAS primitive keeps all four durability/identity/cleanup
    // boundaries and joins the entire group before any capture is returned.
    const values = [{ value: inspector, schemaKind: inspector.format }, { value: containment, schemaKind: 'cliq-process-containment-v1' },
      { value: death, schemaKind: 'cliq-process-containment-death-evidence-v1' }, { value: capture, schemaKind: capture.format }] as const;
    const published = await artifacts.publishCanonicalFour(values);
    if (published.some((value, index) => value.ref !== canonicalSha256(values[index]!.value) ||
        value.byteLength !== canonicalJsonBytes(values[index]!.value).length || value.mediaType !== 'application/json' ||
        value.schemaKind !== values[index]!.schemaKind))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'builtin capture group differs from its complete original native bytes');
    captured = published[3];
    observeNativeBuiltinCaptureDurable(originalResult!);
    return captured;
  };
  const tool = native.tool;
  let originalResult: NativeBuiltinToolResult | undefined = result;
  let acknowledged: Readonly<{ producer: LinuxBlockedInvocation; observed: Awaited<ReturnType<typeof acknowledgeNativeBuiltinToolResult>> }> | undefined;
  return Object.freeze({ tool, model, publish, async acknowledge(producer: LinuxBlockedInvocation) {
    if (acknowledged) {
      if (acknowledged.producer !== producer) throw new TypeError('builtin data release changed its original invocation');
      return acknowledged.observed;
    }
    if (!captured || !outputs || !originalResult) throw new TypeError('builtin data release requires its complete joined original capture publication');
    const observed = await acknowledgeNativeBuiltinToolResult(producer, originalResult);
    // Publication is complete and cached. Drop only producer-owned references;
    // borrowed Buffers and physical RSS are not asserted to have disappeared.
    native = undefined; originalResult = undefined; acknowledged = Object.freeze({ producer, observed });
    return observed;
  } });
}

/** Output projection is reproducible data, independent of native output
 * truncation. Raw bytes stay in CAS; no authority ref enters model content. */
export function builtinCaptureModelContent(capture: Pick<BuiltinToolCaptureV1, 'tool' | 'durationMs' | 'stdoutByteCount' | 'stderrByteCount' |
  'stdoutTruncated' | 'stderrTruncated'> & Termination, stdout: Uint8Array, stderr: Uint8Array, capsule: BuiltinToolInput): unknown {
  if (stdout.byteLength !== capture.stdoutByteCount || stderr.byteLength !== capture.stderrByteCount || capsule.tool !== capture.tool)
    throw new TypeError('builtin model projection substitutes its original bytes');
  const view = (bytes: Uint8Array, nativeTruncated: boolean) => {
    // JSON escaping can expand each byte by six. This fixed prefix keeps both
    // raw binary streams, including NUL-heavy output, below the 1 MiB model cap.
    const maximum = 65_536, prefix = bytes.subarray(0, maximum);
    return { text: Buffer.from(prefix).toString('utf8'), encoding: 'utf8_lossy', byteCount: bytes.byteLength,
      nativeTruncated, modelTruncated: bytes.byteLength > maximum };
  };
  const core = { tool: capture.tool, ...terminationData(capture), durationMs: capture.durationMs };
  let content: unknown;
  if (capture.tool !== 'bash' && capture.terminationReason === 'exit' && capture.exitCode === 0) {
    if (capture.stdoutTruncated) throw new TypeError('a truncated structured builtin frame cannot be a complete result');
    if (stdout.byteLength > BUILTIN_SCRIPT_RECIPE.modelOutputBytes) throw new TypeError('structured builtin output exceeds its fixed frame bound');
    const original = decodeBuiltinReadOutput(Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout), capsule), errorOutput = view(stderr, capture.stderrTruncated);
    const frame = (result: typeof original, modelTruncated: boolean) => ({ ...core, result, sourceComplete: original.complete,
      stdoutByteCount: stdout.byteLength, stdoutNativeTruncated: false, stderr: errorOutput, modelTruncated });
    content = frame(original, false);
    if (canonicalJsonBytes(content).length > BUILTIN_SCRIPT_RECIPE.modelOutputBytes) {
      if (!Array.isArray(original.content)) throw new TypeError('builtin structured model output exceeds its fixed bound');
      const values = original.content, reasons = [...new Set([...original.reasons, 'output_limit' as const])].sort();
      const prefix = (length: number) => frame({ ...original, complete: false, reasons, content: values.slice(0, length) }, true);
      let low = 0, high = values.length;
      while (low < high) {
        const middle = Math.ceil((low + high) / 2);
        if (canonicalJsonBytes(prefix(middle)).length <= BUILTIN_SCRIPT_RECIPE.modelOutputBytes) low = middle; else high = middle - 1;
      }
      content = prefix(low);
    }
  } else content = { ...core, stdout: view(stdout, capture.stdoutTruncated), stderr: view(stderr, capture.stderrTruncated) };
  if (canonicalJsonBytes(content).length > BUILTIN_SCRIPT_RECIPE.modelOutputBytes) throw new TypeError('builtin model output exceeds its fixed bound');
  return immutableSnapshot(content);
}

/** The generic output-schema normalizer may retain an error observation whose
 * diagnostic owns the original native projection. Follow that exact edge;
 * neither a protocol-error label nor a different schema can erase its bytes. */
export async function assertBuiltinCaptureObservation(artifacts: ArtifactCatalog, observation: ToolObservationV1,
  model: BuiltinCaptureModel, outputSchema?: { ref: string; digest: string }): Promise<void> {
  if (observation.outcome === 'executed' && model.outcome === 'executed') {
    requireEqual(observation.content, model.content, 'builtin original captured model content'); return;
  }
  if (observation.outcome === 'error' && model.outcome === 'error' && observation.code === model.code) return;
  if (observation.outcome !== 'error' || observation.code !== 'TOOL_PROTOCOL_ERROR' || model.outcome !== 'executed' || !outputSchema)
    throw new TypeError('builtin observation substitutes its original captured outcome');
  const diagnostic = await readCanonicalArtifact<Record<string, unknown>>(artifacts, observation.diagnosticRef);
  if (!closed(diagnostic, ['schemaVersion', 'format', 'code', 'observationRef']) || diagnostic.schemaVersion !== 1 ||
      diagnostic.format !== 'cliq-tool-output-diagnostic-v1' || diagnostic.code !== 'TOOL_PROTOCOL_ERROR' ||
      typeof diagnostic.observationRef !== 'string' || observation.diagnosticDigest !== canonicalSha256(diagnostic))
    throw new TypeError('normalized builtin output lost its original diagnostic');
  const original = await readCanonicalArtifact<ToolObservationV1>(artifacts, diagnostic.observationRef);
  if (original.outcome !== 'executed' || original.observationDigest !== digestOmitting(original, 'observationDigest'))
    throw new TypeError('normalized builtin output lost its original observation');
  const { outcome: _executed, content, observationDigest: _originalDigest, ...before } = original;
  const { outcome: _error, code: _code, diagnosticRef: _ref, diagnosticDigest: _diagnostic, observationDigest: _digest, ...after } = observation;
  requireEqual(before, after, 'normalized builtin original observation owner');
  requireEqual(content, model.content, 'normalized builtin original captured bytes');
  const schema = await readCanonicalArtifact(artifacts, outputSchema.ref);
  if (outputSchema.digest !== canonicalSha256(schema)) throw new TypeError('normalized builtin output schema digest mismatch');
  if (compileOutputSchema(schema)(content)) throw new TypeError('normalized builtin protocol error is not reproduced by its frozen schema');
}

/** Full independent historical closure. Invocation death never proves parent
 * death or grants a second dispatch, including read/retry contracts. */
export async function readBuiltinToolCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  captureRef: string; captureDigest: string; prepared: InvocationJournalEntry; claim: InvocationJournalEntry;
  assembly: RunAssemblyV1; observedAt: string;
}) {
  const { prepared, claim } = input, capture = decodeBuiltinToolCapture(await readCanonicalArtifact(artifacts, input.captureRef));
  parseCanonicalTime(input.observedAt);
  const launch = decodeBuiltinScriptSandboxLaunchSpec(await readCanonicalArtifact(artifacts, claim.sandboxLaunchSpecRef!));
  if (launch.filesystem.kind !== 'run_generation') throw new TypeError('builtin capture lacks its original private generation');
  const original = await readPrivateBuiltinClaim(artifacts, prepared, claim, { generationRef: launch.filesystem.generationRef });
  if (capture.captureDigest !== input.captureDigest || capture.runId !== prepared.runId || capture.opId !== prepared.opId ||
      capture.attempt !== prepared.attempt || capture.dispatchId !== claim.dispatchId || capture.leaseEpoch !== claim.leaseEpoch ||
      capture.tool !== original.request.toolName || capture.requestRef !== prepared.requestRef || capture.targetRef !== prepared.target ||
      capture.grantRef !== prepared.grantRef || capture.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef ||
      capture.startedAt < claim.timestamp || capture.endedAt > input.observedAt ||
      capture.stdoutByteCount + capture.stderrByteCount > launch.resources.maxInvocationOutputBytes)
    throw new TypeError('builtin capture substitutes its original claim, tool or resource bound');
  const containment = decodeBuiltinProcessContainment(await readCanonicalArtifact(artifacts, capture.containmentRef));
  const death = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, capture.deathEvidenceRef);
  if (!closed(death, ['schemaVersion', 'kind', 'containmentRef', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner',
    'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'backend', 'observedAt', 'evidenceDigest']) ||
      death.schemaVersion !== 1 || death.kind !== 'containment_all_descendants_dead' || death.evidenceDigest !== digestOmitting(death, 'evidenceDigest') ||
      death.containmentRef !== capture.containmentRef || death.planRef !== launch.containmentPlanRef ||
      death.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || death.sandboxLaunchSpecDigest !== launch.launchSpecDigest ||
      containment.planRef !== death.planRef || containment.sandboxLaunchSpecRef !== death.sandboxLaunchSpecRef ||
      containment.sandboxLaunchSpecDigest !== death.sandboxLaunchSpecDigest || containment.launchNonceDigest !== death.launchNonceDigest ||
      containment.createdAt < claim.timestamp || containment.createdAt > capture.startedAt || death.observedAt < capture.endedAt || death.observedAt > input.observedAt)
    throw new TypeError('builtin result lacks its positive original invocation death');
  parseCanonicalTime(death.observedAt);
  requireEqual(containment.owner, launch.owner, 'builtin retired invocation owner');
  requireEqual(death.owner, launch.owner, 'builtin death owner');
  requireEqual(containment.filesystemBinding, { kind: 'run-generation', generationRef: launch.filesystem.generationRef }, 'builtin private generation');
  requireEqual(death.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, 'builtin whole invocation death');
  const plan = original.spec.containmentPlanRef && await readCanonicalArtifact<import('../kernel/execution.js').ProcessContainmentPlanV1>(artifacts, original.spec.containmentPlanRef);
  if (!plan || plan.backend.kind !== 'linux' || containment.backend.kind !== 'linux' ||
      containment.backend.cgroupPath !== plan.backend.cgroupPath || containment.backend.pidNamespaceReservationId !== plan.backend.pidNamespaceReservationId ||
      containment.backend.subreaperStartToken !== plan.backend.subreaperStartToken || containment.launchNonceDigest !== plan.launchNonceDigest)
    throw new TypeError('builtin capture substitutes its original native reservation');
  const parent = readRequiredWorkerLaunch(driver, launch.owner.workerLaunchId);
  if (parent.runId !== prepared.runId || parent.processContainmentRef !== launch.parentWorkerContainmentRef ||
      parent.workspaceGenerationRef !== launch.filesystem.generationRef || parent.leaseEpoch !== claim.leaseEpoch)
    throw new TypeError('builtin result substitutes its original parent worker');
  const owner = claim.stateOwnerEpoch && readStateOwner(driver, claim.stateOwnerEpoch);
  if (!owner || owner.supervisorInstanceId !== claim.supervisorInstanceId || death.inspectorSupervisorInstanceId !== owner.supervisorInstanceId ||
      owner.acquiredAt > death.observedAt || owner.state === 'terminal' && owner.releasedAt < death.observedAt)
    throw new TypeError('builtin capture belongs to another original StateOwner');
  const inspector = await readSupervisorInspector(artifacts, owner, input.assembly, death);
  const raw = await artifacts.mapReads([{ ref: capture.stdoutRef, length: capture.stdoutByteCount }, { ref: capture.stderrRef, length: capture.stderrByteCount }], async value => {
    const chunks: Buffer[] = []; for await (const bytes of artifacts.readChunks(value.ref, value.length)) chunks.push(bytes);
    return Buffer.concat(chunks, value.length);
  });
  const call = await readCanonicalArtifact<import('../protocol/agent-ir.js').ToolCallInputV1>(artifacts, original.request.inputRef);
  const capsule = decodeBuiltinToolInput(builtinToolInputBytes(capture.tool, call.value!, launch.resources));
  let model: BuiltinCaptureModel;
  try { model = { outcome: 'executed', content: builtinCaptureModelContent(capture, raw[0]!, raw[1]!, capsule) }; }
  catch { model = { outcome: 'error', code: 'TOOL_PROTOCOL_ERROR' }; }
  const canonical = (ref: string, value: unknown, schemaKind: string): PublishedArtifact => ({ ref, mediaType: 'application/json', schemaKind, byteLength: canonicalJsonBytes(value).length });
  return { capture, model, metadata: [canonical(input.captureRef, capture, capture.format),
    canonical(capture.containmentRef, containment, 'cliq-process-containment-v1'), canonical(capture.deathEvidenceRef, death, 'cliq-process-containment-death-evidence-v1'),
    canonical(death.inspectorIdentityRef, inspector, inspector.format),
    ...raw.map((bytes, index) => ({ ref: index ? capture.stderrRef : capture.stdoutRef, mediaType: 'application/octet-stream',
      schemaKind: 'cliq-builtin-tool-output-v1', byteLength: bytes.length }))] };
}
