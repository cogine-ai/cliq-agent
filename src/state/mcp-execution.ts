// One original native owner drives the fixed logical-client recipe. The
// original claim owns setup and effect together; no phase may create a claim,
// retry, replacement URL, credential or deadline.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes, identityHash } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeMcpCallResult, decodeMcpHttpCapture, decodeMcpInitializeResult, decodeMcpToolsListResult,
  decodeMcpKnownUnusableResponse, mcpNoReleaseCheckpointId, type McpKnownUnusableResponseV1,
  type McpCallResultV1, type McpHttpCaptureV1, type McpRegistryRevisionV1 } from '../kernel/mcp.js';
import { decodeMcpHttpCaptureData, decodeMcpInboundMessageData, type McpInboundMessageData } from '../kernel/mcp-wire.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, exactKeys, type RuntimeBundleManifest, verifyRuntimeBundle } from '../policy/runtime-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { ResourceRetirementError, KernelStorageError } from './errors.js';
import type { InvocationJournalEntry, RunAssemblyV1 } from '../kernel/types.js';
import type { RecoveryClosureV1, RunFrontier, ToolBatchItem, ToolResultItem, ToolResultPayloadV1 } from '../kernel/types.js';
import type { ToolObservationV1, ToolRequestV1, ToolTargetV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import { readCanonicalArtifact } from './agent-context.js';
import { readMcpHttpCapture, readMcpRegistryClosure } from './mcp-registration.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { settleValidatedInvocation } from './reducers/invocation.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { readWorkerLaunch } from './repositories/worker-launches.js';
import { readRun, readSessionPrincipalId } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from '../kernel/broker-ambiguity.js';
import { decodeBrokerPostClaimNoRelease, type BrokerPostClaimNoReleaseEvidenceV1 } from '../kernel/post-claim-no-release.js';
import { assertInstalledMcpNoReleaseFence } from './mcp-native-binding.js';
import type { NativeMcpNoReleaseFence } from './mcp-broker-native.js';
import { planToolInvocationResult, nextToolFrontier } from './reducers/tool.js';
import { readToolCut } from './tool-cut.js';
import type { ResolveToolInput } from '../model/attempt.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { ZERO_BUDGET } from './rows.js';
import { decodeBudgetSettlement } from './decoders.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { decodeBrokerProcessDomainDeath, type BrokerProcessDomainDeathEvidenceV1 } from '../kernel/broker-process-domain-death.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { stateRootIdentityForLock } from './native-owner.js';
import { assertInstalledMcpBrokerProcess } from './mcp-native-binding.js';
import { readStopSourceData } from './stop-source.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { assertInstalledMcpAdminJoined, assertInstalledMcpAdminOwner, assertInstalledMcpRawResponse,
  assertInstalledMcpRunJoined, assertInstalledMcpRunOwner, assertInstalledMcpUnusableResponse } from './mcp-native-binding.js';
import type { AdminMcpHttpBinding, NativeMcpAdminHttpOwner, NativeMcpAdminJoined, NativeMcpMessage,
  NativeMcpRawResponse, NativeMcpReceipt, NativeMcpRunHttpOwner, NativeMcpRunJoined, RunMcpHttpBinding,
  McpHttpPhase, AdminMcpHttpPhase } from './mcp-broker-native.js';

type Capture = Readonly<{ native: NativeMcpRawResponse; receipt: NativeMcpReceipt;
  descriptor: McpHttpCaptureV1; bytes: Buffer; response: Extract<McpInboundMessageData, { kind: 'result' | 'error' }> }>;
type RunState = { binding: RunMcpHttpBinding; captures: Map<McpHttpPhase, Capture>; result?: McpCallResultV1;
  resultReceived: boolean; receivedFinal?: NativeMcpMessage; running: boolean; joined?: NativeMcpRunJoined; failure?: unknown;
  noReleaseFence?: NativeMcpNoReleaseFence };
const runOwners = new WeakMap<NativeMcpRunHttpOwner, RunState>();
// Strong ownership persists across ordinary errors until original settlement
// or exact manual terminal acknowledgement consumes the retained C domain.
const retainedRunOwners = new Map<string, { owner: NativeMcpRunHttpOwner; state: RunState }>();
const dispatchKey = (claim: Pick<InvocationJournalEntry, 'runId' | 'opId' | 'attempt' | 'dispatchId'>) =>
  canonicalSha256([claim.runId, claim.opId, claim.attempt, claim.dispatchId]);
type McpRunCaptureV1 = Readonly<{ schemaVersion: 1; format: 'cliq-mcp-run-capture-v1' | 'cliq-mcp-known-unusable-run-capture-v1'; binding: RunMcpHttpBinding;
  captures: readonly Readonly<{ phase: McpHttpPhase; captureRef: string }>[]; result: McpCallResultV1 | null;
  malformedResult: boolean; joined: NativeMcpRunJoined; captureDigest: string; unusableResponseRef?: string }>;
const publishedRunCaptures = new Map<string, { owner: NativeMcpRunHttpOwner; binding: RunMcpHttpBinding }>();
const adminOwners = new WeakMap<NativeMcpAdminHttpOwner, { binding: AdminMcpHttpBinding; captures: Map<McpHttpPhase, Capture>;
  running: boolean; joined?: NativeMcpAdminJoined; failure?: unknown }>();

function responseId(phase: McpHttpPhase): number {
  if (phase === 'initialize') return 1;
  if (phase === 'tools_list') return 2;
  if (phase === 'tools_call') return 3;
  throw new TypeError('initialized notification has no JSON response id');
}
function screenedMessage(message: Exclude<NativeMcpMessage, { kind: 'stage_requested' | 'stage_completed' }>) {
  if (message.messageDigest !== sha256Bytes(message.messageBytes)) throw new TypeError('native MCP screened message digest differs');
  return decodeMcpInboundMessageData(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(message.messageBytes)));
}
async function finish(owner: NativeMcpRunHttpOwner | NativeMcpAdminHttpOwner, phase: McpHttpPhase,
  message: Extract<NativeMcpMessage, { kind: 'response' | 'notification' | 'ping' }>): Promise<Capture> {
  const response = screenedMessage(message);
  if ((response.kind !== 'result' && response.kind !== 'error') || response.id !== responseId(phase))
    throw new TypeError('MCP final receipt is not the original expected response');
  const native = await owner.finishResponse(message.receipt);
  assertInstalledMcpRawResponse(owner, message.receipt, native);
  // Copy only from the actual native-screened immutable bytes after its own
  // response workers joined. This original capture survives every CAS error.
  const bytes = native.screenedRawCapture.copy();
  const decoded = decodeMcpHttpCaptureData({ bytes, mediaType: native.mediaType,
    reportedCompletion: native.termination, expectedId: responseId(phase) });
  requireEqual(decoded.response, response, 'MCP screened message and complete original finite capture');
  requireEqual({ bytes: decoded.rawFinitePrefixBytes, digest: decoded.rawFinitePrefixDigest,
    tail: decoded.receivedTailBytes, offset: decoded.responseEventEndOffset ?? null },
  { bytes: native.rawFinitePrefixBytes, digest: native.rawFinitePrefixDigest,
    tail: native.receivedTailBytes, offset: native.responseEventEndOffset ?? null }, 'MCP genuine response receipt framing');
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-http-capture-v1' as const,
    phase: phase as McpHttpCaptureV1['phase'], expectedId: responseId(phase), mediaType: native.mediaType,
    termination: native.termination, rawResponseRef: sha256Bytes(bytes), rawFinitePrefixBytes: bytes.byteLength,
    rawFinitePrefixDigest: sha256Bytes(bytes), receivedTailBytes: native.receivedTailBytes,
    ...(native.responseEventEndOffset === undefined ? {} : { responseEventEndOffset: native.responseEventEndOffset }) };
  return Object.freeze({ native, receipt: message.receipt, descriptor: decodeMcpHttpCapture({ ...core, captureDigest: canonicalSha256(core) }), bytes, response });
}

/** Internal typed caller supplies a synchronous SQL/credential/time assertion.
 * It runs fresh before CONNECT and again immediately before synchronous body
 * release. Nothing from an earlier assertion authorizes the later release. */
async function receiveRunStage(owner: NativeMcpRunHttpOwner, state: RunState, phase: McpHttpPhase,
  assertCurrentAuthority: () => void): Promise<Capture | undefined> {
  assertCurrentAuthority(); assertInstalledMcpRunOwner(owner, state.binding);
  await owner.connectStage(state.binding, phase);
  assertCurrentAuthority(); assertInstalledMcpRunOwner(owner, state.binding); owner.releaseStage(state.binding, phase);
  for (;;) {
    const message = await owner.nextMessage();
    if (message.kind === 'stage_completed') {
      if (phase !== 'initialized' || message.phase !== phase) throw new TypeError('unexpected MCP stage acknowledgement');
      return undefined;
    }
    if (message.kind === 'stage_requested' || message.phase !== phase) throw new TypeError('MCP Run owner changed its fixed recipe phase');
    const decoded = screenedMessage(message);
    if (decoded.kind === 'ping') {
      if (message.kind !== 'ping') throw new TypeError('MCP ping lost its original native receipt kind');
      assertCurrentAuthority(); assertInstalledMcpRunOwner(owner, state.binding);
      await owner.connectPing(state.binding, message.receipt);
      assertCurrentAuthority(); assertInstalledMcpRunOwner(owner, state.binding); owner.releasePing(state.binding, message.receipt);
      continue;
    }
    if (decoded.kind === 'notification') {
      if (message.kind !== 'notification') throw new TypeError('MCP notification changed its native message kind');
      // This loop starts after this phase's genuine release. A discovery
      // change fences setup, while an in-flight call keeps its original reply.
      if (decoded.method === 'notifications/tools/list_changed' && phase !== 'tools_call')
        throw new TypeError('MCP frozen discovery changed before effect release');
      continue;
    }
    if (message.kind !== 'response' || phase === 'initialized') throw new TypeError('MCP response changed its native phase or receipt kind');
    if (phase === 'tools_call') {
      if ((decoded.kind !== 'result' && decoded.kind !== 'error') || decoded.id !== responseId(phase))
        throw new TypeError('MCP effect response does not match its original id');
      // The native matching complete event is known before finite-tail export.
      // A later refusal may make artifacts unusable, never erase receipt truth.
      state.resultReceived = true; state.receivedFinal = message;
    }
    const capture = await finish(owner, phase, message);
    state.captures.set(phase, capture);
    return capture;
  }
}

export async function driveMcpRunProtocol(owner: NativeMcpRunHttpOwner, binding: RunMcpHttpBinding,
  registry: McpRegistryRevisionV1, assertCurrentAuthority: () => void, outputSchema?: unknown) {
  let state = runOwners.get(owner);
  if (state) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP original owner cannot drive another logical client');
  assertInstalledMcpRunOwner(owner, binding);
  state = { binding: immutableSnapshot(binding), captures: new Map(), running: true, resultReceived: false };
  runOwners.set(owner, state);
  retainedRunOwners.set(dispatchKey(binding), { owner, state });
  try {
    const initialized = await receiveRunStage(owner, state, 'initialize', assertCurrentAuthority);
    if (!initialized || initialized.response.kind !== 'result') throw new TypeError('MCP initialization was rejected');
    const negotiation = decodeMcpInitializeResult(initialized.response.result);
    if (negotiation.initializeDigest !== registry.initializeDigest || negotiation.capabilityDigest !== registry.capabilityDigest)
      throw new TypeError('fresh MCP initialize differs from frozen negotiation');
    await receiveRunStage(owner, state, 'initialized', assertCurrentAuthority);
    const listed = await receiveRunStage(owner, state, 'tools_list', assertCurrentAuthority);
    if (!listed || listed.response.kind !== 'result') throw new TypeError('fresh MCP discovery was rejected');
    const tools = decodeMcpToolsListResult(listed.response.result);
    if (canonicalSha256(tools.map(tool => tool.interface)) !== registry.probedToolsListDigest)
      throw new TypeError('fresh MCP complete interfaces differ from the frozen registry');
    const captured = await receiveRunStage(owner, state, 'tools_call', assertCurrentAuthority);
    if (!captured) throw new TypeError('MCP effect has no received response');
    // Receipt custody is registered BEFORE semantic normalization or close.
    // Malformed received result remains known received data, never no-release.
    state.resultReceived = true;
    state.result = captured.response.kind === 'error'
      ? immutableSnapshot({ kind: 'rpc_error' as const, ...captured.response.error })
      : decodeMcpCallResult(captured.response.result, outputSchema);
    return state.result;
  } catch (error) { state.failure = error; throw error; }
  finally {
    state.running = false;
    try { state.joined = await owner.close(); assertInstalledMcpRunJoined(owner, state.joined, binding); }
    catch (cause) { throw cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('MCP original Run owner did not join', cause); }
  }
}

/** Actual known result stays with the original owner through Stop and storage
 * refusal. Publishing this finite graph is repeatable; protocol I/O is not. */
export async function publishMcpRunCaptures(artifacts: ArtifactCatalog, owner: NativeMcpRunHttpOwner) {
  const state = runOwners.get(owner);
  if (!state?.joined || !state.resultReceived) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP has no original joined received-result owner');
  assertInstalledMcpRunJoined(owner, state.joined, state.binding);
  const metadata: PublishedArtifact[] = [], captures: Array<{ phase: McpHttpPhase; captureRef: string; capture: McpHttpCaptureV1 }> = [];
  for (const [phase, capture] of state.captures) {
    assertInstalledMcpRawResponse(owner, capture.receipt, capture.native);
    metadata.push(await artifacts.publishBytes(capture.bytes, capture.native.mediaType, 'cliq-mcp-http-finite-capture-bytes-v1'));
    const descriptor = await artifacts.publishCanonical(capture.descriptor, capture.descriptor.format);
    metadata.push(descriptor); captures.push({ phase, captureRef: descriptor.ref, capture: capture.descriptor });
  }
  return { binding: state.binding, result: state.result, malformedResult: state.result === undefined,
    captures, joined: state.joined, metadata };
}
export async function publishMcpRunCapture(artifacts: ArtifactCatalog, owner: NativeMcpRunHttpOwner) {
  const captured = await publishMcpRunCaptures(artifacts, owner);
  const state = runOwners.get(owner)!;
  let unusableResponseRef: string | undefined;
  if (captured.captures.length !== 3 || !captured.captures.some(item => item.phase === 'tools_call')) {
    // This synchronous native assertion is the only producer of this audit.
    // A generic export/storage/transport exception cannot manufacture it.
    if (!state.receivedFinal || state.receivedFinal.kind !== 'response' || captured.captures.map(item => item.phase).join(',') !== 'initialize,tools_list')
      throw new KernelStorageError('RECOVERY_REQUIRED', 'received MCP result retains unusable original finite capture custody');
    const refused = owner.readUnusableResponse(state.receivedFinal.receipt);
    assertInstalledMcpUnusableResponse(owner, state.receivedFinal.receipt, refused);
    const message = state.receivedFinal.messageBytes, response = screenedMessage(state.receivedFinal);
    if ((response.kind !== 'result' && response.kind !== 'error') || response.id !== 3)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP unsafe response event cannot become a retained safe known result');
    const messageArtifact = await artifacts.publishBytes(message, 'application/json', 'cliq-mcp-screened-known-event-bytes-v1');
    const auditCore = { schemaVersion: 1 as const, format: 'cliq-mcp-known-unusable-response-v1' as const,
      phase: 'tools_call' as const, expectedId: 3 as const, safeMessageRef: messageArtifact.ref,
      safeMessageDigest: state.receivedFinal.messageDigest, safeMessageBytes: message.byteLength,
      mediaType: refused.mediaType, termination: refused.termination, rawFinitePrefixBytes: refused.rawFinitePrefixBytes,
      rawFinitePrefixDigest: refused.rawFinitePrefixDigest, responseEventEndOffset: refused.responseEventEndOffset,
      receivedTailBytes: refused.receivedTailBytes, reason: refused.reason };
    const audit = decodeMcpKnownUnusableResponse({ ...auditCore, auditDigest: canonicalSha256(auditCore) });
    const artifact = await artifacts.publishCanonical(audit, audit.format);
    captured.metadata.push(messageArtifact, artifact); unusableResponseRef = artifact.ref;
    assertInstalledMcpUnusableResponse(owner, state.receivedFinal.receipt, refused);
  }
  const core = { schemaVersion: 1 as const, format: unusableResponseRef ? 'cliq-mcp-known-unusable-run-capture-v1' as const : 'cliq-mcp-run-capture-v1' as const, binding: captured.binding,
    captures: captured.captures.map(({ phase, captureRef }) => ({ phase, captureRef })), result: captured.result ?? null,
    malformedResult: unusableResponseRef ? false : captured.malformedResult, joined: captured.joined,
    ...(unusableResponseRef ? { unusableResponseRef } : {}) };
  const value: McpRunCaptureV1 = immutableSnapshot({ ...core, captureDigest: canonicalSha256(core) });
  const artifact = await artifacts.publishCanonical(value, value.format);
  publishedRunCaptures.set(artifact.ref, { owner, binding: captured.binding });
  return { ref: artifact.ref, value, metadata: [...captured.metadata, artifact] };
}
export function assertOwnedMcpRunCapture(reference: string, prepared: InvocationJournalEntry, claim: InvocationJournalEntry): void {
  const captured = publishedRunCaptures.get(reference), state = captured && runOwners.get(captured.owner);
  if (!captured || !state?.joined || !state.resultReceived || captured.binding.runId !== claim.runId || captured.binding.opId !== claim.opId ||
      captured.binding.attempt !== claim.attempt || captured.binding.dispatchId !== claim.dispatchId || captured.binding.dispatchJournalSeq !== claim.seq ||
      captured.binding.requestRef !== prepared.requestRef || captured.binding.targetRef !== prepared.target || captured.binding.grantRef !== prepared.grantRef ||
      captured.binding.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest)
    throw new KernelStorageError('LEASE_FENCED', 'MCP result has no unique original native producer');
  assertInstalledMcpRunJoined(captured.owner, state.joined, captured.binding);
}
export function acknowledgeMcpRunCapture(reference: string): void {
  const captured = publishedRunCaptures.get(reference);
  if (!captured) throw new KernelStorageError('LEASE_FENCED', 'MCP result acknowledgement lost its original owner');
  const state = runOwners.get(captured.owner)!;
  if (!state.joined) throw new ResourceRetirementError('MCP result cannot release an unjoined original domain', undefined);
  assertInstalledMcpRunJoined(captured.owner, state.joined, captured.binding);
  captured.owner.releaseDispatchFence(); publishedRunCaptures.delete(reference);
  retainedRunOwners.delete(dispatchKey(captured.binding));
}
/** Actual same-process domain only. Absence is never proof of no release or
 * death; successor recovery separately observes original creator-process death. */
export function readMcpManualDispatchOwner(claim: InvocationJournalEntry) {
  const retained = retainedRunOwners.get(dispatchKey(claim));
  if (!retained) return undefined;
  const { owner, state } = retained, binding = state.binding;
  if (binding.runId !== claim.runId || binding.opId !== claim.opId || binding.attempt !== claim.attempt ||
      binding.dispatchId !== claim.dispatchId || binding.dispatchJournalSeq !== claim.seq || binding.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
      binding.supervisorInstanceId !== claim.supervisorInstanceId || binding.stateOwnerEpoch !== claim.stateOwnerEpoch ||
      binding.leaseEpoch !== claim.leaseEpoch || !state.joined || state.resultReceived)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP manual closure has no exact original uncertain joined owner');
  assertInstalledMcpRunJoined(owner, state.joined, binding);
  return Object.freeze({ owner, binding, joined: state.joined,
    assertJoined() { assertInstalledMcpRunJoined(owner, state.joined!, binding); },
    release() { assertInstalledMcpRunJoined(owner, state.joined!, binding); owner.releaseDispatchFence(); retainedRunOwners.delete(dispatchKey(claim)); } });
}
export function assertMcpRunQuiescence(runId: string): void {
  for (const { owner, state } of retainedRunOwners.values()) if (state.binding.runId === runId) {
    if (state.running || !state.joined) throw new ResourceRetirementError('MCP original producer still owns physical work', undefined);
    assertInstalledMcpRunJoined(owner, state.joined, state.binding);
  }
}
async function readMcpOriginalClaim(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; assembly: RunAssemblyV1; throughEpoch: number;
}) {
  const { prepared, claim, assembly } = input;
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef), target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  const grant = prepared.grantRef && await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, prepared.grantRef);
  const run = readRun(driver, prepared.runId), principalId = readSessionPrincipalId(driver, run.sessionId);
  if (!grant || prepared.opKind !== 'mcp' || prepared.replayClass !== 'manual' || claim.opKind !== 'mcp' || claim.replayClass !== 'manual' ||
      prepared.phase !== 'prepared' || claim.phase !== 'dispatch_claimed' || claim.runId !== prepared.runId || claim.opId !== prepared.opId ||
      claim.attempt !== prepared.attempt || claim.requestRef !== prepared.requestRef || claim.target !== prepared.target || claim.grantRef !== prepared.grantRef ||
      !claim.dispatchId || !claim.brokerFenceTokenDigest || !claim.stateOwnerEpoch || !claim.supervisorInstanceId || claim.sandboxLaunchSpecRef !== undefined ||
      request.requestDigest !== digestOmitting(request, 'requestDigest') || target.targetDigest !== digestOmitting(target, 'targetDigest') ||
      target.execution.kind !== 'mcp' || grant.grantDigest !== digestOmitting(grant, 'grantDigest') || grant.principalId !== principalId ||
      grant.runId !== run.id || request.runId !== run.id || request.opId !== prepared.opId || grant.opId !== prepared.opId ||
      grant.requestRef !== prepared.requestRef || grant.requestDigest !== request.requestDigest || grant.targetRef !== prepared.target ||
      grant.targetDigest !== target.targetDigest || grant.frontierRef !== request.frontierRef || grant.subject.replayClass !== 'manual' ||
      request.targetRef !== prepared.target || request.targetDigest !== target.targetDigest || grant.subject.batchItemId !== request.batchItemId ||
      grant.subject.callId !== request.callId || grant.subject.callIndex !== request.callIndex || grant.subject.toolName !== request.toolName ||
      grant.subject.toolContractDigest !== target.toolContractDigest ||
      grant.maxDispatchedAttempts !== 1 || grant.issuedAt > claim.timestamp || grant.expiresAt <= claim.timestamp || claim.timestamp >= run.deadlineAt ||
      request.assemblyRef !== canonicalSha256(assembly))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original permanent claim is not its exact admitted request/target/grant');
  const execution = target.execution;
  const registry = await readMcpRegistryClosure(driver, artifacts, execution.registryRevisionRef, principalId);
  if (registry.registry.transport.kind !== 'streamable_http' || registry.registry.registrationId !== execution.registrationId ||
      execution.registryManifestDigest !== registry.registry.manifestDigest || !registry.registry.tools.some(tool => tool.name === execution.serverToolName && tool.toolContractDigest === execution.toolContractDigest) ||
      !assembly.mcpServers.some(server => server.registrationId === execution.registrationId &&
      server.registryRevisionRef === registry.ref && server.manifestDigest === registry.registry.manifestDigest))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor cannot borrow another frozen registry or transport');
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
  const images = bundle.entries.filter(entry => entry.entryId === 'mcp-streamable-http-broker-v1');
  if (bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest || images.length !== 1 || images[0]!.role !== 'platform_helper' ||
      !images[0]!.executable || images[0]!.version !== '1' || images[0]!.relativePath !== 'native/linux-x64/linux-mcp-http-broker.node')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original claim has no signed creator-process-only native recipe');
  const history = await readRetainedStateOwnerHistory(driver, artifacts, input.throughEpoch);
  const claiming = history.entries.find(entry => entry.owner.ownerEpoch === claim.stateOwnerEpoch);
  if (!claiming || claiming.owner.supervisorInstanceId !== claim.supervisorInstanceId || claiming.owner.acquiredAt > claim.timestamp ||
      claiming.owner.runtimeBundleRef !== assembly.runtime.runtimeBundleRef || claiming.owner.runtimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest ||
      claiming.process.platform !== 'linux' || claiming.owner.state === 'terminal' && claiming.owner.releasedAt < claim.timestamp)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original native creator is outside its retained StateOwner history');
  return { request, target, execution, grant, registry, history, claiming, principalId };
}
/** Retained data audit of a successor-produced UNKNOWN. The genuine death
 * observation is made only by recoverMcpClaimedAfterProcessDeath below. */
export async function readMcpSuccessorAmbiguityHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; unknown: InvocationJournalEntry; assembly: RunAssemblyV1;
}) {
  const ambiguity = decodeBrokerInvocationAmbiguity(await readCanonicalArtifact(artifacts, input.unknown.evidenceRef!));
  if (!ambiguity.creatorProcessDeathEvidenceRef || !ambiguity.creatorProcessDeathEvidenceDigest)
    throw new TypeError('MCP successor ambiguity lost its actual creator-process death evidence');
  const death = decodeBrokerProcessDomainDeath(await readCanonicalArtifact(artifacts, ambiguity.creatorProcessDeathEvidenceRef));
  const original = await readMcpOriginalClaim(driver, artifacts, { ...input, throughEpoch: death.inspectorStateOwnerEpoch });
  const inspecting = original.history.entries.find(entry => entry.owner.ownerEpoch === death.inspectorStateOwnerEpoch);
  if (!inspecting || inspecting.owner.ownerEpoch <= original.claiming.owner.ownerEpoch ||
      death.evidenceDigest !== ambiguity.creatorProcessDeathEvidenceDigest || death.runId !== input.claim.runId || death.opId !== input.claim.opId ||
      death.attempt !== input.claim.attempt || death.dispatchId !== input.claim.dispatchId || death.dispatchJournalSeq !== input.claim.seq ||
      death.operationRequestRef !== input.prepared.requestRef || death.operationTargetDigest !== original.target.targetDigest ||
      death.operationGrantRef !== input.prepared.grantRef || death.claimingSupervisorInstanceId !== original.claiming.owner.supervisorInstanceId ||
      death.claimingStateOwnerEpoch !== original.claiming.owner.ownerEpoch || death.claimingProcessIdentityRef !== original.claiming.owner.processIdentityRef ||
      death.claimingProcessIdentityDigest !== original.claiming.owner.processIdentityDigest || death.brokerFenceTokenDigest !== input.claim.brokerFenceTokenDigest ||
      death.inspectorIdentityRef !== ambiguity.inspectorIdentityRef || death.inspectorIdentityDigest !== ambiguity.inspectorIdentityDigest ||
      death.observedAt < inspecting.owner.acquiredAt || death.observedAt < input.claim.timestamp || death.observedAt > input.unknown.timestamp ||
      Date.parse(input.unknown.timestamp) - Date.parse(death.observedAt) > 5_000 || ambiguity.observedAt !== input.unknown.timestamp ||
      inspecting.owner.state === 'terminal' && inspecting.owner.releasedAt < input.unknown.timestamp)
    throw new TypeError('MCP successor ambiguity substitutes its original creator, exact claim or actual fresh inspector');
  await readSupervisorInspector(artifacts, inspecting.owner, { runtime: { runtimeBundleRef: inspecting.owner.runtimeBundleRef,
    runtimeBundleManifestDigest: inspecting.owner.runtimeBundleManifestDigest } }, ambiguity);
  return { ...original, ambiguity, death, inspecting };
}
/** Both original-owner and actual successor UNKNOWNs use one retained audit.
 * Neither CAS data nor this reader supplies live release/death authority. */
export async function readMcpAmbiguityHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; unknown: InvocationJournalEntry; assembly: RunAssemblyV1;
}) {
  const { prepared, claim, unknown, assembly } = input;
  const ambiguity = decodeBrokerInvocationAmbiguity(await readCanonicalArtifact(artifacts, unknown.evidenceRef!));
  const original = ambiguity.creatorProcessDeathEvidenceRef ? await readMcpSuccessorAmbiguityHistory(driver, artifacts, input) :
    await readMcpOriginalClaim(driver, artifacts, { prepared, claim, assembly, throughEpoch: claim.stateOwnerEpoch! });
  if (unknown.phase !== 'unknown' || unknown.opKind !== 'mcp' || unknown.evidenceDigest !== ambiguity.evidenceDigest || unknown.runId !== claim.runId ||
      unknown.opId !== claim.opId || unknown.attempt !== claim.attempt || unknown.requestRef !== prepared.requestRef || unknown.target !== prepared.target ||
      unknown.grantRef !== prepared.grantRef || unknown.dispatchId !== claim.dispatchId || unknown.stateOwnerEpoch !== claim.stateOwnerEpoch ||
      unknown.supervisorInstanceId !== claim.supervisorInstanceId || unknown.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
      ambiguity.runId !== claim.runId || ambiguity.opId !== claim.opId || ambiguity.opKind !== 'mcp' || ambiguity.attempt !== claim.attempt ||
      ambiguity.dispatchId !== claim.dispatchId || ambiguity.dispatchJournalSeq !== claim.seq || ambiguity.operationRequestRef !== prepared.requestRef ||
      ambiguity.operationRequestDigest !== original.request.requestDigest || ambiguity.operationTargetRef !== prepared.target ||
      ambiguity.operationTargetDigest !== original.target.targetDigest || ambiguity.claimingSupervisorInstanceId !== claim.supervisorInstanceId ||
      ambiguity.claimingStateOwnerEpoch !== claim.stateOwnerEpoch || ambiguity.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
      ambiguity.frontierRef !== original.request.frontierRef || ambiguity.frontierDigest !== original.request.frontierRef || ambiguity.observedAt !== unknown.timestamp ||
      unknown.timestamp < claim.timestamp || !unknown.budgetSettlementRef)
    throw new TypeError('MCP UNKNOWN does not retain its exact original permanent claim and received-result absence audit');
  if (!ambiguity.creatorProcessDeathEvidenceRef) {
    if (original.claiming.owner.state === 'terminal' && original.claiming.owner.releasedAt < unknown.timestamp)
      throw new TypeError('MCP original UNKNOWN inspector is outside its actual owner lifetime');
    await readSupervisorInspector(artifacts, original.claiming.owner, assembly, ambiguity);
  }
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef));
  if (settlement.runId !== claim.runId || settlement.opId !== claim.opId || settlement.attempt !== claim.attempt || settlement.terminalPhase !== 'unknown' ||
      settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== unknown.seq || settlement.settledAt !== unknown.timestamp)
    throw new TypeError('MCP UNKNOWN has no original full-once settlement');
  for (const usage of [unknown.budgetDelta, settlement.reserved, settlement.consumed, settlement.released])
    requireEqual(usage, prepared.budgetDelta, 'MCP UNKNOWN whole original charge exactly once');
  return { ...original, ambiguity, settlement };
}
/** No target I/O or old token is recreated. Real death of the original
 * nontransferable creator closes only its local domain; remote effect and a
 * response never durably handed off remain UNKNOWN/full once. */
export async function recoverMcpClaimedAfterProcessDeath(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  installedRuntime: HeldInstalledRuntime, input: { runId: string; expectedRunRevision: number }) {
  const run = readRun(driver, input.runId);
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'MCP successor claim cut changed');
  const rows = driver.prepare("SELECT op_id,attempt FROM run_journal WHERE run_id=? AND op_kind='mcp' AND phase='dispatch_claimed'").all<{op_id:string;attempt:number}>(run.id);
  const claims = rows.map(row => readInvocationAttempt(driver, run.id, row.op_id, Number(row.attempt))).filter(entries => entries.at(-1)?.phase === 'dispatch_claimed');
  if (!claims.length) return undefined;
  if (claims.length !== 1 || claims[0]!.length !== 2) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor requires exactly one original unsettled claim');
  const [prepared, claim] = claims[0]!;
  const active = assertActiveStateOwner(driver, owner);
  if (claim!.stateOwnerEpoch === active.ownerEpoch || retainedRunOwners.has(dispatchKey(claim!))) return undefined;
  const spec = await readCanonicalArtifact<import('../kernel/types.js').RunSpec>(artifacts, run.specRef);
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  const original = await readMcpOriginalClaim(driver, artifacts, { prepared: prepared!, claim: claim!, assembly, throughEpoch: active.ownerEpoch });
  if (active.ownerEpoch <= original.claiming.owner.ownerEpoch) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor must be a strictly newer retained owner');
  assertInstalledMcpBrokerProcess();
  await withHeldInstalledRuntime(installedRuntime, async installed => {
    const root = stateRootIdentityForLock(owner.filesystem), inspecting = original.history.entries.find(entry => entry.owner.ownerEpoch === active.ownerEpoch);
    if (!inspecting || canonicalSha256(inspecting.owner) !== canonicalSha256(active) || canonicalSha256(root) !== canonicalSha256(original.history.rootIdentity) ||
        installed.bundleDigest !== active.runtimeBundleRef || installed.bundle.manifestDigest !== active.runtimeBundleManifestDigest ||
        installed.stateRoot.canonicalPath !== root.canonicalAbsolutePath || installed.stateRoot.deviceId !== root.deviceId || installed.stateRoot.fileId !== root.directoryFileId)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor is not the actual current installed StateRoot owner');
    await installed.revalidate();
    const process = await (await installed.loadStateOwner()).observeCurrentProcess();
    if (process.pid !== inspecting.process.pid || process.processStartToken !== inspecting.process.processStartToken || process.executableImageDigest !== active.supervisorExecutableDigest)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor inspector is not the actual current signed process');
  });
  const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const observedAt = new Date(owner.filesystem.observePriorProcessDeath(original.claiming.process.pid, original.claiming.process.processStartToken)).toISOString();
  const death: BrokerProcessDomainDeathEvidenceV1 = { schemaVersion: 1, format: 'cliq-broker-process-domain-death-evidence-v1', runId: run.id,
    opId: claim!.opId, attempt: claim!.attempt, dispatchId: claim!.dispatchId!, dispatchJournalSeq: claim!.seq, operationRequestRef: prepared!.requestRef,
    operationTargetDigest: original.target.targetDigest, operationGrantRef: prepared!.grantRef!, claimingSupervisorInstanceId: original.claiming.owner.supervisorInstanceId,
    claimingStateOwnerEpoch: original.claiming.owner.ownerEpoch, claimingProcessIdentityRef: original.claiming.owner.processIdentityRef,
    claimingProcessIdentityDigest: original.claiming.owner.processIdentityDigest, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    inspectorStateOwnerEpoch: active.ownerEpoch, brokerFenceTokenDigest: claim!.brokerFenceTokenDigest!, authorityDomain: 'linux_installed_native_creator_process_v1',
    processObservation: 'absent_or_start_token_mismatch', observedAt, evidenceDigest: '' };
  death.evidenceDigest = digestOmitting(death, 'evidenceDigest'); decodeBrokerProcessDomainDeath(death);
  const deathArtifact = await artifacts.publishCanonical(death, death.format);
  const prototype: BrokerInvocationAmbiguityEvidenceV1 = { schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1', runId: run.id,
    frontierRef: original.request.frontierRef, frontierDigest: original.request.frontierRef, opId: claim!.opId, opKind: 'mcp', attempt: claim!.attempt,
    dispatchId: claim!.dispatchId!, dispatchJournalSeq: claim!.seq, operationRequestRef: prepared!.requestRef, operationRequestDigest: original.request.requestDigest,
    operationTargetRef: prepared!.target, operationTargetDigest: original.target.targetDigest, claimingSupervisorInstanceId: claim!.supervisorInstanceId!,
    claimingStateOwnerEpoch: claim!.stateOwnerEpoch!, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    observedAt, ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: claim!.brokerFenceTokenDigest!, failureCode: 'response_stream_interrupted',
    durableTerminalResultAbsent: true, creatorProcessDeathEvidenceRef: deathArtifact.ref, creatorProcessDeathEvidenceDigest: death.evidenceDigest, evidenceDigest: '' };
  prototype.evidenceDigest = digestOmitting(prototype, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(prototype);
  const evidence = await artifacts.publishCanonical(prototype, prototype.format);
  return settleValidatedInvocation(driver, artifacts, owner, { ...input, opId: claim!.opId, attempt: claim!.attempt },
    { phase: 'unknown', evidenceRef: evidence.ref, evidenceDigest: prototype.evidenceDigest }, async ({ settlement }) => {
      const value = { ...prototype, observedAt: settlement.settledAt, evidenceDigest: '' };
      value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(value);
      const artifact = await artifacts.publishCanonical(value, value.format);
      let fresh: number | undefined;
      return { metadata: [inspectorArtifact, deathArtifact, artifact], unknownEvidence: { evidenceRef: artifact.ref, evidenceDigest: value.evidenceDigest },
        reobserve(connection) { assertActiveStateOwner(connection, owner); fresh = owner.filesystem.observePriorProcessDeath(original.claiming.process.pid, original.claiming.process.processStartToken); },
        validate(connection, current, committedAt) {
          original.history.assertUnchanged(connection); assertActiveStateOwner(connection, owner);
          requireEqual(readInvocationAttempt(connection, run.id, claim!.opId, claim!.attempt), [prepared, claim], 'MCP successor exact original unsettled claim');
          if (current.frontierRef !== original.request.frontierRef || current.specRef !== run.specRef || readSessionPrincipalId(connection, current.sessionId) !== original.principalId ||
              fresh === undefined || fresh < Date.parse(observedAt) || fresh > Date.parse(committedAt) || Date.parse(committedAt) - Date.parse(observedAt) > 5_000)
            throw new KernelStorageError('LEASE_FENCED', 'MCP successor creator death is not fresh at its true original UNKNOWN commit');
        } };
    });
}
/** Whole-claim UNKNOWN after actual original native join. Setup target I/O is
 * part of this same charge; effectReleased=false cannot become a refund. */
export async function settleMcpRunUnknown(driver: SqliteDriver, artifacts: ArtifactCatalog, context: StateOwnerContext,
  owner: NativeMcpRunHttpOwner, prepared: InvocationJournalEntry, claim: InvocationJournalEntry) {
  const state = runOwners.get(owner);
  if (!state?.joined || state.resultReceived) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP unknown cannot discard an actual received result or unjoined producer');
  const binding = state.binding;
  assertInstalledMcpRunJoined(owner, state.joined, binding);
  const history = readInvocationAttempt(driver, claim.runId, claim.opId, claim.attempt);
  if (history.at(-1)?.phase === 'unknown') return { entry: history.at(-1)!, run: readRun(driver, claim.runId) };
  requireEqual(history, [prepared, claim], 'MCP unknown exact one permanent claim');
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef);
  const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  const active = assertActiveStateOwner(driver, context);
  if (active.supervisorInstanceId !== claim.supervisorInstanceId || active.ownerEpoch !== claim.stateOwnerEpoch ||
      prepared.opKind !== 'mcp' || claim.opKind !== 'mcp' || prepared.replayClass !== 'manual' ||
      target.execution.kind !== 'mcp' || !prepared.grantRef || !claim.dispatchId || !claim.brokerFenceTokenDigest)
    throw new KernelStorageError('LEASE_FENCED', 'MCP unknown belongs to another original native claim owner');
  const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const prototype: BrokerInvocationAmbiguityEvidenceV1 = { schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1',
    runId: claim.runId, frontierRef: request.frontierRef, frontierDigest: request.frontierRef, opId: claim.opId, opKind: 'mcp',
    attempt: claim.attempt, dispatchId: claim.dispatchId, dispatchJournalSeq: claim.seq, operationRequestRef: prepared.requestRef,
    operationRequestDigest: request.requestDigest, operationTargetRef: prepared.target, operationTargetDigest: target.targetDigest,
    claimingSupervisorInstanceId: active.supervisorInstanceId, claimingStateOwnerEpoch: active.ownerEpoch,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow(),
    ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: claim.brokerFenceTokenDigest,
    failureCode: 'response_stream_interrupted', durableTerminalResultAbsent: true, evidenceDigest: '' };
  prototype.evidenceDigest = digestOmitting(prototype, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(prototype);
  const original = await artifacts.publishCanonical(prototype, prototype.format);
  return settleValidatedInvocation(driver, artifacts, context, { runId: claim.runId, opId: claim.opId, attempt: claim.attempt,
    expectedRunRevision: readRun(driver, claim.runId).revision }, { phase: 'unknown', evidenceRef: original.ref, evidenceDigest: prototype.evidenceDigest },
  async ({ run, settlement }) => {
    const evidence: BrokerInvocationAmbiguityEvidenceV1 = { ...prototype, observedAt: settlement.settledAt, evidenceDigest: '' };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeBrokerInvocationAmbiguity(evidence);
    const artifact = await artifacts.publishCanonical(evidence, evidence.format);
    return { metadata: [artifact, inspectorArtifact], unknownEvidence: { evidenceRef: artifact.ref, evidenceDigest: evidence.evidenceDigest },
      validate(connection, current, committedAt) {
        assertInstalledMcpRunJoined(owner, state.joined!, binding);
        const currentOwner = assertActiveStateOwner(connection, context);
        requireEqual(readInvocationAttempt(connection, claim.runId, claim.opId, claim.attempt), [prepared, claim], 'MCP unknown original permanent claim at settlement');
        if (currentOwner.ownerEpoch !== claim.stateOwnerEpoch || currentOwner.supervisorInstanceId !== claim.supervisorInstanceId ||
            current.frontierRef !== request.frontierRef || current.specRef !== run.specRef || current.leaseEpoch !== claim.leaseEpoch ||
            readSessionPrincipalId(connection, current.sessionId) !== readSessionPrincipalId(driver, run.sessionId) || committedAt < settlement.settledAt)
          throw new KernelStorageError('LEASE_FENCED', 'MCP unknown no longer owns its original Run/frontier/owner');
      } };
  });
}
export async function failMcpRunWithoutRelease(driver: SqliteDriver, artifacts: ArtifactCatalog, context: StateOwnerContext,
  owner: NativeMcpRunHttpOwner, prepared: InvocationJournalEntry, claim: InvocationJournalEntry, resolveToolInput: ResolveToolInput) {
  const state = runOwners.get(owner);
  if (!state?.joined || state.resultReceived || state.joined.networkStarted || state.joined.requestStarted || state.joined.setupReleased || state.joined.effectReleased)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP no-release requires the exact original joined owner and zero target I/O');
  const binding = state.binding;
  assertInstalledMcpRunJoined(owner, state.joined, binding);
  state.noReleaseFence ??= owner.acquireNoReleaseFence(binding);
  const fence = state.noReleaseFence; assertInstalledMcpNoReleaseFence(fence, binding);
  const selected = await readToolCut(driver, artifacts, claim.runId, resolveToolInput);
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef), target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  const active = assertActiveStateOwner(driver, context);
  if (active.ownerEpoch !== claim.stateOwnerEpoch || active.supervisorInstanceId !== claim.supervisorInstanceId ||
      selected.call.callId !== request.callId || selected.batch.itemId !== request.batchItemId || selected.frontier.nextCallIndex !== request.callIndex)
    throw new KernelStorageError('LEASE_FENCED', 'MCP no-release lost its original owner and ordered prepared call');
  const inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const evidence: BrokerPostClaimNoReleaseEvidenceV1 = { schemaVersion: 1, format: 'cliq-post-claim-no-release-evidence-v1',
    runId: claim.runId, opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId!, dispatchJournalSeq: claim.seq,
    operationRequestRef: prepared.requestRef, operationRequestDigest: request.requestDigest, operationTargetRef: prepared.target,
    operationTargetDigest: target.targetDigest, operationGrantRef: prepared.grantRef!, claimingSupervisorInstanceId: claim.supervisorInstanceId!,
    claimingStateOwnerEpoch: claim.stateOwnerEpoch!, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    observedAt: sampleCanonicalNow(), closure: { kind: 'broker_release_never_started', brokerFenceTokenDigest: claim.brokerFenceTokenDigest!,
      fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero' }, evidenceDigest: '' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeBrokerPostClaimNoRelease(evidence);
  const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.format);
  const error = planCanonicalArtifact({ schemaVersion: 1, format: 'cliq-mcp-no-release-error-v1', runId: claim.runId,
    opId: claim.opId, attempt: claim.attempt, requestRef: prepared.requestRef, evidenceRef: evidenceArtifact.ref,
    evidenceDigest: evidence.evidenceDigest, code: 'TOOL_EXECUTION_FAILED' }, 'cliq-invocation-error-v1');
  await artifacts.publishBytes(error.bytes, error.mediaType, error.schemaKind);
  const settled = await settleValidatedInvocation(driver, artifacts, context, { runId: claim.runId, opId: claim.opId, attempt: claim.attempt,
    expectedRunRevision: selected.run.revision }, { phase: 'failed', requireClaim: true, consumed: ZERO_BUDGET,
    errorRef: error.ref, evidenceRef: evidenceArtifact.ref, evidenceDigest: evidence.evidenceDigest }, async ({ settlement }) => {
      const result = planToolInvocationResult(request, settlement.settledAt, { outcome: 'error', code: 'TOOL_EXECUTION_FAILED',
        diagnosticRef: error.ref, diagnosticDigest: error.ref, opId: claim.opId, attempt: claim.attempt,
        journalErrorRef: error.ref, journalErrorDigest: error.ref }, { code: 'TOOL_EXECUTION_FAILED' });
      const graph = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
        items: [result.item], frontier: nextToolFrontier(selected, 1), checkpointId: mcpNoReleaseCheckpointId(claim.runId, claim.opId, claim.attempt),
        workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [error, ...result.artifacts] });
      return { metadata: [...graph.metadata, evidenceArtifact, inspectorArtifact],
        validate(connection, current, committedAt) {
          assertInstalledMcpNoReleaseFence(fence, binding); assertActiveStateOwner(connection, context);
          requireEqual(readInvocationAttempt(connection, claim.runId, claim.opId, claim.attempt), [prepared, claim], 'MCP zero-I/O original claim');
          if (current.frontierRef !== selected.run.frontierRef || current.latestCheckpointId !== selected.run.latestCheckpointId ||
              current.leaseEpoch !== claim.leaseEpoch || committedAt < evidence.observedAt || Date.parse(committedAt) - Date.parse(evidence.observedAt) > 5000)
            throw new KernelStorageError('LEASE_FENCED', 'MCP no-release original held fence or ordered cut changed');
        }, commit(connection, current, journal, committedAt) { graph.commit(connection, current, journal.seq, committedAt); } };
    });
  fence.close(); state.noReleaseFence = undefined; owner.releaseDispatchFence(); retainedRunOwners.delete(dispatchKey(claim));
  return settled.run;
}
export async function readMcpNoReleaseHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; failed: InvocationJournalEntry; assembly: RunAssemblyV1;
}) {
  const { prepared, claim, failed, assembly } = input;
  if (prepared.opKind !== 'mcp' || claim.opKind !== 'mcp' || failed.opKind !== 'mcp' || prepared.replayClass !== 'manual' ||
      failed.phase !== 'failed' || !failed.errorRef || !failed.evidenceRef || !failed.budgetSettlementRef || !claim.brokerFenceTokenDigest || claim.sandboxLaunchSpecRef)
    throw new TypeError('MCP no-release history lacks its exact original HTTP claim');
  const originalClaim = await readMcpOriginalClaim(driver, artifacts, { prepared, claim, assembly, throughEpoch: claim.stateOwnerEpoch! });
  const { request, target, history } = originalClaim;
  const evidence = decodeBrokerPostClaimNoRelease(await readCanonicalArtifact(artifacts, failed.evidenceRef));
  const error = await readCanonicalArtifact(artifacts, failed.errorRef), settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, failed.budgetSettlementRef));
  requireEqual(error, { schemaVersion: 1, format: 'cliq-mcp-no-release-error-v1', runId: claim.runId, opId: claim.opId,
    attempt: claim.attempt, requestRef: prepared.requestRef, evidenceRef: failed.evidenceRef, evidenceDigest: evidence.evidenceDigest, code: 'TOOL_EXECUTION_FAILED' }, 'MCP original zero-I/O failure');
  requireEqual(evidence, { schemaVersion: 1, format: evidence.format, runId: claim.runId, opId: claim.opId, attempt: claim.attempt,
    dispatchId: claim.dispatchId, dispatchJournalSeq: claim.seq, operationRequestRef: prepared.requestRef,
    operationRequestDigest: request.requestDigest, operationTargetRef: prepared.target, operationTargetDigest: target.targetDigest,
    operationGrantRef: prepared.grantRef, claimingSupervisorInstanceId: claim.supervisorInstanceId, claimingStateOwnerEpoch: claim.stateOwnerEpoch,
    inspectorIdentityRef: evidence.inspectorIdentityRef, inspectorIdentityDigest: evidence.inspectorIdentityDigest, observedAt: evidence.observedAt,
    closure: { kind: 'broker_release_never_started', brokerFenceTokenDigest: claim.brokerFenceTokenDigest,
      fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero' }, evidenceDigest: evidence.evidenceDigest }, 'MCP original held native no-release closure');
  requireEqual(failed, { ...claim, seq: failed.seq, phase: 'failed', errorRef: failed.errorRef, evidenceRef: failed.evidenceRef,
    evidenceDigest: evidence.evidenceDigest, budgetDelta: ZERO_BUDGET, budgetSettlementRef: failed.budgetSettlementRef, timestamp: failed.timestamp }, 'MCP exact zero-consumption failed claim');
  if (evidence.observedAt < claim.timestamp || evidence.observedAt > failed.timestamp || Date.parse(failed.timestamp) - Date.parse(evidence.observedAt) > 5000 ||
      settlement.runId !== claim.runId || settlement.opId !== claim.opId || settlement.attempt !== claim.attempt || settlement.preparedJournalSeq !== prepared.seq ||
      settlement.terminalJournalSeq !== failed.seq || settlement.terminalPhase !== 'failed' || settlement.settledAt !== failed.timestamp)
    throw new TypeError('MCP no-release is outside its original held fence settlement');
  requireEqual(settlement.consumed, ZERO_BUDGET, 'MCP no-release zero charge'); requireEqual(settlement.reserved, prepared.budgetDelta, 'MCP no-release original reservation');
  requireEqual(settlement.released, prepared.budgetDelta, 'MCP no-release original refund');
  const original = originalClaim.claiming.owner;
  if (original.supervisorInstanceId !== claim.supervisorInstanceId || original.acquiredAt > claim.timestamp ||
      original.state === 'terminal' && original.releasedAt < failed.timestamp) throw new TypeError('MCP no-release is outside its original StateOwner lifetime');
  await readSupervisorInspector(artifacts, original, assembly, evidence);
  return { request, target, evidence, error, settlement, history };
}

/** Complete retained data audit. It cannot create a native result, live fence
 * or resource proof; live completion also requires the original owner above. */
export async function readMcpRunCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  captureRef: string; captureDigest: string; prepared: InvocationJournalEntry; claim: InvocationJournalEntry; assembly: RunAssemblyV1;
}) {
  const value = await readCanonicalArtifact<McpRunCaptureV1>(artifacts, input.captureRef), { prepared, claim, assembly } = input;
  const unusable = value.format === 'cliq-mcp-known-unusable-run-capture-v1';
  if (!exactKeys(value, ['schemaVersion', 'format', 'binding', 'captures', 'result', 'malformedResult', 'joined', 'captureDigest', ...(unusable ? ['unusableResponseRef'] : [])]) ||
      value.schemaVersion !== 1 || !['cliq-mcp-run-capture-v1', 'cliq-mcp-known-unusable-run-capture-v1'].includes(value.format) || typeof value.malformedResult !== 'boolean' ||
      unusable && (value.malformedResult || value.result !== null) ||
      value.captureDigest !== input.captureDigest || value.captureDigest !== digestOmitting(value, 'captureDigest'))
    throw new TypeError('MCP retained capture does not rehash');
  const { request, target, execution, grant, registry } = await readMcpOriginalClaim(driver, artifacts,
    { prepared, claim, assembly, throughEpoch: claim.stateOwnerEpoch! });
  const selected = assembly.mcpServers.find(item => item.registrationId === execution.registrationId);
  const launch = readWorkerLaunch(driver, value.binding.workerLaunchId);
  if (!selected || selected.registryRevisionRef !== registry.ref || selected.manifestDigest !== registry.registry.manifestDigest ||
      !exactKeys(value.binding, ['runId', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest',
        'grantRef', 'grantDigest', 'registryRef', 'manifestDigest', 'toolContractDigest', 'batchItemId', 'callId', 'callIndex', 'supervisorInstanceId',
        'stateOwnerEpoch', 'workerLaunchId', 'leaseEpoch', 'brokerFenceTokenDigest', 'deadlineMs']) ||
      !launch || launch.runId !== claim.runId || !launch.activatedAt || launch.activatedAt > claim.timestamp || launch.retiredAt && launch.retiredAt < claim.timestamp ||
      launch.leaseEpoch !== claim.leaseEpoch || !Number.isSafeInteger(value.binding.deadlineMs) || value.binding.deadlineMs <= Date.parse(claim.timestamp) ||
      value.binding.deadlineMs > Math.min(Date.parse(grant.expiresAt), Date.parse(readRun(driver, claim.runId).deadlineAt), Date.parse(claim.timestamp) + registry.registry.lifecycle.callTimeoutMs) ||
      execution.registryManifestDigest !== registry.registry.manifestDigest || prepared.opKind !== 'mcp' || claim.opKind !== 'mcp' ||
      prepared.replayClass !== 'manual' || claim.replayClass !== 'manual' || claim.sandboxLaunchSpecRef !== undefined ||
      value.binding.runId !== claim.runId || value.binding.opId !== claim.opId || value.binding.attempt !== claim.attempt ||
      value.binding.dispatchId !== claim.dispatchId || value.binding.dispatchJournalSeq !== claim.seq || value.binding.requestRef !== prepared.requestRef ||
      value.binding.requestDigest !== request.requestDigest || value.binding.targetRef !== prepared.target || value.binding.targetDigest !== target.targetDigest ||
      value.binding.grantRef !== prepared.grantRef || value.binding.grantDigest !== grant.grantDigest || value.binding.registryRef !== registry.ref ||
      value.binding.manifestDigest !== registry.registry.manifestDigest || value.binding.toolContractDigest !== execution.toolContractDigest ||
      value.binding.batchItemId !== request.batchItemId || value.binding.callId !== request.callId || value.binding.callIndex !== request.callIndex ||
      value.binding.supervisorInstanceId !== claim.supervisorInstanceId || value.binding.stateOwnerEpoch !== claim.stateOwnerEpoch ||
      value.binding.leaseEpoch !== claim.leaseEpoch || value.binding.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest ||
      value.joined.purpose !== 'run' || value.joined.brokerFenceTokenDigest !== claim.brokerFenceTokenDigest || value.joined.tokenRevoked !== true ||
      value.joined.matchingActiveReleaseCount !== 0 || value.joined.networkJoined !== true || value.joined.tasksJoined !== true ||
      !exactKeys(value.joined, ['kind', 'purpose', 'brokerFenceTokenDigest', 'networkStarted', 'requestStarted', 'setupReleased', 'effectReleased',
        'completedStages', 'tokenRevoked', 'matchingActiveReleaseCount', 'networkJoined', 'tasksJoined']) ||
      value.joined.kind !== 'mcp_http_owner_joined' || value.joined.networkStarted !== true || value.joined.requestStarted !== true ||
      value.joined.setupReleased !== true || value.joined.effectReleased !== true ||
      value.joined.completedStages.join(',') !== (unusable ? 'initialize,initialized,tools_list' : 'initialize,initialized,tools_list,tools_call') ||
      value.captures.length !== (unusable ? 2 : 3) || value.captures.map(item => item.phase).join(',') !== (unusable ? 'initialize,tools_list' : 'initialize,tools_list,tools_call'))
    throw new TypeError('MCP result capture differs from its original permanent claim and frozen registry');
  const captures = await artifacts.mapReads(value.captures, item => readMcpHttpCapture(artifacts, item.captureRef));
  for (let index = 0; index < captures.length; index++) {
    const descriptor = captures[index]!.capture;
    if (!exactKeys(value.captures[index]!, ['phase', 'captureRef']) || descriptor.phase !== value.captures[index]!.phase || descriptor.expectedId !== index + 1)
      throw new TypeError('MCP retained capture changes its fixed original response phase or id');
  }
  const [initialize, listed, called] = captures;
  if (initialize!.decoded.response.kind !== 'result' || listed!.decoded.response.kind !== 'result') throw new TypeError('MCP call has no real setup');
  const negotiation = decodeMcpInitializeResult(initialize!.decoded.response.result), tools = decodeMcpToolsListResult(listed!.decoded.response.result);
  if (negotiation.initializeDigest !== registry.registry.initializeDigest || negotiation.capabilityDigest !== registry.registry.capabilityDigest ||
      canonicalSha256(tools.map(item => item.interface)) !== registry.registry.probedToolsListDigest)
    throw new TypeError('MCP received setup differs from frozen discovery');
  const contract = registry.registry.tools.find(item => item.name === execution.serverToolName);
  if (!contract || contract.toolContractDigest !== execution.toolContractDigest) throw new TypeError('MCP call has no frozen exact tool contract');
  let result: McpCallResultV1 | undefined, unusableResponse: McpKnownUnusableResponseV1 | undefined;
  if (unusable) {
    unusableResponse = decodeMcpKnownUnusableResponse(await readCanonicalArtifact(artifacts, value.unusableResponseRef!));
    const bytes = await artifacts.readBoundedBytes(unusableResponse.safeMessageRef, unusableResponse.safeMessageBytes);
    if (bytes.byteLength !== unusableResponse.safeMessageBytes || sha256Bytes(bytes) !== unusableResponse.safeMessageDigest)
      throw new TypeError('MCP known-unusable original screened event changed its complete retained bytes');
    const message = decodeMcpInboundMessageData(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
    if ((message.kind !== 'result' && message.kind !== 'error') || message.id !== 3)
      throw new TypeError('MCP known-unusable audit substitutes an unsafe, partial or unrelated response event');
  } else try { result = called!.decoded.response.kind === 'error' ? { kind: 'rpc_error', ...called!.decoded.response.error }
    : decodeMcpCallResult(called!.decoded.response.result, contract.outputSchemaRef ? await readCanonicalArtifact(artifacts, contract.outputSchemaRef) : undefined); }
  catch (error) { if (!value.malformedResult) throw error; }
  requireEqual(value.result, result ?? null, 'MCP original received result projection');
  if (!unusable && value.malformedResult !== (result === undefined)) throw new TypeError('MCP malformed result flag rewrites received truth');
  const metadata = [await artifacts.describe(input.captureRef, 'application/json', value.format)];
  if (unusableResponse) metadata.push(await artifacts.describe(value.unusableResponseRef!, 'application/json', unusableResponse.format),
    await artifacts.describe(unusableResponse.safeMessageRef, 'application/json', 'cliq-mcp-screened-known-event-bytes-v1'));
  for (let index = 0; index < captures.length; index++) {
    const captured = captures[index]!;
    metadata.push(await artifacts.describe(value.captures[index]!.captureRef, 'application/json', captured.capture.format));
    metadata.push(await artifacts.describe(captured.capture.rawResponseRef, captured.capture.mediaType, 'cliq-mcp-http-finite-capture-bytes-v1'));
  }
  return { value, result, unusableResponse, metadata };
}
export function mcpObservationContent(result: McpCallResultV1): unknown { return immutableSnapshot(result); }
/** Original completed-result cause only. This audit proves native refusal and
 * retained safe event custody; it never claims unsafe omitted bytes were read
 * again. The sole Stop writer owns the resulting terminal transition. */
export async function readMcpKnownUnusableCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  observedAt: string, sourceCheckpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number) {
  if (!cut.journal.some(entry => entry.opKind === 'mcp' && entry.phase === 'completed')) return undefined;
  const source = readStopSourceData(driver, cut, observedAt, sourceCheckpointId, sourceRunRevision, registeredJournalSeq);
  const latest = source.journal.at(-1);
  if (latest?.opKind !== 'mcp' || latest.phase !== 'completed' || !latest.resultRef || !latest.budgetSettlementRef) return undefined;
  const observation = await readCanonicalArtifact<ToolObservationV1>(artifacts, latest.resultRef);
  if (!observation.captureRef || !observation.captureDigest) throw new TypeError('MCP completed result lost its original capture');
  const rawCapture = await readCanonicalArtifact<McpRunCaptureV1>(artifacts, observation.captureRef);
  if (rawCapture.format !== 'cliq-mcp-known-unusable-run-capture-v1') return undefined;
  const entries = source.journal.filter(entry => entry.opId === latest.opId && entry.attempt === latest.attempt), [prepared, claim] = entries;
  if (entries.length !== 3 || prepared?.phase !== 'prepared' || claim?.phase !== 'dispatch_claimed' ||
      source.journal.some(entry => entry.opId === latest.opId && entry.attempt !== latest.attempt && entry.phase === 'dispatch_claimed'))
    throw new TypeError('MCP known-unusable failure does not own one original completed claim');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, cut.runSpec.assemblyRef);
  const captured = await readMcpRunCapture(driver, artifacts, { captureRef: observation.captureRef, captureDigest: observation.captureDigest, prepared, claim, assembly });
  await assertMcpCaptureObservation(artifacts, observation, captured);
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef);
  const row = source.items.at(-1), item = row && await readCanonicalArtifact<ToolResultItem>(artifacts, row.payloadRef);
  if (!row || !item || item.kind !== 'tool_result' || item.outcome !== 'error' || item.opId !== latest.opId ||
      item.batchItemId !== request.batchItemId || item.callId !== request.callId || item.index !== request.callIndex ||
      item.createdAt !== latest.timestamp || row.itemSeq !== source.checkpoint.runItemSeq ||
      source.checkpoint.id !== toolCheckpointId(cut.run.id, latest.opId, latest.attempt) || source.checkpoint.journalSeq !== latest.seq ||
      observation.outcome !== 'error' || observation.code !== 'TOOL_PROTOCOL_ERROR' || observation.observationDigest !== digestOmitting(observation, 'observationDigest') ||
      observation.observedAt > latest.timestamp || latest.timestamp > observedAt)
    throw new TypeError('MCP known-unusable failure is not its original result item and ready Checkpoint');
  const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
  if (payload.outcome !== 'error' || payload.journalErrorRef !== latest.resultRef || payload.journalErrorDigest !== observation.observationDigest ||
      payload.diagnosticRef !== observation.diagnosticRef || payload.diagnosticDigest !== observation.diagnosticDigest)
    throw new TypeError('MCP known-unusable result item substituted its original completed observation');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, latest.budgetSettlementRef));
  if (settlement.runId !== cut.run.id || settlement.opId !== latest.opId || settlement.attempt !== latest.attempt || settlement.terminalPhase !== 'completed' ||
      settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== latest.seq || settlement.settledAt !== latest.timestamp)
    throw new TypeError('MCP known-unusable result has no original completed full-charge settlement');
  requireEqual(settlement.reserved, prepared.budgetDelta, 'MCP known-unusable original reservation');
  requireEqual(settlement.consumed, prepared.budgetDelta, 'MCP known-unusable original full charge');
  const batchRow = source.items.find(entry => entry.itemId === request.batchItemId);
  if (!batchRow) throw new TypeError('MCP known-unusable result lost its original tool batch');
  const batch = await readCanonicalArtifact<ToolBatchItem>(artifacts, batchRow.payloadRef);
  const original = await readCanonicalArtifact<Extract<RunFrontier, {kind:'tool'}>>(artifacts, request.frontierRef);
  const frontier: RunFrontier = request.callIndex + 1 < batch.calls.length ? { ...original, nextCallIndex: request.callIndex + 1 } :
    { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', cut.run.id, batch.itemId),
      contextItemSeq: source.checkpoint.runItemSeq, cause: 'tool_batch_complete' };
  const frontierRef = canonicalSha256(frontier);
  if (sourceCheckpointId === undefined && cut.run.frontierRef !== frontierRef)
    throw new TypeError('MCP known-unusable Stop does not own its original next frontier');
  return { frontierRef, frontierDigest: frontierRef, failingOpId: latest.opId, failureKind: 'mcp_known_result_unusable' as const,
    toolObservationRef: latest.resultRef, toolObservationDigest: observation.observationDigest,
    captureRef: observation.captureRef, captureDigest: observation.captureDigest };
}
export async function assertMcpCaptureObservation(artifacts: ArtifactCatalog, observation: ToolObservationV1,
  captured: Awaited<ReturnType<typeof readMcpRunCapture>>): Promise<void> {
  if (observation.captureDigest !== captured.value.captureDigest) throw new TypeError('MCP observation changes its original capture identity');
  if (observation.outcome === 'executed') {
    if (!captured.result || captured.value.malformedResult) throw new TypeError('malformed MCP received data cannot become execution success');
    requireEqual(observation.content, captured.result, 'MCP exact received semantic result'); return;
  }
  if (observation.code !== 'TOOL_PROTOCOL_ERROR') throw new TypeError('MCP received result cannot become an arbitrary tool failure');
  if (captured.unusableResponse) {
    const diagnostic = await readCanonicalArtifact(artifacts, observation.diagnosticRef);
    requireEqual(diagnostic, { schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR',
      knownUnusableResponseRef: captured.value.unusableResponseRef, knownUnusableResponseDigest: captured.unusableResponse.auditDigest }, 'MCP native known-unusable diagnosis');
    if (canonicalSha256(diagnostic) !== observation.diagnosticDigest) throw new TypeError('MCP known-unusable diagnosis does not rehash');
    return;
  }
  const diagnostic = await readCanonicalArtifact<Record<string, unknown>>(artifacts, observation.diagnosticRef);
  if (canonicalSha256(diagnostic) !== observation.diagnosticDigest) throw new TypeError('MCP output diagnostic differs from its complete bytes');
  if (captured.value.malformedResult) {
    requireEqual(diagnostic, { schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR' }, 'MCP malformed-result diagnosis');
    return;
  }
  if (!captured.result || canonicalJsonBytes(captured.result).byteLength <= 1_048_576 || typeof diagnostic.observationRef !== 'string')
    throw new TypeError('MCP output normalization has no positively reproduced original oversize result');
  requireEqual(diagnostic, { schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR',
    observationRef: diagnostic.observationRef }, 'MCP oversize-result diagnosis');
  const original = await readCanonicalArtifact<ToolObservationV1>(artifacts, diagnostic.observationRef);
  if (original.outcome !== 'executed' || original.captureRef !== observation.captureRef || original.captureDigest !== observation.captureDigest ||
      original.observationDigest !== digestOmitting(original, 'observationDigest')) throw new TypeError('MCP normalization substitutes original received custody');
  requireEqual(original.content, captured.result, 'MCP retained original oversize received projection');
  const { content: _content, observationDigest: _digest, ...base } = original;
  const core = { ...base, outcome: 'error', code: 'TOOL_PROTOCOL_ERROR', diagnosticRef: observation.diagnosticRef, diagnosticDigest: observation.diagnosticDigest };
  requireEqual(observation, { ...core, observationDigest: canonicalSha256(core) }, 'MCP exact oversize normalization');
}
export function readMcpRunResourceOwner(owner: NativeMcpRunHttpOwner, binding: RunMcpHttpBinding) {
  const state = runOwners.get(owner);
  if (!state || canonicalSha256(state.binding) !== canonicalSha256(binding)) throw new KernelStorageError('LEASE_FENCED', 'MCP resource belongs to another original claim');
  assertInstalledMcpRunOwner(owner, binding);
  return Object.freeze({ get resultReceived() { return state.resultReceived; }, get joined() { return state.joined; } });
}

/** Admin helper requests every real stage on its original authenticated peer.
 * Supervisor independently validates the same original response bytes. */
export async function driveMcpAdminProtocol(owner: NativeMcpAdminHttpOwner, binding: AdminMcpHttpBinding,
  assertCurrentAuthority: () => void) {
  if (adminOwners.has(owner)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP Admin owner cannot drive a second probe');
  assertInstalledMcpAdminOwner(owner, binding);
  const state = { binding: immutableSnapshot(binding), captures: new Map<McpHttpPhase, Capture>(), running: true,
    joined: undefined as NativeMcpAdminJoined | undefined, failure: undefined as unknown };
  adminOwners.set(owner, state);
  const stages: AdminMcpHttpPhase[] = ['initialize', 'initialized', 'tools_list'];
  let index = 0;
  try {
    while (index < stages.length) {
      const phase = stages[index]!, requested = await owner.nextMessage();
      if (requested.kind !== 'stage_requested' || requested.phase !== phase) throw new TypeError('Admin helper did not request its exact next recipe frame');
      assertCurrentAuthority(); assertInstalledMcpAdminOwner(owner, binding); await owner.connectStage(binding, phase);
      assertCurrentAuthority(); assertInstalledMcpAdminOwner(owner, binding); owner.releaseStage(binding, phase);
      for (;;) {
        const message = await owner.nextMessage();
        if (message.kind === 'stage_completed' && phase === 'initialized' && message.phase === phase) break;
        if (message.kind === 'stage_requested' || message.kind === 'stage_completed' || message.phase !== phase)
          throw new TypeError('Admin helper advanced before its real preceding response joined');
        const decoded = screenedMessage(message);
        if (decoded.kind === 'ping') {
          if (message.kind !== 'ping') throw new TypeError('Admin ping lost original receipt');
          assertCurrentAuthority(); assertInstalledMcpAdminOwner(owner, binding); await owner.connectPing(binding, message.receipt);
          assertCurrentAuthority(); assertInstalledMcpAdminOwner(owner, binding); owner.releasePing(binding, message.receipt); continue;
        }
        if (decoded.kind === 'notification') {
          if (decoded.method === 'notifications/tools/list_changed') throw new TypeError('Admin discovery changed during its original probe');
          continue;
        }
        if (phase === 'initialized' || message.kind !== 'response') throw new TypeError('Admin probe response has the wrong phase');
        const capture = await finish(owner, phase, message); state.captures.set(phase, capture);
        if (capture.response.kind !== 'result') throw new TypeError('Admin MCP setup was rejected');
        if (phase === 'initialize') decodeMcpInitializeResult(capture.response.result);
        else decodeMcpToolsListResult(capture.response.result);
        break;
      }
      index++;
    }
  } catch (error) { state.failure = error; throw error; }
  finally {
    state.running = false;
    try { state.joined = await owner.close(); assertInstalledMcpAdminJoined(owner, state.joined, binding); }
    catch (cause) { throw cause instanceof ResourceRetirementError ? cause : new ResourceRetirementError('MCP original Admin owner did not join', cause); }
  }
  return { async publish(artifacts: ArtifactCatalog) {
    assertInstalledMcpAdminJoined(owner, state.joined!, binding);
    const metadata: PublishedArtifact[] = [];
    const captures = new Map<AdminMcpHttpPhase, { captureRef: string; descriptor: McpHttpCaptureV1; response: Capture['response'] }>();
    for (const [phase, capture] of state.captures) {
      assertInstalledMcpRawResponse(owner, capture.receipt, capture.native);
      metadata.push(await artifacts.publishBytes(capture.bytes, capture.native.mediaType, 'cliq-mcp-http-finite-capture-bytes-v1'));
      const descriptor = await artifacts.publishCanonical(capture.descriptor, capture.descriptor.format); metadata.push(descriptor);
      captures.set(phase as AdminMcpHttpPhase, { captureRef: descriptor.ref, descriptor: capture.descriptor, response: capture.response });
    }
    return { captures, metadata: [...metadata], joined: state.joined! };
  } };
}
