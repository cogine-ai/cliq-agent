// One call-scoped native stdio owner. Discovery uses the separate server
// launch claim; tools/call is released only after its own durable instance
// identity and ordinary effect claim. A response line is not process EOF.
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeMcpCallResult, decodeMcpInitializeResult, decodeMcpToolsListResult, type McpCallResultV1,
  type McpRegistryRevisionV1 } from '../kernel/mcp.js';
import { decodeMcpInboundMessageData, type McpInboundMessageData } from '../kernel/mcp-wire.js';
import { decodeMcpStdioCapture, decodeMcpStdioCaptureData, type McpStdioCaptureV1 } from '../kernel/mcp-stdio.js';
import { immutableSnapshot } from '../model/immutable.js';
import { acknowledgeMcpServerManualTerminal, acknowledgeMcpServerRetryClosure } from './mcp-server-retirement.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { sampleCanonicalNow } from './canonical-time.js';
import type { AdminMcpStdioBinding, AdminMcpStdioPhase, McpStdioPhase, NativeMcpStdioAdminJoined,
  NativeMcpStdioAdminOwner, NativeMcpStdioMessage, NativeMcpStdioReceipt,
  NativeMcpStdioRunJoined, NativeMcpStdioRunOwner, NativeMcpStdioRecoveryOwner, NativeMcpStdioEffectFence, RunMcpStdioCallBinding, RunMcpStdioLaunchBinding } from './mcp-stdio-broker-native.js';
import { assertInstalledMcpStdioRunOwner, assertInstalledMcpStdioAdminOwner, assertInstalledMcpStdioCallOwner,
  assertInstalledMcpStdioRunJoined, assertInstalledMcpStdioAdminJoined, assertInstalledMcpStdioRawResponse,
  assertInstalledMcpStdioUnusableResponse } from './mcp-stdio-native-binding.js';

type ResponsePhase = Exclude<McpStdioPhase, 'initialized'>;
type Response = Extract<McpInboundMessageData, { kind: 'result' | 'error' }>;
type Screened = Extract<NativeMcpStdioMessage, { kind: 'response' | 'notification' | 'ping' }>;
type Received = Readonly<{ message: Screened; response: Response }>;
type RunState = { launch: RunMcpStdioLaunchBinding; registry: McpRegistryRevisionV1; received: Map<ResponsePhase, Received>;
  call?: RunMcpStdioCallBinding; result?: McpCallResultV1; resultReceived: boolean; setupComplete: boolean; running: boolean;
  callDriven?: boolean; initializedAt?: string; joined?: NativeMcpStdioRunJoined; failure?: unknown; manualFence?: NativeMcpStdioEffectFence; manualFenceClosed?: boolean };
type AdminState = { binding: AdminMcpStdioBinding; received: Map<ResponsePhase, Received>; running: boolean;
  joined?: NativeMcpStdioAdminJoined; failure?: unknown };
const runs = new WeakMap<NativeMcpStdioRunOwner, RunState>(), admins = new WeakMap<NativeMcpStdioAdminOwner, AdminState>();
const retained = new Map<string, { native: NativeMcpStdioRunOwner; state: RunState }>();
const ownedCaptures = new Map<string, { native: NativeMcpStdioRunOwner; state: RunState }>();
const dispatchKey = (binding: RunMcpStdioLaunchBinding) => canonicalSha256([binding.runId, binding.launchOpId, binding.attempt, binding.dispatchId]);
export function readMcpStdioManualDispatchOwner(claim: import('../kernel/types.js').InvocationJournalEntry) {
  const matches = [...retained.values()].filter(original => original.state.call?.opId === claim.opId && original.state.launch.runId === claim.runId &&
    original.state.call.attempt === claim.attempt && original.state.call.dispatchId === claim.dispatchId);
  if (!matches.length) return undefined;
  if (matches.length !== 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio manual closure has multiple retained original domains');
  const { native, state } = matches[0]!, call = state.call!;
  if (!state.joined || state.running || state.resultReceived || call.dispatchJournalSeq !== claim.seq ||
      call.instanceIdentityRef !== claim.evidenceRef || call.instanceIdentityDigest !== claim.evidenceDigest ||
      call.releaseFenceTokenDigest !== claim.brokerFenceTokenDigest || state.launch.supervisorInstanceId !== claim.supervisorInstanceId ||
      state.launch.stateOwnerEpoch !== claim.stateOwnerEpoch || state.launch.leaseEpoch !== claim.leaseEpoch)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio manual closure lost its exact original uncertain joined owner');
  const fence = state.manualFence ??= native.acquireEffectFence(call);
  const assertJoined = () => { assertInstalledMcpStdioRunJoined(native, state.joined!, state.launch); fence.assertHeld(); };
  assertJoined();
  return Object.freeze({ owner: native, binding: call, joined: state.joined, assertJoined,
    releaseRetry(closureRef: string) { return acknowledgeMcpServerRetryClosure(native, call.instanceIdentityRef, closureRef); },
    release() { acknowledgeMcpServerManualTerminal(native, call.instanceIdentityRef); } });
}
/** Friend of the original durable abandonment writer only. The caller first
 * verifies that same original effect is actually abandoned. Closing this
 * irreversibly joined fence supplies no effect outcome or execution permit. */
export function closeMcpStdioManualTerminalFence(native: NativeMcpStdioRunOwner, instanceRef: string) {
  const state = runs.get(native);
  if (!state?.joined || !state.call || state.call.instanceIdentityRef !== instanceRef || !state.manualFence || state.running || state.resultReceived)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP manual acknowledgement lost its original uncertain joined fence');
  assertInstalledMcpStdioRunJoined(native, state.joined, state.launch);
  if (!state.manualFenceClosed) { state.manualFence.assertHeld(); state.manualFence.close(); state.manualFenceClosed = true; }
}
/** Friend of the original persisted reconcile-wait acknowledgement only.
 * This is native resource release, never a remote outcome or retry permit. */
export function closeMcpStdioReconcileWaitFence(native: NativeMcpStdioRunOwner, instanceRef: string) {
  const state = runs.get(native), call = state?.call;
  if (!state?.joined || !call || call.instanceIdentityRef !== instanceRef || state.running || state.resultReceived)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP reconcile acknowledgement lost its original uncertain joined native domain');
  assertInstalledMcpStdioRunJoined(native, state.joined, state.launch);
  if (!state.manualFenceClosed) {
    const fence = state.manualFence ??= native.acquireEffectFence(call);
    fence.assertHeld(); fence.close(); state.manualFenceClosed = true;
  }
}
export function assertMcpStdioRunQuiescence(runId: string): void {
  for (const { native, state } of retained.values()) if (state.launch.runId === runId) {
    if (state.running || !state.joined) throw new ResourceRetirementError('MCP stdio original producer still owns physical pipe/process work', undefined);
    assertInstalledMcpStdioRunJoined(native, state.joined, state.launch);
  }
}
const responseId = (phase: ResponsePhase) => phase === 'initialize' ? 1 : phase === 'tools_list' ? 2 : 3;
function screened(message: Screened) {
  if (message.messageDigest !== sha256Bytes(message.messageBytes)) throw new TypeError('MCP stdio screened message digest differs');
  return decodeMcpInboundMessageData(parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(message.messageBytes)));
}
function assertRun(native: NativeMcpStdioRunOwner, state: RunState, phase: McpStdioPhase) {
  assertInstalledMcpStdioRunOwner(native, state.launch);
  if (phase === 'tools_call') {
    if (!state.call) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stdio effect has no durable instance-bound claim');
    assertInstalledMcpStdioCallOwner(native, state.call);
  }
}
async function receive(native: NativeMcpStdioRunOwner | NativeMcpStdioAdminOwner | NativeMcpStdioRecoveryOwner, phase: McpStdioPhase,
  release: () => void, reply: (receipt: NativeMcpStdioReceipt) => void,
  assertCurrent: () => void, assertNative: () => void, received: Map<ResponsePhase, Received>): Promise<Received | undefined> {
  let released = false;
  for (;;) {
    const message = await native.nextMessage();
    if (message.phase !== phase) throw new TypeError('MCP stdio owner changed its fixed recipe phase');
    if (message.kind === 'stage_requested') {
      if (released) throw new TypeError('MCP stdio recipe requested a duplicate stage release');
      assertCurrent(); assertNative();
      // The bound fixed-frame capability enters C synchronously immediately
      // after this fresh gate; no getter, async read or JS write intervenes.
      release(); released = true; continue;
    }
    if (!released) throw new TypeError('MCP stdio message precedes its genuine local fixed-stage release');
    if (message.kind === 'stage_written') {
      if (phase !== 'initialized') throw new TypeError('MCP stdio unexpected initialized write completion');
      return undefined;
    }
    const decoded = screened(message);
    if (decoded.kind === 'ping') {
      if (message.kind !== 'ping') throw new TypeError('MCP stdio ping changed its native receipt kind');
      assertCurrent(); assertNative(); reply(message.receipt); continue;
    }
    if (decoded.kind === 'notification') {
      if (message.kind !== 'notification') throw new TypeError('MCP stdio notification changed its native receipt kind');
      if (decoded.method === 'notifications/tools/list_changed' && phase !== 'tools_call')
        throw new TypeError('MCP stdio interface changed before its effect release');
      continue;
    }
    if (phase === 'initialized' || message.kind !== 'response' || decoded.id !== responseId(phase))
      throw new TypeError('MCP stdio response differs from its original expected id or native receipt');
    const value = Object.freeze({ message, response: decoded });
    // Retain the real safe matching event BEFORE semantic projection, storage,
    // subsequent phase or teardown can fail. No raw pipe bytes cross here.
    received.set(phase, value); return value;
  }
}
export async function driveMcpStdioRunSetup(native: NativeMcpStdioRunOwner, launch: RunMcpStdioLaunchBinding,
  registry: McpRegistryRevisionV1, assertCurrent: () => void) {
  if (runs.has(native) || registry.transport.kind !== 'stdio') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stdio owner cannot drive another launch');
  assertInstalledMcpStdioRunOwner(native, launch);
  const state: RunState = { launch: immutableSnapshot(launch), registry, received: new Map(), resultReceived: false, setupComplete: false, running: true };
  runs.set(native, state); retained.set(dispatchKey(launch), { native, state });
  try {
    const initialize = await receive(native, 'initialize', () => native.releaseStage(launch, 'initialize'), receipt => native.releasePing(launch, receipt),
      assertCurrent, () => assertRun(native, state, 'initialize'), state.received);
    if (initialize?.response.kind !== 'result') throw new TypeError('MCP stdio initialize was rejected');
    const negotiation = decodeMcpInitializeResult(initialize.response.result);
    if (negotiation.initializeDigest !== registry.initializeDigest || negotiation.capabilityDigest !== registry.capabilityDigest)
      throw new TypeError('MCP stdio initialize differs from its immutable registered negotiation');
    native.advanceResponse(initialize.message.receipt);
    await receive(native, 'initialized', () => native.releaseStage(launch, 'initialized'), receipt => native.releasePing(launch, receipt),
      assertCurrent, () => assertRun(native, state, 'initialized'), state.received);
    const listed = await receive(native, 'tools_list', () => native.releaseStage(launch, 'tools_list'), receipt => native.releasePing(launch, receipt),
      assertCurrent, () => assertRun(native, state, 'tools_list'), state.received);
    if (listed?.response.kind !== 'result') throw new TypeError('MCP stdio tools/list was rejected');
    const tools = decodeMcpToolsListResult(listed.response.result);
    if (canonicalSha256(tools.map(tool => tool.interface)) !== registry.probedToolsListDigest)
      throw new TypeError('MCP stdio complete tools/list differs from its immutable registry');
    // The complete screened and semantically matching discovery result is
    // already owned. A concurrent cancellation of local phase advancement
    // cannot relabel that actual initialized negotiation as not initialized.
    state.initializedAt = sampleCanonicalNow(); state.setupComplete = true; native.advanceResponse(listed.message.receipt);
    return immutableSnapshot({ initializeDigest: negotiation.initializeDigest, capabilityDigest: negotiation.capabilityDigest,
      probedToolsListDigest: canonicalSha256(tools.map(tool => tool.interface)) });
  } catch (error) { state.failure = error; throw error; }
  finally { state.running = false; }
}
export async function driveMcpStdioRunCall(native: NativeMcpStdioRunOwner, binding: RunMcpStdioCallBinding,
  assertCurrent: () => void, outputSchema?: unknown) {
  const state = runs.get(native);
  if (!state?.setupComplete || state.running || state.callDriven || state.joined) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stdio effect lost its single original initialized owner');
  requireEqual(binding.launch, state.launch, 'MCP stdio exact original launch binding');
  bindMcpStdioRunCall(native, binding); state.callDriven = true; state.running = true;
  try {
    const captured = await receive(native, 'tools_call', () => native.releaseStage(binding, 'tools_call'), receipt => native.releasePing(binding, receipt),
      assertCurrent, () => assertRun(native, state, 'tools_call'), state.received);
    if (!captured) throw new TypeError('MCP stdio effect has no response');
    state.resultReceived = true;
    state.result = captured.response.kind === 'error' ? immutableSnapshot({ kind: 'rpc_error' as const, ...captured.response.error })
      : decodeMcpCallResult(captured.response.result, outputSchema);
    return state.result;
  } catch (error) { state.resultReceived = state.received.has('tools_call'); state.failure = error; throw error; }
  finally { state.running = false; }
}
/** Retain the exact bound call BEFORE the claim transaction can commit. A
 * cancellation immediately after claim cannot erase its native domain. */
export function bindMcpStdioRunCall(native: NativeMcpStdioRunOwner, binding: RunMcpStdioCallBinding) {
  const state = runs.get(native);
  if (!state?.setupComplete || state.running || state.joined) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stdio has no original initialized call owner');
  requireEqual(binding.launch, state.launch, 'MCP stdio exact original bound call launch'); assertInstalledMcpStdioCallOwner(native, binding);
  if (state.call) requireEqual(state.call, binding, 'MCP stdio one immutable original effect binding');
  else state.call = immutableSnapshot(binding);
}
export function recordMcpStdioRunJoined(native: NativeMcpStdioRunOwner, joined: NativeMcpStdioRunJoined, launch: RunMcpStdioLaunchBinding) {
  assertInstalledMcpStdioRunJoined(native, joined, launch);
  const state = runs.get(native);
  if (!state) return; // No protocol task was started; the genuine scope still owns its birth/join.
  if (state.running) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original protocol task has not joined');
  requireEqual(launch, state.launch, 'MCP stdio original joined launch binding'); state.joined = joined;
}
export function readMcpStdioRunCustody(native: NativeMcpStdioRunOwner, launch: RunMcpStdioLaunchBinding) {
  const state = runs.get(native); if (!state) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio original owner is unavailable');
  requireEqual(launch, state.launch, 'MCP stdio original custody launch'); assertInstalledMcpStdioRunOwner(native, launch);
  return Object.freeze({ get setupComplete() { return state.setupComplete; }, get resultReceived() { return state.resultReceived; },
    get joined() { return state.joined; }, get call() { return state.call; } });
}
export function readMcpStdioSetupFailureState(native: NativeMcpStdioRunOwner, launch: RunMcpStdioLaunchBinding) {
  assertInstalledMcpStdioRunOwner(native, launch);
  const state = runs.get(native);
  if (!state) return undefined;
  requireEqual(state.launch, launch, 'MCP original local setup failure owner');
  return Object.freeze({ setupComplete: state.setupComplete, resultReceived: state.resultReceived });
}
export function readMcpStdioRunSetup(native: NativeMcpStdioRunOwner, launch: RunMcpStdioLaunchBinding) {
  const state = runs.get(native);
  if (!state?.setupComplete || state.running || !state.initializedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio has no original completed immutable discovery');
  requireEqual(launch, state.launch, 'MCP stdio original completed setup launch'); assertInstalledMcpStdioRunOwner(native, launch);
  const initialize = state.received.get('initialize')?.response, listed = state.received.get('tools_list')?.response;
  if (initialize?.kind !== 'result' || listed?.kind !== 'result') throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio setup lost its actual safe response receipts');
  const negotiation = decodeMcpInitializeResult(initialize.result), tools = decodeMcpToolsListResult(listed.result);
  return immutableSnapshot({ ...negotiation, probedToolsListDigest: canonicalSha256(tools.map(tool => tool.interface)), initializedAt: state.initializedAt });
}
async function finiteCapture(native: NativeMcpStdioRunOwner | NativeMcpStdioAdminOwner | NativeMcpStdioRecoveryOwner, phase: ResponsePhase, received: Received) {
  const raw = await native.finishResponse(received.message.receipt);
  assertInstalledMcpStdioRawResponse(native, received.message.receipt, raw);
  const bytes = raw.screenedRawCapture.copy(), decoded = decodeMcpStdioCaptureData({ bytes, termination: raw.termination, expectedId: responseId(phase) });
  requireEqual(decoded.response, received.response, 'MCP stdio screened response and original joined finite capture');
  requireEqual({ count: decoded.rawFinitePrefixBytes, digest: decoded.rawFinitePrefixDigest, end: decoded.responseLineEndOffset, tail: decoded.receivedTailBytes },
    { count: raw.rawFinitePrefixBytes, digest: raw.rawFinitePrefixDigest, end: raw.responseLineEndOffset, tail: raw.receivedTailBytes }, 'MCP stdio native finite capture offsets');
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-stdio-capture-v1' as const, phase, expectedId: responseId(phase),
    framing: raw.framing, termination: raw.termination, rawResponseRef: sha256Bytes(bytes), rawFinitePrefixBytes: bytes.byteLength,
    responseLineEndOffset: raw.responseLineEndOffset, receivedTailBytes: raw.receivedTailBytes };
  return { raw, bytes, descriptor: decodeMcpStdioCapture({ ...core, captureDigest: canonicalSha256(core) }) };
}
/** Internal protocol mechanics only. The purpose-specific native owner and
 * release callback still supply every actual current authority check. */
export { receive as receiveMcpStdioPhase, finiteCapture as captureMcpStdioPhase };
export type McpStdioReceived = Received;
export async function publishMcpStdioRunCaptures(artifacts: ArtifactCatalog, native: NativeMcpStdioRunOwner) {
  const state = runs.get(native);
  if (!state?.joined || !state.call || !state.resultReceived) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio has no original joined received effect');
  assertInstalledMcpStdioRunJoined(native, state.joined, state.launch); assertInstalledMcpStdioCallOwner(native, state.call);
  const captures: Array<{ phase: ResponsePhase; captureRef: string }> = [], metadata: PublishedArtifact[] = [];
  const unusable: Array<{ phase: ResponsePhase; ref: string }> = [];
  for (const [phase, original] of state.received) {
    let captured: Awaited<ReturnType<typeof finiteCapture>>;
    try {
      captured = await finiteCapture(native, phase, original);
    } catch {
      // C alone distinguishes a safe received line plus full-capture refusal.
      // A generic catch, timeout or receipt-shaped object cannot do so.
      const refused = native.readUnusableResponse(original.message.receipt);
      assertInstalledMcpStdioUnusableResponse(native, original.message.receipt, refused);
      const safe = await artifacts.publishBytes(original.message.messageBytes, 'application/json', 'cliq-mcp-stdio-screened-known-event-bytes-v1');
      const core = { schemaVersion: 1, format: 'cliq-mcp-stdio-known-unusable-response-v1', phase, expectedId: responseId(phase),
        safeMessageRef: safe.ref, safeMessageDigest: original.message.messageDigest, safeMessageBytes: original.message.messageBytes.byteLength,
        framing: refused.framing, termination: refused.termination, rawFinitePrefixBytes: refused.rawFinitePrefixBytes,
        rawFinitePrefixDigest: refused.rawFinitePrefixDigest, responseLineEndOffset: refused.responseLineEndOffset,
        receivedTailBytes: refused.receivedTailBytes, reason: refused.reason };
      const value = immutableSnapshot({ ...core, auditDigest: canonicalSha256(core) });
      const artifact = await artifacts.publishCanonical(value, core.format); metadata.push(safe, artifact);
      unusable.push({ phase, ref: artifact.ref }); continue;
    }
    metadata.push(await artifacts.publishBytes(captured.bytes, 'application/octet-stream', 'cliq-mcp-stdio-finite-capture-bytes-v1'));
    const artifact = await artifacts.publishCanonical(captured.descriptor, captured.descriptor.format); metadata.push(artifact);
    captures.push({ phase, captureRef: artifact.ref });
  }
  const core = { schemaVersion: 1, format: unusable.length ? 'cliq-mcp-stdio-known-unusable-run-capture-v1' : 'cliq-mcp-stdio-run-capture-v1',
    launch: state.launch, binding: state.call, captures, result: state.result ?? null, malformedResult: state.result === undefined,
    joined: state.joined, ...(unusable.length ? { unusableResponses: unusable } : {}) };
  const value = immutableSnapshot({ ...core, captureDigest: canonicalSha256(core) }), artifact = await artifacts.publishCanonical(value, core.format);
  ownedCaptures.set(artifact.ref, { native, state });
  return { value, ref: artifact.ref, metadata: [...metadata, artifact] };
}
export function assertOwnedMcpStdioRunCapture(reference: string, prepared: import('../kernel/types.js').InvocationJournalEntry,
  claim: import('../kernel/types.js').InvocationJournalEntry) {
  const original = ownedCaptures.get(reference), call = original?.state.call;
  if (!original?.state.joined || !call || prepared.opKind !== 'mcp' || prepared.runId !== call.launch.runId || prepared.opId !== call.opId ||
      prepared.attempt !== call.attempt || prepared.requestRef !== call.requestRef || prepared.target !== call.targetRef || prepared.grantRef !== call.grantRef ||
      claim.dispatchId !== call.dispatchId || claim.seq !== call.dispatchJournalSeq || claim.brokerFenceTokenDigest !== call.releaseFenceTokenDigest ||
      claim.evidenceRef !== call.instanceIdentityRef || claim.evidenceDigest !== call.instanceIdentityDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio capture lost its original native effect/launch owner');
  assertInstalledMcpStdioRunJoined(original.native, original.state.joined, original.state.launch);
  assertInstalledMcpStdioCallOwner(original.native, call);
}
export function acknowledgeMcpStdioRun(native: NativeMcpStdioRunOwner) {
  const state = runs.get(native); if (!state?.joined) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio cannot release an unjoined original domain');
  assertInstalledMcpStdioRunJoined(native, state.joined, state.launch); native.releaseDomain(); retained.delete(dispatchKey(state.launch));
  for (const [reference, original] of ownedCaptures) if (original.native === native) ownedCaptures.delete(reference);
}
export function acknowledgeMcpStdioSetupFailure(native: NativeMcpStdioRunOwner, joined: NativeMcpStdioRunJoined, launch: RunMcpStdioLaunchBinding) {
  assertInstalledMcpStdioRunJoined(native, joined, launch);
  const state = runs.get(native);
  if (state) {
    requireEqual(state.launch, launch, 'MCP setup failure original native domain');
    if (!state.joined || state.setupComplete || state.resultReceived || state.call) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP setup acknowledgement cannot discard an initialized or claimed effect owner');
  }
  native.releaseDomain(); retained.delete(dispatchKey(launch));
}
export async function driveMcpStdioAdminProtocol(native: NativeMcpStdioAdminOwner, binding: AdminMcpStdioBinding,
  assertCurrent: () => void) {
  if (admins.has(native)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stdio Admin owner cannot drive another probe');
  assertInstalledMcpStdioAdminOwner(native, binding);
  const state: AdminState = { binding: immutableSnapshot(binding), received: new Map(), running: true }; admins.set(native, state);
  try {
    let initialize: ReturnType<typeof decodeMcpInitializeResult> | undefined, tools: ReturnType<typeof decodeMcpToolsListResult> | undefined;
    for (const phase of ['initialize', 'initialized', 'tools_list'] as readonly AdminMcpStdioPhase[]) {
      const captured = await receive(native, phase, () => native.releaseStage(binding, phase), receipt => native.releasePing(binding, receipt),
        assertCurrent, () => assertInstalledMcpStdioAdminOwner(native, binding), state.received);
      if (phase === 'initialized') continue;
      if (captured?.response.kind !== 'result') throw new TypeError('MCP stdio Admin negotiation/discovery was rejected');
      if (phase === 'initialize') initialize = decodeMcpInitializeResult(captured.response.result);
      else tools = decodeMcpToolsListResult(captured.response.result);
      if (phase === 'initialize') native.advanceResponse(captured.message.receipt);
    }
    if (!initialize || !tools) throw new TypeError('MCP stdio Admin fixed recipe has no complete discovery');
    return { initialize, tools, async publish(artifacts: ArtifactCatalog, joined: NativeMcpStdioAdminJoined) {
      assertInstalledMcpStdioAdminJoined(native, joined, binding); state.joined = joined;
      const captures = new Map<'initialize' | 'tools_list', { captureRef: string; descriptor: McpStdioCaptureV1; response: Response }>();
      const metadata: PublishedArtifact[] = [];
      for (const phase of ['initialize', 'tools_list'] as const) {
        const captured = await finiteCapture(native, phase, state.received.get(phase)!);
        metadata.push(await artifacts.publishBytes(captured.bytes, 'application/octet-stream', 'cliq-mcp-stdio-finite-capture-bytes-v1'));
        const artifact = await artifacts.publishCanonical(captured.descriptor, captured.descriptor.format); metadata.push(artifact);
        captures.set(phase, { captureRef: artifact.ref, descriptor: captured.descriptor, response: state.received.get(phase)!.response });
      }
      return { captures, metadata, joined };
    } };
  } catch (error) { state.failure = error; throw error; }
  finally { state.running = false; }
}
