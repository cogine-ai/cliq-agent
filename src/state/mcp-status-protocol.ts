// The fixed native purpose3 owns this status-only protocol. All framing,
// NoEcho, finite-tail and receive-before-projection mechanics are shared with
// the existing stdio implementation; an effect grant is never accepted here.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpCallResult, decodeMcpInitializeResult, decodeMcpToolsListResult } from '../kernel/mcp.js';
import { evaluateMcpRecoveryPredicates } from '../kernel/mcp-recovery.js';
import type { McpInboundMessageData } from '../kernel/mcp-wire.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { InstalledMcpStdioRecoveryScope } from '../sandbox/mcp-stdio-native.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import type { NativeMcpStdioRecoveryOwner, NativeMcpStdioRecoveryJoined, McpStdioRecoveryBinding, McpStdioPhase } from './mcp-stdio-broker-native.js';
import { assertInstalledMcpStdioRecoveryOwner, assertInstalledMcpStdioRecoveryJoined } from './mcp-stdio-native-binding.js';
import { receiveMcpStdioPhase, captureMcpStdioPhase, type McpStdioReceived } from './mcp-stdio-execution.js';
import { publishOriginalMcpStdioRecoveryRetirement } from './mcp-stdio-resource-closure.js';
import { decodeMcpStatusRetirement } from './mcp-status-proof.js';
import type { HeldRecoveryMcpStdioInput } from './native-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import type { readMcpReconcileSource } from './mcp-status-source.js';

type Source = Awaited<ReturnType<typeof readMcpReconcileSource>>;
type Response = Extract<McpInboundMessageData, { kind: 'result' | 'error' }>;
type ResponsePhase = Exclude<McpStdioPhase, 'initialized'>;
type State = { binding: McpStdioRecoveryBinding; source: Source; received: Map<ResponsePhase, McpStdioReceived>; running: boolean;
  statusReceivedAt?: string; joined?: NativeMcpStdioRecoveryJoined; failure?: unknown };
const states = new WeakMap<NativeMcpStdioRecoveryOwner, State>();
export function hasReceivedMcpStatusResponse(native: NativeMcpStdioRecoveryOwner, binding: McpStdioRecoveryBinding): boolean {
  assertInstalledMcpStdioRecoveryOwner(native, binding);
  const state = states.get(native);
  if (!state) return false;
  requireEqual(state.binding, binding, 'MCP status original single response custody');
  return state.received.has('tools_call') && state.statusReceivedAt !== undefined;
}
export function projectMcpStatusResponse(response: Response, source: Pick<Source, 'validateOutput' | 'completed' | 'failed'>) {
  let value: unknown, projection: 'structured_content' | 'rpc_error' | 'tool_error' | 'missing_structured_content' | 'malformed_result', schemaValid = false;
  if (response.kind === 'error') { value = response.error; projection = 'rpc_error'; }
  else {
    try {
      const result = decodeMcpCallResult(response.result);
      if (result.kind !== 'tool_result') throw new TypeError('status result changed its RPC branch');
      if (result.isError) { value = response.result; projection = 'tool_error'; }
      else if (result.structuredContent === undefined) { value = response.result; projection = 'missing_structured_content'; }
      else { value = result.structuredContent; projection = 'structured_content'; schemaValid = source.validateOutput(value); }
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      value = response.result; projection = 'malformed_result';
    }
  }
  const disposition = evaluateMcpRecoveryPredicates({ completed: source.completed, failed: source.failed, response: value, schemaValid });
  return immutableSnapshot({ response: value, projection, schemaValid, disposition });
}

export async function driveMcpStatusProtocol(native: NativeMcpStdioRecoveryOwner, binding: McpStdioRecoveryBinding,
  source: Source, assertCurrent: () => void) {
  if (states.has(native)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP status owner cannot run a second protocol');
  assertInstalledMcpStdioRecoveryOwner(native, binding);
  if (binding.originalOpId !== source.claim.opId || binding.originalAttempt !== source.claim.attempt || binding.originalDispatchId !== source.claim.dispatchId ||
      binding.originalDispatchJournalSeq !== source.claim.seq || binding.statusOperationName !== source.template.statusOperationName ||
      binding.effectServerToolName !== source.original.execution.serverToolName || binding.statusOperationName === binding.effectServerToolName ||
      binding.statusRequestDigest !== source.statusRequest.digest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status native owner substitutes the original effect or signed distinct read-only frame');
  const state: State = { binding: immutableSnapshot(binding), source, received: new Map(), running: true }; states.set(native, state);
  const check = () => assertInstalledMcpStdioRecoveryOwner(native, binding);
  const receive = (phase: McpStdioPhase) => receiveMcpStdioPhase(native, phase, () => native.releaseStage(binding, phase),
    receipt => native.releasePing(binding, receipt), assertCurrent, check, state.received);
  try {
    const initialized = await receive('initialize');
    if (initialized?.response.kind !== 'result') throw new TypeError('MCP status initialization was rejected');
    const negotiation = decodeMcpInitializeResult(initialized.response.result);
    if (negotiation.initializeDigest !== source.template.initializeDigest || negotiation.capabilityDigest !== source.template.capabilityDigest)
      throw new TypeError('MCP status initialization changed the original signed registry negotiation');
    native.advanceResponse(initialized.message.receipt); await receive('initialized');
    const listed = await receive('tools_list');
    if (listed?.response.kind !== 'result') throw new TypeError('MCP status tools/list was rejected');
    const tools = decodeMcpToolsListResult(listed.response.result);
    if (canonicalSha256(tools.map(tool => tool.interface)) !== source.template.probedToolsListDigest)
      throw new TypeError('MCP status complete discovery changed its original signed profile');
    native.advanceResponse(listed.message.receipt);
    const status = await receive('tools_call');
    if (!status) throw new TypeError('MCP read-only status has no matching response');
    state.statusReceivedAt = sampleCanonicalNow();
    return projectMcpStatusResponse(status.response, source);
  } catch (error) { state.failure = error; throw error; }
  finally { state.running = false; }
}

/** Raw catalog only: an already received real result and native retirement
 * must survive cancellation of the owning task's ordinary source reads. */
export async function publishMcpStatusCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  native: NativeMcpStdioRecoveryOwner, binding: McpStdioRecoveryBinding, scope: InstalledMcpStdioRecoveryScope, input: HeldRecoveryMcpStdioInput,
  retained?: Awaited<ReturnType<typeof publishMcpStatusRetirement>>) {
  const state = states.get(native);
  if (!state || state.running || !state.received.has('tools_call') || !state.statusReceivedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status capture has no actual single received original protocol');
  requireEqual(state.binding, binding, 'MCP exact original read-only status binding');
  const retired = retained ?? await publishMcpStatusRetirement(driver, artifacts, owner, native, binding, scope, input);
  const retirement = retired.physical, joined = retirement.joined.ownerJoined;
  assertInstalledMcpStdioRecoveryJoined(native, joined, binding);
  if (!joined.execReleased || !joined.setupReleased || !joined.statusReleased || joined.completedStages.join(',') !== 'initialize,initialized,tools_list,tools_call' ||
      retirement.evidence.kind !== 'containment_all_descendants_dead' || retirement.observedAt < state.statusReceivedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status result lacks its actual full protocol and process/pipe/FD/output join');
  state.joined = joined;
  const metadata: PublishedArtifact[] = [...retired.metadata], captures: Array<{ phase: ResponsePhase; captureRef: string }> = [];
  for (const phase of ['initialize', 'tools_list', 'tools_call'] as const) {
    const received = state.received.get(phase);
    if (!received) throw new TypeError('MCP status lost an original preceding protocol response');
    const captured = await captureMcpStdioPhase(native, phase, received);
    metadata.push(await artifacts.publishBytes(captured.bytes, 'application/octet-stream', 'cliq-mcp-stdio-finite-capture-bytes-v1'));
    const artifact = await artifacts.publishCanonical(captured.descriptor, captured.descriptor.format); metadata.push(artifact);
    captures.push({ phase, captureRef: artifact.ref });
  }
  const projection = projectMcpStatusResponse(state.received.get('tools_call')!.response, state.source);
  const response = await artifacts.publishCanonical(projection.response, 'cliq-mcp-status-response-v1'); metadata.push(response);
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-stdio-recovery-capture-v1' as const, binding, captures,
    statusResponseRef: response.ref, statusResponseDigest: response.ref, responseProjection: projection.projection,
    schemaValid: projection.schemaValid, disposition: projection.disposition, statusReceivedAt: state.statusReceivedAt,
    retirementRef: retired.ref, retirementDigest: retired.value.retirementDigest, observedAt: retirement.observedAt };
  const value = immutableSnapshot({ ...core, captureDigest: canonicalSha256(core) });
  const artifact = await artifacts.publishCanonical(value, core.format); metadata.push(artifact);
  return { value, ref: artifact.ref, retirement: retired, metadata };
}

/** Unlike a transport close, this publishes the actual same-scope physical
 * retirement and the original native owner join even without a response. */
export async function publishMcpStatusRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  native: NativeMcpStdioRecoveryOwner, binding: McpStdioRecoveryBinding, scope: InstalledMcpStdioRecoveryScope, input: HeldRecoveryMcpStdioInput) {
  const physical = await publishOriginalMcpStdioRecoveryRetirement(driver, artifacts, owner, native, binding, scope, input);
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-stdio-recovery-retirement-v1' as const, binding,
    joined: physical.joined.ownerJoined, nativeClosure: physical.nativeClosure,
    ...(physical.containmentRef ? { processContainmentRef: physical.containmentRef } : {}),
    retirementEvidenceRef: physical.evidenceRef, observedAt: physical.observedAt };
  const value = decodeMcpStatusRetirement({ ...core, retirementDigest: canonicalSha256(core) });
  const artifact = await artifacts.publishCanonical(value, value.format);
  return { value, ref: artifact.ref, physical, metadata: [...physical.metadata, artifact] };
}
