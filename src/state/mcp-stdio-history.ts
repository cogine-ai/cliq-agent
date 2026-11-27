// Retained stdio data audit. These readers never recreate a native owner,
// release a recipe, infer remote effects from death, or replace a raw birth.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { controlWireInteger, controlWireRecord, controlWireRef, controlWireText, assertControlWireJson } from '../kernel/control-wire-data.js';
import { parseJsonStrict, assertBoundedJsonValue } from '../kernel/json.js';
import { decodeMcpCallResult, decodeMcpInitializeResult, decodeMcpToolsListResult, MCP_RESPONSE_BYTES,
  type McpCallResultV1 } from '../kernel/mcp.js';
import { decodeMcpInboundMessageData, type McpInboundMessageData } from '../kernel/mcp-wire.js';
import { decodeMcpServerInstanceIdentity, decodeMcpStdioCapture, decodeMcpStdioCaptureData } from '../kernel/mcp-stdio.js';
import { decodeMcpServerLaunchRequest, decodeMcpServerLaunchTarget } from '../kernel/mcp-server-authorization.js';
import type { InvocationJournalEntry, RunAssemblyV1 } from '../kernel/types.js';
import type { ToolRequestV1, ToolTargetV1, ToolObservationV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { readMcpRegistryClosure } from './mcp-registration.js';
import { readInvocationAttempt } from './repositories/journal.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { RunMcpStdioCallBinding, RunMcpStdioLaunchBinding } from './mcp-stdio-broker-native.js';

const launchTexts = ['runId', 'launchOpId', 'batchItemId', 'callId', 'workerLaunchId', 'principalId', 'supervisorInstanceId', 'dispatchId'] as const;
const launchRefs = ['registryRef', 'manifestDigest', 'toolRequestRef', 'toolRequestDigest', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest',
  'grantRef', 'grantDigest', 'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'releaseFenceTokenDigest'] as const;
const launchNumbers = ['attempt', 'lifecycleSeq', 'callIndex', 'leaseEpoch', 'stateOwnerEpoch', 'dispatchJournalSeq', 'launchDeadlineMs', 'callDeadlineMs'] as const;
export function decodeMcpStdioLaunchBindingData(value: unknown): RunMcpStdioLaunchBinding {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP stdio retained launch binding');
  const data = controlWireRecord(value, [...launchTexts, ...launchRefs, ...launchNumbers, 'nonce']);
  for (const name of launchTexts) controlWireText(data[name], 256);
  for (const name of launchRefs) controlWireRef(data[name]);
  for (const name of launchNumbers) controlWireInteger(data[name], ['attempt', 'lifecycleSeq', 'callIndex'].includes(name) ? 0 : 1);
  if (typeof data.nonce !== 'string' || !/^[0-9a-f]{64}$/u.test(data.nonce) || (data.launchDeadlineMs as number) > (data.callDeadlineMs as number))
    throw new TypeError('MCP stdio launch binding changes its original nonce or deadlines');
  return immutableSnapshot(data) as RunMcpStdioLaunchBinding;
}
export function decodeMcpStdioCallBindingData(value: unknown): RunMcpStdioCallBinding {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP stdio retained effect binding');
  const data = controlWireRecord(value, ['launch', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq', 'requestRef', 'requestDigest', 'targetRef',
    'targetDigest', 'grantRef', 'grantDigest', 'toolContractDigest', 'instanceIdentityRef', 'instanceIdentityDigest', 'releaseFenceTokenDigest']);
  const launch = decodeMcpStdioLaunchBindingData(data.launch);
  controlWireText(data.opId, 256); controlWireText(data.dispatchId, 256); controlWireInteger(data.attempt); controlWireInteger(data.dispatchJournalSeq, 1);
  for (const name of ['requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef', 'grantDigest', 'toolContractDigest', 'instanceIdentityRef', 'instanceIdentityDigest', 'releaseFenceTokenDigest'])
    controlWireRef(data[name]);
  if (data.releaseFenceTokenDigest !== launch.releaseFenceTokenDigest) throw new TypeError('MCP effect substitutes another original launch domain');
  return immutableSnapshot(data) as RunMcpStdioCallBinding;
}
export async function readMcpStdioCapture(artifacts: ArtifactCatalog, reference: string) {
  const capture = decodeMcpStdioCapture(await readCanonicalArtifact(artifacts, reference));
  const bytes = await artifacts.readBytes(capture.rawResponseRef), decoded = decodeMcpStdioCaptureData({ bytes,
    termination: capture.termination, expectedId: capture.expectedId });
  if (canonicalSha256(capture) !== reference || bytes.length !== capture.rawFinitePrefixBytes || decoded.rawFinitePrefixDigest !== capture.rawResponseRef ||
      decoded.responseLineEndOffset !== capture.responseLineEndOffset || decoded.receivedTailBytes !== capture.receivedTailBytes)
    throw new TypeError('MCP stdio capture changes its exact original finite bytes or response-line offsets');
  return { capture, bytes, decoded };
}
export function decodeMcpStdioUnusableResponseData(input: unknown) {
  assertControlWireJson(input); assertBoundedJsonValue(input, 'MCP stdio retained known-unusable response');
  const value = controlWireRecord(input, ['schemaVersion', 'format', 'phase', 'expectedId',
    'safeMessageRef', 'safeMessageDigest', 'safeMessageBytes', 'framing', 'termination', 'rawFinitePrefixBytes', 'rawFinitePrefixDigest',
    'responseLineEndOffset', 'receivedTailBytes', 'reason', 'auditDigest']);
  if (value.schemaVersion !== 1 || value.format !== 'cliq-mcp-stdio-known-unusable-response-v1' || value.framing !== 'newline_json_rpc' ||
      value.termination !== 'stdio_response_line' || value.reason !== 'full_capture_no_echo_refused' ||
      !['initialize', 'tools_list', 'tools_call'].includes(value.phase as string) || value.auditDigest !== digestOmitting(value, 'auditDigest'))
    throw new TypeError('MCP stdio known-unusable audit has no exact closed safe-line refusal');
  for (const name of ['safeMessageRef', 'safeMessageDigest', 'rawFinitePrefixDigest', 'auditDigest']) controlWireRef(value[name]);
  const length = controlWireInteger(value.rawFinitePrefixBytes, 1, MCP_RESPONSE_BYTES), end = controlWireInteger(value.responseLineEndOffset, 1, length);
  if (controlWireInteger(value.receivedTailBytes, 0, length) !== length - end || value.expectedId !== (value.phase === 'initialize' ? 1 : value.phase === 'tools_list' ? 2 : 3))
    throw new TypeError('MCP stdio known-unusable line/tail or original request id differs');
  controlWireInteger(value.safeMessageBytes, 1, Math.min(MCP_RESPONSE_BYTES, end - 1));
  if (value.safeMessageRef !== value.safeMessageDigest) throw new TypeError('MCP stdio retained safe event complete-byte identity differs');
  return immutableSnapshot(value);
}
async function readUnusable(artifacts: ArtifactCatalog, reference: string) {
  const value = decodeMcpStdioUnusableResponseData(await readCanonicalArtifact(artifacts, reference));
  const bytes = await artifacts.readBytes(value.safeMessageRef as string);
  if (bytes.length !== controlWireInteger(value.safeMessageBytes, 1, MCP_RESPONSE_BYTES) || sha256Bytes(bytes) !== value.safeMessageDigest ||
      value.safeMessageRef !== value.safeMessageDigest) throw new TypeError('MCP stdio retained safe event bytes differ');
  const response = decodeMcpInboundMessageData(parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)));
  if ((response.kind !== 'result' && response.kind !== 'error') || response.id !== value.expectedId) throw new TypeError('MCP stdio unusable capture has no safe matching response');
  return { value, response, bytes };
}
function joinedData(value: unknown) {
  const data = controlWireRecord(value, ['kind', 'purpose', 'releaseFenceTokenDigest', 'execReleased', 'setupReleased', 'effectReleased', 'completedStages',
    'tokenRevoked', 'matchingActiveReleaseCount', 'processJoined', 'pipesJoined', 'tasksJoined', 'outputCustodyRetired']);
  if (data.kind !== 'mcp_stdio_owner_joined' || data.purpose !== 'run' || data.tokenRevoked !== true || data.matchingActiveReleaseCount !== 0 ||
      data.processJoined !== true || data.pipesJoined !== true || data.tasksJoined !== true || data.outputCustodyRetired !== true ||
      data.execReleased !== true || data.setupReleased !== true || data.effectReleased !== true || !Array.isArray(data.completedStages) ||
      data.completedStages.join(',') !== 'initialize,initialized,tools_list,tools_call') throw new TypeError('MCP stdio retained received capture has no complete original local custody projection');
  controlWireRef(data.releaseFenceTokenDigest); return data;
}
export function decodeMcpStdioRunCaptureRoot(input: unknown) {
  assertControlWireJson(input); assertBoundedJsonValue(input, 'MCP stdio retained run capture');
  const value = controlWireRecord(input, ['schemaVersion', 'format', 'launch', 'binding', 'captures',
    'result', 'malformedResult', 'joined', 'captureDigest'], ['unusableResponses']);
  const unusable = value.format === 'cliq-mcp-stdio-known-unusable-run-capture-v1';
  if (value.schemaVersion !== 1 || (!unusable && value.format !== 'cliq-mcp-stdio-run-capture-v1') || typeof value.malformedResult !== 'boolean' ||
      value.captureDigest !== digestOmitting(value, 'captureDigest') || !Array.isArray(value.captures) || value.captures.length > 3 ||
      (unusable ? !Array.isArray(value.unusableResponses) || !value.unusableResponses.length || value.unusableResponses.length > 3 : value.unusableResponses !== undefined))
    throw new TypeError('MCP stdio run capture changes its closed received graph');
  const launch = decodeMcpStdioLaunchBindingData(value.launch), binding = decodeMcpStdioCallBindingData(value.binding), joined = joinedData(value.joined);
  requireEqual(binding.launch, launch, 'MCP stdio capture original launch/call');
  const phases = new Set<string>();
  function phase(phase: unknown, reference: unknown) {
    if (!['initialize', 'tools_list', 'tools_call'].includes(phase as string) || phases.has(phase as string))
      throw new TypeError('MCP stdio run capture repeats or substitutes a fixed response phase');
    controlWireRef(reference); phases.add(phase as string);
  }
  for (const entry of value.captures) { const descriptor = controlWireRecord(entry, ['phase', 'captureRef']); phase(descriptor.phase, descriptor.captureRef); }
  for (const entry of unusable ? value.unusableResponses as unknown[] : []) { const descriptor = controlWireRecord(entry, ['phase', 'ref']); phase(descriptor.phase, descriptor.ref); }
  if (phases.size !== 3) throw new TypeError('MCP stdio retained received graph lost a fixed response phase');
  return immutableSnapshot({ schemaVersion: 1 as const,
    format: unusable ? 'cliq-mcp-stdio-known-unusable-run-capture-v1' as const : 'cliq-mcp-stdio-run-capture-v1' as const,
    result: value.result, malformedResult: value.malformedResult, captureDigest: controlWireRef(value.captureDigest),
    launch, binding, joined, captures: value.captures,
    ...(unusable ? { unusableResponses: value.unusableResponses as unknown[] } : {}) });
}
export async function readMcpStdioRunCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  captureRef: string; captureDigest: string; prepared: InvocationJournalEntry; claim: InvocationJournalEntry; assembly: RunAssemblyV1;
}) {
  const value = decodeMcpStdioRunCaptureRoot(await readCanonicalArtifact(artifacts, input.captureRef));
  if (value.captureDigest !== input.captureDigest || canonicalSha256(value) !== input.captureRef)
    throw new TypeError('MCP stdio run capture changes its complete original artifact identity');
  const { launch, binding, joined } = value, unusable = value.format === 'cliq-mcp-stdio-known-unusable-run-capture-v1';
  const { prepared, claim, assembly } = input;
  if (prepared.opKind !== 'mcp' || prepared.phase !== 'prepared' || claim.phase !== 'dispatch_claimed' || binding.opId !== prepared.opId || binding.attempt !== prepared.attempt ||
      launch.runId !== prepared.runId || binding.requestRef !== prepared.requestRef || binding.targetRef !== prepared.target || binding.grantRef !== prepared.grantRef ||
      binding.dispatchId !== claim.dispatchId || binding.dispatchJournalSeq !== claim.seq || claim.brokerFenceTokenDigest !== binding.releaseFenceTokenDigest ||
      claim.evidenceRef !== binding.instanceIdentityRef || claim.evidenceDigest !== binding.instanceIdentityDigest ||
      claim.stateOwnerEpoch !== launch.stateOwnerEpoch || claim.supervisorInstanceId !== launch.supervisorInstanceId || claim.leaseEpoch !== launch.leaseEpoch ||
      joined.releaseFenceTokenDigest !== launch.releaseFenceTokenDigest) throw new TypeError('MCP stdio capture substitutes its exact ordinary effect claim');
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef), target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  if (request.requestDigest !== binding.requestDigest || target.targetDigest !== binding.targetDigest || request.batchItemId !== launch.batchItemId ||
      request.callId !== launch.callId || request.callIndex !== launch.callIndex || request.assemblyRef !== canonicalSha256(assembly) || target.execution.kind !== 'mcp' ||
      target.execution.toolContractDigest !== binding.toolContractDigest || target.execution.registryRevisionRef !== launch.registryRef || target.execution.registryManifestDigest !== launch.manifestDigest)
    throw new TypeError('MCP stdio capture changes its immutable owning effect request');
  const execution = target.execution;
  const registry = await readMcpRegistryClosure(driver, artifacts, launch.registryRef, launch.principalId);
  if (registry.registry.transport.kind !== 'stdio') throw new TypeError('MCP stdio capture borrows another registered transport');
  const instance = decodeMcpServerInstanceIdentity(await readCanonicalArtifact(artifacts, binding.instanceIdentityRef));
  if (instance.identityDigest !== binding.instanceIdentityDigest || instance.runId !== launch.runId || instance.batchItemId !== launch.batchItemId ||
      instance.callId !== launch.callId || instance.callIndex !== launch.callIndex || instance.launchOpId !== launch.launchOpId || instance.launchAttempt !== launch.attempt ||
      instance.launchDispatchId !== launch.dispatchId || instance.lifecycleSeq !== launch.lifecycleSeq || instance.registryRevisionRef !== launch.registryRef ||
      instance.registryManifestDigest !== launch.manifestDigest || instance.registrationId !== registry.registry.registrationId ||
      instance.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef || instance.instanceNonceDigest !== sha256Bytes(Buffer.from(launch.nonce)) ||
      parseCanonicalTime(instance.initializedAt) > parseCanonicalTime(claim.timestamp)) throw new TypeError('MCP stdio effect has no exact earlier initialized server identity');
  const history = readInvocationAttempt(driver, launch.runId, launch.launchOpId, launch.attempt), launchPrepared = history[0], launchClaim = history[1];
  if (!launchPrepared || !launchClaim || launchPrepared.opKind !== 'mcp-server' || launchPrepared.phase !== 'prepared' || launchClaim.phase !== 'dispatch_claimed' ||
      launchPrepared.requestRef !== launch.requestRef || launchPrepared.target !== launch.targetRef || launchPrepared.grantRef !== launch.grantRef ||
      launchClaim.dispatchId !== launch.dispatchId || launchClaim.seq !== launch.dispatchJournalSeq || launchClaim.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef ||
      launchClaim.timestamp > instance.initializedAt || launchClaim.supervisorInstanceId !== launch.supervisorInstanceId || launchClaim.stateOwnerEpoch !== launch.stateOwnerEpoch ||
      launchPrepared.leaseEpoch !== launch.leaseEpoch) throw new TypeError('MCP stdio capture loses its independent original server launch claim');
  const launchRequest = decodeMcpServerLaunchRequest(await readCanonicalArtifact(artifacts, launch.requestRef));
  const launchTarget = decodeMcpServerLaunchTarget(await readCanonicalArtifact(artifacts, launch.targetRef));
  if (launchRequest.requestDigest !== launch.requestDigest || launchTarget.targetDigest !== launch.targetDigest || launchRequest.toolRequestRef !== prepared.requestRef ||
      launchRequest.toolRequestDigest !== request.requestDigest) throw new TypeError('MCP server launch substitutes another originating tool request');
  const responses = new Map<string, Extract<McpInboundMessageData, { kind: 'result' | 'error' }>>(), metadata: PublishedArtifact[] = [];
  for (const entry of value.captures) {
    const descriptor = controlWireRecord(entry, ['phase', 'captureRef']); controlWireRef(descriptor.captureRef);
    const captured = await readMcpStdioCapture(artifacts, descriptor.captureRef as string);
    if (descriptor.phase !== captured.capture.phase || responses.has(captured.capture.phase)) throw new TypeError('MCP stdio capture repeats/substitutes a fixed phase');
    responses.set(captured.capture.phase, captured.decoded.response);
    metadata.push(await artifacts.describe(descriptor.captureRef as string, 'application/json', captured.capture.format),
      await artifacts.describe(captured.capture.rawResponseRef, 'application/octet-stream', 'cliq-mcp-stdio-finite-capture-bytes-v1'));
  }
  for (const entry of unusable ? value.unusableResponses as unknown[] : []) {
    const descriptor = controlWireRecord(entry, ['phase', 'ref']); controlWireRef(descriptor.ref);
    const captured = await readUnusable(artifacts, descriptor.ref as string);
    if (descriptor.phase !== captured.value.phase || responses.has(descriptor.phase as string)) throw new TypeError('MCP stdio known-unusable repeats/substitutes a fixed phase');
    responses.set(descriptor.phase as string, captured.response);
    metadata.push(await artifacts.describe(descriptor.ref as string, 'application/json', 'cliq-mcp-stdio-known-unusable-response-v1'),
      await artifacts.describe(captured.value.safeMessageRef as string, 'application/json', 'cliq-mcp-stdio-screened-known-event-bytes-v1'));
  }
  const initialized = responses.get('initialize'), listed = responses.get('tools_list'), response = responses.get('tools_call');
  if (responses.size !== 3 || initialized?.kind !== 'result' || listed?.kind !== 'result' || !response) throw new TypeError('MCP stdio has no complete original discovery/effect response graph');
  const negotiation = decodeMcpInitializeResult(initialized.result), tools = decodeMcpToolsListResult(listed.result);
  if (negotiation.initializeDigest !== instance.initializeDigest || negotiation.capabilityDigest !== instance.capabilityDigest ||
      canonicalSha256(tools.map(tool => tool.interface)) !== instance.probedToolsListDigest || instance.initializeDigest !== registry.registry.initializeDigest ||
      instance.capabilityDigest !== registry.registry.capabilityDigest || instance.probedToolsListDigest !== registry.registry.probedToolsListDigest)
    throw new TypeError('MCP stdio received negotiation/interfaces differ from its original instance/registry');
  const registeredTool = registry.registry.tools.find(tool => tool.name === execution.serverToolName);
  const output = registeredTool?.outputSchemaRef ? await readCanonicalArtifact(artifacts, registeredTool.outputSchemaRef) : undefined;
  let result: McpCallResultV1 | undefined;
  try { result = response.kind === 'error' ? immutableSnapshot({ kind: 'rpc_error' as const, ...response.error }) : decodeMcpCallResult(response.result, output); }
  catch { if (!value.malformedResult || value.result !== null) throw new TypeError('MCP stdio invalid received result lost its exact protocol-error projection'); }
  if (result) {
    if (value.malformedResult) throw new TypeError('MCP stdio valid received result was relabeled malformed');
    requireEqual(value.result, result, 'MCP stdio exact retained normalized result');
  }
  metadata.push(await artifacts.describe(input.captureRef, 'application/json', value.format as string));
  return { value, launch, binding, instance, registry, history, result, unusable, metadata };
}
export async function assertMcpStdioCaptureObservation(artifacts: ArtifactCatalog, observation: ToolObservationV1,
  captured: Awaited<ReturnType<typeof readMcpStdioRunCapture>>): Promise<void> {
  if (observation.captureDigest !== captured.value.captureDigest) throw new TypeError('MCP stdio observation changes its original capture identity');
  if (observation.outcome === 'executed') {
    if (!captured.result || captured.unusable) throw new TypeError('MCP stdio malformed or unusable capture cannot become executed content');
    requireEqual(observation.content, captured.result, 'MCP stdio original model-safe result'); return;
  }
  if (observation.code !== 'TOOL_PROTOCOL_ERROR') throw new TypeError('MCP stdio received response cannot become an arbitrary tool failure');
  const diagnostic = await readCanonicalArtifact<Record<string, unknown>>(artifacts, observation.diagnosticRef);
  if (canonicalSha256(diagnostic) !== observation.diagnosticDigest) throw new TypeError('MCP stdio output diagnostic differs from its complete original bytes');
  if (captured.unusable) {
    requireEqual(diagnostic, { schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR',
      knownUnusableCaptureRef: observation.captureRef, knownUnusableCaptureDigest: observation.captureDigest }, 'MCP stdio original known-unusable diagnosis');
    return;
  }
  if (captured.value.malformedResult) {
    requireEqual(diagnostic, { schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR' }, 'MCP stdio malformed-result diagnosis');
    return;
  }
  if (!captured.result || canonicalJsonBytes(captured.result).byteLength <= 1_048_576 || typeof diagnostic.observationRef !== 'string')
    throw new TypeError('MCP stdio output normalization has no reproduced original oversize result');
  requireEqual(diagnostic, { schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_PROTOCOL_ERROR',
    observationRef: diagnostic.observationRef }, 'MCP stdio oversize-result diagnosis');
  const original = await readCanonicalArtifact<ToolObservationV1>(artifacts, diagnostic.observationRef);
  if (original.outcome !== 'executed' || original.captureRef !== observation.captureRef || original.captureDigest !== observation.captureDigest ||
      original.observationDigest !== digestOmitting(original, 'observationDigest')) throw new TypeError('MCP stdio normalization substitutes its original received custody');
  requireEqual(original.content, captured.result, 'MCP stdio retained original oversize projection');
  const { content: _content, observationDigest: _digest, ...base } = original;
  const core = { ...base, outcome: 'error', code: 'TOOL_PROTOCOL_ERROR', diagnosticRef: observation.diagnosticRef, diagnosticDigest: observation.diagnosticDigest };
  requireEqual(observation, { ...core, observationDigest: canonicalSha256(core) }, 'MCP stdio exact oversize normalization');
}
