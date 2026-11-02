// Closed MCP data only. Decoding never creates a registration, grant,
// AdminOperation, native owner, dispatch fence or resource/death evidence.
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { assertRequestId, digestOmitting, parseCanonicalTime, identityHash } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactRef } from './types.js';
import { compileInputSchema, compileOutputSchema } from '../tools/input-schema.js';

export const MCP_PROTOCOL_VERSION = '2025-11-25' as const;
export const MCP_RESPONSE_BYTES = 1_048_576;
/** One numeric attempt identity shared by the real no-I/O producer/history. */
export function mcpNoReleaseCheckpointId(runId: string, opId: string, attempt: number): string {
  controlWireText(runId); controlWireText(opId); controlWireInteger(attempt, 0);
  return identityHash('cliq-mcp-no-release-checkpoint-v1', runId, opId, attempt);
}
/** Stable qualified identity, independent of revision. The full 256-bit hash
 * preserves Unicode and long names while the exposed ASCII name fits native
 * provider function-name constraints. The original names remain the policy,
 * display and actual server-call identity. */
export function mcpExposedToolName(registrationId: string, serverToolName: string): string {
  controlWireText(registrationId); controlWireText(serverToolName, 128);
  const readable = `${registrationId}_${serverToolName}`.replace(/[^A-Za-z0-9_-]/gu, '_').slice(0, 16);
  return `mcp_${readable}_${identityHash('cliq-mcp-exposed-tool-v1', registrationId, serverToolName)}`;
}
export function mcpExposedToolDescription(registrationId: string, serverToolName: string, description: string): string {
  controlWireText(registrationId); controlWireText(serverToolName, 128); controlWireText(description, MCP_RESPONSE_BYTES, 0);
  return `MCP registration ${JSON.stringify(registrationId)}, server tool ${JSON.stringify(serverToolName)}.\n${description}`;
}
export type McpLifecycleV1 = Readonly<{ launchTimeoutMs: number; callTimeoutMs: number; maxLaunchesPerCall: number }>;
export type McpRecoveryRequestV1 = Readonly<{ kind: 'manual' }> |
  Readonly<{ kind: 'retry'; acknowledgeDuplicateEffectRisk: true; idempotencyKeyJsonPointer?: string }> |
  Readonly<{ kind: 'reconcile'; bundledAdapterId: string; idempotencyKeyJsonPointer: string }>;
export type McpRegisterRequestV1 = Readonly<{
  protocolVersion: 1; method: 'mcp.register'; requestId: string; requestDigest: string; registrationId: string;
  target: Readonly<{ kind: 'stdio'; executionIdentityGrantId: string;
    argv: readonly Readonly<{ kind: 'non_secret_literal'; value: string }>[] }> |
    Readonly<{ kind: 'streamable_http'; endpointRegistrationId: string; credentialGrantIds: readonly string[] }>;
  assertStatelessPerCall: true; toolRecovery: Readonly<Record<string, McpRecoveryRequestV1>>;
  lifecycle?: Readonly<Partial<McpLifecycleV1>>;
}>;
export type McpRefreshRequestV1 = Readonly<{ protocolVersion: 1; method: 'mcp.refresh'; requestId: string;
  requestDigest: string; registrationId: string; expectedRegistryRevision: number }>;
export type McpMutationRequestV1 = McpRegisterRequestV1 | McpRefreshRequestV1;

export type McpResolvedTransportV1 = Readonly<{
  kind: 'stdio'; executionIdentityGrantId: string; executionIdentityConsumptionReceiptRef: ArtifactRef;
  executionIdentityConsumptionReceiptDigest: string;
  executable: Readonly<{ kind: 'guest_toolchain'; toolchainManifestRef: ArtifactRef; toolId: string;
    executionPath: string; executableDigest: string }> |
    Readonly<{ kind: 'runtime_bundle'; runtimeBundleRef: ArtifactRef; executableId: string;
      executionPath: string; executableDigest: string }>;
  argv: readonly Readonly<{ kind: 'non_secret_literal'; value: string }>[];
}> | Readonly<{
  kind: 'streamable_http'; endpointRegistrationRef: ArtifactRef; endpointIdentityDigest: string;
  tlsPolicyDigest: string; credentialGrantRefs: readonly ArtifactRef[];
}>;
export type McpProbedToolInterfaceV1 = Readonly<{
  name: string; version: 'mcp-tool-interface-v1'; description: string; access: 'exec';
  inputSchemaRef: ArtifactRef; inputSchemaDigest: string; outputSchemaRef?: ArtifactRef; outputSchemaDigest?: string;
  interfaceDigest: string;
}>;
export type McpRecoveryContractV1 = Readonly<{ kind: 'manual' }> | Readonly<{
  kind: 'retry'; explicitRiskConsentRef: ArtifactRef; explicitRiskConsentDigest: string;
  safetyAssertionRef: ArtifactRef; safetyAssertionDigest: string; idempotencyKeyInjection?: Readonly<{ jsonPointer: string }>;
}> | Readonly<{
  kind: 'reconcile'; adapterRef: ArtifactRef; adapterDigest: string; profileId: string; profileDigest: string;
  idempotencyKeyInjection: Readonly<{ jsonPointer: string }>;
  statusRequestTemplateRef: ArtifactRef; statusRequestTemplateDigest: string;
  completedPredicateRef: ArtifactRef; completedPredicateDigest: string;
  failedPredicateRef: ArtifactRef; failedPredicateDigest: string;
}>;
export type RequestedMcpRecoveryV1 = Readonly<{ kind: 'manual' }> | Readonly<{
  kind: 'retry'; explicitRiskConsentRef: ArtifactRef; explicitRiskConsentDigest: string;
  safetyAssertionRef: ArtifactRef; safetyAssertionDigest: string; idempotencyKeyJsonPointer?: string;
}> | Readonly<{ kind: 'reconcile'; bundledAdapterId: string; idempotencyKeyJsonPointer: string }>;
export type McpToolContractV1 = Omit<McpProbedToolInterfaceV1, 'version'> & Readonly<{
  version: 'mcp-tool-contract-v1'; recovery: McpRecoveryContractV1; toolContractDigest: string;
}>;
export type McpRegistryRevisionV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-registry-v1'; registrationId: string; registryRevision: number; ownerPrincipalId: string;
  transport: McpResolvedTransportV1; initializeDigest: string; capabilityDigest: string; probedToolsListDigest: string;
  toolsListDigest: string; stateModel: 'stateless_per_call'; tools: readonly McpToolContractV1[];
  lifecycle: McpLifecycleV1; registrationReceiptRef: ArtifactRef; manifestDigest: string; createdAt: string;
}>;
export type McpRegistrySummaryV1 = Readonly<{
  schemaVersion: 1; registrationId: string; registryRevision: number; transport: 'stdio' | 'streamable_http';
  stateModel: 'stateless_per_call'; toolCount: number; toolsListDigest: string; manifestDigest: string;
  registrationReceiptRef: ArtifactRef; createdAt: string;
}>;
export type McpRegistrationReceiptV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-registration-receipt-v1'; registrationId: string; registryRevision: number;
  ownerPrincipalId: string; requestDigest: string; adminOperationId: string; adminAttempt: number; dispatchId: string;
  probeRequestDigest: string; adminProbeTargetRef: ArtifactRef; adminProbeTargetDigest: string;
  probeResultRef: ArtifactRef; probeResultDigest: string; probeClosureEvidenceRef: ArtifactRef;
  probeClosureEvidenceDigest: string; initializeDigest: string; capabilityDigest: string;
  probedToolsListDigest: string; toolsListDigest: string; registryCoreDigest: string; createdAt: string; receiptDigest: string;
}>;
export type AdminProbePayloadCoreV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-admin-probe-payload-core-v1'; probeKind: 'mcp_stdio' | 'mcp_streamable_http';
  runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string; adapterExecutableId: string;
  adapterVersion: string; adapterExecutableDigest: string; protocolRecipe: 'mcp-initialize-capabilities-tools-list-v1';
  maximumResponseBytes: number; payloadCoreDigest: string;
}>;
export type McpAdminProbeTargetV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-admin-probe-target-v1'; ownerPrincipalId: string; registrationId: string;
  method: 'mcp.register' | 'mcp.refresh'; expectedRegistryRevision?: number; sourceRegistryRevisionRef?: ArtifactRef;
  resolvedTransport: McpResolvedTransportV1; assertStatelessPerCall: true;
  originalRequestRef: ArtifactRef; channelIdentityRef: ArtifactRef; channelIdentityDigest: string;
  requestedToolRecovery: readonly Readonly<{ toolName: string; recovery: RequestedMcpRecoveryV1 }>[];
  lifecycle: McpLifecycleV1; requestCoreDigest: string; targetDigest: string; createdAt: string;
}>;
export type AdminProbeDispatchStateV1 = Readonly<{ state: 'blocked' }> |
  Readonly<{ state: 'claimed'; probeRequestDigest: string; dispatchId: string; claimedAt: string }> |
  Readonly<{ state: 'released'; probeRequestDigest: string; dispatchId: string; claimedAt: string; releasedAt: string }>;
type AdminOperationBaseV1 = Readonly<{
  schemaVersion: 1; adminOperationId: string; principalId: string; method: 'mcp.register' | 'mcp.refresh';
  requestId: string; requestDigest: string; attempt: number; maxAttempts: 3; deadlineAt: string;
  targetRef: ArtifactRef; targetDigest: string; probePayloadCoreRef: ArtifactRef; probePayloadCoreDigest: string;
  supervisorInstanceId: string; plannedContainmentRef: ArtifactRef; plannedContainmentDigest: string;
  sandboxLaunchSpecRef: ArtifactRef; sandboxLaunchSpecDigest: string; rowVersion: number; createdAt: string;
}>;
export type AdminOperationV1 = AdminOperationBaseV1 & (
  Readonly<{ phase: 'prepared' }> |
  Readonly<{ phase: 'active'; processContainmentRef: ArtifactRef; leaseExpiresAt: string; probeDispatch: AdminProbeDispatchStateV1 }> |
  Readonly<{ phase: 'completed'; processContainmentRef: ArtifactRef;
    probeDispatch: Extract<AdminProbeDispatchStateV1, { state: 'released' }>;
    resultRef: ArtifactRef; resultDigest: string; evidenceRef: ArtifactRef; evidenceDigest: string;
    controlResponseRef: ArtifactRef; controlResponseDigest: string; finishedAt: string }> |
  Readonly<{ phase: 'failed'; failureDisposition: 'retryable_recovery'; processContainmentRef?: ArtifactRef;
    probeDispatch?: AdminProbeDispatchStateV1; evidenceRef: ArtifactRef; evidenceDigest: string; errorRef: ArtifactRef;
    errorDigest: string; retryNotBeforeAt: string; finishedAt: string }> |
  Readonly<{ phase: 'failed'; failureDisposition: 'final_rejection' | 'retry_exhausted'; processContainmentRef?: ArtifactRef;
    probeDispatch?: AdminProbeDispatchStateV1; evidenceRef: ArtifactRef; evidenceDigest: string; errorRef: ArtifactRef;
    errorDigest: string; controlResponseRef: ArtifactRef; controlResponseDigest: string; finishedAt: string }>
);
export type McpAdminProbeResultV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-admin-probe-result-v1'; adminOperationId: string; attempt: number;
  dispatchId: string; probeRequestDigest: string; targetRef: ArtifactRef; targetDigest: string;
  probePayloadCoreRef: ArtifactRef; probePayloadCoreDigest: string; processContainmentRef: ArtifactRef;
  initializeResponseRef: ArtifactRef; initializeResponseDigest: string; capabilityResponseRef: ArtifactRef;
  capabilityResponseDigest: string; toolsListResponseRef: ArtifactRef; toolsListResponseDigest: string;
  initializeDigest: string; capabilityDigest: string; normalizedTools: readonly McpProbedToolInterfaceV1[];
  probedToolsListDigest: string; completedAt: string; resultDigest: string;
  initializeCaptureRef?: ArtifactRef; toolsListCaptureRef?: ArtifactRef;
}>;
export type McpHttpCaptureV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-http-capture-v1'; phase: 'initialize' | 'tools_list' | 'tools_call';
  expectedId: string | number; mediaType: 'application/json' | 'text/event-stream';
  termination: 'http_eof' | 'sse_response_event'; rawResponseRef: ArtifactRef;
  rawFinitePrefixBytes: number; rawFinitePrefixDigest: string; responseEventEndOffset?: number;
  receivedTailBytes: number; captureDigest: string;
}>;
export type AdminProbeClosureEvidenceV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-admin-probe-closure-evidence-v1'; adminOperationId: string; attempt: number;
  targetRef: ArtifactRef; targetDigest: string; plannedContainmentRef: ArtifactRef; plannedContainmentDigest: string;
  sandboxLaunchSpecRef: ArtifactRef; sandboxLaunchSpecDigest: string; inspectorIdentityRef: ArtifactRef;
  inspectorIdentityDigest: string; observedAt: string; evidenceDigest: string;
  nativeLifecycleRef?: ArtifactRef; nativeLifecycleDigest?: string;
  nativeLifecycleProjectionRef?: ArtifactRef; nativeLifecycleProjectionDigest?: string;
  nativeCleanupRef?: ArtifactRef; nativeCleanupDigest?: string;
}> & (Readonly<{ closureKind: 'no_spawn'; noSpawnEvidenceRef: ArtifactRef; noSpawnEvidenceDigest: string }> |
  Readonly<{ closureKind: 'containment_dead'; processContainmentRef: ArtifactRef; dispatchId?: string;
    probeRequestDigest?: string; deathEvidenceRef: ArtifactRef; deathEvidenceDigest: string }>);
export type AdminProbeErrorV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-admin-probe-error-v1'; adminOperationId: string; attempt: number;
  targetRef: ArtifactRef; targetDigest: string; closureEvidenceRef: ArtifactRef; closureEvidenceDigest: string;
  diagnosticRef: ArtifactRef; diagnosticDigest: string; createdAt: string; errorDigest: string;
}> & (Readonly<{ code: 'target_rejected' | 'schema_invalid' | 'capability_mismatch'; deterministicRejection: true }> |
  Readonly<{ code: 'preactivation_no_spawn' | 'transport_failed_no_effect' | 'timeout_after_containment_death'; deterministicRejection: false }>);
export type ManualInvocationWaitV1 = Readonly<{
  schemaVersion: 1; kind: 'reconciliation'; runId: string; createdFromRevision: number; createdAt: string; frontierRef: ArtifactRef;
  subject: Readonly<{ kind: 'invocation'; recovery: 'manual'; opKind: 'tool' | 'mcp'; opId: string; attempt: number }>;
  probeState: Readonly<{ phase: 'manual_only'; automaticProbeCount: 0; userProbeCount: 0 }>;
}>;
export type ManualAbandonAttestationV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-manual-abandon-attestation-v1'; principalId: string;
  channelIdentityRef: ArtifactRef; channelIdentityDigest: string; requestId: string; requestDigest: string;
  runId: string; waitingSubjectRef: ArtifactRef; frontierRef: ArtifactRef; opId: string; attempt: number;
  unknownJournalSeq: number; operationRequestRef: ArtifactRef; operationRequestDigest: string; targetRef: ArtifactRef;
  targetDigest: string; ambiguityEvidenceRef: ArtifactRef; ambiguityEvidenceDigest: string;
  acknowledgedRisk: 'effect_may_have_occurred_result_will_not_be_used_and_run_will_stop';
  createdAt: string; attestationDigest: string;
}>;
export type ToolAbandonedItem = Readonly<{
  schemaVersion: 1; itemId: string; runId: string; kind: 'tool_abandoned'; batchItemId: string; callId: string; index: number;
  opId: string; attempt: number; abandonedJournalSeq: number; attestationRef: ArtifactRef; createdAt: string;
}>;

/** Semantic projections of genuinely received data. These values are inert:
 * only the original native receipt proves receipt, screening and retirement. */
export type McpInitializeProjectionV1 = Readonly<{
  protocolVersion: typeof MCP_PROTOCOL_VERSION; serverInfo: Readonly<Record<string, unknown>>;
  capabilities: Readonly<Record<string, unknown>>; instructions?: string;
  initializeDigest: string; capabilityDigest: string;
}>;
export type McpDiscoveredToolV1 = Readonly<{
  interface: McpProbedToolInterfaceV1; inputSchema: Readonly<Record<string, unknown>>;
  outputSchema?: Readonly<Record<string, unknown>>;
}>;
export type McpCallResultV1 = Readonly<{
  kind: 'tool_result'; content: readonly Readonly<Record<string, unknown>>[];
  structuredContent?: Readonly<Record<string, unknown>>; isError: boolean;
}> | Readonly<{ kind: 'rpc_error'; code: number; message: string; data?: unknown }>;

function jsonObject(value: unknown): Record<string, unknown> {
  bounded(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('MCP value must be an object');
  return value as Record<string, unknown>;
}
export function decodeMcpInitializeResult(value: unknown): McpInitializeProjectionV1 {
  bounded(value);
  const data = controlWireRecord(value, ['protocolVersion', 'capabilities', 'serverInfo'], ['instructions', '_meta']);
  if (data.protocolVersion !== MCP_PROTOCOL_VERSION) throw new TypeError('MCP protocol version differs from the frozen profile');
  const capabilities = jsonObject(data.capabilities), serverInfo = controlWireRecord(data.serverInfo, ['name', 'version'], ['title', 'websiteUrl', 'icons']);
  controlWireText(serverInfo.name); controlWireText(serverInfo.version);
  if (!Object.hasOwn(capabilities, 'tools')) throw new TypeError('MCP server does not advertise tools');
  const tools = controlWireRecord(capabilities.tools, [], ['listChanged']);
  if (Object.hasOwn(tools, 'listChanged') && typeof tools.listChanged !== 'boolean') throw new TypeError('invalid MCP tools capability');
  for (const [key, item] of Object.entries(capabilities)) {
    if (!['experimental', 'logging', 'completions', 'prompts', 'resources', 'tools', 'tasks'].includes(key))
      throw new TypeError('unsupported MCP capability');
    jsonObject(item);
  }
  if (Object.hasOwn(data, 'instructions')) controlWireText(data.instructions, MCP_RESPONSE_BYTES, 0);
  return immutableSnapshot({ protocolVersion: MCP_PROTOCOL_VERSION, serverInfo, capabilities,
    ...(Object.hasOwn(data, 'instructions') ? { instructions: data.instructions as string } : {}),
    initializeDigest: canonicalSha256(data), capabilityDigest: canonicalSha256(capabilities) });
}

/** Pagination is explicitly outside the first profile. Never silently retain
 * one page as the complete immutable registry. Remote schema resolution is
 * disabled by the same synchronous AJV compiler used by ordinary tools. */
export function decodeMcpToolsListResult(value: unknown): readonly McpDiscoveredToolV1[] {
  bounded(value);
  const data = controlWireRecord(value, ['tools'], ['nextCursor', '_meta']);
  if (Object.hasOwn(data, 'nextCursor')) throw new TypeError('paginated MCP discovery is not implemented');
  if (!Array.isArray(data.tools) || data.tools.length < 1 || data.tools.length > 128) throw new TypeError('MCP tools exceed their discovery bound');
  const result = data.tools.map(value => {
    const item = controlWireRecord(value, ['name', 'inputSchema'], ['description', 'title', 'outputSchema', 'annotations', '_meta', 'icons']);
    const name = controlWireText(item.name, 128), description = controlWireText(item.description ?? '', MCP_RESPONSE_BYTES, 0);
    const inputSchema = jsonObject(item.inputSchema);
    if (inputSchema.type !== 'object') throw new TypeError('MCP input schema must describe an object');
    compileInputSchema(inputSchema);
    const outputSchema = Object.hasOwn(item, 'outputSchema') ? jsonObject(item.outputSchema) : undefined;
    if (outputSchema) { if (outputSchema.type !== 'object') throw new TypeError('MCP output schema must describe an object'); compileOutputSchema(outputSchema); }
    if (Object.hasOwn(item, 'annotations')) jsonObject(item.annotations);
    if (Object.hasOwn(item, '_meta')) jsonObject(item._meta);
    const core = { name, version: 'mcp-tool-interface-v1' as const, description, access: 'exec' as const,
      inputSchemaRef: canonicalSha256(inputSchema), inputSchemaDigest: canonicalSha256(inputSchema),
      ...(outputSchema ? { outputSchemaRef: canonicalSha256(outputSchema), outputSchemaDigest: canonicalSha256(outputSchema) } : {}) };
    return immutableSnapshot({ interface: { ...core, interfaceDigest: canonicalSha256(core) }, inputSchema,
      ...(outputSchema ? { outputSchema } : {}) });
  }).sort((left, right) => Buffer.compare(Buffer.from(left.interface.name), Buffer.from(right.interface.name)));
  if (result.some((item, index) => index > 0 && item.interface.name === result[index - 1]!.interface.name))
    throw new TypeError('MCP discovery has duplicate tool names');
  return Object.freeze(result);
}

function contentBlock(value: unknown): Readonly<Record<string, unknown>> {
  const kind = jsonObject(value).type;
  const data = kind === 'text' ? controlWireRecord(value, ['type', 'text'], ['annotations', '_meta'])
    : kind === 'image' || kind === 'audio' ? controlWireRecord(value, ['type', 'data', 'mimeType'], ['annotations', '_meta'])
    : kind === 'resource_link' ? controlWireRecord(value, ['type', 'uri', 'name'], ['title', 'description', 'mimeType', 'size', 'icons', 'annotations', '_meta'])
    : kind === 'resource' ? controlWireRecord(value, ['type', 'resource'], ['annotations', '_meta'])
    : (() => { throw new TypeError('unsupported MCP content block'); })();
  if (kind === 'text') controlWireText(data.text, MCP_RESPONSE_BYTES, 0);
  else if (kind === 'image' || kind === 'audio') {
    controlWireText(data.mimeType, 256); const encoded = controlWireText(data.data, MCP_RESPONSE_BYTES, 0);
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) throw new TypeError('MCP media data is not canonical base64');
  } else if (kind === 'resource_link') { controlWireText(data.uri, 8192); controlWireText(data.name); }
  else {
    const resource = jsonObject(data.resource), text = Object.hasOwn(resource, 'text');
    controlWireRecord(resource, ['uri', text ? 'text' : 'blob'], ['mimeType', '_meta']);
    controlWireText(resource.uri, 8192); controlWireText(resource[text ? 'text' : 'blob'], MCP_RESPONSE_BYTES, 0);
  }
  if (Object.hasOwn(data, 'annotations')) {
    const annotations = controlWireRecord(data.annotations, [], ['audience', 'priority', 'lastModified']);
    if (annotations.audience !== undefined && (!Array.isArray(annotations.audience) || annotations.audience.some(item => !['user', 'assistant'].includes(item as string))))
      throw new TypeError('invalid MCP content audience');
    if (annotations.priority !== undefined && (typeof annotations.priority !== 'number' || annotations.priority < 0 || annotations.priority > 1)) throw new TypeError('invalid MCP content priority');
    if (annotations.lastModified !== undefined) controlWireText(annotations.lastModified);
  }
  return immutableSnapshot(data);
}
export function decodeMcpCallResult(value: unknown, outputSchema?: unknown): McpCallResultV1 {
  bounded(value);
  const data = controlWireRecord(value, ['content'], ['structuredContent', 'isError', '_meta']);
  if (!Array.isArray(data.content)) throw new TypeError('MCP call result has no content array');
  if (data.isError !== undefined && typeof data.isError !== 'boolean') throw new TypeError('invalid MCP isError flag');
  const structuredContent = data.structuredContent === undefined ? undefined : jsonObject(data.structuredContent);
  if (outputSchema !== undefined && data.isError !== true && (!structuredContent || !compileOutputSchema(outputSchema)(structuredContent)))
    throw new TypeError('MCP structured result differs from its frozen output schema');
  return immutableSnapshot({ kind: 'tool_result', content: data.content.map(contentBlock), isError: data.isError === true,
    ...(structuredContent ? { structuredContent } : {}) });
}

function bounded(value: unknown): void {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP data');
  if (canonicalJsonBytes(value).byteLength > MCP_RESPONSE_BYTES) throw new TypeError('MCP data exceeds its original byte limit');
}
function time(value: unknown): void { parseCanonicalTime(controlWireText(value, 24, 24)); }
function digest(data: Record<string, unknown>, key: string): void {
  if (controlWireRef(data[key]) !== digestOmitting(data, key)) throw new TypeError('MCP artifact digest does not rehash');
}
function pointer(value: unknown): string {
  const text = controlWireText(value, MCP_RESPONSE_BYTES, 0);
  if (text && (!text.startsWith('/') || /~(?:[^01]|$)/u.test(text))) throw new TypeError('invalid MCP JSON pointer');
  return text;
}
function refs(value: unknown, maximum: number): void {
  if (!Array.isArray(value) || value.length > maximum || new Set(value).size !== value.length) throw new TypeError('MCP refs must be bounded and unique');
  let prior = '';
  for (const ref of value) {
    controlWireRef(ref);
    if (prior && Buffer.compare(Buffer.from(prior), Buffer.from(ref)) >= 0) throw new TypeError('MCP refs must be byte sorted');
    prior = ref;
  }
}
function argumentsData(value: unknown): void {
  if (!Array.isArray(value) || value.length > 128) throw new TypeError('MCP argv exceeds its original bound');
  for (const literal of value) {
    const data = controlWireRecord(literal, ['kind', 'value']);
    if (data.kind !== 'non_secret_literal') throw new TypeError('MCP argv must assert non-secret literals');
    controlWireText(data.value, 8192, 0);
  }
}
export function normalizeMcpLifecycle(value: unknown = {}): McpLifecycleV1 {
  bounded(value);
  const data = controlWireRecord(value, [], ['launchTimeoutMs', 'callTimeoutMs', 'maxLaunchesPerCall']);
  return Object.freeze({ launchTimeoutMs: controlWireInteger(data.launchTimeoutMs ?? 30_000, 1000, 300_000),
    callTimeoutMs: controlWireInteger(data.callTimeoutMs ?? 600_000, 1000, 3_600_000),
    maxLaunchesPerCall: controlWireInteger(data.maxLaunchesPerCall ?? 2, 1, 3) });
}
function recoveryRequest(value: unknown): void {
  const kind = (value as { kind?: unknown } | null)?.kind;
  if (kind === 'manual') controlWireRecord(value, ['kind']);
  else if (kind === 'retry') {
    const data = controlWireRecord(value, ['kind', 'acknowledgeDuplicateEffectRisk'], ['idempotencyKeyJsonPointer']);
    if (data.acknowledgeDuplicateEffectRisk !== true) throw new TypeError('MCP retry requires its exact duplicate-effect acknowledgement');
    if (Object.hasOwn(data, 'idempotencyKeyJsonPointer')) pointer(data.idempotencyKeyJsonPointer);
  } else if (kind === 'reconcile') {
    const data = controlWireRecord(value, ['kind', 'bundledAdapterId', 'idempotencyKeyJsonPointer']);
    controlWireText(data.bundledAdapterId); pointer(data.idempotencyKeyJsonPointer);
  } else throw new TypeError('unsupported MCP recovery request');
}
export function decodeMcpMutationRequest(value: unknown): McpMutationRequestV1 {
  bounded(value);
  const method = (value as { method?: unknown } | null)?.method;
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'requestDigest', 'registrationId',
    ...(method === 'mcp.refresh' ? ['expectedRegistryRevision'] : ['target', 'assertStatelessPerCall', 'toolRecovery'])],
  method === 'mcp.register' ? ['lifecycle'] : []);
  if (data.protocolVersion !== 1 || !['mcp.register', 'mcp.refresh'].includes(method as string)) throw new TypeError('invalid MCP method or version');
  assertRequestId(controlWireText(data.requestId)); controlWireText(data.registrationId);
  const { requestDigest, ...core } = data;
  if (controlWireRef(requestDigest) !== canonicalSha256(core)) throw new TypeError('MCP request digest differs from its original bytes');
  if (method === 'mcp.refresh') controlWireInteger(data.expectedRegistryRevision, 1);
  else {
    if (data.assertStatelessPerCall !== true) throw new TypeError('MCP registration requires explicit stateless-per-call intent');
    const targetKind = (data.target as { kind?: unknown } | null)?.kind;
    if (targetKind === 'stdio') {
      const target = controlWireRecord(data.target, ['kind', 'executionIdentityGrantId', 'argv']);
      controlWireText(target.executionIdentityGrantId); argumentsData(target.argv);
    } else if (targetKind === 'streamable_http') {
      const target = controlWireRecord(data.target, ['kind', 'endpointRegistrationId', 'credentialGrantIds']);
      controlWireText(target.endpointRegistrationId);
      if (!Array.isArray(target.credentialGrantIds) || target.credentialGrantIds.length > 32 ||
          new Set(target.credentialGrantIds).size !== target.credentialGrantIds.length) throw new TypeError('MCP credentials must be bounded and unique');
      target.credentialGrantIds.forEach(value => controlWireText(value));
    } else throw new TypeError('unsupported MCP target');
    const recovery = data.toolRecovery;
    if (!recovery || typeof recovery !== 'object' || Array.isArray(recovery) || Object.keys(recovery).length > 128)
      throw new TypeError('MCP recovery requests exceed their tool bound');
    for (const [name, request] of Object.entries(recovery)) { controlWireText(name); recoveryRequest(request); }
    if (Object.hasOwn(data, 'lifecycle')) normalizeMcpLifecycle(data.lifecycle);
  }
  return immutableSnapshot(data) as McpMutationRequestV1;
}
export function mcpMutationCoreDigest(value: McpMutationRequestV1): string {
  const { protocolVersion: _version, requestId: _requestId, requestDigest: _digest, ...body } = decodeMcpMutationRequest(value);
  return canonicalSha256(body);
}

export function decodeMcpResolvedTransport(value: unknown): McpResolvedTransportV1 {
  bounded(value);
  const kind = (value as { kind?: unknown } | null)?.kind;
  if (kind === 'streamable_http') {
    const data = controlWireRecord(value, ['kind', 'endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest', 'credentialGrantRefs']);
    for (const key of ['endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest']) controlWireRef(data[key]);
    refs(data.credentialGrantRefs, 32);
  } else if (kind === 'stdio') {
    const data = controlWireRecord(value, ['kind', 'executionIdentityGrantId', 'executionIdentityConsumptionReceiptRef',
      'executionIdentityConsumptionReceiptDigest', 'executable', 'argv']);
    controlWireText(data.executionIdentityGrantId); controlWireRef(data.executionIdentityConsumptionReceiptRef);
    controlWireRef(data.executionIdentityConsumptionReceiptDigest); argumentsData(data.argv);
    const executableKind = (data.executable as { kind?: unknown } | null)?.kind;
    const executable = controlWireRecord(data.executable, ['kind', 'executionPath', 'executableDigest',
      ...(executableKind === 'guest_toolchain' ? ['toolchainManifestRef', 'toolId'] : ['runtimeBundleRef', 'executableId'])]);
    if (executableKind !== 'guest_toolchain' && executableKind !== 'runtime_bundle') throw new TypeError('MCP executable is not a signed discovery identity');
    controlWireRef(executable.executableDigest);
    controlWireRef(executable[executableKind === 'guest_toolchain' ? 'toolchainManifestRef' : 'runtimeBundleRef']);
    controlWireText(executable[executableKind === 'guest_toolchain' ? 'toolId' : 'executableId']);
    const pathname = controlWireText(executable.executionPath, 4096);
    if (!pathname.startsWith('/') || pathname.includes('\\') || pathname.split('/').slice(1).some(part => !part || part === '.' || part === '..'))
      throw new TypeError('MCP executable path is not absolute canonical identity');
  } else throw new TypeError('unsupported retained MCP transport');
  return immutableSnapshot(value) as McpResolvedTransportV1;
}

function tool(value: unknown, final: boolean): void {
  const data = controlWireRecord(value, ['name', 'version', 'description', 'access', 'inputSchemaRef', 'inputSchemaDigest', 'interfaceDigest',
    ...(final ? ['recovery', 'toolContractDigest'] : [])], ['outputSchemaRef', 'outputSchemaDigest']);
  if (data.version !== (final ? 'mcp-tool-contract-v1' : 'mcp-tool-interface-v1') || data.access !== 'exec')
    throw new TypeError('MCP interface changed its canonical version or exec class');
  controlWireText(data.name); controlWireText(data.description, MCP_RESPONSE_BYTES, 0);
  controlWireRef(data.inputSchemaRef); controlWireRef(data.inputSchemaDigest);
  if (data.inputSchemaRef !== data.inputSchemaDigest || Object.hasOwn(data, 'outputSchemaRef') !== Object.hasOwn(data, 'outputSchemaDigest'))
    throw new TypeError('MCP schema identity is not complete');
  if (Object.hasOwn(data, 'outputSchemaRef') && controlWireRef(data.outputSchemaRef) !== controlWireRef(data.outputSchemaDigest))
    throw new TypeError('MCP output schema digest differs');
  const { recovery: _recovery, toolContractDigest: _contract, ...raw } = data;
  const probed = { ...raw, version: 'mcp-tool-interface-v1' };
  digest(probed, 'interfaceDigest');
  if (final) { decodeMcpRecoveryContract(data.recovery); digest(data, 'toolContractDigest'); }
}
export function decodeMcpRecoveryContract(value: unknown): McpRecoveryContractV1 {
  bounded(value);
  const kind = (value as { kind?: unknown } | null)?.kind;
  if (kind === 'manual') controlWireRecord(value, ['kind']);
  else if (kind === 'retry') {
    const data = controlWireRecord(value, ['kind', 'explicitRiskConsentRef', 'explicitRiskConsentDigest', 'safetyAssertionRef', 'safetyAssertionDigest'], ['idempotencyKeyInjection']);
    for (const key of ['explicitRiskConsentRef', 'explicitRiskConsentDigest', 'safetyAssertionRef', 'safetyAssertionDigest']) controlWireRef(data[key]);
    if (Object.hasOwn(data, 'idempotencyKeyInjection')) pointer(controlWireRecord(data.idempotencyKeyInjection, ['jsonPointer']).jsonPointer);
  } else if (kind === 'reconcile') {
    const data = controlWireRecord(value, ['kind', 'adapterRef', 'adapterDigest', 'profileId', 'profileDigest', 'idempotencyKeyInjection',
      'statusRequestTemplateRef', 'statusRequestTemplateDigest', 'completedPredicateRef', 'completedPredicateDigest', 'failedPredicateRef', 'failedPredicateDigest']);
    for (const [key, item] of Object.entries(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(item);
    controlWireText(data.profileId); pointer(controlWireRecord(data.idempotencyKeyInjection, ['jsonPointer']).jsonPointer);
  } else throw new TypeError('unsupported MCP recovery contract');
  return immutableSnapshot(value) as McpRecoveryContractV1;
}
export function decodeMcpRegistryRevision(value: unknown): McpRegistryRevisionV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'registrationId', 'registryRevision', 'ownerPrincipalId', 'transport',
    'initializeDigest', 'capabilityDigest', 'probedToolsListDigest', 'toolsListDigest', 'stateModel', 'tools', 'lifecycle',
    'registrationReceiptRef', 'manifestDigest', 'createdAt']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-registry-v1' || data.stateModel !== 'stateless_per_call')
    throw new TypeError('invalid retained MCP registry kind');
  controlWireText(data.registrationId); controlWireText(data.ownerPrincipalId); controlWireInteger(data.registryRevision, 1);
  decodeMcpResolvedTransport(data.transport); time(data.createdAt);
  for (const key of ['initializeDigest', 'capabilityDigest', 'probedToolsListDigest', 'toolsListDigest', 'registrationReceiptRef']) controlWireRef(data[key]);
  const lifecycle = controlWireRecord(data.lifecycle, ['launchTimeoutMs', 'callTimeoutMs', 'maxLaunchesPerCall']);
  normalizeMcpLifecycle(lifecycle);
  if (!Array.isArray(data.tools) || data.tools.length < 1 || data.tools.length > 128) throw new TypeError('MCP registry has no bounded tool set');
  let prior = '';
  for (const value of data.tools) {
    tool(value, true); const name = (value as McpToolContractV1).name;
    if (prior && Buffer.compare(Buffer.from(prior), Buffer.from(name)) >= 0) throw new TypeError('MCP tools must have unique byte-sorted names');
    prior = name;
  }
  if (canonicalSha256(data.tools) !== data.toolsListDigest) throw new TypeError('MCP final tools list does not rehash');
  const raw = (data.tools as McpToolContractV1[]).map(({ recovery: _recovery, toolContractDigest: _digest, ...tool }) => ({ ...tool, version: 'mcp-tool-interface-v1' }));
  if (canonicalSha256(raw) !== data.probedToolsListDigest) throw new TypeError('MCP interfaces differ from their original discovery set');
  digest(data, 'manifestDigest');
  return immutableSnapshot(data) as McpRegistryRevisionV1;
}
export function mcpRegistrySummary(value: McpRegistryRevisionV1): McpRegistrySummaryV1 {
  const registry = decodeMcpRegistryRevision(value);
  return Object.freeze({ schemaVersion: 1, registrationId: registry.registrationId, registryRevision: registry.registryRevision,
    transport: registry.transport.kind, stateModel: registry.stateModel, toolCount: registry.tools.length,
    toolsListDigest: registry.toolsListDigest, manifestDigest: registry.manifestDigest,
    registrationReceiptRef: registry.registrationReceiptRef, createdAt: registry.createdAt });
}
export function decodeManualInvocationWait(value: unknown): ManualInvocationWaitV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject', 'probeState']);
  const subject = controlWireRecord(data.subject, ['kind', 'recovery', 'opKind', 'opId', 'attempt']);
  const probe = controlWireRecord(data.probeState, ['phase', 'automaticProbeCount', 'userProbeCount']);
  if (data.schemaVersion !== 1 || data.kind !== 'reconciliation' || subject.kind !== 'invocation' || subject.recovery !== 'manual' ||
      !['tool', 'mcp'].includes(subject.opKind as string) || probe.phase !== 'manual_only' || probe.automaticProbeCount !== 0 || probe.userProbeCount !== 0)
    throw new TypeError('manual wait cannot substitute another reconciliation subject or a probe');
  controlWireText(data.runId); controlWireInteger(data.createdFromRevision, 1); time(data.createdAt); controlWireRef(data.frontierRef);
  controlWireText(subject.opId); controlWireInteger(subject.attempt);
  return immutableSnapshot(data) as ManualInvocationWaitV1;
}
export function decodeToolAbandonedItem(value: unknown): ToolAbandonedItem {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'batchItemId', 'callId', 'index',
    'opId', 'attempt', 'abandonedJournalSeq', 'attestationRef', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'tool_abandoned') throw new TypeError('invalid terminal-only abandoned tool item');
  for (const key of ['itemId', 'runId', 'batchItemId', 'callId', 'opId']) controlWireText(data[key]);
  controlWireInteger(data.index); controlWireInteger(data.attempt); controlWireInteger(data.abandonedJournalSeq, 1);
  controlWireRef(data.attestationRef); time(data.createdAt);
  return immutableSnapshot(data) as ToolAbandonedItem;
}
export function decodeManualAbandonAttestation(value: unknown): ManualAbandonAttestationV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'principalId', 'channelIdentityRef', 'channelIdentityDigest',
    'requestId', 'requestDigest', 'runId', 'waitingSubjectRef', 'frontierRef', 'opId', 'attempt', 'unknownJournalSeq', 'operationRequestRef',
    'operationRequestDigest', 'targetRef', 'targetDigest', 'ambiguityEvidenceRef', 'ambiguityEvidenceDigest', 'acknowledgedRisk', 'createdAt', 'attestationDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-manual-abandon-attestation-v1' ||
      data.acknowledgedRisk !== 'effect_may_have_occurred_result_will_not_be_used_and_run_will_stop') throw new TypeError('manual abandonment lacks the exact acknowledged risk');
  for (const key of ['principalId', 'runId', 'opId']) controlWireText(data[key]);
  assertRequestId(controlWireText(data.requestId)); controlWireInteger(data.attempt); controlWireInteger(data.unknownJournalSeq, 1); time(data.createdAt);
  for (const [key, item] of Object.entries(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(item);
  digest(data, 'attestationDigest');
  return immutableSnapshot(data) as ManualAbandonAttestationV1;
}

function identityFields(data: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(data)) {
    if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(value);
    if (key.endsWith('At')) time(value);
  }
}
function orderedNames(value: unknown, read: (value: unknown) => string, minimum = 0): void {
  if (!Array.isArray(value) || value.length < minimum || value.length > 128) throw new TypeError('MCP names exceed their original bound');
  let prior = '';
  for (const item of value) {
    const name = read(item);
    if (prior && Buffer.compare(Buffer.from(prior), Buffer.from(name)) >= 0) throw new TypeError('MCP names must be unique and byte sorted');
    prior = name;
  }
}
function requestedRecovery(value: unknown): void {
  const kind = (value as { kind?: unknown } | null)?.kind;
  if (kind === 'manual') controlWireRecord(value, ['kind']);
  else if (kind === 'retry') {
    const data = controlWireRecord(value, ['kind', 'explicitRiskConsentRef', 'explicitRiskConsentDigest',
      'safetyAssertionRef', 'safetyAssertionDigest'], ['idempotencyKeyJsonPointer']);
    identityFields(data);
    if (Object.hasOwn(data, 'idempotencyKeyJsonPointer')) pointer(data.idempotencyKeyJsonPointer);
  } else if (kind === 'reconcile') {
    const data = controlWireRecord(value, ['kind', 'bundledAdapterId', 'idempotencyKeyJsonPointer']);
    controlWireText(data.bundledAdapterId); pointer(data.idempotencyKeyJsonPointer);
  } else throw new TypeError('invalid retained MCP recovery intent');
}
export function decodeAdminProbePayloadCore(value: unknown): AdminProbePayloadCoreV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'probeKind', 'runtimeBundleRef', 'runtimeBundleManifestDigest',
    'adapterExecutableId', 'adapterVersion', 'adapterExecutableDigest', 'protocolRecipe', 'maximumResponseBytes', 'payloadCoreDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-admin-probe-payload-core-v1' ||
      !['mcp_stdio', 'mcp_streamable_http'].includes(data.probeKind as string) ||
      data.protocolRecipe !== 'mcp-initialize-capabilities-tools-list-v1') throw new TypeError('invalid fixed MCP admin recipe');
  controlWireText(data.adapterExecutableId); controlWireText(data.adapterVersion);
  controlWireInteger(data.maximumResponseBytes, 65_536, MCP_RESPONSE_BYTES); identityFields(data); digest(data, 'payloadCoreDigest');
  return immutableSnapshot(data) as AdminProbePayloadCoreV1;
}
export function decodeMcpAdminProbeTarget(value: unknown): McpAdminProbeTargetV1 {
  bounded(value);
  const method = (value as { method?: unknown } | null)?.method;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'ownerPrincipalId', 'registrationId', 'method',
    'resolvedTransport', 'assertStatelessPerCall', 'requestedToolRecovery', 'lifecycle', 'requestCoreDigest', 'targetDigest', 'createdAt',
    'originalRequestRef', 'channelIdentityRef', 'channelIdentityDigest',
    ...(method === 'mcp.refresh' ? ['expectedRegistryRevision', 'sourceRegistryRevisionRef'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-admin-probe-target-v1' ||
      !['mcp.register', 'mcp.refresh'].includes(method as string) || data.assertStatelessPerCall !== true)
    throw new TypeError('invalid retained MCP admin target');
  controlWireText(data.ownerPrincipalId); controlWireText(data.registrationId); identityFields(data);
  if (method === 'mcp.refresh') controlWireInteger(data.expectedRegistryRevision, 1);
  decodeMcpResolvedTransport(data.resolvedTransport);
  normalizeMcpLifecycle(controlWireRecord(data.lifecycle, ['launchTimeoutMs', 'callTimeoutMs', 'maxLaunchesPerCall']));
  orderedNames(data.requestedToolRecovery, value => {
    const row = controlWireRecord(value, ['toolName', 'recovery']); requestedRecovery(row.recovery); return controlWireText(row.toolName);
  });
  digest(data, 'targetDigest');
  return immutableSnapshot(data) as McpAdminProbeTargetV1;
}
function dispatchState(value: unknown): AdminProbeDispatchStateV1 {
  const state = (value as { state?: unknown } | null)?.state;
  const data = controlWireRecord(value, ['state', ...(state === 'blocked' ? [] : ['probeRequestDigest', 'dispatchId', 'claimedAt']),
    ...(state === 'released' ? ['releasedAt'] : [])]);
  if (!['blocked', 'claimed', 'released'].includes(state as string)) throw new TypeError('invalid MCP admin dispatch phase');
  if (state !== 'blocked') { identityFields(data); controlWireText(data.dispatchId); }
  if (state === 'released' && (data.releasedAt as string) < (data.claimedAt as string)) throw new TypeError('MCP admin release predates its claim');
  return data as AdminProbeDispatchStateV1;
}
export function decodeAdminOperation(value: unknown): AdminOperationV1 {
  bounded(value);
  const phase = (value as { phase?: unknown } | null)?.phase;
  const disposition = (value as { failureDisposition?: unknown } | null)?.failureDisposition;
  const data = controlWireRecord(value, ['schemaVersion', 'adminOperationId', 'principalId', 'method', 'requestId', 'requestDigest',
    'attempt', 'maxAttempts', 'deadlineAt', 'targetRef', 'targetDigest', 'probePayloadCoreRef', 'probePayloadCoreDigest',
    'supervisorInstanceId', 'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest',
    'rowVersion', 'createdAt', 'phase',
    ...(phase === 'active' ? ['processContainmentRef', 'leaseExpiresAt', 'probeDispatch'] : []),
    ...(phase === 'completed' ? ['processContainmentRef', 'probeDispatch', 'resultRef', 'resultDigest', 'evidenceRef', 'evidenceDigest',
      'controlResponseRef', 'controlResponseDigest', 'finishedAt'] : []),
    ...(phase === 'failed' ? ['failureDisposition', 'evidenceRef', 'evidenceDigest', 'errorRef', 'errorDigest', 'finishedAt',
      ...(disposition === 'retryable_recovery' ? ['retryNotBeforeAt'] : ['controlResponseRef', 'controlResponseDigest'])] : [])],
  phase === 'failed' ? ['processContainmentRef', 'probeDispatch'] : []);
  if (data.schemaVersion !== 1 || data.maxAttempts !== 3 || !['prepared', 'active', 'completed', 'failed'].includes(phase as string) ||
      !['mcp.register', 'mcp.refresh'].includes(data.method as string)) throw new TypeError('invalid original MCP admin operation');
  for (const key of ['adminOperationId', 'principalId', 'supervisorInstanceId']) controlWireText(data[key]);
  assertRequestId(controlWireText(data.requestId)); controlWireInteger(data.attempt, 1, 3); controlWireInteger(data.rowVersion, 1); identityFields(data);
  if ((data.deadlineAt as string) <= (data.createdAt as string)) throw new TypeError('MCP admin deadline is not after creation');
  if (Object.hasOwn(data, 'probeDispatch')) {
    const dispatch = dispatchState(data.probeDispatch);
    if (dispatch.state !== 'blocked' && (dispatch.claimedAt < (data.createdAt as string) || dispatch.claimedAt >= (data.deadlineAt as string)))
      throw new TypeError('MCP admin claim is outside its original deadline');
    if (dispatch.state === 'released' && dispatch.releasedAt >= (data.deadlineAt as string)) throw new TypeError('MCP admin release is expired');
    if (phase === 'completed' && dispatch.state !== 'released') throw new TypeError('completed MCP admin never released its original claim');
  }
  if (phase === 'active' && ((data.leaseExpiresAt as string) <= (data.createdAt as string) || (data.leaseExpiresAt as string) > (data.deadlineAt as string)))
    throw new TypeError('MCP admin lease exceeds its immutable deadline');
  if (phase === 'failed') {
    if (!['retryable_recovery', 'retry_exhausted', 'final_rejection'].includes(disposition as string)) throw new TypeError('invalid closed MCP admin failure');
    if (Object.hasOwn(data, 'processContainmentRef') !== Object.hasOwn(data, 'probeDispatch')) throw new TypeError('MCP admin containment and last dispatch must be retained together');
    if ((disposition === 'retryable_recovery' && data.attempt === 3) || (disposition === 'retry_exhausted' && data.attempt !== 3))
      throw new TypeError('MCP admin retry disposition changed its original maximum');
    if (disposition === 'retryable_recovery' && Date.parse(data.retryNotBeforeAt as string) !== Date.parse(data.finishedAt as string) + (data.attempt === 1 ? 1000 : 5000))
      throw new TypeError('MCP admin recovery backoff differs from its original attempt');
  }
  if (Object.hasOwn(data, 'finishedAt') && (data.finishedAt as string) < (data.createdAt as string)) throw new TypeError('MCP admin finished before creation');
  return immutableSnapshot(data) as AdminOperationV1;
}
export function decodeMcpAdminProbeResult(value: unknown): McpAdminProbeResultV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'adminOperationId', 'attempt', 'dispatchId', 'probeRequestDigest',
    'targetRef', 'targetDigest', 'probePayloadCoreRef', 'probePayloadCoreDigest', 'processContainmentRef', 'initializeResponseRef',
    'initializeResponseDigest', 'capabilityResponseRef', 'capabilityResponseDigest', 'toolsListResponseRef', 'toolsListResponseDigest',
    'initializeDigest', 'capabilityDigest', 'normalizedTools', 'probedToolsListDigest', 'completedAt', 'resultDigest'],
    ['initializeCaptureRef', 'toolsListCaptureRef']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-admin-probe-result-v1') throw new TypeError('invalid MCP probe result');
  controlWireText(data.adminOperationId); controlWireText(data.dispatchId); controlWireInteger(data.attempt, 1, 3); identityFields(data);
  orderedNames(data.normalizedTools, value => { tool(value, false); return (value as McpProbedToolInterfaceV1).name; }, 1);
  if (canonicalSha256(data.normalizedTools) !== data.probedToolsListDigest) throw new TypeError('MCP probe interfaces do not rehash');
  digest(data, 'resultDigest');
  return immutableSnapshot(data) as McpAdminProbeResultV1;
}
export function decodeMcpHttpCapture(value: unknown): McpHttpCaptureV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'phase', 'expectedId', 'mediaType', 'termination',
    'rawResponseRef', 'rawFinitePrefixBytes', 'rawFinitePrefixDigest', 'receivedTailBytes', 'captureDigest'], ['responseEventEndOffset']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-http-capture-v1' ||
      !['initialize', 'tools_list', 'tools_call'].includes(data.phase as string) ||
      !['application/json', 'text/event-stream'].includes(data.mediaType as string) ||
      !['http_eof', 'sse_response_event'].includes(data.termination as string)) throw new TypeError('invalid MCP finite capture');
  if (typeof data.expectedId === 'string') controlWireText(data.expectedId, MCP_RESPONSE_BYTES, 0);
  else controlWireInteger(data.expectedId, Number.MIN_SAFE_INTEGER);
  const bytes = controlWireInteger(data.rawFinitePrefixBytes, 1, MCP_RESPONSE_BYTES);
  controlWireInteger(data.receivedTailBytes, 0, bytes); controlWireRef(data.rawResponseRef); controlWireRef(data.rawFinitePrefixDigest);
  if (data.rawResponseRef !== data.rawFinitePrefixDigest) throw new TypeError('MCP capture does not retain its exact raw bytes');
  if (data.mediaType === 'application/json') {
    if (data.termination !== 'http_eof' || data.receivedTailBytes !== 0 || Object.hasOwn(data, 'responseEventEndOffset'))
      throw new TypeError('JSON MCP capture requires original complete body EOF');
  } else if (!Object.hasOwn(data, 'responseEventEndOffset') ||
      controlWireInteger(data.responseEventEndOffset, 1, bytes) + (data.receivedTailBytes as number) !== bytes)
    throw new TypeError('SSE MCP capture lost its finite event/tail distinction');
  digest(data, 'captureDigest');
  return immutableSnapshot(data) as McpHttpCaptureV1;
}
/** Audit of a real received safe matching event whose complete finite prefix
 * was refused by the original native NoEcho guard. The unsafe prefix is not
 * an artifact and this data never claims it can be independently re-read. */
export type McpKnownUnusableResponseV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-known-unusable-response-v1'; phase: 'tools_call'; expectedId: 3;
  safeMessageRef: string; safeMessageDigest: string; safeMessageBytes: number;
  mediaType: 'text/event-stream'; termination: 'sse_response_event'; rawFinitePrefixBytes: number;
  rawFinitePrefixDigest: string; responseEventEndOffset: number; receivedTailBytes: number;
  reason: 'full_capture_no_echo_refused'; auditDigest: string;
}>;
export function decodeMcpKnownUnusableResponse(value: unknown): McpKnownUnusableResponseV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'phase', 'expectedId', 'safeMessageRef',
    'safeMessageDigest', 'safeMessageBytes', 'mediaType', 'termination', 'rawFinitePrefixBytes',
    'rawFinitePrefixDigest', 'responseEventEndOffset', 'receivedTailBytes', 'reason', 'auditDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-known-unusable-response-v1' || data.phase !== 'tools_call' ||
      data.expectedId !== 3 || data.mediaType !== 'text/event-stream' || data.termination !== 'sse_response_event' ||
      data.reason !== 'full_capture_no_echo_refused') throw new TypeError('invalid MCP known-unusable response audit');
  controlWireRef(data.safeMessageRef); controlWireRef(data.safeMessageDigest); controlWireRef(data.rawFinitePrefixDigest);
  if (data.safeMessageRef !== data.safeMessageDigest) throw new TypeError('MCP safe known event bytes differ from their original digest');
  controlWireInteger(data.safeMessageBytes, 1, MCP_RESPONSE_BYTES);
  const bytes = controlWireInteger(data.rawFinitePrefixBytes, 1, MCP_RESPONSE_BYTES);
  if (controlWireInteger(data.responseEventEndOffset, 1, bytes) + controlWireInteger(data.receivedTailBytes, 0, bytes) !== bytes)
    throw new TypeError('MCP known-unusable audit lost the complete original prefix/event/tail distinction');
  digest(data, 'auditDigest');
  return immutableSnapshot(data) as McpKnownUnusableResponseV1;
}
export function decodeAdminProbeClosureEvidence(value: unknown): AdminProbeClosureEvidenceV1 {
  bounded(value);
  const kind = (value as { closureKind?: unknown } | null)?.closureKind;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'adminOperationId', 'attempt', 'targetRef', 'targetDigest',
    'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'inspectorIdentityRef',
    'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'closureKind',
    ...(kind === 'no_spawn' ? ['noSpawnEvidenceRef', 'noSpawnEvidenceDigest'] : ['processContainmentRef', 'deathEvidenceRef', 'deathEvidenceDigest'])],
  ['nativeLifecycleRef', 'nativeLifecycleDigest', 'nativeLifecycleProjectionRef', 'nativeLifecycleProjectionDigest', 'nativeCleanupRef', 'nativeCleanupDigest',
    ...(kind === 'containment_dead' ? ['dispatchId', 'probeRequestDigest'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-admin-probe-closure-evidence-v1' || !['no_spawn', 'containment_dead'].includes(kind as string))
    throw new TypeError('invalid MCP admin resource closure');
  controlWireText(data.adminOperationId); controlWireInteger(data.attempt, 1, 3); identityFields(data);
  if (Object.hasOwn(data, 'dispatchId') !== Object.hasOwn(data, 'probeRequestDigest')) throw new TypeError('MCP closure lost its original dispatch pair');
  for (const [reference, hash] of [['nativeLifecycleRef', 'nativeLifecycleDigest'], ['nativeLifecycleProjectionRef', 'nativeLifecycleProjectionDigest'],
    ['nativeCleanupRef', 'nativeCleanupDigest']]) {
    if (Object.hasOwn(data, reference!) !== Object.hasOwn(data, hash!) || Object.hasOwn(data, reference!) && data[reference!] !== data[hash!])
      throw new TypeError('MCP native lifecycle/cleanup audit lost its exact complete artifact pair');
  }
  if (Object.hasOwn(data, 'nativeLifecycleRef') !== Object.hasOwn(data, 'nativeLifecycleProjectionRef') ||
      Object.hasOwn(data, 'nativeCleanupRef') && !Object.hasOwn(data, 'nativeLifecycleRef'))
    throw new TypeError('MCP native cleanup audit requires the complete original raw lifecycle and canonical projection');
  if (Object.hasOwn(data, 'dispatchId')) controlWireText(data.dispatchId);
  digest(data, 'evidenceDigest');
  return immutableSnapshot(data) as AdminProbeClosureEvidenceV1;
}
export function decodeAdminProbeError(value: unknown): AdminProbeErrorV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'adminOperationId', 'attempt', 'targetRef', 'targetDigest',
    'closureEvidenceRef', 'closureEvidenceDigest', 'diagnosticRef', 'diagnosticDigest', 'createdAt', 'errorDigest', 'code', 'deterministicRejection']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-admin-probe-error-v1' ||
      !['target_rejected', 'schema_invalid', 'capability_mismatch', 'preactivation_no_spawn', 'transport_failed_no_effect', 'timeout_after_containment_death'].includes(data.code as string) ||
      data.deterministicRejection !== ['target_rejected', 'schema_invalid', 'capability_mismatch'].includes(data.code as string))
    throw new TypeError('MCP error cannot replace a deterministic rejection or physical closure');
  controlWireText(data.adminOperationId); controlWireInteger(data.attempt, 1, 3); identityFields(data); digest(data, 'errorDigest');
  return immutableSnapshot(data) as AdminProbeErrorV1;
}
export function decodeMcpRegistrationReceipt(value: unknown): McpRegistrationReceiptV1 {
  bounded(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'registrationId', 'registryRevision', 'ownerPrincipalId', 'requestDigest',
    'adminOperationId', 'adminAttempt', 'dispatchId', 'probeRequestDigest', 'adminProbeTargetRef', 'adminProbeTargetDigest', 'probeResultRef',
    'probeResultDigest', 'probeClosureEvidenceRef', 'probeClosureEvidenceDigest', 'initializeDigest', 'capabilityDigest', 'probedToolsListDigest',
    'toolsListDigest', 'registryCoreDigest', 'createdAt', 'receiptDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-registration-receipt-v1') throw new TypeError('invalid retained MCP registration receipt');
  for (const key of ['registrationId', 'ownerPrincipalId', 'adminOperationId', 'dispatchId']) controlWireText(data[key]);
  controlWireInteger(data.registryRevision, 1); controlWireInteger(data.adminAttempt, 1, 3); identityFields(data); digest(data, 'receiptDigest');
  return immutableSnapshot(data) as McpRegistrationReceiptV1;
}
