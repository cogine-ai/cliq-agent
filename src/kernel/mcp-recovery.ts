// Closed recovery data. A profile projection, predicate result or decoded
// request is never a release token, native fence or proof of an external effect.
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertBoundedJsonValue } from './json.js';
import { decodeMcpResolvedTransport, MCP_RESPONSE_BYTES, type McpRecoveryRequestV1, type McpResolvedTransportV1 } from './mcp.js';
import { immutableSnapshot } from '../model/immutable.js';

export type McpRetryRiskConsentV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-retry-risk-consent-v1'; ownerPrincipalId: string;
  registrationId: string; serverToolName: string; recoveryRequestDigest: string;
  acknowledgedRisk: 'prior_attempt_may_have_succeeded_and_retry_may_duplicate_effect';
  channelIdentityRef: string; channelIdentityDigest: string; createdAt: string; consentDigest: string;
}>;
export type McpRetrySafetyAssertionV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-retry-safety-assertion-v1'; ownerPrincipalId: string;
  registrationId: string; serverToolName: string; recoveryRequestDigest: string;
  assertion: 'no_server_safety_claim_duplicate_effect_remains_possible';
  idempotencyKeyJsonPointer?: string; assertionDigest: string;
}>;
export type McpRecoveryProfileV1 = Readonly<{
  profileId: string; profileSigningIdentityDigest: string; serverToolName: string;
  initializeDigest: string; capabilityDigest: string; probedToolsListDigest: string; effectToolInterfaceDigest: string;
  statusOperationName: string; statusOperationSemantics: 'signed_read_only_status_query';
  statusToolInterfaceDigest: string; statusInputSchemaDigest: string; statusOutputSchemaDigest: string;
  staticArgumentsRef: string; staticArgumentsDigest: string;
  completedPredicateRef: string; completedPredicateDigest: string;
  failedPredicateRef: string; failedPredicateDigest: string; profileDigest: string;
}>;
export type McpRecoveryAdapterManifestV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-recovery-adapter-v1'; adapterId: string; entryId: string;
  version: string; executableDigest: string; protocol: 'cliq-mcp-reconcile-v1';
  profiles: readonly McpRecoveryProfileV1[]; adapterDigest: string; publisherKeyId: string; signature: string;
}>;
export type McpRecoveryStatusRequestTemplateV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-recovery-status-template-v1'; adapterRef: string; adapterDigest: string;
  profileId: string; profileDigest: string; registrationId: string; registryRevision: number;
  adminProbeTargetRef: string; adminProbeTargetDigest: string; probeResultRef: string; probeResultDigest: string;
  serverToolName: string; serverExecutionIdentityDigest: string; profileSigningIdentityDigest: string;
  initializeDigest: string; capabilityDigest: string; probedToolsListDigest: string; effectToolInterfaceDigest: string;
  statusOperationName: string; statusOperationSemantics: 'signed_read_only_status_query';
  statusToolInterfaceDigest: string; statusInputSchemaDigest: string; statusOutputSchemaDigest: string;
  idempotencyKeyJsonPointer: string; staticArgumentsRef: string; staticArgumentsDigest: string; templateDigest: string;
}>;
export type McpRecoveryPredicateExpressionV1 = Readonly<{ op: 'exists'; jsonPointer: string }> |
  Readonly<{ op: 'equals'; jsonPointer: string; value: null | boolean | string | number }> |
  Readonly<{ op: 'and' | 'or'; operands: readonly McpRecoveryPredicateExpressionV1[] }>;
export type McpRecoveryPredicateV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-recovery-predicate-v1'; expression: McpRecoveryPredicateExpressionV1; predicateDigest: string;
}>;
function json(value: unknown): void {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP recovery data');
  if (canonicalJsonBytes(value).byteLength > MCP_RESPONSE_BYTES) throw new TypeError('MCP recovery data exceeds its byte limit');
}
function digest(data: Record<string, unknown>, member: string): void {
  if (controlWireRef(data[member]) !== digestOmitting(data, member)) throw new TypeError('MCP recovery semantic digest differs');
}
function header(data: Record<string, unknown>, format: string): void {
  if (data.schemaVersion !== 1 || data.format !== format) throw new TypeError('foreign MCP recovery data');
}
function refs(data: Record<string, unknown>, names: readonly string[]): void { for (const name of names) controlWireRef(data[name]); }
function identity(data: Record<string, unknown>): void {
  for (const name of ['ownerPrincipalId', 'registrationId', 'serverToolName']) controlWireText(data[name]);
  controlWireRef(data.recoveryRequestDigest);
}
/** RFC-6901 text, including the empty root pointer. No URI fragments or
 * percent-decoding: the exact original bytes are the policy identity. */
export function decodeMcpJsonPointer(value: unknown): string {
  const text = controlWireText(value, MCP_RESPONSE_BYTES, 0);
  if (text && (!text.startsWith('/') || /~(?:[^01]|$)/u.test(text))) throw new TypeError('invalid MCP recovery JSON pointer');
  return text;
}
export function decodeMcpRetryRiskConsent(value: unknown): McpRetryRiskConsentV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'ownerPrincipalId', 'registrationId', 'serverToolName',
    'recoveryRequestDigest', 'acknowledgedRisk', 'channelIdentityRef', 'channelIdentityDigest', 'createdAt', 'consentDigest']);
  header(data, 'cliq-mcp-retry-risk-consent-v1'); identity(data);
  if (data.acknowledgedRisk !== 'prior_attempt_may_have_succeeded_and_retry_may_duplicate_effect')
    throw new TypeError('MCP retry consent loses its duplicate-effect risk');
  refs(data, ['channelIdentityRef', 'channelIdentityDigest']); parseCanonicalTime(controlWireText(data.createdAt)); digest(data, 'consentDigest');
  return immutableSnapshot(data) as McpRetryRiskConsentV1;
}
export function decodeMcpRetrySafetyAssertion(value: unknown): McpRetrySafetyAssertionV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'ownerPrincipalId', 'registrationId', 'serverToolName',
    'recoveryRequestDigest', 'assertion', 'assertionDigest'], ['idempotencyKeyJsonPointer']);
  header(data, 'cliq-mcp-retry-safety-assertion-v1'); identity(data);
  if (data.assertion !== 'no_server_safety_claim_duplicate_effect_remains_possible')
    throw new TypeError('MCP retry assertion invents a server safety guarantee');
  if (Object.hasOwn(data, 'idempotencyKeyJsonPointer')) decodeMcpJsonPointer(data.idempotencyKeyJsonPointer);
  digest(data, 'assertionDigest'); return immutableSnapshot(data) as McpRetrySafetyAssertionV1;
}
export function mcpRetryRequestFromAssertion(value: McpRetrySafetyAssertionV1): Extract<McpRecoveryRequestV1, {kind: 'retry'}> {
  const assertion = decodeMcpRetrySafetyAssertion(value);
  const request = { kind: 'retry' as const, acknowledgeDuplicateEffectRisk: true as const,
    ...(assertion.idempotencyKeyJsonPointer === undefined ? {} : { idempotencyKeyJsonPointer: assertion.idempotencyKeyJsonPointer }) };
  if (canonicalSha256(request) !== assertion.recoveryRequestDigest) throw new TypeError('MCP retry assertion substitutes its original normalized request');
  return immutableSnapshot(request);
}
const PROFILE_FIELDS = ['profileId', 'profileSigningIdentityDigest', 'serverToolName', 'initializeDigest', 'capabilityDigest',
  'probedToolsListDigest', 'effectToolInterfaceDigest', 'statusOperationName', 'statusOperationSemantics', 'statusToolInterfaceDigest',
  'statusInputSchemaDigest', 'statusOutputSchemaDigest', 'staticArgumentsRef', 'staticArgumentsDigest', 'completedPredicateRef',
  'completedPredicateDigest', 'failedPredicateRef', 'failedPredicateDigest', 'profileDigest'] as const;
export function decodeMcpRecoveryProfile(value: unknown): McpRecoveryProfileV1 {
  json(value); const data = controlWireRecord(value, PROFILE_FIELDS);
  for (const name of ['profileId', 'serverToolName', 'statusOperationName']) controlWireText(data[name]);
  for (const name of PROFILE_FIELDS) if (name.endsWith('Digest') || name.endsWith('Ref')) controlWireRef(data[name]);
  if (data.statusOperationSemantics !== 'signed_read_only_status_query' || data.statusOperationName === data.serverToolName ||
      data.completedPredicateRef === data.failedPredicateRef || data.completedPredicateDigest === data.failedPredicateDigest ||
      data.staticArgumentsRef !== data.staticArgumentsDigest)
    throw new TypeError('MCP recovery profile has no distinct read-only status/predicates or complete static bytes');
  digest(data, 'profileDigest'); return immutableSnapshot(data) as McpRecoveryProfileV1;
}
export function decodeMcpRecoveryAdapterManifest(value: unknown): McpRecoveryAdapterManifestV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'adapterId', 'entryId', 'version', 'executableDigest', 'protocol',
    'profiles', 'adapterDigest', 'publisherKeyId', 'signature']);
  header(data, 'cliq-mcp-recovery-adapter-v1');
  for (const name of ['adapterId', 'entryId', 'version', 'publisherKeyId']) controlWireText(data[name]);
  refs(data, ['executableDigest', 'adapterDigest']);
  if (data.protocol !== 'cliq-mcp-reconcile-v1' || typeof data.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/u.test(data.signature) ||
      !Array.isArray(data.profiles) || !data.profiles.length || data.profiles.length > 128)
    throw new TypeError('MCP recovery adapter has no closed protocol, signature or bounded profiles');
  let previous = ''; const tuples = new Set<string>();
  for (const value of data.profiles) {
    const profile = decodeMcpRecoveryProfile(value);
    const tuple = canonicalSha256([profile.profileSigningIdentityDigest, profile.serverToolName, profile.effectToolInterfaceDigest]);
    if (previous && Buffer.compare(Buffer.from(previous), Buffer.from(profile.profileId)) >= 0 || tuples.has(tuple))
      throw new TypeError('MCP recovery profiles are not uniquely byte-sorted or repeat an execution/tool/interface tuple');
    previous = profile.profileId; tuples.add(tuple);
  }
  const { signature: _signature, adapterDigest: _digest, ...core } = data;
  if (canonicalSha256(core) !== data.adapterDigest) throw new TypeError('MCP adapter signed identity differs');
  return immutableSnapshot(data) as McpRecoveryAdapterManifestV1;
}
export function decodeMcpRecoveryStatusRequestTemplate(value: unknown): McpRecoveryStatusRequestTemplateV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'adapterRef', 'adapterDigest', 'profileId', 'profileDigest',
    'registrationId', 'registryRevision', 'adminProbeTargetRef', 'adminProbeTargetDigest', 'probeResultRef', 'probeResultDigest',
    'serverToolName', 'serverExecutionIdentityDigest', 'profileSigningIdentityDigest', 'initializeDigest', 'capabilityDigest',
    'probedToolsListDigest', 'effectToolInterfaceDigest', 'statusOperationName', 'statusOperationSemantics', 'statusToolInterfaceDigest',
    'statusInputSchemaDigest', 'statusOutputSchemaDigest', 'idempotencyKeyJsonPointer', 'staticArgumentsRef', 'staticArgumentsDigest', 'templateDigest']);
  header(data, 'cliq-mcp-recovery-status-template-v1');
  for (const name of ['profileId', 'registrationId', 'serverToolName', 'statusOperationName']) controlWireText(data[name]);
  controlWireInteger(data.registryRevision, 1); decodeMcpJsonPointer(data.idempotencyKeyJsonPointer);
  for (const [name, value] of Object.entries(data)) if (name.endsWith('Ref') || name.endsWith('Digest')) controlWireRef(value);
  if (data.statusOperationSemantics !== 'signed_read_only_status_query' || data.statusOperationName === data.serverToolName ||
      data.staticArgumentsRef !== data.staticArgumentsDigest) throw new TypeError('MCP status template changes read-only status or static bytes');
  digest(data, 'templateDigest'); return immutableSnapshot(data) as McpRecoveryStatusRequestTemplateV1;
}
/** Full execution identity remains bound to the original outer signed Bundle. */
export function mcpServerExecutionIdentityDigest(value: McpResolvedTransportV1): string {
  const transport = decodeMcpResolvedTransport(value);
  if (transport.kind !== 'stdio') throw new TypeError('MCP HTTP has no signed stdio recovery identity');
  return canonicalSha256({ executable: transport.executable, argv: transport.argv });
}
/** Signing identity omits only the outer selector to avoid Bundle -> profile ->
 * Bundle recursion. It does not authorize execution or cross-Bundle adoption. */
export function mcpProfileSigningIdentityDigest(value: McpResolvedTransportV1): string {
  const transport = decodeMcpResolvedTransport(value);
  if (transport.kind !== 'stdio' || transport.executable.kind !== 'runtime_bundle')
    throw new TypeError('MCP recovery profile requires an exact runtime-bundle server');
  const { runtimeBundleRef: _selector, ...executable } = transport.executable;
  return canonicalSha256({ executable: { ...executable, role: 'mcp_server' }, argv: transport.argv });
}
export function decodeMcpRecoveryPredicate(value: unknown): McpRecoveryPredicateV1 {
  json(value); const data = controlWireRecord(value, ['schemaVersion', 'format', 'expression', 'predicateDigest']);
  header(data, 'cliq-mcp-recovery-predicate-v1'); let nodes = 0;
  const expression = (value: unknown, depth: number): void => {
    if (++nodes > 64 || depth > 8) throw new TypeError('MCP predicate exceeds its fixed node/depth bounds');
    const op = (value as {op?: unknown} | null)?.op;
    if (op === 'exists' || op === 'equals') {
      const item = controlWireRecord(value, ['op', 'jsonPointer', ...(op === 'equals' ? ['value'] : [])]);
      decodeMcpJsonPointer(item.jsonPointer);
      if (op === 'equals' && !(item.value === null || typeof item.value === 'boolean' || typeof item.value === 'string' ||
          typeof item.value === 'number' && Number.isSafeInteger(item.value))) throw new TypeError('MCP predicate equality requires a closed scalar');
    } else if (op === 'and' || op === 'or') {
      const item = controlWireRecord(value, ['op', 'operands']);
      if (!Array.isArray(item.operands) || !item.operands.length || item.operands.length > 64) throw new TypeError('MCP predicate conjunction is empty or unbounded');
      item.operands.forEach(child => expression(child, depth + 1));
    } else throw new TypeError('MCP predicate operator is unsupported');
  };
  expression(data.expression, 1); digest(data, 'predicateDigest'); return immutableSnapshot(data) as McpRecoveryPredicateV1;
}
function tokens(pointer: string): string[] { return pointer ? pointer.slice(1).split('/').map(value => value.replace(/~1/gu, '/').replace(/~0/gu, '~')) : []; }
function member(container: unknown, key: string): {found: boolean; value?: unknown} {
  if (container === null || typeof container !== 'object') return { found: false };
  if (Array.isArray(container) && (!/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= container.length)) return { found: false };
  return Object.hasOwn(container, key) ? { found: true, value: (container as Record<string, unknown>)[key] } : { found: false };
}
function lookup(value: unknown, pointer: string): {found: boolean; value?: unknown} {
  let current = value;
  for (const key of tokens(pointer)) { const next = member(current, key); if (!next.found) return next; current = next.value; }
  return { found: true, value: current };
}
export function evaluateMcpRecoveryPredicates(input: Readonly<{ completed: unknown; failed: unknown; response: unknown; schemaValid: boolean }>): 'completed' | 'failed' | 'unresolved' {
  const completed = decodeMcpRecoveryPredicate(input.completed), failed = decodeMcpRecoveryPredicate(input.failed);
  json(input.response);
  if (completed.predicateDigest === failed.predicateDigest) throw new TypeError('MCP recovery predicates must be distinct');
  if (input.schemaValid !== true) return 'unresolved';
  const evaluate = (expression: McpRecoveryPredicateExpressionV1): boolean => {
    if (expression.op === 'and') return expression.operands.every(evaluate);
    if (expression.op === 'or') return expression.operands.some(evaluate);
    // TypeScript's overlapping compound discriminator needs the explicit
    // scalar branch before accessing pointer/value.
    if (expression.op !== 'exists' && expression.op !== 'equals') throw new TypeError('foreign MCP predicate');
    const result = lookup(input.response, expression.jsonPointer);
    return result.found && (expression.op === 'exists' || result.value === expression.value);
  };
  const yes = evaluate(completed.expression), no = evaluate(failed.expression);
  return yes === no ? 'unresolved' : yes ? 'completed' : 'failed';
}
/** Replaces one leaf in a copy of the original arguments. Parent containers
 * must already exist; arrays cannot append and the arguments root stays an
 * object. The consumer must validate the resulting exact wire arguments with
 * the frozen input schema before requesting a native release. */
export function injectMcpIdempotencyKey(value: unknown, pointer: string | undefined, key: string): Readonly<Record<string, unknown>> {
  json(value); controlWireText(key, 43, 43);
  // The original call id is H(...), a canonical 32-byte base64url identity.
  // Artifact refs are hex SHA-256 and must not be substituted for that id.
  if (!/^[A-Za-z0-9_-]{43}$/u.test(key) || Buffer.from(key, 'base64url').byteLength !== 32 ||
      Buffer.from(key, 'base64url').toString('base64url') !== key) throw new TypeError('MCP stable key is not its canonical call identity');
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('MCP arguments must be an object');
  if (pointer === undefined) return immutableSnapshot(value as Record<string, unknown>);
  const path = tokens(decodeMcpJsonPointer(pointer));
  if (!path.length) throw new TypeError('MCP idempotency injection cannot replace the arguments object');
  const result = structuredClone(value as Record<string, unknown>); let parent: unknown = result;
  for (const token of path.slice(0, -1)) {
    const next = member(parent, token); if (!next.found) throw new TypeError('MCP idempotency parent does not exist'); parent = next.value;
  }
  const leaf = path[path.length - 1];
  if (leaf === undefined || parent === null || typeof parent !== 'object' || Array.isArray(parent) && !member(parent, leaf).found)
    throw new TypeError('MCP idempotency target is not an existing container/array element');
  Object.defineProperty(parent, leaf, { value: key, writable: true, enumerable: true, configurable: true });
  json(result); return immutableSnapshot(result);
}
