// The existing first prepared Admin transaction is the sole one-use consumer.
// This module retains preparation data; it never spawns or supplies native proof.
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantV1 } from '../kernel/authorization.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeMcpMutationRequest, type McpAdminProbeTargetV1, type McpRegisterRequestV1, type McpResolvedTransportV1 } from '../kernel/mcp.js';
import { immutableSnapshot } from '../model/immutable.js';
import { authorizationGrantCore, decodeAuthorizationConsumptionReceipt, decodeAuthorizationGrant, McpStdioAuthorizationError } from './authorization-artifacts.js';
import { readMcpStdioAuthorizationHistory, type AuthorizationRuntime } from './authorization.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { consumeOrRevokeAuthorization, readAuthorizationCreationControl, readAuthorizationGrant } from './repositories/authorization-grants.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type StdioTransport = Extract<McpResolvedTransportV1, { kind: 'stdio' }>;
declare const preparedMcpStdioBrand: unique symbol;
export type PreparedMcpStdioAuthorization = Readonly<{ readonly [preparedMcpStdioBrand]: true }>;
type Binding = { owner: StateOwnerContext; principalId: string; requestId: string; requestDigest: string; registrationId: string;
  prior: AuthorizationGrantV1; next: AuthorizationGrantV1; receipt: AuthorizationConsumptionReceiptV1;
  metadata: readonly PublishedArtifact[]; transport: StdioTransport };
const preparations = new WeakMap<PreparedMcpStdioAuthorization, Binding>();
const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function refuse(): never { throw new McpStdioAuthorizationError(); }
function held(owner: StateOwnerContext, token: PreparedMcpStdioAuthorization) {
  const binding = token !== null && typeof token === 'object' ? preparations.get(token) : undefined;
  if (!binding || binding.owner !== owner) throw new TypeError('MCP identity preparation belongs to another owner');
  return binding;
}

export async function prepareMcpStdioAuthorization(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, principalId: string, input: McpRegisterRequestV1, signal?: AbortSignal): Promise<PreparedMcpStdioAuthorization> {
  signal?.throwIfAborted();
  const request = decodeMcpMutationRequest(input), active = assertActiveStateOwner(driver, owner);
  if (request.method !== 'mcp.register' || request.target.kind !== 'stdio') throw new TypeError('MCP executable consent requires its original stdio registration');
  const prior = readAuthorizationGrant(driver, request.target.executionIdentityGrantId);
  if (!prior || prior.state !== 'active' || prior.ownerPrincipalId !== principalId || prior.target.kind !== 'execution_identity_read' ||
      prior.target.purpose !== 'mcp_stdio') refuse();
  if (prior.target.identity.kind !== 'runtime_bundle_executable')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP guest executable closure is unsupported before registration consumption');
  if (active.runtimeBundleRef !== canonicalSha256(runtime.bundle) || active.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest ||
      prior.target.identity.runtimeBundleRef !== active.runtimeBundleRef || prior.target.identity.runtimeBundleManifestDigest !== active.runtimeBundleManifestDigest)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP initial registration requires its exact current signed executable bundle');
  const history = await readMcpStdioAuthorizationHistory(driver, artifacts, owner, prior, runtime.releaseKeys, signal);
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const consumedAt = sampleCanonicalNow();
  if (consumedAt < history.committedAt || consumedAt >= prior.expiresAt) refuse();
  const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: prior.grantId, ownerPrincipalId: principalId,
    targetDigest: prior.targetDigest, consumer: { kind: 'mcp_registration', registrationId: request.registrationId, registryRevision: 1 },
    consumedAt, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); decodeAuthorizationConsumptionReceipt(receipt);
  const next: AuthorizationGrantV1 = { ...authorizationGrantCore(prior), grantCoreDigest: prior.grantCoreDigest, rowVersion: 2,
    state: 'consumed', useCount: 1, consumptionReceiptRef: canonicalSha256(receipt), consumedAt, rowDigest: '' };
  next.rowDigest = digestOmitting(next, 'rowDigest'); decodeAuthorizationGrant(next);
  const identity = prior.target.identity;
  const transport: StdioTransport = immutableSnapshot({ kind: 'stdio', executionIdentityGrantId: prior.grantId,
    executionIdentityConsumptionReceiptRef: canonicalSha256(receipt), executionIdentityConsumptionReceiptDigest: receipt.receiptDigest,
    executable: { kind: 'runtime_bundle', runtimeBundleRef: identity.runtimeBundleRef, executableId: identity.executableId,
      executionPath: identity.executionPath, executableDigest: identity.executableDigest }, argv: request.target.argv });
  const metadata = await artifacts.publishCanonicalPair([
    { value: receipt, schemaKind: 'cliq-authorization-consumption-receipt-v1' },
    { value: next, schemaKind: 'cliq-authorization-grant-v1' }
  ]);
  for (const [index, value] of [receipt, next].entries()) if (metadata[index]!.ref !== canonicalSha256(value) ||
      metadata[index]!.byteLength !== canonicalJsonBytes(value).length || metadata[index]!.mediaType !== 'application/json')
    throw new TypeError('MCP executable consent publication differs from its exact original bytes');
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const token = Object.freeze({}) as PreparedMcpStdioAuthorization;
  preparations.set(token, { owner, principalId, requestId: request.requestId, requestDigest: request.requestDigest,
    registrationId: request.registrationId, prior: immutableSnapshot(prior), next: immutableSnapshot(next),
    receipt: immutableSnapshot(receipt), metadata: immutableSnapshot(metadata), transport });
  return token;
}

export function mcpStdioAuthorizationData(owner: StateOwnerContext, token: PreparedMcpStdioAuthorization) {
  const binding = held(owner, token);
  return immutableSnapshot({ transport: binding.transport, metadata: binding.metadata,
    consumedAt: binding.receipt.consumedAt, expiresAt: binding.prior.expiresAt });
}

/** Synchronous friend of the first original prepared Admin INSERT. Its caller
 * registers the published metadata and original intent in this same transaction. */
export function consumeMcpStdioAuthorization(connection: SqliteConnection, owner: StateOwnerContext,
  token: PreparedMcpStdioAuthorization, target: McpAdminProbeTargetV1, requestId: string, requestDigest: string, createdAt: string): void {
  const binding = held(owner, token); assertActiveStateOwner(connection, owner);
  const current = readAuthorizationGrant(connection, binding.prior.grantId);
  if (!current || !same(current, binding.prior) || target.method !== 'mcp.register' || target.ownerPrincipalId !== binding.principalId ||
      target.registrationId !== binding.registrationId || requestId !== binding.requestId || requestDigest !== binding.requestDigest ||
      !same(target.resolvedTransport, binding.transport) || target.createdAt < binding.receipt.consumedAt ||
      createdAt < target.createdAt || createdAt >= binding.prior.expiresAt ||
      binding.receipt.consumedAt < readAuthorizationCreationControl(connection, binding.prior).committedAt) refuse();
  consumeOrRevokeAuthorization(connection, binding.prior, binding.next);
}

/** Transaction rollback cannot turn a retained JS preparation into consent. */
export function assertMcpStdioAuthorizationConsumed(driver: SqliteConnection, owner: StateOwnerContext, token: PreparedMcpStdioAuthorization): void {
  const binding = held(owner, token); assertActiveStateOwner(driver, owner);
  const current = readAuthorizationGrant(driver, binding.next.grantId);
  if (!current || !same(current, binding.next)) refuse();
}
