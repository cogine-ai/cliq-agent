// Retained provenance of the one original first-prepared registration use.
// It is data audit only, never a current server launch or effect permission.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { McpResolvedTransportV1 } from '../kernel/mcp.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readMcpStdioAuthorizationHistory } from './authorization.js';
import { readRetainedControlRoot } from './control-channel.js';
import { KernelStorageError } from './errors.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

export async function readMcpStdioRegistrationConsent(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string,
  registrationId: string, transport: Extract<McpResolvedTransportV1, { kind: 'stdio' }>) {
  const grant = readAuthorizationGrant(driver, transport.executionIdentityGrantId);
  if (!grant || grant.state !== 'consumed' || grant.ownerPrincipalId !== principalId || grant.target.kind !== 'execution_identity_read' ||
      grant.target.purpose !== 'mcp_stdio' || grant.target.identity.kind !== 'runtime_bundle_executable')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio registration lost its exact original consumed identity read');
  const history = await readMcpStdioAuthorizationHistory(driver, artifacts, await readRetainedControlRoot(driver, artifacts), grant, artifacts.releaseTrustRoots());
  const receipt = history.consumption?.receipt;
  if (!receipt || receipt.consumer.kind !== 'mcp_registration' || receipt.consumer.registryRevision !== 1 || receipt.consumer.registrationId !== registrationId ||
      grant.consumptionReceiptRef !== transport.executionIdentityConsumptionReceiptRef || receipt.receiptDigest !== transport.executionIdentityConsumptionReceiptDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio retained receipt crosses its one original registration consumer');
  const identity = grant.target.identity;
  requireEqual(transport.executable, { kind: 'runtime_bundle', runtimeBundleRef: identity.runtimeBundleRef, executableId: identity.executableId,
    executionPath: identity.executionPath, executableDigest: identity.executableDigest }, 'MCP stdio original exact executable identity');
  const digest = canonicalSha256(grant), grantId = grant.grantId;
  function assertUnchanged(connection: SqliteConnection) {
    const current = readAuthorizationGrant(connection, grantId);
    if (!current || canonicalSha256(current) !== digest) throw new KernelStorageError('REVISION_CONFLICT', 'MCP original one-use identity receipt registration changed');
  }
  assertUnchanged(driver); return { grant, receipt, history, assertUnchanged };
}
