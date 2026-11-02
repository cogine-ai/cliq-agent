// Installed MCP selection. A registered revision supplies discovery provenance;
// neither it nor this inert selection is permission to execute a tool.
import type { RunAssemblyV1 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { MCP_HTTP_BROKER_ENTRY_ID, MCP_HTTP_BROKER_RELATIVE_PATH,
  MCP_ADMIN_HELPER_ENTRY_ID, MCP_ADMIN_HELPER_RELATIVE_PATH } from './mcp-broker-native.js';
import { readMcpRegistry, readMcpRegistryClosure } from './mcp-registration.js';
import type { SqliteDriver } from './sqlite-driver.js';

export type InstalledMcpSelection = Awaited<ReturnType<typeof readMcpRegistry>>;

/** The caller already holds/revalidates the signed installation. This checks
 * its fixed recipe, without loading an image or opening a transport early. */
function assertMcpHttpRecipe(bundle: RuntimeBundleManifest, count: number): void {
  if (!count) return;
  for (const [entryId, relativePath, executable] of [
    [MCP_HTTP_BROKER_ENTRY_ID, MCP_HTTP_BROKER_RELATIVE_PATH, true],
    [MCP_ADMIN_HELPER_ENTRY_ID, MCP_ADMIN_HELPER_RELATIVE_PATH, false],
  ] as const) {
    const entries = bundle.entries.filter(entry => entry.entryId === entryId);
    if (entries.length !== 1 || entries[0]!.role !== 'platform_helper' || entries[0]!.version !== '1' ||
        entries[0]!.relativePath !== relativePath || entries[0]!.executable !== executable)
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime lacks the complete fixed MCP HTTP recipe');
  }
}

export async function readMcpAdmissionSelections(driver: SqliteDriver, artifacts: ArtifactCatalog,
  principalId: string, registrationIds: readonly string[], bundle: RuntimeBundleManifest,
  signal?: AbortSignal): Promise<readonly InstalledMcpSelection[]> {
  signal?.throwIfAborted();
  assertMcpHttpRecipe(bundle, registrationIds.length);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selections = await reads.mapReads(registrationIds,
    registrationId => readMcpRegistry(driver, reads, principalId, registrationId));
  reads.assertReadActive(); signal?.throwIfAborted();
  for (const selection of selections) selection.assertUnchanged(driver);
  return Object.freeze(selections);
}

/** Existing Runs keep their original revision after a registry refresh. Never
 * replace a frozen ref with today's pointer, even when the tool names match. */
export async function readFrozenMcpSelections(driver: SqliteDriver, artifacts: ArtifactCatalog,
  principalId: string, servers: RunAssemblyV1['mcpServers'], bundle: RuntimeBundleManifest,
  signal?: AbortSignal): Promise<readonly InstalledMcpSelection[]> {
  signal?.throwIfAborted();
  assertMcpHttpRecipe(bundle, servers.length);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selections = await reads.mapReads(servers, async server => {
    const selected = await readMcpRegistryClosure(driver, reads, server.registryRevisionRef, principalId);
    if (selected.registry.registrationId !== server.registrationId || selected.registry.registryRevision !== server.registryRevision ||
        selected.registry.manifestDigest !== server.manifestDigest)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP assembly substitutes its original registered revision');
    return selected;
  });
  reads.assertReadActive(); signal?.throwIfAborted();
  for (const selection of selections) selection.assertUnchanged(driver);
  return Object.freeze(selections);
}

export function mcpSelectionCredentialRefs(selections: readonly Pick<InstalledMcpSelection, 'registry'>[]): string[] {
  const references = selections.flatMap(({ registry }) => {
    if (registry.transport.kind !== 'streamable_http' || registry.transport.credentialGrantRefs.length > 1 ||
        registry.tools.some(tool => tool.recovery.kind !== 'manual'))
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP selection requires the implemented manual HTTP profile');
    return [...registry.transport.credentialGrantRefs];
  });
  return [...new Set(references)].sort();
}
