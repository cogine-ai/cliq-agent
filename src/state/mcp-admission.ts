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
import { canonicalSha256 } from '../kernel/canonical.js';
import { MCP_STDIO_BROKER_ENTRY_ID, MCP_STDIO_BROKER_RELATIVE_PATH } from './mcp-stdio-broker-native.js';

export type InstalledMcpSelection = Awaited<ReturnType<typeof readMcpRegistry>>;

/** The caller already holds/revalidates the signed installation. This checks
 * its fixed recipe, without loading an image or opening a transport early. */
export function hasInstalledMcpRecipe(bundle: Pick<RuntimeBundleManifest, 'entries'>, kind: 'streamable_http' | 'stdio'): boolean {
  const entries: readonly (readonly [entryId: string, role: string, executable: boolean, relativePath?: string])[] = kind === 'streamable_http' ? [
    [MCP_HTTP_BROKER_ENTRY_ID, 'platform_helper', true, MCP_HTTP_BROKER_RELATIVE_PATH],
    [MCP_ADMIN_HELPER_ENTRY_ID, 'platform_helper', false, MCP_ADMIN_HELPER_RELATIVE_PATH],
  ] as const : [
    [MCP_STDIO_BROKER_ENTRY_ID, 'platform_helper', true, MCP_STDIO_BROKER_RELATIVE_PATH],
    ['linux_worker_controller', 'platform_helper', true], ['linux_worker_native', 'platform_helper', true],
    ['linux_bubblewrap', 'platform_helper', true], ['installed-empty-root', 'sandbox_root_profile', false],
  ] as const;
  return entries.every(([entryId, role, executable, relativePath]) => {
    const selected = bundle.entries.filter(entry => entry.entryId === entryId);
    return selected.length === 1 && selected[0]!.role === role && selected[0]!.version === '1' &&
      selected[0]!.executable === executable && (relativePath === undefined || selected[0]!.relativePath === relativePath);
  });
}
function assertMcpSelectedRecipes(bundle: RuntimeBundleManifest, selections: readonly Pick<InstalledMcpSelection, 'registry'>[]) {
  if (selections.some(selection => selection.registry.transport.kind === 'streamable_http') && !hasInstalledMcpRecipe(bundle, 'streamable_http'))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime lacks the complete fixed MCP HTTP recipe');
  if (!selections.some(selection => selection.registry.transport.kind === 'stdio')) return;
  if (!hasInstalledMcpRecipe(bundle, 'stdio'))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime lacks the complete fixed MCP stdio recipe');
  for (const { registry } of selections) if (registry.transport.kind === 'stdio') {
    const executable = registry.transport.executable;
    if (executable.kind !== 'runtime_bundle' || executable.runtimeBundleRef !== canonicalSha256(bundle))
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP stdio executable has no exact current signed runtime closure');
    const servers = bundle.entries.filter(entry => entry.entryId === executable.executableId);
    if (servers.length !== 1 || servers[0]!.role !== 'mcp_server' || !servers[0]!.executable || servers[0]!.digest !== executable.executableDigest)
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP stdio Run selects no exact current signed server executable');
  }
}

export async function readMcpAdmissionSelections(driver: SqliteDriver, artifacts: ArtifactCatalog,
  principalId: string, registrationIds: readonly string[], bundle: RuntimeBundleManifest,
  signal?: AbortSignal): Promise<readonly InstalledMcpSelection[]> {
  signal?.throwIfAborted();
  if (registrationIds.length && !hasInstalledMcpRecipe(bundle, 'streamable_http') && !hasInstalledMcpRecipe(bundle, 'stdio'))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime lacks a complete fixed MCP execution recipe');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selections = await reads.mapReads(registrationIds,
    registrationId => readMcpRegistry(driver, reads, principalId, registrationId));
  reads.assertReadActive(); signal?.throwIfAborted();
  assertMcpSelectedRecipes(bundle, selections);
  for (const selection of selections) selection.assertUnchanged(driver);
  return Object.freeze(selections);
}

/** Existing Runs keep their original revision after a registry refresh. Never
 * replace a frozen ref with today's pointer, even when the tool names match. */
export async function readFrozenMcpSelections(driver: SqliteDriver, artifacts: ArtifactCatalog,
  principalId: string, servers: RunAssemblyV1['mcpServers'], bundle: RuntimeBundleManifest,
  signal?: AbortSignal): Promise<readonly InstalledMcpSelection[]> {
  signal?.throwIfAborted();
  if (servers.length && !hasInstalledMcpRecipe(bundle, 'streamable_http') && !hasInstalledMcpRecipe(bundle, 'stdio'))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime lacks a complete fixed MCP execution recipe');
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const selections = await reads.mapReads(servers, async server => {
    const selected = await readMcpRegistryClosure(driver, reads, server.registryRevisionRef, principalId);
    if (selected.registry.registrationId !== server.registrationId || selected.registry.registryRevision !== server.registryRevision ||
        selected.registry.manifestDigest !== server.manifestDigest)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP assembly substitutes its original registered revision');
    return selected;
  });
  reads.assertReadActive(); signal?.throwIfAborted();
  assertMcpSelectedRecipes(bundle, selections);
  for (const selection of selections) selection.assertUnchanged(driver);
  return Object.freeze(selections);
}

export function mcpSelectionCredentialRefs(selections: readonly Pick<InstalledMcpSelection, 'registry'>[]): string[] {
  const references = selections.flatMap(({ registry }) => {
    if (registry.transport.kind === 'streamable_http' && (registry.transport.credentialGrantRefs.length > 1 ||
        registry.tools.some(tool => tool.recovery.kind === 'reconcile')))
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP HTTP cannot select multiple credentials or a signed stdio status profile');
    return registry.transport.kind === 'streamable_http' ? [...registry.transport.credentialGrantRefs] : [];
  });
  return [...new Set(references)].sort();
}
