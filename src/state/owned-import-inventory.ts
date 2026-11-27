// Bounded exact inventory graph over the original native backup observations.
// Publication is retained data only; final native source/Owner checks remain
// with commitInstalledOwnedLegacyImport.
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeOwnedImportInventory, decodeOwnedImportInventoryPage, type OwnedImportInventoryV1,
  type OwnedImportInventoryPage, type OwnedImportInventoryEdge } from '../kernel/owned-import-data.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { readHeldMigrationBackupInventory, type HeldMigrationFilesystem, type HeldMigrationBackupEntry } from './native-owner.js';
type Edge = OwnedImportInventoryEdge & Readonly<{ height: number }>;
export type OwnedInventoryEvent = Readonly<{ kind: 'page'; artifact: PublishedArtifact }> |
  Readonly<{ kind: 'entry'; entry: HeldMigrationBackupEntry }>;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function entriesHash() { return createHash('sha256').update('cliq-owned-import-inventory-entries-v1\n'); }
function leaf(entries: readonly HeldMigrationBackupEntry[]): OwnedImportInventoryPage {
  return { schemaVersion: 1, format: 'cliq-owned-import-inventory-page-v1', kind: 'leaf', height: 0,
    firstPath: entries[0]!.canonicalRootRelativePath, lastPath: entries.at(-1)!.canonicalRootRelativePath,
    entryCount: entries.length, entries };
}
function branch(children: readonly Edge[], height: number): OwnedImportInventoryPage {
  const entryCount = children.reduce((count, edge) => count + edge.entryCount, 0);
  return { schemaVersion: 1, format: 'cliq-owned-import-inventory-page-v1', kind: 'branch', height,
    firstPath: children[0]!.firstPath, lastPath: children.at(-1)!.lastPath, entryCount,
    children: children.map(({ ref, firstPath, lastPath, entryCount }) => ({ ref, firstPath, lastPath, entryCount })) };
}
/** Consumes actual native metadata EOF. No entries array/callback may stand in
 * for that original producer; each leaf/parent is bounded before publication. */
export async function publishOwnedImportInventory(scope: HeldMigrationFilesystem, artifacts: ArtifactCatalog,
  input: Readonly<{ migrationId: string; preparationRef: string; preparationDigest: string;
    legacyRootIdentityRef: string; legacyRootIdentityDigest: string; signal?: AbortSignal }>):
  Promise<Readonly<{ manifest: OwnedImportInventoryV1; artifact: PublishedArtifact }>> {
  const current = () => { input.signal?.throwIfAborted(); scope.assertHeld(); artifacts.assertReadActive(); };
  const hash = entriesHash(), levels: Edge[][] = []; let pending: HeldMigrationBackupEntry[] = [], count = 0, previous = '';
  const publish = async (page: OwnedImportInventoryPage): Promise<Edge> => {
    current(); const checked = decodeOwnedImportInventoryPage(page);
    const artifact = await artifacts.publishCanonical(checked, checked.format); current();
    return { ref: artifact.ref, firstPath: checked.firstPath, lastPath: checked.lastPath, entryCount: checked.entryCount, height: checked.height };
  };
  const add = async (edge: Edge): Promise<void> => {
    if (edge.height > 7) invalid('inventory exceeds its fixed complete graph profile');
    const rows = levels[edge.height] ?? (levels[edge.height] = []);
    if (rows.length && Buffer.compare(Buffer.from(rows.at(-1)!.lastPath), Buffer.from(edge.firstPath)) >= 0)
      invalid('inventory pages are not in exact original byte order');
    rows.push(edge);
    if (rows.length === 128) {
      if (edge.height === 7) invalid('inventory exceeds its fixed complete graph profile');
      const parent = await publish(branch(rows, edge.height + 1)); levels[edge.height] = []; await add(parent);
    }
  };
  const flush = async () => { if (!pending.length) return; await add(await publish(leaf(pending))); pending = [];
    await setImmediate(); current(); };
  for await (const entry of readHeldMigrationBackupInventory(scope, input.signal)) {
    current();
    if (Buffer.compare(Buffer.from(previous), Buffer.from(entry.canonicalRootRelativePath)) >= 0 || !Number.isSafeInteger(count + 1))
      invalid('native inventory is not a complete exact sorted stream');
    // Check one full fragment before retaining it in the bounded current leaf.
    decodeOwnedImportInventoryPage(leaf([entry]));
    const next = [...pending, entry];
    if (next.length > 64 || canonicalJsonBytes(leaf(next)).length > 262_144) await flush();
    pending.push(entry); previous = entry.canonicalRootRelativePath; count++;
    hash.update(canonicalJsonBytes(entry)).update('\n');
  }
  await flush(); let root: Edge | undefined;
  for (let height = 0; height < levels.length; height++) {
    const rows = levels[height]!; if (!rows.length) continue;
    if (rows.length === 1 && !levels.slice(height + 1).some(level => level.length)) { root = rows[0]!; break; }
    if (height === 7) invalid('inventory exceeds its fixed complete graph profile');
    const parent = await publish(branch(rows, height + 1)); levels[height] = []; await add(parent);
  }
  const core = { schemaVersion: 1, format: 'cliq-owned-legacy-import-inventory-v1', migrationId: input.migrationId,
    preparationRef: input.preparationRef, preparationDigest: input.preparationDigest, legacyRootIdentityRef: input.legacyRootIdentityRef,
    legacyRootIdentityDigest: input.legacyRootIdentityDigest, rootPageRef: root?.ref ?? null, pageHeight: root?.height ?? 0,
    entryCount: count, entriesDigest: hash.digest('hex'), inventoryDigest: '' };
  core.inventoryDigest = digestOmitting(core, 'inventoryDigest'); const manifest = decodeOwnedImportInventory(core);
  current(); const artifact = await artifacts.publishCanonical(manifest, manifest.format); current();
  return Object.freeze({ manifest, artifact });
}

/** Every page edge is rehashed and decoded for its actual expected purpose.
 * A repeated ref is not memoized as permission to skip another use. */
export async function* readOwnedImportInventory(artifacts: ArtifactCatalog, input: OwnedImportInventoryV1,
  signal?: AbortSignal): AsyncIterableIterator<OwnedInventoryEvent> {
  const manifest = decodeOwnedImportInventory(input), hash = entriesHash();
  let count = 0, previous = '';
  const current = () => { signal?.throwIfAborted(); artifacts.assertReadActive(); };
  async function* visit(ref: string, height: number, expected?: OwnedImportInventoryEdge): AsyncIterableIterator<OwnedInventoryEvent> {
    current(); const bytes = await artifacts.readBoundedBytes(ref, 262_144); current();
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const page = decodeOwnedImportInventoryPage(value);
    if (!canonicalJsonBytes(page).equals(bytes) || page.height !== height || expected &&
        (page.firstPath !== expected.firstPath || page.lastPath !== expected.lastPath || page.entryCount !== expected.entryCount))
      invalid('retained inventory page differs from its exact original edge');
    yield { kind: 'page', artifact: { ref, byteLength: bytes.length, mediaType: 'application/json', schemaKind: page.format } };
    if (page.kind === 'branch') for (const edge of page.children) yield* visit(edge.ref, height - 1, edge);
    else for (const entry of page.entries) {
      current();
      if (Buffer.compare(Buffer.from(previous), Buffer.from(entry.canonicalRootRelativePath)) >= 0 || !Number.isSafeInteger(count + 1))
        invalid('retained inventory leaves are not exactly ordered');
      previous = entry.canonicalRootRelativePath; count++; hash.update(canonicalJsonBytes(entry)).update('\n');
      yield { kind: 'entry', entry };
    }
    await setImmediate(); current();
  }
  if (manifest.rootPageRef !== null) yield* visit(manifest.rootPageRef, manifest.pageHeight);
  if (count !== manifest.entryCount || hash.digest('hex') !== manifest.entriesDigest)
    invalid('retained inventory omitted, reordered or changed an original complete entry');
}

