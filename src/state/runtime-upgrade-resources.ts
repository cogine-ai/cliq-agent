/** Bounded immutable evidence only. No page, index or decoded row grants an
 * owner, retirement proof, permission or ability to execute an old operation. */
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef } from '../kernel/control-wire-data.js';
import { digestOmitting } from '../kernel/identity.js';
import type { RuntimeUpgradeResourceFamilyV1, RuntimeUpgradeResourceIndexV1, RuntimeUpgradeResourcePageV1 } from '../kernel/runtime-upgrade.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { checkCanonicalBytes } from './installed-artifacts.js';

export const UPGRADE_RESOURCE_PAGE_ROWS = 512;
export const UPGRADE_RESOURCE_FAMILY_ROWS = 100_000;
export const UPGRADE_RESOURCE_FAMILIES = ['run_terminal', 'worker_launch', 'workspace_generation', 'source_inspection'] as const;
const MAX_PAGES = Math.ceil(UPGRADE_RESOURCE_FAMILY_ROWS / UPGRADE_RESOURCE_PAGE_ROWS);
const OBJECT_BYTES = 1_048_576;
type OwnerCut = Readonly<{ sourceOwnerEpoch: number; sourceOwnerRowDigest: string }>;
export type UpgradeResourceRefs = Record<RuntimeUpgradeResourceFamilyV1, string[]>;
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'upgrade resource graph lacks its complete bounded original sequence'); }

function owner(value: OwnerCut): void {
  assertControlWireJson(value); controlWireRecord(value, ['sourceOwnerEpoch', 'sourceOwnerRowDigest']);
  controlWireInteger(value.sourceOwnerEpoch, 1); controlWireRef(value.sourceOwnerRowDigest);
}
function refs(value: unknown, maximum: number): asserts value is string[] {
  if (value !== null && typeof value === 'object' && types.isProxy(value) || !Array.isArray(value) || value.length > maximum) invalid();
  assertControlWireJson(value);
  for (let index = 0; index < value.length; index++) controlWireRef(value[index]);
}
function context(value: Record<string, unknown>, cut: OwnerCut, family: RuntimeUpgradeResourceFamilyV1): void {
  if (!UPGRADE_RESOURCE_FAMILIES.includes(family) || value.family !== family ||
      value.sourceOwnerEpoch !== cut.sourceOwnerEpoch || value.sourceOwnerRowDigest !== cut.sourceOwnerRowDigest) invalid();
}
function sequenceHash(cut: OwnerCut, family: RuntimeUpgradeResourceFamilyV1, count: number) {
  // Counts are canonical decimal and refs have exactly 64 ASCII hex bytes.
  // No large JSON serialization, separator ambiguity or page-boundary alias.
  return createHash('sha256').update(`cliq-upgrade-resource-sequence-v1\0${family}\0${cut.sourceOwnerEpoch}\0${cut.sourceOwnerRowDigest}\0${count}\0`);
}
export function upgradeResourceSequenceDigest(cut: OwnerCut, family: RuntimeUpgradeResourceFamilyV1, values: readonly string[]): string {
  owner(cut); if (!UPGRADE_RESOURCE_FAMILIES.includes(family)) invalid(); refs(values, UPGRADE_RESOURCE_FAMILY_ROWS);
  const hash = sequenceHash(cut, family, values.length); let previous = '';
  for (let index = 0; index < values.length; index++) { const value = values[index]!; if (value <= previous) invalid(); hash.update(value); previous = value; }
  return hash.digest('hex');
}
function canonicalObject(value: unknown): Buffer {
  const bytes = canonicalJsonBytes(value); if (bytes.length > OBJECT_BYTES) invalid();
  // Enforce the unchanged strict 10k-entry/depth32/Unicode JSON contract on
  // each real artifact rather than on an in-memory collection of page refs.
  checkCanonicalBytes(bytes); return bytes;
}
export function decodeUpgradeResourceIndex(value: unknown, cut: OwnerCut, family: RuntimeUpgradeResourceFamilyV1): RuntimeUpgradeResourceIndexV1 {
  assertControlWireJson(value);
  const row = controlWireRecord(value, ['schemaVersion', 'format', 'family', 'sourceOwnerEpoch', 'sourceOwnerRowDigest',
    'rowCount', 'pageCount', 'pageRefs', 'orderedRefsDigest', 'indexDigest']);
  owner(cut); context(row, cut, family);
  if (row.schemaVersion !== 1 || row.format !== 'cliq-upgrade-resource-index-v1') invalid();
  const count = controlWireInteger(row.rowCount, 0, UPGRADE_RESOURCE_FAMILY_ROWS), pages = controlWireInteger(row.pageCount, 0, MAX_PAGES);
  refs(row.pageRefs, MAX_PAGES); controlWireRef(row.orderedRefsDigest); controlWireRef(row.indexDigest);
  if (pages !== Math.ceil(count / UPGRADE_RESOURCE_PAGE_ROWS) || row.pageRefs.length !== pages ||
      new Set(row.pageRefs).size !== pages || row.indexDigest !== digestOmitting(row, 'indexDigest') ||
      count === 0 && row.orderedRefsDigest !== sequenceHash(cut, family, 0).digest('hex')) invalid();
  canonicalObject(row); return row as RuntimeUpgradeResourceIndexV1;
}
export function decodeUpgradeResourcePage(value: unknown, cut: OwnerCut, family: RuntimeUpgradeResourceFamilyV1,
  pageIndex: number, rowCount: number): RuntimeUpgradeResourcePageV1 {
  controlWireInteger(pageIndex, 0, MAX_PAGES - 1); controlWireInteger(rowCount, 1, UPGRADE_RESOURCE_PAGE_ROWS);
  assertControlWireJson(value);
  const row = controlWireRecord(value, ['schemaVersion', 'format', 'family', 'sourceOwnerEpoch', 'sourceOwnerRowDigest',
    'pageIndex', 'firstOrdinal', 'rowRefs', 'pageDigest']);
  owner(cut); context(row, cut, family); refs(row.rowRefs, UPGRADE_RESOURCE_PAGE_ROWS); controlWireRef(row.pageDigest);
  if (row.schemaVersion !== 1 || row.format !== 'cliq-upgrade-resource-ref-page-v1' || row.pageIndex !== pageIndex ||
      row.firstOrdinal !== pageIndex * UPGRADE_RESOURCE_PAGE_ROWS || row.rowRefs.length !== rowCount || rowCount < 1 ||
      row.pageDigest !== digestOmitting(row, 'pageDigest')) invalid();
  let previous = ''; for (const ref of row.rowRefs) { if (ref <= previous) invalid(); previous = ref; }
  canonicalObject(row); return row as RuntimeUpgradeResourcePageV1;
}
async function read(artifacts: ArtifactCatalog, ref: string): Promise<unknown> {
  // Exact full verify + exact-size chunk read + strict canonical parse. A
  // malicious oversized CAS object cannot allocate beyond the consumer bound.
  return checkCanonicalBytes(await artifacts.readBoundedBytes(ref, OBJECT_BYTES));
}
export async function readUpgradeResourceRow<T>(artifacts: ArtifactCatalog, ref: string): Promise<T> {
  return await read(artifacts, ref) as T;
}
async function publish(artifacts: ArtifactCatalog, values: readonly unknown[], schemaKind: string): Promise<PublishedArtifact[]> {
  if (!values.length || values.length > 4) invalid();
  const inputs = values.map(value => { canonicalObject(value); return { value, schemaKind }; });
  const result = inputs.length === 4 ? await artifacts.publishCanonicalFour([inputs[0]!, inputs[1]!, inputs[2]!, inputs[3]!]) :
    inputs.length === 3 ? await artifacts.publishCanonicalTriple([inputs[0]!, inputs[1]!, inputs[2]!]) :
    inputs.length === 2 ? await artifacts.publishCanonicalPair([inputs[0]!, inputs[1]!]) :
    [await artifacts.publishCanonical(inputs[0]!.value, schemaKind)];
  if (result.length !== values.length || result.some((item, index) => item.ref !== canonicalSha256(values[index]) ||
      item.byteLength !== canonicalJsonBytes(values[index]).length)) invalid();
  return [...result];
}

/** Pure publication family: all original CAS writes and their own full reads
 * finish before this returns. Its caller samples death/commit time later. */
export async function publishUpgradeResourceGraph(artifacts: ArtifactCatalog, cut: OwnerCut, source: UpgradeResourceRefs) {
  owner(cut); if (source !== null && typeof source === 'object' && types.isProxy(source)) invalid();
  controlWireRecord(source, UPGRADE_RESOURCE_FAMILIES);
  const indexes: RuntimeUpgradeResourceIndexV1[] = [], objects: PublishedArtifact[] = [], allRefs = new Set<string>();
  for (const family of UPGRADE_RESOURCE_FAMILIES) {
    refs(source[family], UPGRADE_RESOURCE_FAMILY_ROWS);
    const ordered: string[] = [];
    for (let i = 0; i < source[family].length; i++) { const ref = source[family][i]!; if (allRefs.has(ref)) invalid(); allRefs.add(ref); ordered.push(ref); }
    ordered.sort(); const orderedRefsDigest = upgradeResourceSequenceDigest(cut, family, ordered), pageRefs: string[] = [];
    for (let offset = 0; offset < ordered.length;) {
      const pages: RuntimeUpgradeResourcePageV1[] = [];
      for (let lane = 0; lane < 4 && offset < ordered.length; lane++, offset += UPGRADE_RESOURCE_PAGE_ROWS) {
        const page: RuntimeUpgradeResourcePageV1 = { schemaVersion: 1, format: 'cliq-upgrade-resource-ref-page-v1', family, ...cut,
          pageIndex: offset / UPGRADE_RESOURCE_PAGE_ROWS, firstOrdinal: offset,
          rowRefs: ordered.slice(offset, offset + UPGRADE_RESOURCE_PAGE_ROWS), pageDigest: '' };
        page.pageDigest = digestOmitting(page, 'pageDigest'); pages.push(page);
      }
      const group = await publish(artifacts, pages, 'cliq-upgrade-resource-ref-page-v1');
      objects.push(...group); pageRefs.push(...group.map(item => item.ref));
    }
    const index: RuntimeUpgradeResourceIndexV1 = { schemaVersion: 1, format: 'cliq-upgrade-resource-index-v1', family, ...cut,
      rowCount: ordered.length, pageCount: pageRefs.length, pageRefs, orderedRefsDigest, indexDigest: '' };
    index.indexDigest = digestOmitting(index, 'indexDigest'); indexes.push(index);
  }
  const roots = await publish(artifacts, indexes, 'cliq-upgrade-resource-index-v1'); objects.push(...roots);
  const resourceIndexRefs = { run_terminal: roots[0]!.ref, worker_launch: roots[1]!.ref,
    workspace_generation: roots[2]!.ref, source_inspection: roots[3]!.ref };
  const totalRowCount = allRefs.size;
  const retained = await readUpgradeResourceGraph(artifacts, cut, resourceIndexRefs, totalRowCount);
  return { resourceIndexRefs, totalRowCount, objects, refs: retained };
}

export async function readUpgradeResourceGraph(artifacts: ArtifactCatalog, cut: OwnerCut,
  resourceIndexRefs: Record<RuntimeUpgradeResourceFamilyV1, string>, totalRowCount: number): Promise<UpgradeResourceRefs> {
  owner(cut); assertControlWireJson(resourceIndexRefs); controlWireRecord(resourceIndexRefs, UPGRADE_RESOURCE_FAMILIES);
  controlWireInteger(totalRowCount, 0, UPGRADE_RESOURCE_FAMILIES.length * UPGRADE_RESOURCE_FAMILY_ROWS);
  const indexes = new Map<RuntimeUpgradeResourceFamilyV1, RuntimeUpgradeResourceIndexV1>(), metadataRefs = new Set<string>();
  for (const family of UPGRADE_RESOURCE_FAMILIES) {
    const ref = resourceIndexRefs[family]; controlWireRef(ref); if (metadataRefs.has(ref)) invalid(); metadataRefs.add(ref);
  }
  let count = 0;
  for (const family of UPGRADE_RESOURCE_FAMILIES) {
    const index = decodeUpgradeResourceIndex(await read(artifacts, resourceIndexRefs[family]), cut, family);
    for (const ref of index.pageRefs) { if (metadataRefs.has(ref)) invalid(); metadataRefs.add(ref); }
    count += index.rowCount; indexes.set(family, index);
  }
  if (count !== totalRowCount) invalid();
  const result: UpgradeResourceRefs = { run_terminal: [], worker_launch: [], workspace_generation: [], source_inspection: [] };
  const seenRows = new Set<string>();
  for (const family of UPGRADE_RESOURCE_FAMILIES) {
    const index = indexes.get(family)!, hash = sequenceHash(cut, family, index.rowCount); let previous = '';
    for (let pageIndex = 0; pageIndex < index.pageCount; pageIndex++) {
      const expectedRows = Math.min(UPGRADE_RESOURCE_PAGE_ROWS, index.rowCount - pageIndex * UPGRADE_RESOURCE_PAGE_ROWS);
      const page = decodeUpgradeResourcePage(await read(artifacts, index.pageRefs[pageIndex]!), cut, family, pageIndex, expectedRows);
      for (const ref of page.rowRefs) {
        if (ref <= previous || metadataRefs.has(ref) || seenRows.has(ref)) invalid();
        seenRows.add(ref); result[family].push(ref); hash.update(ref); previous = ref;
      }
      artifacts.assertReadActive();
    }
    if (result[family].length !== index.rowCount || hash.digest('hex') !== index.orderedRefsDigest) invalid();
  }
  return result;
}
