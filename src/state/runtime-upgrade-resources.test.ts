import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { mkdir, mkdtemp, rm, readdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { RuntimeUpgradeResourceIndexV1, RuntimeUpgradeResourcePageV1 } from '../kernel/runtime-upgrade.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { checkCanonicalBytes } from './installed-artifacts.js';
import { iterateNodeSqliteStatement } from './sqlite-driver.js';
import { decodeRuntimeUpgradeRetirement } from './runtime-upgrade-history.js';
import { decodeUpgradeResourceIndex, publishUpgradeResourceGraph, readUpgradeResourceGraph, upgradeResourceSequenceDigest,
  UPGRADE_RESOURCE_PAGE_ROWS, UPGRADE_RESOURCE_FAMILY_ROWS, type UpgradeResourceRefs } from './runtime-upgrade-resources.js';

const cut = { sourceOwnerEpoch: 3, sourceOwnerRowDigest: 'a'.repeat(64) };
const hex = (i: number) => (i * 2).toString(16).padStart(64, '0');
function source(refs: string[]): UpgradeResourceRefs { return { run_terminal: refs, worker_launch: [], workspace_generation: [], source_inspection: [] }; }
async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-upgrade-pages-'));
  await mkdir(path.join(root, 'cas'), { mode: 0o700 });
  const cas = new ContentAddressedStore(path.join(root, 'cas')), artifacts = new ArtifactCatalog(cas);
  return { root, cas, artifacts, close: () => rm(root, { recursive: true, force: true }) };
}

test('the upgrade retirement consumer preserves all 20000 ordered historical references through bounded real CAS pages', async () => {
  // Pure reference graph, not accepted Run rows, retirement or native authority.
  const f = await fixture(), values = Array.from({ length: 20_000 }, (_, i) => hex(i));
  try {
    const graph = await publishUpgradeResourceGraph(f.artifacts, cut, source([...values].reverse()));
    assert.equal(graph.totalRowCount, values.length); assert.deepEqual(graph.refs.run_terminal, values);
    const row = { schemaVersion: 1, format: 'cliq-retired-runtime-cut-v1', ...cut,
      sourceProcessIdentityRef: 'b'.repeat(64), sourceProcessIdentityDigest: 'c'.repeat(64),
      sourceProcessObservation: 'absent_or_start_token_mismatch', resourceIndexRefs: graph.resourceIndexRefs,
      totalRowCount: graph.totalRowCount, sourceDataVersion: 1, sourceTotalChanges: 0,
      observedAt: '2026-10-27T00:00:00.000Z', retirementDigest: '' };
    row.retirementDigest = digestOmitting(row, 'retirementDigest');
    const decoded = decodeRuntimeUpgradeRetirement(checkCanonicalBytes(canonicalJsonBytes(row)));
    assert.equal(decoded.totalRowCount, values.length);
    const read = await readUpgradeResourceGraph(f.artifacts, cut, decoded.resourceIndexRefs, decoded.totalRowCount);
    assert.deepEqual(read.run_terminal, values);
    for (const object of graph.objects) {
      assert(object.byteLength <= 1_048_576); checkCanonicalBytes(await f.artifacts.readBytes(object.ref));
    }
    assert.equal((await f.artifacts.readCanonical<RuntimeUpgradeResourceIndexV1>(graph.resourceIndexRefs.run_terminal)).pageCount,
      Math.ceil(values.length / UPGRADE_RESOURCE_PAGE_ROWS));
  } finally { await f.close(); }
});

test('actual SQLite supplies exactly 100000 ordered refs and every bounded CAS page is reread without a large JSON array', async () => {
  // Exact representation boundary only; this is not 100000 real retired Runs.
  const f = await fixture(), db = new DatabaseSync(':memory:');
  try {
    db.exec('CREATE TABLE historical(ref TEXT PRIMARY KEY) STRICT; BEGIN');
    const insert = db.prepare('INSERT INTO historical(ref) VALUES(?)');
    for (let i = UPGRADE_RESOURCE_FAMILY_ROWS - 1; i >= 0; i--) insert.run(hex(i));
    db.exec('COMMIT');
    const statement = db.prepare('SELECT ref FROM historical ORDER BY ref COLLATE BINARY'), values: string[] = [];
    for (const row of iterateNodeSqliteStatement(statement)) values.push(String(row.ref));
    assert.equal(values.length, 100_000);
    const graph = await publishUpgradeResourceGraph(f.artifacts, cut, source(values));
    const read = await readUpgradeResourceGraph(f.artifacts, cut, graph.resourceIndexRefs, graph.totalRowCount);
    assert.deepEqual(read.run_terminal, values);
    const index = await f.artifacts.readCanonical<RuntimeUpgradeResourceIndexV1>(graph.resourceIndexRefs.run_terminal);
    assert.equal(index.rowCount, 100_000); assert.equal(index.pageCount, 196);
    assert.equal(index.orderedRefsDigest, upgradeResourceSequenceDigest(cut, 'run_terminal', values));
    assert.notEqual(index.orderedRefsDigest, upgradeResourceSequenceDigest({ ...cut, sourceOwnerEpoch: cut.sourceOwnerEpoch + 1 }, 'run_terminal', values));
    assert.notEqual(index.orderedRefsDigest, upgradeResourceSequenceDigest(cut, 'worker_launch', values));
    assert.notEqual(index.orderedRefsDigest, upgradeResourceSequenceDigest(cut, 'run_terminal', values.slice(0, -1)));
    await assert.rejects(publishUpgradeResourceGraph(f.artifacts, cut, source([...values, hex(100_000)])));
    for (const descriptor of graph.objects) assert(descriptor.byteLength < 1_048_576);
  } finally { db.close(); await f.close(); }
});

test('missing, reordered, duplicate, changed, truncated, foreign and aliased pages cannot replace a complete graph', async () => {
  const f = await fixture(), values = Array.from({ length: 1025 }, (_, i) => hex(i));
  try {
    const graph = await publishUpgradeResourceGraph(f.artifacts, cut, source(values));
    const original = await f.artifacts.readCanonical<RuntimeUpgradeResourceIndexV1>(graph.resourceIndexRefs.run_terminal);
    const readIndex = async (index: RuntimeUpgradeResourceIndexV1, total = graph.totalRowCount) => {
      index.indexDigest = digestOmitting(index, 'indexDigest');
      const object = await f.artifacts.publishCanonical(index, 'negative-upgrade-index-data');
      return readUpgradeResourceGraph(f.artifacts, cut, { ...graph.resourceIndexRefs, run_terminal: object.ref }, total);
    };
    for (const change of [
      (index: RuntimeUpgradeResourceIndexV1) => { index.pageRefs[1] = 'f'.repeat(64); },
      (index: RuntimeUpgradeResourceIndexV1) => { index.pageRefs[1] = index.pageRefs[0]!; },
      (index: RuntimeUpgradeResourceIndexV1) => { [index.pageRefs[0], index.pageRefs[1]] = [index.pageRefs[1]!, index.pageRefs[0]!]; },
      (index: RuntimeUpgradeResourceIndexV1) => { index.rowCount--; },
      (index: RuntimeUpgradeResourceIndexV1) => { index.pageRefs.pop(); },
      (index: RuntimeUpgradeResourceIndexV1) => { index.sourceOwnerEpoch++; },
    ]) {
      const changed = structuredClone(original); change(changed); await assert.rejects(readIndex(changed));
    }
    for (const change of [
      (page: RuntimeUpgradeResourcePageV1) => { page.rowRefs[0] = hex(511); }, // Cross-page duplicate.
      (page: RuntimeUpgradeResourcePageV1) => { page.rowRefs[0] = (1025).toString(16).padStart(64, '0'); }, // Still ordered; complete hash differs.
      (page: RuntimeUpgradeResourcePageV1) => { page.rowRefs.pop(); },
      (page: RuntimeUpgradeResourcePageV1) => { page.firstOrdinal--; },
      (page: RuntimeUpgradeResourcePageV1) => { page.family = 'worker_launch'; },
    ]) {
      const index = structuredClone(original), page = await f.artifacts.readCanonical<RuntimeUpgradeResourcePageV1>(index.pageRefs[1]!);
      change(page); page.pageDigest = digestOmitting(page, 'pageDigest');
      index.pageRefs[1] = (await f.artifacts.publishCanonical(page, 'negative-upgrade-page-data')).ref;
      await assert.rejects(readIndex(index));
    }
    await assert.rejects(readUpgradeResourceGraph(f.artifacts, cut,
      { ...graph.resourceIndexRefs, worker_launch: graph.resourceIndexRefs.run_terminal }, graph.totalRowCount));
    const aliasPage: RuntimeUpgradeResourcePageV1 = { schemaVersion: 1, format: 'cliq-upgrade-resource-ref-page-v1', family: 'run_terminal',
      ...cut, pageIndex: 0, firstOrdinal: 0, rowRefs: [graph.resourceIndexRefs.worker_launch], pageDigest: '' };
    aliasPage.pageDigest = digestOmitting(aliasPage, 'pageDigest');
    const aliasRef = (await f.artifacts.publishCanonical(aliasPage, 'negative-row-metadata-alias')).ref;
    const aliasIndex: RuntimeUpgradeResourceIndexV1 = { ...original, rowCount: 1, pageCount: 1, pageRefs: [aliasRef],
      orderedRefsDigest: upgradeResourceSequenceDigest(cut, 'run_terminal', aliasPage.rowRefs) };
    await assert.rejects(readIndex(aliasIndex, 1));
    await assert.rejects(readUpgradeResourceGraph(f.artifacts, { ...cut, sourceOwnerRowDigest: 'b'.repeat(64) }, graph.resourceIndexRefs, graph.totalRowCount));
    const extra = { ...original, permission: true }; extra.indexDigest = digestOmitting(extra, 'indexDigest');
    assert.throws(() => decodeUpgradeResourceIndex(extra, cut, 'run_terminal'));
    assert.throws(() => decodeUpgradeResourceIndex({ ...original, pageCount: 197 }, cut, 'run_terminal'));
    assert.deepEqual((await readUpgradeResourceGraph(f.artifacts, cut, graph.resourceIndexRefs, graph.totalRowCount)).run_terminal, values);
  } finally { await f.close(); }
});

test('a publication failure never publishes later index roots and all original issued CAS members have joined', async () => {
  const f = await fixture(), values = Array.from({ length: 2049 }, (_, i) => hex(i));
  const original = f.artifacts.publishCanonicalFour.bind(f.artifacts), marker = new Error('owned post-durability publication refusal');
  let groupJoined = false, groupCount = 0;
  f.artifacts.publishCanonicalFour = async entries => {
    await original(entries); groupCount++; groupJoined = true;
    throw marker; // Actual complete CAS writes/reads/closes precede this injected refusal.
  };
  try {
    await assert.rejects(publishUpgradeResourceGraph(f.artifacts, cut, source(values)), error => error === marker);
    assert.equal(groupJoined, true); assert.equal(groupCount, 1);
    const names = await readdir(path.join(f.root, 'cas')); assert.equal(names.length, 4);
    for (const ref of names) {
      const page = await f.artifacts.readCanonical<RuntimeUpgradeResourcePageV1>(ref);
      assert.equal(page.format, 'cliq-upgrade-resource-ref-page-v1');
      assert.equal(canonicalSha256(page), ref);
    }
  } finally { await f.close(); }
});

test('page and index inputs reject getters, proxies, nonfixed families and extra fields without invoking caller code', async () => {
  const f = await fixture(); let touched = false;
  try {
    const graph = await publishUpgradeResourceGraph(f.artifacts, cut, source([hex(1)]));
    const index = await f.artifacts.readCanonical<RuntimeUpgradeResourceIndexV1>(graph.resourceIndexRefs.run_terminal);
    const getter = { ...index }; Object.defineProperty(getter, 'pageRefs', { enumerable: true, get() { touched = true; return []; } });
    assert.throws(() => decodeUpgradeResourceIndex(getter, cut, 'run_terminal'));
    assert.throws(() => decodeUpgradeResourceIndex(new Proxy(index, { ownKeys() { touched = true; return []; } }), cut, 'run_terminal'));
    assert.throws(() => decodeUpgradeResourceIndex({ ...index, family: 'other' }, cut, 'other' as 'run_terminal'));
    const refs = source([hex(1)]); Object.defineProperty(refs, 'run_terminal', { enumerable: true, get() { touched = true; return []; } });
    await assert.rejects(publishUpgradeResourceGraph(f.artifacts, cut, refs));
    await assert.rejects(publishUpgradeResourceGraph(f.artifacts, new Proxy(cut, { get() { touched = true; return 1; } }), source([])));
    assert.equal(touched, false);
  } finally { await f.close(); }
});
