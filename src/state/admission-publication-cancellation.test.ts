// Execute the original private publication boundary with real CAS operations.
// These inert bytes create no StateOwner, Run, grant or execution authority.
import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import ts from 'typescript';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

type SinglePublisher = (value: unknown, kind: string) => Promise<PublishedArtifact>;
type FourValues = Parameters<ArtifactCatalog['publishCanonicalFour']>[0];
type FourPublisher = (values: FourValues) => ReturnType<ArtifactCatalog['publishCanonicalFour']>;

function publisher(artifacts: ArtifactCatalog, signal: AbortSignal): SinglePublisher;
function publisher(artifacts: ArtifactCatalog, signal: AbortSignal, four: true): FourPublisher;
function publisher(artifacts: ArtifactCatalog, signal: AbortSignal, four = false): SinglePublisher | FourPublisher {
  const source = readFileSync(new URL('./reducers/admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('admission.ts', source, ts.ScriptTarget.Latest, true);
  const admission = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'admitRunInternal');
  assert(admission?.body);
  const publications: ts.VariableDeclaration[] = [], raw: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(parsed) === (four ? 'publishFour' : 'publish')) publications.push(node);
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === (four ? 'artifacts.publishCanonicalFour' : 'artifacts.publishCanonical')) raw.push(node);
    ts.forEachChild(node, visit);
  };
  visit(admission.body);
  assert.equal(publications.length, 1); assert(publications[0]!.initializer);
  assert.equal(raw.length, 1, 'only the guarded boundary may start a raw admission publication');
  const body = ts.transpileModule('return ' + publications[0]!.initializer!.getText(parsed), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText;
  return new Function('artifacts', 'signal', 'canonicalSha256', 'canonicalJsonBytes', 'KernelStorageError', body)
    (artifacts, signal, canonicalSha256, canonicalJsonBytes, KernelStorageError);
}

test('revoked admission starts no new CAS publication', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-revoked-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const owner = new AbortController(), reason = new Error('original preparation revoked'); owner.abort(reason);
  const publish = publisher(new ArtifactCatalog(new ContentAddressedStore(directory)), owner.signal);
  let opened = 0;
  t.mock.method(fs, 'open', async () => { opened++; throw new Error('revoked work opened CAS'); });
  await assert.rejects(publish({ inert: true }, 'inert-publication-v1'), error => error === reason);
  assert.equal(opened, 0); assert.deepEqual(await fs.readdir(directory), []);
});

for (const fault of ['cancel', 'retirement'] as const)
  test(`admission joins its original complete publication before reporting ${fault} and starts no successor`, async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-publication-'));
    t.after(() => fs.rm(directory, { recursive: true, force: true }));
    const catalog = new ArtifactCatalog(new ContentAddressedStore(directory));
    const owner = new AbortController(), reason = new Error('original preparation revoked');
    const failure = new Error('original root close reported uncertainty');
    const publish = publisher(catalog, owner.signal), open = fs.open.bind(fs), active = new Set<object>();
    let enter!: () => void, release!: () => void, settled = false, roots = 0;
    const entered = new Promise<void>(resolve => { enter = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const fd = await open(...args); active.add(fd);
      const close = fd.close.bind(fd);
      t.mock.method(fd, 'close', async () => {
        await close(); assert(active.delete(fd));
        if (args[0] === directory && ++roots === 1) {
          enter(); await gate;
          if (fault === 'retirement') throw failure;
        }
      });
      return fd;
    });
    const bytes = { inert: true, text: 'complete original publication' };
    const work = (async () => { await publish(bytes, 'inert-publication-v1'); await publish({ successor: true }, 'inert-publication-v1'); })();
    void work.then(() => { settled = true; }, () => { settled = true; });
    try {
      await entered; assert.equal(active.size, 0);
      owner.abort(reason); await setImmediate();
      assert.equal(settled, false, 'revocation cannot detach the original publisher');
      release();
      await assert.rejects(work, error => fault === 'cancel' ? error === reason
        : error instanceof ResourceRetirementError && error.cause === failure);
      assert.equal(active.size, 0); assert.equal(roots, 1, 'a revoked admission never starts the successor');
      const names = await fs.readdir(directory); assert.equal(names.length, 1);
      assert.match(names[0]!, /^[a-f0-9]{64}$/u);
      assert.deepEqual(await catalog.readCanonical(names[0]!), bytes, 'all original bytes remain independently verifiable');
    } finally { release(); await Promise.allSettled([work]); t.mock.restoreAll(); }
  });

const fourValues = (group = 0): FourValues => [0, 1, 2, 3].map(index => ({
  value: { inert: true, group, index }, schemaKind: `inert-admission-${group}-${index}`
})) as unknown as FourValues;

test('two installed admission groups preserve eight real namespace barriers, every file sync and all original bytes', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-four-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const catalog = new ArtifactCatalog(new ContentAddressedStore(directory)), owner = new AbortController();
  const publish = publisher(catalog, owner.signal, true), open = fs.open.bind(fs), active = new Set<object>();
  let rootSyncs = 0, fileSyncs = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const fd = await open(...args); active.add(fd);
    const close = fd.close.bind(fd), sync = fd.sync.bind(fd);
    t.mock.method(fd, 'close', async () => { await close(); assert(active.delete(fd)); });
    t.mock.method(fd, 'sync', async () => { await sync(); if (args[0] === directory) rootSyncs++; else fileSyncs++; });
    return fd;
  });
  for (const group of [0, 1]) {
    const values = fourValues(group), result = await publish(values);
    assert.equal(active.size, 0);
    for (const [index, artifact] of result.entries()) {
      const selected = values[index]!;
      assert.deepEqual(artifact, { ref: canonicalSha256(selected.value), byteLength: canonicalJsonBytes(selected.value).length,
        mediaType: 'application/json', schemaKind: selected.schemaKind });
      assert.deepEqual(await catalog.readBytes(artifact.ref), canonicalJsonBytes(selected.value));
    }
  }
  assert.equal(rootSyncs, 8); assert.equal(fileSyncs, 8); assert.equal(active.size, 0);
  assert.equal((await fs.readdir(directory)).length, 8);
});

test('a revoked installed admission group starts no file operation', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-four-revoked-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const owner = new AbortController(), reason = new Error('original admission revoked'); owner.abort(reason);
  const publish = publisher(new ArtifactCatalog(new ContentAddressedStore(directory)), owner.signal, true);
  let opened = 0;
  t.mock.method(fs, 'open', async () => { opened++; throw new Error('revoked group opened CAS'); });
  await assert.rejects(publish(fourValues()), error => error === reason);
  assert.equal(opened, 0); assert.deepEqual(await fs.readdir(directory), []);
});

for (const fault of ['cancel', 'retirement'] as const)
  test(`the installed admission group joins all original files before ${fault} and cannot start its successor`, async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-four-join-'));
    t.after(() => fs.rm(directory, { recursive: true, force: true }));
    const catalog = new ArtifactCatalog(new ContentAddressedStore(directory)), owner = new AbortController();
    const publish = publisher(catalog, owner.signal, true), open = fs.open.bind(fs), active = new Set<object>();
    const reason = new Error('original group revoked'), failure = new Error('actual joined root reported uncertainty');
    let enter!: () => void, release!: () => void, roots = 0, settled = false;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const fd = await open(...args); active.add(fd); const close = fd.close.bind(fd);
      t.mock.method(fd, 'close', async () => {
        await close(); assert(active.delete(fd));
        if (args[0] === directory && ++roots === 1) { enter(); await gate; if (fault === 'retirement') throw failure; }
      }); return fd;
    });
    const work = (async () => { await publish(fourValues()); await publish(fourValues(1)); })();
    void work.then(() => { settled = true; }, () => { settled = true; });
    try {
      await entered; assert.equal(active.size, 0); owner.abort(reason); await setImmediate(); assert.equal(settled, false);
      release();
      await assert.rejects(work, error => fault === 'cancel' ? error === reason
        : error instanceof ResourceRetirementError && error.cause === failure);
      assert.equal(roots, 1); assert.equal(active.size, 0); assert.equal((await fs.readdir(directory)).length, 4);
      for (const { value } of fourValues()) assert.deepEqual(await catalog.readBytes(canonicalSha256(value)), canonicalJsonBytes(value));
    } finally { release(); await Promise.allSettled([work]); t.mock.restoreAll(); }
  });

test('every installed admission group descriptor must retain its exact original slot and complete metadata', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-admission-four-descriptor-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const catalog = new ArtifactCatalog(new ContentAddressedStore(directory)), owner = new AbortController();
  const original = catalog.publishCanonicalFour.bind(catalog), publish = publisher(catalog, owner.signal, true);
  for (const index of [0, 1, 2, 3]) for (const field of ['ref', 'byteLength', 'mediaType', 'schemaKind'] as const) {
    t.mock.method(catalog, 'publishCanonicalFour', async (values: FourValues) => {
      const result = [...await original(values)]; result[index] = { ...result[index]!,
        [field]: field === 'byteLength' ? result[index]!.byteLength + 1 : field === 'ref' ? 'f'.repeat(64) : 'different' };
      return result as unknown as Awaited<ReturnType<ArtifactCatalog['publishCanonicalFour']>>;
    });
    await assert.rejects(publish(fourValues()), error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    t.mock.restoreAll();
  }
});
