// Exercise the actual retained-seed consumer over real CAS files. This is a
// data-reader regression, not an installed genesis or execution authority.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import workerThreads from 'node:worker_threads';
import ts from 'typescript';
import { SKILL_RESOURCE_BYTES } from '../kernel/skill.js';
import { isNpmDataEntry } from '../sandbox/dependency-recipe.js';
import { GUEST_EXTRACTOR_RECIPE } from '../sandbox/guest-toolchain.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';

async function retainedSeedDataLoop() {
  const parsed = ts.createSourceFile('state-owner-history.ts', await fs.readFile(new URL('./state-owner-history.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const reader = parsed.statements.filter(ts.isFunctionDeclaration).find(node => node.name?.text === 'readInstalledSeed');
  assert(reader?.body);
  const consumers = reader.body.statements.filter(node => node.getText(parsed).includes('isNpmDataEntry(entry)'));
  assert.equal(consumers.length, 1);
  const body = ts.transpileModule(consumers[0]!.getText(parsed), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  return new Function('data', 'artifacts', 'isNpmDataEntry', 'guestImages', 'GUEST_EXTRACTOR_RECIPE', 'skillMembers',
    'guestSignatures', 'SKILL_RESOURCE_BYTES', 'invalid', `return (async () => { ${body} })();`) as (...args: unknown[]) => Promise<void>;
}

test('retained installed image consumers use full joined reads, not main-thread chunk walks or settled proofs', async t => {
  const home = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-retained-seed-read-')));
  const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  const size = 8_388_609, ref = await cas.publish(Buffer.alloc(size, 0x61)), filename = path.join(root, ref);
  const loop = await retainedSeedDataLoop(), actualOpen = fs.open.bind(fs), OriginalWorker = workerThreads.Worker;
  const active = new Set<object>(), jobs = new Map<workerThreads.Worker, number>();
  let mainReads = 0, threads = 0, failClose = false, groupFiles = 0;
  let groupClose: (() => Promise<void>) | undefined;
  const closeFailure = new Error('original file close reported uncertainty');
  workerThreads.Worker = class extends OriginalWorker {
    constructor(source: string | URL, options?: workerThreads.WorkerOptions) {
      super(source, options);
      if (options?.workerData?.ref === ref) { threads++; jobs.set(this, options.workerData.fd); this.once('exit', () => jobs.delete(this)); }
    }
  };
  syncBuiltinESMExports();
  t.after(() => { workerThreads.Worker = OriginalWorker; syncBuiltinESMExports(); });
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const file = await actualOpen(...args); active.add(file);
    if (groupClose && args[0] === filename) groupFiles++;
    const close = file.close.bind(file), read = file.read.bind(file);
    if (args[0] === filename) t.mock.method(file, 'read', async (...args: Parameters<typeof read>) => {
      mainReads++; return read(...args);
    });
    t.mock.method(file, 'close', async () => {
      assert(![...jobs.values()].includes(file.fd), 'the original read thread must exit before its borrowed descriptor closes');
      await close(); assert(active.delete(file));
      if (args[0] === filename) await groupClose?.();
      if (failClose && args[0] === filename) throw closeFailure;
    });
    return file;
  });
  const read = (kind: 'guest' | 'skill', reads = artifacts, byteCount = size, copies = 1) => {
    const entry = { digest: ref, byteCount, entryId: 'retained-seed-data', role: 'bundle_object', executable: false,
      version: '1', relativePath: 'data/image' };
    return loop(Array.from({ length: copies }, () => entry), reads, isNpmDataEntry, new Set(kind === 'guest' ? [ref] : []), GUEST_EXTRACTOR_RECIPE,
      { resources: new Set(kind === 'skill' ? [ref] : []), instructions: new Set() }, new Set(), SKILL_RESOURCE_BYTES,
      (message: string) => { throw new Error(message); });
  };
  for (const kind of ['guest', 'skill'] as const) {
    await read(kind); assert.equal(active.size, 0); assert.equal(jobs.size, 0);
  }
  assert.equal(threads, 2, 'each later consumer must reread the original file');
  assert.equal(mainReads, 0, 'large retained images must leave the event loop available');
  let release!: () => void, entered!: () => void, closedFiles = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const fourClosed = new Promise<void>(resolve => { entered = resolve; });
  groupClose = async () => { if (++closedFiles === 4) entered(); await gate; };
  const grouped = read('guest', artifacts, size, 5);
  void grouped.catch(() => {});
  const timer = setTimeout(entered, 2000);
  try {
    await fourClosed;
    assert.equal(closedFiles, 4, 'the real seed consumer must overlap four independent readers');
    assert.equal(groupFiles, 4, 'the fifth member must wait for the first group to join its closes');
    release(); await grouped; assert.equal(groupFiles, 5); assert.equal(active.size, 0);
  } finally { release(); clearTimeout(timer); await grouped; groupClose = undefined; }
  await assert.rejects(read('guest', artifacts, size + 1));
  const abort = new AbortController(), reason = new Error('original history cancelled'); abort.abort(reason);
  const before = threads;
  await assert.rejects(read('guest', artifacts.withReadSignal(abort.signal)), error => error === reason);
  assert.equal(threads, before); assert.equal(active.size, 0);
  await fs.chmod(filename, 0o600);
  const changed = await actualOpen(filename, 'r+');
  try { await changed.write(Buffer.from([0x62]), 0, 1, size - 1); }
  finally { await changed.close(); await fs.chmod(filename, 0o400); }
  await assert.rejects(read('guest'), /digest/);
  failClose = true;
  await assert.rejects(read('guest'), error => error instanceof ResourceRetirementError && error.cause === closeFailure);
  assert.equal(active.size, 0); assert.equal(jobs.size, 0);
});
