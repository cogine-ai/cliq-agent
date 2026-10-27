// The real admission metadata read expression against real CAS, without a
// Run, StateOwner or mutable-authority substitute.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import ts from 'typescript';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';
import { readCanonicalArtifact } from './agent-context.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';

async function metadataCut() {
  const source = await readFile(new URL('./reducers/admission.ts', import.meta.url), 'utf8');
  const end = source.indexOf('  const now = installed?.data.admittedAt ?? sampleCanonicalNow();');
  const metadata = source.lastIndexOf('  const referencedMetadata =', end);
  const redundant = source.lastIndexOf('  await reads.readBytes(input.assemblyRef);', metadata);
  assert(metadata >= 0 && end > metadata);
  const body = source.slice(redundant < 0 ? metadata : redundant, end);
  const code = ts.transpileModule(`${body}\nreturn referencedMetadata;`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const execute = new Function('readCanonicalArtifact', 'canonicalJsonBytes', 'reads', 'input', 'sourceManifest',
    `return (async () => { ${code} })();`);
  return (reads: ArtifactCatalog, input: Record<string, unknown>, sourceManifest: { entriesRef: string }) =>
    execute(readCanonicalArtifact, canonicalJsonBytes, reads, input, sourceManifest) as Promise<Array<{ ref: string; byteLength: number }>>;
}
async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-admission-metadata-')); await fs.chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), owner = new AbortController();
  const fields = ['assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'sourceProjectionRef', 'frozenIgnoreRulesRef',
    'baseWorkspaceManifestRef', 'entriesRef', 'credentialRef'];
  const data = await Promise.all(fields.map(async field => ({ field, value: await artifacts.publishCanonical({ field, bytes: 'complete inert object' }, field) })));
  const refs = Object.fromEntries(data.map(({ field, value }) => [field, value.ref]));
  return { root, owner, reads: artifacts.withReadSignal(owner.signal), data,
    input: { ...refs, credentialGrantRefs: [refs.credentialRef] } as Record<string, unknown>, sourceManifest: { entriesRef: refs.entriesRef! } };
}
test('the same admission cut fully reads every described object exactly once instead of discarding three duplicate reads', async t => {
  const f = await fixture(t), read = f.reads.readBytes.bind(f.reads), counts = new Map<string, number>();
  t.mock.method(f.reads, 'readBytes', async (ref: string) => { counts.set(ref, (counts.get(ref) ?? 0) + 1); return read(ref); });
  const result = await (await metadataCut())(f.reads, f.input, f.sourceManifest);
  assert.equal(result.length, f.data.length);
  for (const { value } of f.data) {
    assert.equal(counts.get(value.ref), 1, 'later describe retains its genuine complete read on the same signal');
    assert.equal(result.find(item => item.ref === value.ref)!.byteLength, value.byteLength);
  }
});
for (const fault of ['cancel', 'retirement'] as const)
  test(`admission metadata retains its original signal and joins all dispatched real descriptors during ${fault}`, async t => {
    const f = await fixture(t), cut = await metadataCut(), open = fs.open.bind(fs), active = new Set<object>();
    const reason = new Error('original admission read cancelled'), closeFailure = new Error('actual root close failed');
    let enter!: () => void, release!: () => void, gated = false, settled = false;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args); active.add(handle); const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => {
        await close(); assert(active.delete(handle));
        if (!gated && args[0] === path.join(f.root, f.input.assemblyRef as string)) { gated = true; enter(); await gate; }
        if (fault === 'retirement' && args[0] === f.root) throw closeFailure;
      }); return handle;
    });
    const pending = cut(f.reads, f.input, f.sourceManifest);
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([entered, pending.then(() => { throw new Error('original read close join bypassed'); })]);
      f.owner.abort(reason); await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(settled, false); release();
      await assert.rejects(pending, error => fault === 'cancel' ? error === reason : error instanceof ResourceRetirementError);
      assert.equal(active.size, 0);
    } finally { release(); await Promise.allSettled([pending]); }
  });
