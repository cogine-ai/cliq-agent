// Pure composition and actual CAS publication only. These inert bytes cannot
// grant authorization, create a StateOwner/Run or qualify installed execution.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Script } from 'node:vm';
import { transformSync } from 'esbuild';
import ts from 'typescript';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import type { GuestToolchainManifest } from '../kernel/execution.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { testFixture } from '../model/testing/fixtures.js';
import { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeGuestToolchainManifest } from './guest-toolchain.js';
import * as admission from './verifier-admission.js';

function composition(count = 1) {
  const imageRef = canonicalSha256('inert image data; never mounted or executed');
  const executable = (logicalName: string) => ({ logicalName, canonicalGuestPath: `/usr/bin/${logicalName}`,
    digest: canonicalSha256({ logicalName }), version: '1' });
  const manifest: GuestToolchainManifest = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1',
    guestImageRef: imageRef, guestImageDigest: imageRef, guestImageByteCount: 64,
    guestImageFormat: 'raw-ext4-v1', architecture: 'x86_64', kernelAbi: 'data-only', userspaceAbi: 'data-only',
    worker: executable('worker'), shell: executable('sh'), git: executable('git'), node: executable('node'),
    searchTools: [], verifiers: [], admittedExecutables: [], publisherKeyId: 'data-only',
    signatureRef: canonicalSha256('not a signature or native proof'), manifestDigest: '' };
  const { signatureRef: _signature, manifestDigest: _digest, ...core } = manifest;
  manifest.manifestDigest = canonicalSha256(core);
  const selected = { manifest: decodeGuestToolchainManifest(manifest), manifestRef: canonicalSha256(manifest),
    abiFingerprint: manifest.manifestDigest };
  const assembly = testFixture().assembly;
  assembly.runtime.guestToolchainManifestRef = selected.manifestRef;
  assembly.runtime.guestToolchainManifestDigest = selected.manifest.manifestDigest;
  assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
  const requests: VerifierRequest[] = Array.from({ length: count }, (_, index) => ({ id: `tests-${index}`, version: '1', required: true,
    executable: { kind: 'toolchain', guestToolchainManifestId: 'data-only', toolId: 'node' },
    argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
      { kind: 'non_secret_literal', value: `tests-${index}.mjs` }], cwd: '.', env: {}, writableEphemeralPaths: [],
    identityReadGrantId: `data-only-${index}` }));
  const composed = admission.composeVerifierSpec({ requests, toolchain: selected, assembly, sourceProjectionRef: canonicalSha256('source') });
  return { assembly, composed };
}

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-verifier-assembly-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  return { root, catalog: new ArtifactCatalog(new ContentAddressedStore(root)) };
}

async function inertArtifactPublisher() {
  // Reuse the existing inert publication seam, never resolve an authority or
  // manufacture a StateOwner, Run, grant, toolchain or native observation.
  const source = await readFile(new URL('./verifier-admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'publishVerifierArtifacts');
  assert(declaration?.body);
  const context = { readCanonicalArtifact, canonicalJsonBytes, sha256Bytes, KernelStorageError,
    same: (a: unknown, b: unknown) => canonicalJsonBytes(a).equals(canonicalJsonBytes(b)),
    invoke: undefined as unknown as (catalog: ArtifactCatalog, data: ReturnType<typeof composition>['composed'],
      historical?: unknown, signal?: AbortSignal) => Promise<unknown> };
  new Script(transformSync(`${declaration.getText(parsed)}; globalThis.invoke = publishVerifierArtifacts;`, { loader: 'ts' }).code)
    .runInNewContext(context);
  return context.invoke;
}

for (const existing of [false, true]) test(`final verifier preparation ${existing ? 'republishes' : 'publishes'} all three full objects with four joined barriers`, async t => {
  const publish = await inertArtifactPublisher(), { root, catalog } = await fixture(t), { composed } = composition();
  if (existing) for (const { value, format } of composed.artifacts) await catalog.publishCanonical(value, format);
  const open = fs.open.bind(fs), active = new Set<object>(); let rootSyncs = 0, fileSyncs = 0, opened = 0, closed = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const fd = await open(...args); active.add(fd); opened++;
    const sync = fd.sync.bind(fd), close = fd.close.bind(fd);
    t.mock.method(fd, 'sync', async () => { await sync(); if (args[0] === root) rootSyncs++; else fileSyncs++; });
    t.mock.method(fd, 'close', async () => { await close(); assert(active.delete(fd)); closed++; }); return fd;
  });
  const result = await publish(catalog, composed);
  assert.equal(rootSyncs, 4, 'fresh final resolution may share only its four real namespace barriers');
  assert.equal(fileSyncs, 3, 'existing CAS bytes never substitute for any complete original write and file sync');
  assert.equal(active.size, 0); assert.equal(opened, closed);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), composed.artifacts.map(({ ref, value, format }) => ({
    ref, mediaType: 'application/json', schemaKind: format, byteLength: canonicalJsonBytes(value).length })));
  for (const { ref, value } of composed.artifacts) assert.deepEqual(await catalog.readBytes(ref), canonicalJsonBytes(value));
  assert.deepEqual((await readdir(root)).sort(), composed.artifacts.map(value => value.ref).sort());
  assert.equal(active.size, 0); assert.equal(opened, closed);
});

test('final preparation cancelled before publication opens no descriptor', async t => {
  const publish = await inertArtifactPublisher(), { root, catalog } = await fixture(t), { composed } = composition();
  const controller = new AbortController(), reason = new Error('original final preparation cancelled'); controller.abort(reason);
  t.mock.method(fs, 'open', async () => { throw new Error('a cancelled publication cannot open CAS'); });
  await assert.rejects(publish(catalog, composed, undefined, controller.signal), error => error === reason);
  assert.deepEqual(await readdir(root), []);
});

for (const fault of ['cancel', 'write', 'retirement'] as const)
  test(`final preparation joins its actual triple before ${fault} returns without masking storage failures`, async t => {
    const publish = await inertArtifactPublisher(), { root, catalog } = await fixture(t), { composed } = composition();
    const controller = new AbortController(), reason = new Error('cancelled during actual final publication');
    const writeFailure = new Error('actual final publication write failed'), closeFailure = new Error('actual final publication root close failed');
    const open = fs.open.bind(fs), active = new Set<object>();
    let enter!: () => void, release!: () => void, settled = false, writes = 0;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const fd = await open(...args); active.add(fd);
      const close = fd.close.bind(fd), write = fd.writeFile.bind(fd);
      if (String(args[0]).includes('/.tmp-stream-')) t.mock.method(fd, 'writeFile', async (...values: Parameters<typeof write>) => {
        await write(...values); if (++writes === 1 && fault !== 'cancel') throw writeFailure;
      });
      t.mock.method(fd, 'close', async () => {
        await close(); assert(active.delete(fd));
        if (args[0] === root) { enter(); await gate; if (fault === 'retirement') throw closeFailure; }
      }); return fd;
    });
    const pending = publish(catalog, composed, undefined, controller.signal);
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([entered, pending.then(() => { throw new Error('original close join was bypassed'); })]);
      assert.equal(writes, 3); assert.equal(active.size, 0);
      controller.abort(reason); await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(settled, false); release();
      await assert.rejects(pending, error => fault === 'cancel' ? error === reason : fault === 'write' ? error === writeFailure :
        error instanceof ResourceRetirementError && error.cause === closeFailure);
      assert.equal(settled, true); assert.equal(active.size, 0);
      assert((await readdir(root)).every(name => /^[a-f0-9]{64}$/u.test(name)));
    } finally { release(); await Promise.allSettled([pending]); assert.equal(active.size, 0); }
  });

test('final preparation validates all three returned full-byte descriptors and their original order', async t => {
  const publish = await inertArtifactPublisher(), { catalog } = await fixture(t), { composed } = composition();
  const triple = catalog.publishCanonicalTriple.bind(catalog);
  const other = await catalog.publishBytes(Buffer.from('different data'), 'text/plain', 'different-format');
  for (const slot of [0, 1, 2]) for (const field of ['ref', 'byteLength', 'mediaType', 'schemaKind', 'missing'] as const) {
    const replaced = t.mock.method(catalog, 'publishCanonicalTriple', async (...args: Parameters<typeof triple>) => {
      const actual = await triple(...args), changed = [...actual];
      if (field === 'missing') delete changed[slot]; else changed[slot] = { ...actual[slot]!, [field]: other[field] };
      return changed as unknown as typeof actual;
    });
    try { await assert.rejects(publish(catalog, composed), { code: 'ARTIFACT_MISMATCH' }, `${slot}:${field}`); }
    finally { replaced.mock.restore(); }
  }
});

test('one installed verifier publishes only its command, environment, spec and assembly in one real four-stage group', async t => {
  const { root, catalog } = await fixture(t), { assembly, composed } = composition();
  const originalOpen = fs.open.bind(fs), active = new Set<object>();
  let opened = 0, closed = 0, peak = 0, rootSyncs = 0, fileSyncs = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args); active.add(handle); opened++; peak = Math.max(peak, active.size);
    const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
    t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); closed++; });
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === root) rootSyncs++; else fileSyncs++; });
    return handle;
  });
  const publish = admission.publishVerifierAssembly;
  assert.equal(typeof publish, 'function', 'the data-only installed publication seam must use the fixed-four lifecycle');
  const metadata = await publish(catalog, composed, assembly);
  assert.equal(rootSyncs, 4, 'the shared four namespace durability boundaries are not four independent lifecycles');
  assert.equal(fileSyncs, 4, 'every original object receives its actual file sync');
  assert.equal(active.size, 0); assert.equal(opened, closed);
  assert(peak > 2 && peak <= 5, 'the actual delivered CAS ownership is one root plus at most four files');
  assert.deepEqual(metadata.map(artifact => artifact.schemaKind),
    ['cliq-verifier-command-v1', 'cliq-verifier-environment-v1', 'cliq-verifier-spec-v1']);
  for (const { value, ref } of [...composed.artifacts, { value: assembly, ref: canonicalSha256(assembly) }])
    assert.deepEqual(await catalog.readBytes(ref), canonicalJsonBytes(value));
  assert.deepEqual((await readdir(root)).sort(), [...composed.artifacts.map(value => value.ref), canonicalSha256(assembly)].sort());
  assert.equal(active.size, 0); assert.equal(opened, closed);
});

test('installed assembly uses the shared full verifier resolution before publication and keeps sandbox, policy and final authority checks', async () => {
  // Wiring only: executing this assertion does not create any authority.
  const verifierSource = await readFile(new URL('./verifier-admission.ts', import.meta.url), 'utf8');
  const installedSource = await readFile(new URL('./installed-run.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', verifierSource, ts.ScriptTarget.Latest, true);
  const functions = new Map(parsed.statements.filter(ts.isFunctionDeclaration).map(value => [value.name?.text, value]));
  const installed = functions.get('prepareInstalledVerifierAssembly');
  assert(installed?.body, 'installed assembly must have an explicit current-only wrapper, not a historical feature flag');
  const body = installed.body.getText(parsed);
  assert.match(body, /await resolveVerifierSpec\(driver, artifacts, owner, runtime, input, undefined, signal, onPreparationPhase\)/u);
  assert.match(body, /await publishVerifierAssembly\(artifacts, composed, input\.assembly, signal\)/u);
  assert(body.indexOf('await resolveVerifierSpec') < body.indexOf('await publishVerifierAssembly'));
  assert(!installed.parameters.some(parameter => parameter.name.getText(parsed) === 'historical'));
  const ordinary = functions.get('prepareVerifierSpec')!.body!.getText(parsed);
  assert.match(ordinary, /await resolveVerifierSpec\(driver, artifacts, owner, runtime, input, historical, signal\)/u);
  assert.match(ordinary, /await publishVerifierArtifacts\(artifacts, composed, historical, signal\)/u);
  assert(!ordinary.includes('publishVerifierAssembly'), 'the original historical reader never enters the current-only publisher');
  const start = installedSource.indexOf('const sandbox = installedSandboxProfile(request.sandboxResources);');
  const end = installedSource.indexOf('admissions.set(result,', start);
  assert(start >= 0 && end > start);
  const publication = installedSource.slice(start, end);
  const stages = ['await artifacts.publishCanonical(sandbox, sandbox.format)', 'await prepareInstalledVerifierAssembly(',
    'await artifacts.publishCanonical(policy, policy.format)', 'await installed.revalidate(signal)',
    'await validateControlChannelClosure(reads, owner, identity)', 'assertActiveStateOwner(driver, owner)'];
  let previous = -1;
  for (const stage of stages) { const next = publication.indexOf(stage); assert(next > previous, stage); previous = next; }
  assert(!publication.includes('publishCanonical(assembly,'), 'the same original assembly is not republished after its fixed group');
});

for (const count of [0, 2]) test(`installed assembly with ${count} verifiers publishes each original object once without padding`, async t => {
  const { root, catalog } = await fixture(t), { assembly, composed } = composition(count);
  const publish = catalog.publishCanonical.bind(catalog), writes: string[] = [];
  t.mock.method(catalog, 'publishCanonicalFour', async () => { throw new Error('only exactly one verifier may use the fixed group'); });
  t.mock.method(catalog, 'publishCanonical', async (...args: Parameters<typeof publish>) => {
    writes.push(args[1]); return publish(...args);
  });
  const metadata = await admission.publishVerifierAssembly(catalog, composed, assembly);
  assert.deepEqual(writes, [...composed.artifacts.map(value => value.format), 'cliq-run-assembly-v1']);
  assert.deepEqual(metadata.map(value => value.ref), composed.artifacts.map(value => value.ref));
  assert.equal((await readdir(root)).length, 2 * count + 2, 'no dummy or duplicate object is introduced');
  for (const { value, ref } of [...composed.artifacts, { value: assembly, ref: canonicalSha256(assembly) }])
    assert.deepEqual(await catalog.readBytes(ref), canonicalJsonBytes(value));
});

test('an already cancelled installed group starts no file operation and preserves its exact reason', async t => {
  const { root, catalog } = await fixture(t), { assembly, composed } = composition();
  const owner = new AbortController(), reason = new Error('the caller cancelled before publication'); owner.abort(reason);
  t.mock.method(fs, 'open', async () => { throw new Error('a cancelled group cannot open a CAS descriptor'); });
  await assert.rejects(admission.publishVerifierAssembly(catalog, composed, assembly, owner.signal), error => error === reason);
  assert.deepEqual(await readdir(root), []);
});

for (const fault of ['cancel', 'write', 'retirement'] as const)
  test(`the complete real group joins before ${fault} can return and an actual retirement failure keeps precedence`, async t => {
    const { root, catalog } = await fixture(t), { assembly, composed } = composition();
    const owner = new AbortController(), reason = new Error('cancelled while the original publication was pending');
    const writeFailure = new Error('actual complete temporary write reported failure');
    const closeFailure = new Error('actual root close reported failure');
    const originalOpen = fs.open.bind(fs), active = new Set<object>();
    let release!: () => void, enter!: () => void, settled = false, opened = 0, closed = 0, writeFailed = false;
    const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { enter = resolve; });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args); active.add(handle); opened++;
      const close = handle.close.bind(handle), write = handle.writeFile.bind(handle);
      if (String(args[0]).includes('/.tmp-stream-') && fault !== 'cancel') t.mock.method(handle, 'writeFile',
        async (...values: Parameters<typeof write>) => {
          await write(...values);
          if (!writeFailed) { writeFailed = true; throw writeFailure; }
        });
      t.mock.method(handle, 'close', async () => {
        await close(); assert(active.delete(handle)); closed++;
        if (args[0] === root) {
          enter(); await gate;
          if (fault === 'retirement') throw closeFailure;
        }
      });
      return handle;
    });
    const pending = admission.publishVerifierAssembly(catalog, composed, assembly, owner.signal);
    void pending.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([entered, pending.then(() => { throw new Error('the original root close return gate was bypassed'); })]);
      assert.equal(active.size, 0, 'the actual file/root descriptors close before the logical return gate');
      assert.equal(opened, closed); assert(opened >= 5, 'all four real files and the original root were owned');
      owner.abort(reason);
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(settled, false, 'cancellation cannot abandon the already-issued durability group');
      release();
      await assert.rejects(pending, error => fault === 'cancel' ? error === reason : fault === 'write' ? error === writeFailure :
        error instanceof ResourceRetirementError && error.cause === closeFailure);
      assert.equal(settled, true); assert.equal(active.size, 0); assert.equal(opened, closed);
      assert((await readdir(root)).every(name => /^[0-9a-f]{64}$/u.test(name)), 'no temporary is falsely reported joined');
    } finally { release(); await Promise.allSettled([pending]); assert.equal(active.size, 0); }
  });

test('all four actual publication descriptors, including the assembly slot, must match their complete original bytes', async t => {
  const { catalog } = await fixture(t), { assembly, composed } = composition();
  const publish = catalog.publishCanonicalFour.bind(catalog);
  const other = await catalog.publishBytes(Buffer.from('x'), 'text/plain', 'different-real-object');
  for (const slot of [0, 1, 2, 3]) for (const field of ['ref', 'byteLength', 'mediaType', 'schemaKind', 'missing'] as const) {
    const replacement = t.mock.method(catalog, 'publishCanonicalFour', async (...args: Parameters<typeof publish>) => {
      const actual = await publish(...args), changed = [...actual];
      if (field === 'missing') delete changed[slot];
      else changed[slot] = { ...actual[slot]!, [field]: other[field] };
      return changed as unknown as typeof actual;
    });
    try { await assert.rejects(admission.publishVerifierAssembly(catalog, composed, assembly), { code: 'ARTIFACT_MISMATCH' }, `${slot}:${field}`); }
    finally { replacement.mock.restore(); }
  }
});

test('the unchanged historical publication loop only verifies original complete objects, never writes or repairs a missing one', async t => {
  const { root, catalog } = await fixture(t), { assembly, composed } = composition();
  await admission.publishVerifierAssembly(catalog, composed, assembly);
  const original = await readFile(new URL('./verifier-admission.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-admission.ts', original, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'publishVerifierArtifacts');
  assert(declaration?.body, 'execute only the real inert historical publication loop, not an admission or authority substitute');
  const context = { readCanonicalArtifact, same: (a: unknown, b: unknown) => canonicalJsonBytes(a).equals(canonicalJsonBytes(b)),
    invoke: undefined as unknown as (artifacts: ArtifactCatalog, data: typeof composed, historical: unknown) => Promise<unknown> };
  new Script(transformSync(`${declaration.getText(parsed)}; globalThis.invoke = publishVerifierArtifacts;`, { loader: 'ts' }).code)
    .runInNewContext(context);
  t.mock.method(catalog, 'publishCanonical', async () => { throw new Error('historical validation cannot publish'); });
  t.mock.method(catalog, 'publishCanonicalFour', async () => { throw new Error('historical validation cannot enter an installed group'); });
  t.mock.method(catalog, 'publishCanonicalTriple', async () => { throw new Error('historical validation cannot enter a final preparation group'); });
  const before = (await readdir(root)).sort();
  const metadata = await context.invoke(catalog, composed, { admittedAt: 'original inert history', runId: 'not an authority', admissionIntentDigest: 'data-only' });
  assert.deepEqual(JSON.parse(JSON.stringify(metadata)), composed.artifacts.map(({ ref, value, format }) => ({
    ref, mediaType: 'application/json', schemaKind: format, byteLength: canonicalJsonBytes(value).length })));
  assert.deepEqual((await readdir(root)).sort(), before);
  const substituted = { ...composed, artifacts: composed.artifacts.map((artifact, index) => index ? artifact :
    { ...artifact, value: { ...artifact.value, verifierVersion: 'changed inert data' } }) };
  await assert.rejects(context.invoke(catalog, substituted, { original: true }),
    { name: 'TypeError', message: 'verifier history substitutes an immutable artifact' });
  assert.deepEqual((await readdir(root)).sort(), before, 'historical mismatch cannot publish substituted bytes');
  await fs.unlink(path.join(root, composed.artifacts[0]!.ref));
  await assert.rejects(context.invoke(catalog, composed, { original: true }));
  assert.equal((await readdir(root)).length, before.length - 1, 'a missing historical object stays missing, never reconstructed');
});
