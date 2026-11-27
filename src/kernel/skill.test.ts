import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, sha256Bytes } from './identity.js';
import { decodeBundledSkillClosure, decodeSkillManifest, decodeSkillResourceInput, decodeSkillResourceOutput,
  decodeSkillSourceIdentity, type SkillSourceIdentityV1, type SkillSourceFileBytesV1 } from './skill.js';

const ref = 'a'.repeat(64), raw = Buffer.from('---\nname: example\ndescription: Example\n---\nFrozen instruction.\n');
const file: SkillSourceFileBytesV1 = { canonicalRelativePath: 'SKILL.md', rawBytesRef: sha256Bytes(raw), rawBytesDigest: sha256Bytes(raw), rawByteCount: raw.length };
const source = (scope: SkillSourceIdentityV1['sourceScope']) => {
  const base = { schemaVersion: 1, format: 'cliq-skill-source-identity-v1', skillId: 'example', sourceScope: scope };
  const root = { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 };
  const descriptor = { deviceId: '1', fileId: '3', ownerUid: 501, mode: 420, linkCount: 1 };
  if (scope === 'bundled') {
    const entry = { ...file, sourceEntryDigest: canonicalSha256({ sourceScope: scope, bundledClosureDigest: ref, ...file }) };
    const value = { ...base, runtimeBundleRef: ref, runtimeBundleManifestDigest: ref, bundleEntryId: 'example', bundleEntryVersion: '1',
      bundledClosureRef: ref, bundledClosureDigest: ref, files: [entry] };
    return { ...value, sourceIdentityDigest: canonicalSha256(value) };
  }
  const rootDescriptor = scope === 'workspace' ? { canonicalRootRelativePath: '.cliq/skills/example', ...root }
    : { canonicalAbsolutePath: '/home/example/.cliq/skills/example', ...root };
  const identity = scope === 'workspace' ? { workspaceIdentityRef: ref, workspaceIdentityDigest: ref }
    : { ownerPrincipalId: 'principal', principalIdentityRef: ref, principalIdentityDigest: ref };
  const binding = scope === 'workspace' ? { workspaceIdentityDigest: ref } : { principalIdentityDigest: ref };
  const entry = { ...file, fileDescriptor: descriptor, sourceEntryDigest: canonicalSha256({ sourceScope: scope, ...binding,
    rootDescriptor, ...file, fileDescriptor: descriptor }) };
  const value = { ...base, ...identity, rootDescriptor, files: [entry] };
  return { ...value, sourceIdentityDigest: canonicalSha256(value) };
};

test('all three exact source identity shapes retain descriptor and hash domains as immutable data', () => {
  for (const scope of ['workspace', 'user', 'bundled'] as const) {
    const value = source(scope), decoded = decodeSkillSourceIdentity(value);
    assert.equal(canonicalSha256(decoded), canonicalSha256(value)); assert(Object.isFrozen(decoded)); assert(Object.isFrozen(decoded.files));
    const mutated = structuredClone(value) as any;
    mutated.files[0].rawByteCount++;
    mutated.sourceIdentityDigest = digestOmitting(mutated, 'sourceIdentityDigest');
    assert.throws(() => decodeSkillSourceIdentity(mutated));
  }
});

test('bundled closure and skill manifest have separate omission and complete-byte domains', () => {
  const closureCore = { schemaVersion: 1, format: 'cliq-bundled-skill-closure-v1', skillId: 'example', files: [file] };
  const closure = { ...closureCore, closureDigest: canonicalSha256(closureCore) };
  assert.equal(decodeBundledSkillClosure(closure).closureDigest, closure.closureDigest);
  assert.notEqual(canonicalSha256(closure), closure.closureDigest);
  const manifestCore = { schemaVersion: 1, format: 'cliq-skill-manifest-v1', skillId: 'example', sourceScope: 'bundled',
    sourceIdentityRef: ref, sourceIdentityDigest: ref, instructionRef: ref, instructionDigest: ref,
    resources: [{ canonicalRelativePath: 'scripts/check.sh', kind: 'executable-disabled', contentRef: ref, contentDigest: ref }] };
  const manifest = { ...manifestCore, manifestDigest: canonicalSha256(manifestCore) };
  assert.equal(canonicalSha256(decodeSkillManifest(manifest)), canonicalSha256(manifest));
  const invented = { ...manifest, resources: [{ ...manifest.resources[0], contentDigest: 'b'.repeat(64) }] };
  invented.manifestDigest = digestOmitting(invented, 'manifestDigest');
  assert.throws(() => decodeSkillManifest(invented));
});

test('source graph rejects over-budget, unsorted, missing instruction and impossible file ancestry', () => {
  const core = { schemaVersion: 1, format: 'cliq-bundled-skill-closure-v1', skillId: 'example', files: [file] };
  const accept = (files: typeof file[]) => { const value = { ...core, files }; return decodeBundledSkillClosure({ ...value, closureDigest: canonicalSha256(value) }); };
  assert.throws(() => accept([]));
  assert.throws(() => accept([{ ...file, canonicalRelativePath: '../SKILL.md' }]));
  assert.throws(() => accept([file, { ...file, canonicalRelativePath: 'A' }]));
  assert.throws(() => accept([file, { ...file, canonicalRelativePath: 'a' }, { ...file, canonicalRelativePath: 'a/b' }]));
  assert.throws(() => accept([file, { ...file, canonicalRelativePath: 'a', rawByteCount: 16777216 },
    { ...file, canonicalRelativePath: 'b', rawByteCount: 1 }]));
  assert.throws(() => accept([file, ...Array.from({ length: 129 }, (_, index) => ({ ...file, canonicalRelativePath: `z${index.toString().padStart(3, '0')}` }))]));
});

test('closed skill data rejects accessors and proxies before invoking any trap', () => {
  let calls = 0;
  const getters = Object.defineProperty({}, 'schemaVersion', { enumerable: true, get() { calls++; return 1; } });
  const proxy = new Proxy({}, { getPrototypeOf() { calls++; throw new Error('reflection'); }, ownKeys() { calls++; throw new Error('reflection'); } });
  for (const decoder of [decodeSkillSourceIdentity, decodeSkillManifest, decodeBundledSkillClosure, decodeSkillResourceInput, decodeSkillResourceOutput]) {
    assert.throws(() => decoder(getters)); assert.throws(() => decoder(proxy));
  }
  assert.equal(calls, 0);
});

test('resource ranges preserve full size, explicit empty EOF and exact bounded base64 without host refs', () => {
  assert.deepEqual(decodeSkillResourceInput({ skillId: 'example', canonicalRelativePath: 'scripts/a.sh', offset: 0, length: 65536 }),
    { skillId: 'example', canonicalRelativePath: 'scripts/a.sh', offset: 0, length: 65536 });
  for (const data of [{ skillId: 'example', canonicalRelativePath: '/etc/passwd', offset: 0, length: 1 },
    { skillId: 'example', canonicalRelativePath: 'SKILL.md', offset: 0, length: 1 },
    { skillId: 'example', canonicalRelativePath: 'a', offset: 0, length: 65537 },
    { skillId: 'example', canonicalRelativePath: 'a', offset: 0, length: 1, ref }]) assert.throws(() => decodeSkillResourceInput(data));
  const output = { schemaVersion: 1, skillId: 'example', canonicalRelativePath: 'a', kind: 'executable-disabled', byteCount: 2,
    offset: 0, bytesBase64: Buffer.from([0, 255]).toString('base64'), nextOffset: 2, eof: true };
  assert.equal(decodeSkillResourceOutput(output).bytesBase64, 'AP8=');
  assert.throws(() => decodeSkillResourceOutput({ ...output, eof: false }));
  assert.throws(() => decodeSkillResourceOutput({ ...output, bytesBase64: 'AP8' }));
  assert.throws(() => decodeSkillResourceOutput({ ...output, byteCount: 3, bytesBase64: '', nextOffset: 0, eof: false }));
  assert.equal(decodeSkillResourceOutput({ ...output, byteCount: 0, bytesBase64: '', nextOffset: 0 }).eof, true);
});
