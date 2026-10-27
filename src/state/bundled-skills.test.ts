// Actual signatures and CAS reads over inert data. No installation, native
// process, Run admission or execution authority is constructed by these tests.
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { decodeBundledSkillClosure, decodeSkillManifest, decodeSkillSourceIdentity } from '../kernel/skill.js';
import { identityHash } from '../kernel/identity.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { bundledSkillMembers, bundledSkillRoots } from './bundled-skills.js';
import { validateBundle, validateInstalledStructuredArtifacts } from './installed-artifacts.js';
import { frozenSkillResourceRange, readFrozenSkillData, skillInstruction } from './skill-data.js';

async function fixture(t: TestContext, instructionName = 'example') {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-frozen-skill-cas-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keys = generateKeyPairSync('ed25519'), releaseKeys = [{ keyId: 'inert-skill-publisher',
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(directory), undefined, releaseKeys);
  const skill = Buffer.from(`---\nname: ${instructionName}\ndescription: Frozen source.\n---\nRead [the data](data.bin).\n`), bytes = Buffer.from([0, 1, 255]);
  const raw = [{ canonicalRelativePath: 'SKILL.md', bytes: skill }, { canonicalRelativePath: 'data.bin', bytes }];
  const files = raw.map(file => ({ canonicalRelativePath: file.canonicalRelativePath, rawBytesRef: sha256Bytes(file.bytes),
    rawBytesDigest: sha256Bytes(file.bytes), rawByteCount: file.bytes.length }));
  for (const file of raw) await artifacts.publishBytes(file.bytes, 'application/octet-stream', 'cliq-skill-source-file-v1');
  const closureCore = { schemaVersion: 1 as const, format: 'cliq-bundled-skill-closure-v1' as const, skillId: 'example', files };
  const closure = decodeBundledSkillClosure({ ...closureCore, closureDigest: canonicalSha256(closureCore) });
  const closureRef = (await artifacts.publishCanonical(closure, closure.format)).ref, profile = policyProfile();
  const entry = (entryId: string, role: string, executable: boolean) => ({ entryId, role, executable, version: '1',
    relativePath: `data/${entryId}`, digest: sha256Bytes(Buffer.from(entryId)), byteCount: Buffer.byteLength(entryId) });
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'inert-skill-test-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 3, max: 3 }, stateSchemaRange: { min: 8, max: 8 },
    workerProtocolRange: { min: 1, max: 1 }, entries: [entry('supervisor', 'supervisor', true), entry('worker', 'worker', true),
      { ...entry('policy', 'policy_engine', false), digest: canonicalSha256(profile), byteCount: canonicalJsonBytes(profile).length },
      entry('default_https_trust_store', 'trust_store', false), entry('root', 'sandbox_root_profile', false),
      { ...entry('skill-example', 'skill_bundle', false), version: '3', digest: closureRef, byteCount: canonicalJsonBytes(closure).length },
      ...files.map(file => ({ entryId: identityHash('runtime-bundle-object-v1', file.rawBytesRef), role: 'bundle_object', executable: false,
        version: '1', relativePath: `objects/sha256/${file.rawBytesRef.slice(0, 2)}/${file.rawBytesRef}`, digest: file.rawBytesRef, byteCount: file.rawByteCount }))],
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy', rootEntryId: 'policy', artifactRef: canonicalSha256(profile),
      semanticDigest: profile.profileDigest, memberRefs: [] }, { kind: 'bundled_skill', artifactId: 'example', rootEntryId: 'skill-example',
      artifactRef: closureRef, semanticDigest: closure.closureDigest, memberRefs: files.map(file => file.rawBytesRef).sort() }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '' };
  bundle.structuredArtifacts.sort((left, right) => Buffer.compare(Buffer.from([left.kind, left.provider ?? '', left.model ?? '', left.artifactId].join('\0')),
    Buffer.from([right.kind, right.provider ?? '', right.model ?? '', right.artifactId].join('\0'))));
  const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const bundleRef = (await artifacts.publishCanonical(bundle, 'cliq-runtime-bundle-v1')).ref;
  const sourceCore = { schemaVersion: 1 as const, format: 'cliq-skill-source-identity-v1' as const, skillId: 'example', sourceScope: 'bundled' as const,
    runtimeBundleRef: bundleRef, runtimeBundleManifestDigest: bundle.manifestDigest, bundleEntryId: 'skill-example', bundleEntryVersion: '3',
    bundledClosureRef: closureRef, bundledClosureDigest: closure.closureDigest,
    files: files.map(file => ({ ...file, sourceEntryDigest: canonicalSha256({ sourceScope: 'bundled', bundledClosureDigest: closure.closureDigest, ...file }) })) };
  const source = decodeSkillSourceIdentity({ ...sourceCore, sourceIdentityDigest: canonicalSha256(sourceCore) });
  assert(source.sourceScope === 'bundled');
  const identityRef = (await artifacts.publishCanonical(source, source.format)).ref;
  const text = skillInstruction(instructionName, skill), textRef = (await artifacts.publishCanonical(text, text.format)).ref;
  const manifestCore = { schemaVersion: 1 as const, format: 'cliq-skill-manifest-v1' as const, skillId: 'example', sourceScope: 'bundled' as const,
    sourceIdentityRef: identityRef, sourceIdentityDigest: source.sourceIdentityDigest, instructionRef: textRef, instructionDigest: text.textDigest,
    resources: [{ canonicalRelativePath: 'data.bin', kind: 'executable-disabled' as const, contentRef: files[1]!.rawBytesRef, contentDigest: files[1]!.rawBytesDigest }] };
  const manifest = decodeSkillManifest({ ...manifestCore, manifestDigest: canonicalSha256(manifestCore) });
  const manifestRef = (await artifacts.publishCanonical(manifest, manifest.format)).ref;
  const binding = { workspaceIdentityRef: 'a'.repeat(64), workspaceIdentityDigest: 'b'.repeat(64), ownerPrincipalId: 'inert-data-only',
    runtimeBundleRef: bundleRef, runtimeBundleManifestDigest: bundle.manifestDigest };
  const objects = new Map([[canonicalSha256(profile), canonicalJsonBytes(profile)], [closureRef, canonicalJsonBytes(closure)], [files[0]!.rawBytesRef, skill]]);
  return { directory, artifacts, bundle, releaseKeys, closure, source, manifest, selected: { skillId: 'example', manifestRef, manifestDigest: manifest.manifestDigest }, binding, objects };
}

test('a real signed non-executable bundled closure keeps raw, semantic and complete-byte identities separate', async t => {
  const value = await fixture(t); validateBundle(value.bundle, value.releaseKeys);
  const structured = validateInstalledStructuredArtifacts(value.bundle, value.objects);
  assert(structured.objects.some(object => object.artifactRef === value.source.bundledClosureRef));
  const data = await readFrozenSkillData(value.artifacts, value.selected, value.binding);
  assert.equal(data.instruction.utf8, 'Read [the data](data.bin).'); assert.equal(data.source.sourceScope, 'bundled');
  assert.notEqual(value.source.bundledClosureRef, value.source.bundledClosureDigest);
  assert.equal(value.source.bundleEntryVersion, '3');
  assert.deepEqual(frozenSkillResourceRange(data, { skillId: 'example', canonicalRelativePath: 'data.bin', offset: 0, length: 65536 }),
    { schemaVersion: 1, skillId: 'example', canonicalRelativePath: 'data.bin', kind: 'executable-disabled', byteCount: 3, offset: 0,
      bytesBase64: 'AAH/', nextOffset: 3, eof: true });
});

test('complete frozen readers refuse another publisher, original bundle or a validly hashed wrong instruction', async t => {
  const value = await fixture(t), other = await fixture(t);
  await assert.rejects(readFrozenSkillData(value.artifacts, value.selected, { ...value.binding, runtimeBundleRef: other.binding.runtimeBundleRef }));
  const untrusted = new ArtifactCatalog(new ContentAddressedStore(value.directory), undefined, other.releaseKeys);
  // Use the same actual original CAS with only another real public key; a key
  // id string never establishes the original publisher's signature.
  assert.equal(sha256Bytes(await untrusted.readBytes(value.selected.manifestRef)), value.selected.manifestRef);
  await assert.rejects(readFrozenSkillData(untrusted, value.selected, value.binding), /signature/u);
  const wrong = await fixture(t, 'different');
  await assert.rejects(readFrozenSkillData(wrong.artifacts, wrong.selected, wrong.binding));
});

test('root/member aliases and missing signed declarations are refused even when the underlying content hashes remain valid', async t => {
  const value = await fixture(t), root = bundledSkillRoots(value.bundle)[0]!;
  assert.equal(bundledSkillMembers(value.bundle, structuredClone(root), value.closure).length, 2);
  const missing = structuredClone(value.bundle); missing.structuredArtifacts = missing.structuredArtifacts.filter(root => root.kind !== 'bundled_skill');
  assert.throws(() => bundledSkillRoots(missing));
  assert.throws(() => bundledSkillMembers(value.bundle, { ...root, memberRefs: [root.memberRefs[0]!] }, value.closure));
  const executable = structuredClone(value.bundle); executable.entries.find(entry => entry.entryId === 'skill-example')!.executable = true;
  assert.throws(() => bundledSkillRoots(executable));
});
