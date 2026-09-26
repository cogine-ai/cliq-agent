import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';

import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, sha256Bytes } from '../kernel/identity.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { verifyBundleStructuredPayloads } from './structured-payloads.js';

const keyPair = generateKeyPairSync('ed25519');
const releaseKeys = [{ keyId: 'test-release',
  publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];

function text(utf8: string) {
  const core = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const,
    utf8, byteCount: Buffer.byteLength(utf8) };
  return { ...core, textDigest: canonicalSha256(core) };
}

type Fixture = { bundle: RuntimeBundleManifest; bytes: Map<string, Uint8Array> };

function signBundle(bundle: RuntimeBundleManifest): void {
  const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`),
    keyPair.privateKey).toString('base64');
}

function fixture(): Fixture {
  const bytes = new Map<string, Uint8Array>();
  const entries: RuntimeBundleManifest['entries'] = [
    { entryId: 'supervisor', role: 'supervisor', version: '1', relativePath: 'bin/supervisor',
      digest: canonicalSha256('supervisor'), byteCount: 1, executable: true },
    { entryId: 'worker', role: 'worker', version: '1', relativePath: 'bin/worker',
      digest: canonicalSha256('worker'), byteCount: 1, executable: true },
    { entryId: 'default_https_trust_store', role: 'trust_store', version: '1', relativePath: 'data/trust',
      digest: canonicalSha256('trust'), byteCount: 1, executable: false },
    { entryId: 'root-profile', role: 'sandbox_root_profile', version: '1', relativePath: 'data/root',
      digest: canonicalSha256('root'), byteCount: 1, executable: false }
  ];
  const structuredArtifacts: RuntimeBundleManifest['structuredArtifacts'] = [];
  const addRoot = (kind: string, id: string, role: string, value: object, semanticDigest: string,
    memberRefs: string[] = [], provider?: string, model?: string) => {
    const data = canonicalJsonBytes(value);
    const ref = sha256Bytes(data);
    bytes.set(id, data);
    entries.push({ entryId: id, role, version: '1', relativePath: `data/${id}`,
      digest: ref, byteCount: data.byteLength, executable: false });
    structuredArtifacts.push({ kind, artifactId: id, rootEntryId: id, artifactRef: ref,
      semanticDigest, memberRefs, ...(provider === undefined ? {} : { provider, model }) });
  };
  const addMember = (value: object | string) => {
    const data = typeof value === 'string' ? Buffer.from(value) : canonicalJsonBytes(value);
    const ref = sha256Bytes(data);
    const id = identityHash('runtime-bundle-object-v1', ref);
    bytes.set(id, data);
    entries.push({ entryId: id, role: 'bundle_object', version: '1',
      relativePath: `objects/sha256/${ref.slice(0, 2)}/${ref}`,
      digest: ref, byteCount: data.byteLength, executable: false });
    return ref;
  };

  const skillBytes = '---\nname: example\n---\nA useful skill.\n';
  const skillRef = addMember(skillBytes);
  const skillCore = { schemaVersion: 1, format: 'cliq-bundled-skill-closure-v1', skillId: 'example-skill',
    files: [{ canonicalRelativePath: 'SKILL.md', rawBytesRef: skillRef,
      rawBytesDigest: skillRef, rawByteCount: Buffer.byteLength(skillBytes) }] };
  addRoot('bundled_skill', 'example-skill', 'skill_bundle',
    { ...skillCore, closureDigest: canonicalSha256(skillCore) }, canonicalSha256(skillCore), [skillRef]);

  const compactionTexts = [text('System.'), text('Prefix.'), text('Suffix.')];
  const compactionRefs = compactionTexts.map(addMember);
  const envelopeCore = { schemaVersion: 1, format: 'cliq-compaction-prompt-envelope-v1',
    systemInstructionRef: compactionRefs[0], systemInstructionDigest: compactionTexts[0]!.textDigest,
    userPrefixRef: compactionRefs[1], userPrefixDigest: compactionTexts[1]!.textDigest,
    sourcePlaceholder: '{{CLIQ_SOURCE_CONTEXT_UTF8}}',
    userSuffixRef: compactionRefs[2], userSuffixDigest: compactionTexts[2]!.textDigest,
    resultContract: { toolsAllowed: false, requiredStopReason: 'end',
      mediaType: 'text/markdown; charset=utf-8', summaryFormat: 'cliq-context-summary-markdown-v1' } };
  addRoot('compaction_prompt', 'compaction', 'compaction_prompt',
    { ...envelopeCore, envelopeDigest: canonicalSha256(envelopeCore) }, canonicalSha256(envelopeCore),
    [...compactionRefs].sort(), 'openai', 'example');

  const profile = policyProfile();
  addRoot('policy_engine_profile', 'policy', 'policy_engine', profile, profile.profileDigest);
  const system = text('You are a coding assistant.');
  addRoot('system_prompt', 'system', 'system_prompt', system, system.textDigest, [], 'openai', 'example');
  structuredArtifacts.sort((left, right) => Buffer.compare(
    Buffer.from([left.kind, left.provider ?? '', left.model ?? '', left.artifactId].join('\0')),
    Buffer.from([right.kind, right.provider ?? '', right.model ?? '', right.artifactId].join('\0'))));
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'test-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 }, workerProtocolRange: { min: 1, max: 1 },
    entries, structuredArtifacts, guestToolchainManifestRefs: [],
    publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '' };
  signBundle(bundle);
  return { bundle, bytes };
}

async function verify(input: Fixture): Promise<void> {
  await verifyBundleStructuredPayloads(input.bundle, releaseKeys, async (entry) => {
    const value = input.bytes.get(entry.entryId);
    if (!value) throw new Error(`missing fixture bytes: ${entry.entryId}`);
    return value;
  });
}

function replaceRoot(input: Fixture, id: string, value: object, semanticDigest?: string): void {
  const entry = input.bundle.entries.find((candidate) => candidate.entryId === id)!;
  const root = input.bundle.structuredArtifacts.find((candidate) => candidate.rootEntryId === id)!;
  const bytes = canonicalJsonBytes(value);
  input.bytes.set(id, bytes);
  entry.digest = sha256Bytes(bytes);
  entry.byteCount = bytes.byteLength;
  root.artifactRef = entry.digest;
  if (semanticDigest) root.semanticDigest = semanticDigest;
  signBundle(input.bundle);
}

test('signed structured roots and transitive member bytes decode under distinct digest domains', async () => {
  const input = fixture();
  const policy = input.bundle.structuredArtifacts.find((root) => root.kind === 'policy_engine_profile')!;
  assert.notEqual(policy.artifactRef, policy.semanticDigest);
  await verify(input);
});

test('signed byte substitution and semantically invalid re-signed roots fail', async () => {
  const changedMember = fixture();
  const member = changedMember.bundle.entries.find((entry) => entry.role === 'bundle_object')!;
  changedMember.bytes.set(member.entryId, Buffer.from('modified'));
  await assert.rejects(verify(changedMember), /signed bytes/);

  const wrongPolicy = fixture();
  const value = { ...policyProfile(), evaluator: 'attacker-evaluator' };
  const { profileDigest: _old, ...core } = value;
  replaceRoot(wrongPolicy, 'policy', { ...core, profileDigest: canonicalSha256(core) }, canonicalSha256(core));
  await assert.rejects(verify(wrongPolicy), /fixed Supervisor profile/);

  const blankPrompt = fixture();
  const empty = text('');
  replaceRoot(blankPrompt, 'system', empty, empty.textDigest);
  await assert.rejects(verify(blankPrompt), /system prompt is empty/);

  const wrongSemantic = fixture();
  wrongSemantic.bundle.structuredArtifacts.find((root) => root.kind === 'system_prompt')!.semanticDigest = canonicalSha256('wrong');
  signBundle(wrongSemantic.bundle);
  await assert.rejects(verify(wrongSemantic), /semantic digest differs/);
});

test('signed index cannot omit actual compaction or skill members', async () => {
  const missingCompaction = fixture();
  const omitted = missingCompaction.bundle.structuredArtifacts.find((root) => root.kind === 'compaction_prompt')!.memberRefs.pop()!;
  missingCompaction.bundle.entries.splice(missingCompaction.bundle.entries.findIndex((entry) => entry.digest === omitted), 1);
  signBundle(missingCompaction.bundle);
  await assert.rejects(verify(missingCompaction), /member closure/);

  const missingSkill = fixture();
  const skill = missingSkill.bundle.structuredArtifacts.find((root) => root.kind === 'bundled_skill')!;
  skill.memberRefs = [];
  const memberId = identityHash('runtime-bundle-object-v1',
    (JSON.parse(Buffer.from(missingSkill.bytes.get('example-skill')!).toString()) as { files: [{ rawBytesRef: string }] }).files[0].rawBytesRef);
  missingSkill.bundle.entries.splice(missingSkill.bundle.entries.findIndex((entry) => entry.entryId === memberId), 1);
  signBundle(missingSkill.bundle);
  await assert.rejects(verify(missingSkill), /signed object/);
});

test('signed root JSON must be byte-exact canonical encoding', async () => {
  const input = fixture();
  const entry = input.bundle.entries.find((candidate) => candidate.entryId === 'system')!;
  const root = input.bundle.structuredArtifacts.find((candidate) => candidate.rootEntryId === 'system')!;
  const pretty = Buffer.from(JSON.stringify(JSON.parse(Buffer.from(input.bytes.get('system')!).toString()), null, 2));
  input.bytes.set('system', pretty);
  entry.digest = sha256Bytes(pretty);
  entry.byteCount = pretty.byteLength;
  root.artifactRef = entry.digest;
  signBundle(input.bundle);
  await assert.rejects(verify(input), /exact canonical JSON/);
});
