import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from './runtime-authority.js';

const keys = generateKeyPairSync('ed25519');
const releaseKeys = [{
  keyId: 'structured-index-test',
  publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString()
}];

function entry(entryId: string, role: string, executable: boolean, digest: string) {
  return { entryId, role, version: '1', relativePath: `test/${entryId}`,
    digest, byteCount: 1, executable };
}

function signBundle(bundle: RuntimeBundleManifest): RuntimeBundleManifest {
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null,
    Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`),
    keys.privateKey).toString('base64');
  return bundle;
}

function fixture(): RuntimeBundleManifest {
  const profile = policyProfile();
  const profileRef = canonicalSha256(profile);
  return signBundle({
    schemaVersion: 1, bundleVersion: 'structured-index-test-v1',
    controlProtocolRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 },
    workerProtocolRange: { min: 1, max: 1 },
    entries: [
      entry('supervisor', 'supervisor', true, canonicalSha256('supervisor')),
      entry('worker', 'worker', true, canonicalSha256('worker')),
      entry('policy', 'policy_engine', false, profileRef),
      entry('default_https_trust_store', 'trust_store', false, canonicalSha256('trust')),
      entry('root-profile', 'sandbox_root_profile', false, canonicalSha256('root'))
    ],
    structuredArtifacts: [{
      kind: 'policy_engine_profile', artifactId: 'policy', rootEntryId: 'policy',
      artifactRef: profileRef, semanticDigest: profile.profileDigest, memberRefs: []
    }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId,
    manifestDigest: '', signature: ''
  });
}

test('signed RuntimeBundle structured index binds roots, members, roles and ordering', () => {
  const valid = fixture();
  assert.doesNotThrow(() => verifyRuntimeBundle(valid, releaseKeys));
  const member = canonicalSha256('member');
  const withMember = structuredClone(valid);
  withMember.structuredArtifacts[0]!.memberRefs = [member];
  withMember.entries.push({
    ...entry(identityHash('runtime-bundle-object-v1', member), 'bundle_object', false, member),
    relativePath: `objects/sha256/${member.slice(0, 2)}/${member}`
  });
  assert.doesNotThrow(() => verifyRuntimeBundle(signBundle(withMember), releaseKeys));

  const ordered = structuredClone(valid);
  const promptRef = canonicalSha256('prompt');
  ordered.entries.push(entry('system', 'system_prompt', false, promptRef));
  ordered.structuredArtifacts.push({
    kind: 'system_prompt', artifactId: 'system', rootEntryId: 'system',
    artifactRef: promptRef, semanticDigest: canonicalSha256('prompt semantics'),
    memberRefs: [], provider: 'openai', model: 'example'
  });
  assert.doesNotThrow(() => verifyRuntimeBundle(signBundle(ordered), releaseKeys));
  ordered.structuredArtifacts.reverse();
  assert.throws(() => verifyRuntimeBundle(signBundle(ordered), releaseKeys));

  const changes: Array<(bundle: RuntimeBundleManifest) => void> = [
    (bundle) => { bundle.structuredArtifacts[0]!.rootEntryId = 'default_https_trust_store'; },
    (bundle) => { bundle.structuredArtifacts[0]!.memberRefs = [member]; },
    (bundle) => { bundle.entries.push({
      ...entry(identityHash('runtime-bundle-object-v1', member), 'bundle_object', false, member),
      relativePath: `objects/sha256/${member.slice(0, 2)}/${member}`
    }); },
    (bundle) => { bundle.guestToolchainManifestRefs = [member]; },
    (bundle) => { (bundle.structuredArtifacts[0] as unknown as Record<string, unknown>).provider = 'openai'; },
    (bundle) => { (bundle.structuredArtifacts[0] as unknown as Record<string, unknown>).kind = 'unknown'; },
    (bundle) => { bundle.structuredArtifacts[0]!.memberRefs = [member, member]; }
  ];
  for (const change of changes) {
    const mutated = structuredClone(valid);
    change(mutated);
    assert.throws(() => verifyRuntimeBundle(signBundle(mutated), releaseKeys));
  }
});

test('signed RuntimeBundle paths reject alternate Unicode and unsafe native components', () => {
  const paths = [
    'test/e\u0301',
    `test/${'a'.repeat(256)}`,
    Array.from({ length: 21 }, () => 'a'.repeat(200)).join('/'),
    'test//supervisor', 'test/../supervisor', '/test/supervisor',
    'test/with\\backslash', 'test/with\0nul'
  ];
  for (const relativePath of paths) {
    const bundle = fixture();
    bundle.entries[0]!.relativePath = relativePath;
    assert.throws(() => verifyRuntimeBundle(signBundle(bundle), releaseKeys),
      /invalid signed RuntimeBundle entry/, JSON.stringify(relativePath));
  }
});
