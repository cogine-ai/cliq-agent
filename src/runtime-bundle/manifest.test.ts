import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';

import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeSignedRuntimeBundle, verifySignedRuntimeBundlePayloads } from './manifest.js';

const keys = generateKeyPairSync('ed25519');
const releaseKeys = [{ keyId: 'manifest-test',
  publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];

function fixture(): Buffer {
  const profile = policyProfile();
  const profileBytes = canonicalJsonBytes(profile);
  const entry = (entryId: string, role: string, executable: boolean, digest: string, byteCount: number) => ({
    entryId, role, version: '1', relativePath: `payload/${entryId}`,
    digest, byteCount, executable
  });
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'manifest-test-v1',
    controlProtocolRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 },
    workerProtocolRange: { min: 1, max: 1 },
    entries: [
      entry('supervisor', 'supervisor', true, canonicalSha256('supervisor'), 1),
      entry('worker', 'worker', true, canonicalSha256('worker'), 1),
      entry('policy', 'policy_engine', false, sha256Bytes(profileBytes), profileBytes.byteLength),
      entry('default_https_trust_store', 'trust_store', false, canonicalSha256('trust'), 1),
      entry('root-profile', 'sandbox_root_profile', false, canonicalSha256('root'), 1)
    ],
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy',
      rootEntryId: 'policy', artifactRef: sha256Bytes(profileBytes),
      semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId,
    manifestDigest: '', signature: ''
  };
  const { manifestDigest: _digest, signature: _signature, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`),
    keys.privateKey).toString('base64');
  return canonicalJsonBytes(bundle);
}

test('signed RuntimeBundle decoder binds complete canonical bytes and freezes the verified graph', () => {
  const bytes = fixture();
  const decoded = decodeSignedRuntimeBundle(bytes, releaseKeys);
  assert.equal(decoded.bundleRef, sha256Bytes(bytes));
  assert.notEqual(decoded.bundleRef, decoded.bundle.manifestDigest);
  assert.equal(Object.isFrozen(decoded.bundle), true);
  assert.equal(Object.isFrozen(decoded.bundle.entries[0]), true);
  assert.equal(Object.isFrozen(decoded.bundle.structuredArtifacts[0]?.memberRefs), true);
  bytes.fill(0);
  assert.equal(decoded.bundle.bundleVersion, 'manifest-test-v1');
});

test('signed RuntimeBundle decoder rejects noncanonical encoding, invalid UTF-8 and untrusted keys', () => {
  const bytes = fixture();
  assert.throws(() => decodeSignedRuntimeBundle(Buffer.from(JSON.stringify(JSON.parse(bytes.toString()), null, 2)),
    releaseKeys), /byte-exact canonical/);
  assert.throws(() => decodeSignedRuntimeBundle(Buffer.from([0xff, 0xfe]), releaseKeys), /UTF-8 JSON/);
  assert.throws(() => decodeSignedRuntimeBundle(bytes, []), /trusted release signature/);
  const changed = JSON.parse(bytes.toString()) as RuntimeBundleManifest;
  changed.bundleVersion = 'substituted';
  assert.throws(() => decodeSignedRuntimeBundle(canonicalJsonBytes(changed), releaseKeys), /identity mismatch/);
});

test('package gate requires the signed structured root bytes after manifest decoding', async () => {
  const bytes = fixture();
  const expected = canonicalJsonBytes(policyProfile());
  const accepted = await verifySignedRuntimeBundlePayloads(bytes, releaseKeys, async (entry) => {
    if (entry.entryId !== 'policy') throw new Error('unexpected structured root');
    return expected;
  });
  assert.equal(accepted.bundleRef, sha256Bytes(bytes));
  await assert.rejects(verifySignedRuntimeBundlePayloads(bytes, releaseKeys, async () => Buffer.from('wrong')),
    /signed bytes/);
});
