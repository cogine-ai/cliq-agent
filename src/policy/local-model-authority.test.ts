import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { localModelManifestDigest } from '../kernel/local-inference.js';
import { localManifestFixture } from '../state/testing/local-inference-data.js';
import { verifyLocalModelManifestAuthority } from './local-model-authority.js';
import type { RuntimeBundleManifest } from './runtime-authority.js';

test('local model authenticates complete original detached signature and fixed signed bootstrap without a signature cycle', () => {
  const keys = generateKeyPairSync('ed25519'), publisherKeyId = 'local-model-test-publisher';
  const releaseKeys = [{ keyId: publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const entry = (entryId: string, role: string, executable: boolean) => ({ entryId, role, executable, version: '1', relativePath: `fixed/${entryId}`,
    digest: canonicalSha256(entryId), byteCount: 10 });
  const core = { schemaVersion: 1 as const, bundleVersion: '1', controlProtocolRange: { min: 1 as const, max: 1 as const },
    headlessSchemaRange: { min: 3, max: 3 }, stateSchemaRange: { min: 8, max: 8 }, workerProtocolRange: { min: 9, max: 9 },
    entries: [entry('supervisor', 'supervisor', true), entry('worker', 'worker', true), entry('policy', 'policy_engine', false),
      entry('default_https_trust_store', 'trust_store', false), entry('root', 'sandbox_root_profile', false), entry('ollama_local_inference', 'local_inference', true)],
    structuredArtifacts: [], guestToolchainManifestRefs: [], publisherKeyId };
  function bundle(value = core): RuntimeBundleManifest {
    const manifestDigest = canonicalSha256(value);
    return { ...value, manifestDigest, signature: sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`), keys.privateKey).toString('base64') };
  }
  const manifest = localManifestFixture(), digest = localModelManifestDigest(manifest);
  const signatureBytes = sign(null, Buffer.from(`cliq-local-model-manifest-v1\0${digest}`), keys.privateKey);
  const signed = { ...manifest, signatureRef: sha256Bytes(signatureBytes) };
  assert.equal(signed.modelManifestDigest, digest, 'detached signature ref is omitted only from semantic signed core');
  const input = { bundle: bundle(), releaseKeys, manifestBytes: canonicalJsonBytes(signed), signatureBytes };
  assert.deepEqual(verifyLocalModelManifestAuthority(input), signed);
  const different = generateKeyPairSync('ed25519');
  const foreign = sign(null, Buffer.from(`cliq-local-model-manifest-v1\0${digest}`), different.privateKey);
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, manifestBytes: canonicalJsonBytes({ ...signed, signatureRef: sha256Bytes(foreign) }), signatureBytes: foreign }));
  const wrongDomain = sign(null, Buffer.from(`cliq-model-catalog-entry-v1\0${digest}`), keys.privateKey);
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, manifestBytes: canonicalJsonBytes({ ...signed, signatureRef: sha256Bytes(wrongDomain) }), signatureBytes: wrongDomain }));
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, signatureBytes: signatureBytes.subarray(0, 63) }));
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, signatureBytes: Buffer.alloc(64) }));
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, manifestBytes: Buffer.concat([input.manifestBytes, Buffer.from('\n')]) }));
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, bundle: bundle({ ...core,
    entries: core.entries.map(value => value.entryId === 'ollama_local_inference' ? { ...value, role: 'mcp_server' } : value) }) }));
  assert.throws(() => verifyLocalModelManifestAuthority({ ...input, releaseKeys: [{ ...releaseKeys[0]!, publicKeyPem: different.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] }));
});
