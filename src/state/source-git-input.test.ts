import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodeSourceGitInputIntent, readSourceGitInputIntent } from './source-git-input.js';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';

const ref = 'a'.repeat(64), other = 'b'.repeat(64);
function intent() {
  const value = { schemaVersion: 2, format: 'cliq-source-inspection-input-v2',
    inspectionId: identityHash('source-input-fixture'), targetRef: ref, targetDigest: other,
    repositoryIdentityDigest: ref, inspectionGrantId: identityHash('source-grant-fixture'),
    inspectionReceiptRef: ref, inspectionReceiptDigest: other, recipe: 'cliq-source-git-inspection-v1',
    snapshotPolicy: 'ephemeral_native_sealed_shards', resources: { ...DEFAULT_SANDBOX_RESOURCES }, inputDigest: '' };
  value.inputDigest = digestOmitting(value, 'inputDigest'); return value;
}

test('source Git prepared input is immutable authorized intent, never a completed snapshot or native capability', () => {
  const value = intent(), result = decodeSourceGitInputIntent(value);
  assert.deepEqual(result, value); assert.equal(canonicalSha256(result), canonicalSha256(value));
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.resources));
  value.resources.maxProcesses = 1;
  assert.equal(result.resources.maxProcesses, DEFAULT_SANDBOX_RESOURCES.maxProcesses);
  for (const key of ['entriesRef', 'treeDigest', 'objectFormat', 'snapshotDigest', 'byteCount', 'native', 'fd', 'sourcePath']) {
    const bad = { ...intent(), [key]: ref, inputDigest: '' }; bad.inputDigest = digestOmitting(bad, 'inputDigest');
    assert.throws(() => decodeSourceGitInputIntent(bad), TypeError);
  }
});

test('source Git input rejects forged versions, missing consent, partial resources, getters and proxies without observing them', () => {
  const original = intent();
  for (const change of [{ schemaVersion: 1 }, { format: 'cliq-source-inspection-input-v1' },
    { recipe: 'caller_recipe' }, { snapshotPolicy: 'durable_raw_cas' }, { inspectionGrantId: '' },
    { inspectionReceiptRef: true }, { resources: {} }, { resources: { ...original.resources, maxOpenFiles: 8193 } },
    { resources: { ...original.resources, extra: 1 } }, { targetRef: other }, { inputDigest: other }]) {
    const value = { ...original, ...change };
    // Keep the target mutation's old digest: a content identity mismatch is not
    // repaired by this reader. Other closed-shape mutations get a valid digest.
    if (!Object.hasOwn(change, 'targetRef') && !Object.hasOwn(change, 'inputDigest')) value.inputDigest = digestOmitting(value, 'inputDigest');
    assert.throws(() => decodeSourceGitInputIntent(value), TypeError);
  }
  let calls = 0;
  const getter = { ...original }; Object.defineProperty(getter, 'targetRef', { enumerable: true, get() { calls++; return ref; } });
  assert.throws(() => decodeSourceGitInputIntent(getter), TypeError);
  const hidden = { ...original }; Object.defineProperty(hidden, 'hidden', { value: true });
  assert.throws(() => decodeSourceGitInputIntent(hidden), TypeError);
  const symbol = { ...original, [Symbol('private')]: true };
  assert.throws(() => decodeSourceGitInputIntent(symbol), TypeError);
  const proxy = new Proxy(original, { get() { calls++; throw new Error('must not be observed'); },
    getPrototypeOf() { calls++; throw new Error('must not be observed'); }, ownKeys() { calls++; throw new Error('must not be observed'); } });
  assert.throws(() => decodeSourceGitInputIntent(proxy), TypeError);
  const resourceGetter = { ...original, resources: { ...original.resources } };
  Object.defineProperty(resourceGetter.resources, 'maxProcesses', { enumerable: true, get() { calls++; return 1; } });
  assert.throws(() => decodeSourceGitInputIntent(resourceGetter), TypeError);
  assert.equal(calls, 0);
});

test('source Git intent reopening keeps the real one-MiB and strict-JSON gates before returning only immutable data', async () => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-intent-cas-'));
  try {
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(directory)), expected = intent();
    const original = await artifacts.publishCanonical(expected, expected.format);
    assert.deepEqual(await readSourceGitInputIntent(new ArtifactCatalog(new ContentAddressedStore(directory)), original.ref), expected);
    const canonical = canonicalJsonBytes(expected).toString();
    for (const bytes of [Buffer.from(`${canonical}\n`), Buffer.from(canonical.replace('{', '{"schemaVersion":2,')),
      Buffer.from(`{"padding":"${'x'.repeat(1_048_576)}"}`)]) {
      const malformed = await artifacts.publishBytes(bytes, 'application/json', 'own-invalid-source-intent');
      await assert.rejects(readSourceGitInputIntent(artifacts, malformed.ref));
    }
    const abort = new AbortController(), reason = new Error('own intent read cancelled'); abort.abort(reason);
    await assert.rejects(readSourceGitInputIntent(artifacts, original.ref, abort.signal), error => error === reason);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
