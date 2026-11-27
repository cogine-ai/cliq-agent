// Closed retained data only, not a held root, read permission or native proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { digestOmitting } from '../kernel/identity.js';

const descriptor = () => ({ schemaVersion: 2, format: 'cliq-repository-identity-v2', platform: 'linux',
  gitDirectoryRelativePath: '.git', gitDirectoryIdentity: { deviceId: '12', fileId: '34', ownerUid: 1001 }, repositoryIdentityDigest: '' });
function seal<T extends { repositoryIdentityDigest: string }>(value: T): T {
  value.repositoryIdentityDigest = digestOmitting(value, 'repositoryIdentityDigest'); return value;
}

test('repository identity V2 records only descriptors and keeps complete V1 historical semantics distinct', async () => {
  const module = await import('./repository-identity.js').catch(() => undefined);
  assert.equal(typeof module?.decodeRepositoryIdentity, 'function', 'a versioned closed repository decoder is required');
  const decode = module!.decodeRepositoryIdentity, input = seal(descriptor()), result = decode(input);
  assert.deepEqual(result, input); assert.notEqual(result, input);
  assert(Object.isFrozen(result) && Object.isFrozen(result.gitDirectoryIdentity));
  assert.equal(Object.hasOwn(result, 'objectFormat'), false);
  input.gitDirectoryIdentity.fileId = '56'; assert.equal(result.gitDirectoryIdentity.fileId, '34');
  for (const objectFormat of ['sha1', 'sha256']) {
    const original = seal({ ...descriptor(), schemaVersion: 1, format: 'cliq-repository-identity-v1', objectFormat });
    assert.deepEqual(decode(original), original);
  }
  for (const changed of [
    { ...descriptor(), objectFormat: 'sha1' },
    { ...descriptor(), schemaVersion: 1, format: 'cliq-repository-identity-v1' },
    { ...descriptor(), schemaVersion: 2, format: 'cliq-repository-identity-v1', objectFormat: 'sha1' },
    { ...descriptor(), gitDirectoryRelativePath: '../.git' },
    { ...descriptor(), gitDirectoryIdentity: { ...descriptor().gitDirectoryIdentity, fileId: '034' } },
    { ...descriptor(), gitDirectoryIdentity: { ...descriptor().gitDirectoryIdentity, ownerUid: -1 } },
    { ...descriptor(), config: 'raw inert configuration must not be retained' },
  ]) assert.throws(() => decode(seal(changed)));
  assert.throws(() => decode({ ...seal(descriptor()), repositoryIdentityDigest: 'a'.repeat(64) }));
});

test('repository identity rejects hidden fields, accessors and proxies without observing them', async () => {
  const module = await import('./repository-identity.js').catch(() => undefined);
  assert.equal(typeof module?.decodeRepositoryIdentity, 'function');
  const decode = module!.decodeRepositoryIdentity; let calls = 0;
  const getter = Object.defineProperty(seal(descriptor()), 'platform', { enumerable: true, get() { calls++; return 'linux'; } });
  const hidden = Object.defineProperty(seal(descriptor()), 'hidden', { value: true });
  const symbol = Object.assign(seal(descriptor()), { [Symbol('foreign')]: true });
  const proxy = new Proxy(seal(descriptor()), { getPrototypeOf() { calls++; return Object.prototype; }, ownKeys() { calls++; return []; } });
  for (const value of [getter, hidden, symbol, proxy]) assert.throws(() => decode(value));
  assert.equal(calls, 0);
});
