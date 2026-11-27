import { types } from 'node:util';
import type { RepositoryIdentity } from '../kernel/types.js';
import { digestOmitting } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';

const reject = (): never => { throw new TypeError('repository identity has an invalid closed schema'); };
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return reject();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') return reject();
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (!property.enumerable || !Object.hasOwn(property, 'value')) return reject();
  }
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) reject();
}

/** Closed immutable data, not permission to open Git or native ownership. */
export function decodeRepositoryIdentity(value: unknown): RepositoryIdentity {
  const data = record(value), historical = data.schemaVersion === 1 && data.format === 'cliq-repository-identity-v1';
  if (!historical && !(data.schemaVersion === 2 && data.format === 'cliq-repository-identity-v2')) return reject();
  exact(data, ['schemaVersion', 'format', 'platform', 'gitDirectoryRelativePath', 'gitDirectoryIdentity',
    'repositoryIdentityDigest', ...(historical ? ['objectFormat'] : [])]);
  const directory = record(data.gitDirectoryIdentity); exact(directory, ['deviceId', 'fileId', 'ownerUid']);
  if ((data.platform !== 'linux' && data.platform !== 'macos') || data.gitDirectoryRelativePath !== '.git' ||
      [directory.deviceId, directory.fileId].some(value => typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(value)) ||
      !Number.isSafeInteger(directory.ownerUid) || (directory.ownerUid as number) < 0 ||
      (historical && data.objectFormat !== 'sha1' && data.objectFormat !== 'sha256') ||
      typeof data.repositoryIdentityDigest !== 'string' || !/^[0-9a-f]{64}$/u.test(data.repositoryIdentityDigest) ||
      data.repositoryIdentityDigest !== digestOmitting(data, 'repositoryIdentityDigest')) return reject();
  return immutableSnapshot(data as RepositoryIdentity);
}
