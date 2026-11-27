import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeLegacyEntryRendezvous } from './legacy-entry.js';
import { KernelStorageError } from './errors.js';

// Inert initial control JSON. No AuthorityMarker, native holder or filesystem
// observation is created; real SH/root/EOF/close belongs to the Linux campaign.
function initial() { const data = { schemaVersion: 1, format: 'cliq-migration-control-v1', phase: 'cutover_preflight', migrationId: 'a'.repeat(43),
  controlRevision: 1, sourceGenerationDigest: 'b'.repeat(64), targetGenerationId: 'c'.repeat(43), stateRootIdentityRef: 'd'.repeat(64),
  stateRootIdentityDigest: 'e'.repeat(64), stateRootCanonicalAbsolutePath: '/inert/root', preparationRef: 'f'.repeat(64), preparationDigest: '0'.repeat(64),
  createdAt: '2026-10-02T00:00:00.000Z', updatedAt: '2026-10-02T00:00:00.000Z', controlDigest: '' };
  data.controlDigest = digestOmitting(data, 'controlDigest'); return data; }
test('initial rendezvous decoder verifies complete canonical bytes and native full-byte hash before returning control data', () => {
  const value = initial(), bytes = canonicalJsonBytes(value), digest = canonicalSha256(value);
  assert.deepEqual(decodeLegacyEntryRendezvous(bytes, digest), value);
  for (const bad of [Buffer.concat([bytes, Buffer.from('\n')]), Buffer.from(JSON.stringify(value, null, 2)),
    Buffer.from('{"format":"first","format":"second"}'), Buffer.from([0xc0, 0x80])])
    assert.throws(() => decodeLegacyEntryRendezvous(bad, digest), error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
  assert.throws(() => decodeLegacyEntryRendezvous(bytes, 'a'.repeat(64)), { code: 'RECOVERY_REQUIRED' });
});
test('malformed rendezvous text cannot escape through public exception messages or causes', () => {
  const marker = 'untrusted-private-looking-text', value = { ...initial(), createdAt: marker }, bytes = canonicalJsonBytes(value);
  assert.throws(() => decodeLegacyEntryRendezvous(bytes, canonicalSha256(value)), error => {
    assert(error instanceof KernelStorageError); assert.equal(error.code, 'RECOVERY_REQUIRED');
    assert(!String(error).includes(marker)); assert.equal(error.cause, undefined); return true;
  });
});
