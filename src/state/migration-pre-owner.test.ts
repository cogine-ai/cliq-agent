import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { assertKernelEntryAllowsStateOwner } from './migration-pre-owner.js';
import { inspectInstalledAccountBeforeOwner } from './installed-account-participant.js';
import { assertHeldMigrationGateOwner, openHeldCurrentMigrationInspector, verifyHeldCurrentMigrationLegacy,
  verifyHeldCurrentKernelArchive, releaseHeldCurrentMigrationLegacyLocks } from './native-owner.js';
import { assertOriginalCompletedKernelArchive } from './kernel-archive.js';
import { assertInstalledCurrentMigrationInspection, inspectInstalledOriginalKernelArchive } from './current-migration-inspection.js';
import { readInstalledCompletedImportUnderShared, readInstalledCompletedImportUnderExclusive } from './migration-history.js';
import { inspectInstalledBorrowMigrationEntry } from './installed-runtime.js';

// Data-only initial control; never an authority marker, physical observation,
// Owner, scope or installed credential. The real RootFD/SH belongs to Linux.
function initial() {
  const data = { schemaVersion: 1, format: 'cliq-migration-control-v1', phase: 'cutover_preflight', migrationId: 'a'.repeat(43),
    controlRevision: 1, sourceGenerationDigest: 'b'.repeat(64), targetGenerationId: 'c'.repeat(43), stateRootIdentityRef: 'd'.repeat(64),
    stateRootIdentityDigest: 'e'.repeat(64), stateRootCanonicalAbsolutePath: '/inert/root', preparationRef: 'f'.repeat(64), preparationDigest: '0'.repeat(64),
    createdAt: '2026-10-02T00:00:00.000Z', updatedAt: '2026-10-02T00:00:00.000Z', controlDigest: '' };
  data.controlDigest = digestOmitting(data, 'controlDigest'); return data;
}
const root = { canonicalAbsolutePath: '/inert/root', identityRef: 'd'.repeat(64), identityDigest: 'e'.repeat(64) };
test('pre-Owner data refuses mismatched or unknown control before returning permission to attempt Owner acquisition', () => {
  const control = canonicalJsonBytes(initial());
  assert.doesNotThrow(() => assertKernelEntryAllowsStateOwner({ kind: 'unmigrated' }, root));
  assert.doesNotThrow(() => assertKernelEntryAllowsStateOwner({ kind: 'controlled', controlBytes: control }, root));
  for (const changed of [{ ...root, identityRef: 'f'.repeat(64) }, { ...root, identityDigest: 'f'.repeat(64) },
    { ...root, canonicalAbsolutePath: '/inert/foreign' }])
    assert.throws(() => assertKernelEntryAllowsStateOwner({ kind: 'controlled', controlBytes: control }, changed), { code: 'RECOVERY_REQUIRED' });
  for (const bytes of [Buffer.concat([control, Buffer.from('\n')]), Buffer.from('{"phase":"rollback_draining"}'),
    Buffer.from('{"private":"do-not-echo","private":"duplicate"}'), Buffer.from([0xc0, 0x80])])
    assert.throws(() => assertKernelEntryAllowsStateOwner({ kind: 'controlled', controlBytes: bytes }, root), error => {
      assert(error instanceof Error); assert(!String(error).includes('do-not-echo')); assert.equal(error.cause, undefined); return true;
    });
});
test('pre-Owner reader friends reject structural tokens before invoking caller code', () => {
  let calls = 0;
  // Existing closed type is deliberately supplied by a Proxy: its traps must
  // never run, because the genuine private issuer is checked first.
  const foreign = new Proxy(Object.create(null), { get() { calls++; throw new Error('caller trap'); } });
  assert.throws(() => inspectInstalledAccountBeforeOwner(foreign, foreign), /original account participant/u);
  assert.throws(() => inspectInstalledBorrowMigrationEntry(foreign, foreign), /genuine active installed borrow/u);
  assert.equal(calls, 0);
});

test('completed import history rejects structural SH/EX and original Owner tokens before touching native/SQL/CAS callbacks', async () => {
  let calls = 0;
  const foreign = new Proxy(Object.create(null), { get() { calls++; throw new Error('caller token trap'); } });
  const context = { filesystem: foreign } as Parameters<typeof readInstalledCompletedImportUnderExclusive>[1];
  const originalOwnerRefusal = (error: unknown) => error instanceof TypeError && error.message === 'migration EX requires its exact original StateOwner holder';
  assert.throws(() => assertHeldMigrationGateOwner(foreign, foreign, foreign), originalOwnerRefusal);
  await assert.rejects(readInstalledCompletedImportUnderExclusive(foreign, context, foreign, foreign, foreign), originalOwnerRefusal);
  await assert.rejects(readInstalledCompletedImportUnderShared(foreign, context, foreign, foreign, foreign),
    (error: unknown) => error instanceof TypeError && error.message === 'installed account participation requires its original holder');
  assert.equal(calls, 0);
});
test('current archive consumers reject copied/structural issuers before reading any supplied data or invoking callbacks', async () => {
  let calls = 0;
  const foreign = new Proxy(Object.create(null), { get() { calls++; throw new Error('caller trap'); } });
  const context = { filesystem: foreign } as Parameters<typeof inspectInstalledOriginalKernelArchive>[2];
  assert.throws(() => openHeldCurrentMigrationInspector(foreign, foreign, foreign, foreign), {
    name: 'TypeError', message: 'migration EX requires its exact original StateOwner holder' });
  await assert.rejects(verifyHeldCurrentMigrationLegacy(foreign, foreign), {
    name: 'TypeError', message: 'current observation requires its genuine native inspector' });
  await assert.rejects(verifyHeldCurrentKernelArchive(foreign, foreign, foreign), {
    name: 'TypeError', message: 'current observation requires its genuine native inspector' });
  assert.throws(() => releaseHeldCurrentMigrationLegacyLocks(foreign), {
    name: 'TypeError', message: 'current observation requires its genuine native inspector' });
  assert.throws(() => assertOriginalCompletedKernelArchive(foreign, foreign, foreign, foreign), {
    name: 'TypeError', message: 'current archive consumer requires its genuine completed original producer' });
  await assert.rejects(inspectInstalledOriginalKernelArchive(foreign, foreign, context, foreign, foreign, foreign), {
    name: 'TypeError', message: 'migration EX requires its exact original StateOwner holder' });
  assert.throws(() => assertInstalledCurrentMigrationInspection(foreign, foreign, foreign, foreign, context), {
    name: 'TypeError', message: 'current migration inspection requires its genuine original Store issuer' });
  assert.equal(calls, 0);
});
test('even well-formed raw draining control refuses before ordinary Owner acquisition without a complete handoff', () => {
  const markerCore = { schemaVersion: 1, format: 'cliq-state-authority-v1', authority: 'kernel', generationId: 'c'.repeat(43),
    migrationId: 'a'.repeat(43), receiptRef: '1'.repeat(64), receiptDigest: '2'.repeat(64), stateRootIdentityRef: root.identityRef,
    stateRootIdentityDigest: root.identityDigest, stateRootCanonicalAbsolutePath: root.canonicalAbsolutePath,
    publishedAt: '2026-10-02T00:00:00.000Z', candidateRef: '3'.repeat(64), candidateDigest: '4'.repeat(64),
    kernelGenerationIdentityRef: '5'.repeat(64), kernelGenerationIdentityDigest: '6'.repeat(64) };
  const marker = { ...markerCore, markerDigest: canonicalSha256(markerCore) };
  const controlCore = { schemaVersion: 1, format: 'cliq-kernel-rollback-control-v1', phase: 'rollback_draining', controlRevision: 1,
    migrationId: marker.migrationId, archiveId: 'b'.repeat(43), kernelGenerationId: marker.generationId,
    stateRootIdentityRef: root.identityRef, stateRootIdentityDigest: root.identityDigest, stateRootCanonicalAbsolutePath: root.canonicalAbsolutePath,
    requestRef: '7'.repeat(64), requestDigest: '8'.repeat(64), originalImportControlRef: '9'.repeat(64), originalImportControlDigest: '0'.repeat(64),
    originalKernelAuthorityRef: canonicalSha256(marker), originalKernelAuthorityDigest: marker.markerDigest, preparedAt: '2026-10-02T00:00:01.000Z' };
  const observation = (change: Record<string, unknown> = {}, authority = marker) => {
    const core = { ...controlCore, ...change };
    return { kind: 'controlled' as const, controlBytes: canonicalJsonBytes({ ...core, controlDigest: canonicalSha256(core) }),
      authorityBytes: canonicalJsonBytes(authority) };
  };
  assert.throws(() => assertKernelEntryAllowsStateOwner(observation(), root), { code: 'RECOVERY_REQUIRED' });
  for (const change of [{ phase: 'rollback_restoring' }, { kernelGenerationId: 'x'.repeat(43) }, { migrationId: 'x'.repeat(43) },
    { originalKernelAuthorityRef: 'f'.repeat(64) }, { originalKernelAuthorityDigest: 'f'.repeat(64) },
    { preparedAt: '2026-10-01T23:59:59.999Z' }, { stateRootIdentityDigest: 'f'.repeat(64) }, { unknown: true }])
    assert.throws(() => assertKernelEntryAllowsStateOwner(observation(change), root), { code: 'RECOVERY_REQUIRED' });
  assert.throws(() => assertKernelEntryAllowsStateOwner({ kind: 'controlled', controlBytes: observation().controlBytes }, root),
    { code: 'RECOVERY_REQUIRED' });
  const { candidateRef: _candidateRef, candidateDigest: _candidateDigest, kernelGenerationIdentityRef: _generationRef,
    kernelGenerationIdentityDigest: _generationDigest, ...common } = markerCore;
  const legacyCore = { ...common, authority: 'legacy', legacyGenerationRef: '7'.repeat(64), legacyGenerationDigest: '8'.repeat(64) };
  const legacy = { ...legacyCore, markerDigest: canonicalSha256(legacyCore) };
  assert.throws(() => assertKernelEntryAllowsStateOwner({ ...observation(), authorityBytes: canonicalJsonBytes(legacy) }, root),
    { code: 'RECOVERY_REQUIRED' });
});
