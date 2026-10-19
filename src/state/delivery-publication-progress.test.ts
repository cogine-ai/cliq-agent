// Retained-data locator checks only. These values create no claim, native birth,
// physical progress or SQL cleanup permission.
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodePublicationArenaBirth, publicationArenaId, type PublicationAbortOperation } from '../kernel/publication.js';
import { publicationEnvelopeLocations } from './delivery-publication-progress.js';

test('an actual claimed abort has exactly one fixed private preimage slot, never a workspace locator', () => {
  const ref = 'a'.repeat(64), operation: PublicationAbortOperation = { index: 0,
    operationId: identityHash('data-only-abort-directory'), kind: 'abort_rmdir', path: 'directory',
    createdByOperationId: identityHash('data-only-directory-creator'), quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } };
  const arenaId = publicationArenaId('data-only-run', operation.operationId, 'data-only-op', 0, 'data-only-dispatch');
  const source = { schemaVersion: 1, format: 'cliq-publication-arena-birth-v1', deliveryRunId: 'data-only-run', deliveryPlanRef: ref,
    workspaceIdentityRef: ref, workspaceIdentityDigest: ref, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, sequence: 'abort', operationIndex: 0, operationId: operation.operationId,
    opId: 'data-only-op', attempt: 0, dispatchId: 'data-only-dispatch', arenaId,
    arenaIdentity: { deviceId: '1', fileId: '2', ownerUid: 501, mode: 448 }, parentIdentity: { deviceId: '1', fileId: '3', ownerUid: 501, mode: 448 },
    observedAt: '2026-10-18T00:00:00.000Z', birthDigest: '' };
  source.birthDigest = digestOmitting(source, 'birthDigest');
  const birth = decodePublicationArenaBirth(source);
  assert.deepEqual(publicationEnvelopeLocations({ birth, operation }), [{ kind: 'publication_arena', arenaId, component: 'preimage' }]);
  assert.deepEqual(publicationEnvelopeLocations({ operation }), []);
});
