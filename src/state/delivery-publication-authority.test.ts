// Refusals at a retained-data boundary, not publication/native qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readPublicationClaimHistory, validatePublicationInvocationHistory } from './delivery-publication-authority.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';

test('publication history never treats caller native/parent fields or another Run kind as a claim', async () => {
  const driver = undefined as unknown as SqliteDriver, artifacts = undefined as unknown as ArtifactCatalog;
  const agent = { runSpec: { operation: 'agent' } } as RecoveryClosureV1;
  await assert.rejects(readPublicationClaimHistory(driver, artifacts, agent, { opId: 'operation', attempt: 0 }), /delivery/);
  const delivery = { runSpec: { operation: 'delivery' } } as RecoveryClosureV1;
  for (const input of [{ opId: 'operation', attempt: 1 }, { opId: 'operation', attempt: 0, parentIdentities: [] },
    { opId: 'operation', attempt: 0, assertCurrent: () => {} }])
    await assert.rejects(readPublicationClaimHistory(driver, artifacts, delivery, input), /exact original/);
});

test('publication recovery refuses every orphan claimed or terminal operation before accepting a history', async () => {
  // Untrusted retained data only; no SQL rows, claim or positive proof minted.
  for (const phase of ['dispatch_claimed', 'completed', 'unknown', 'failed']) {
    const cut = { runSpec: { operation: 'delivery' }, journal: [{ opKind: 'publish', opId: 'orphan', phase }] } as unknown as RecoveryClosureV1;
    await assert.rejects(validatePublicationInvocationHistory(undefined as unknown as SqliteDriver,
      undefined as unknown as ArtifactCatalog, cut), /original preparation/);
  }
});
