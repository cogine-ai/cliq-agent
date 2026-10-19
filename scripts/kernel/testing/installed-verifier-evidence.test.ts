// Data refusal only. No synthetic successful retirement/native proof or
// authority is constructed; physical positives remain the Linux campaigns.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledVerifierRetirement } from './installed-verifier-evidence.js';

test('shared verifier evidence refuses an unclaimed/mismatched attempt before reading retained objects', async () => {
  let reads = 0;
  await assert.rejects(assertInstalledVerifierRetirement({ run: { id: 'data-run', deadlineAt: '2026-10-18T00:01:00.000Z' },
    checkpoints: [], prepared: { phase: 'prepared' }, claim: { phase: 'prepared' }, terminal: { phase: 'completed' },
    requestContext: {}, measurement: {}, readRetainedArtifact: async () => { reads++; throw new Error('private-data-must-not-escape'); },
    readOwnerHistory: async () => { reads++; throw new Error('private-owner-must-not-escape'); } }),
  { message: 'installed verifier retirement evidence refused' });
  assert.equal(reads, 0);
});
