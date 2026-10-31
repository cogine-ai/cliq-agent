import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CredentialFinalizationTimeError,
  joinResourceOperations,
  KernelStorageError,
  ResourceRetirementError
} from './errors.js';

test('joinResourceOperations returns fulfilled values in order', async () => {
  const result = await joinResourceOperations([Promise.resolve(1), Promise.resolve('a')] as const);
  assert.deepEqual(result, [1, 'a']);
});

test('joinResourceOperations prefers ResourceRetirementError over an earlier rejection', async () => {
  const retirement = new ResourceRetirementError('descriptor retirement is uncertain', new Error('cause'));
  await assert.rejects(joinResourceOperations([
    Promise.reject(new KernelStorageError('NOT_FOUND', 'missing')),
    Promise.reject(retirement)
  ] as const), retirement);
});

test('joinResourceOperations throws the first failure when no ResourceRetirementError is present', async () => {
  const first = new KernelStorageError('NOT_FOUND', 'first');
  await assert.rejects(joinResourceOperations([
    Promise.reject(first),
    Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'second'))
  ] as const), first);
});

test('CredentialFinalizationTimeError preserves its reason for wire diagnosis', () => {
  for (const reason of ['noncausal_time', 'expired'] as const) {
    const error = new CredentialFinalizationTimeError(reason);
    assert.equal(error.reason, reason);
    assert.equal(error.code, 'STATE_TRANSITION_INVALID');
    assert.equal(error.name, 'CredentialFinalizationTimeError');
    assert.equal(error.retryable, false);
  }
});
