import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  CredentialFinalizationTimeError,
  joinResourceOperations,
  KernelStorageError,
  ResourceRetirementError
} from './errors.js';

test('joinResourceOperations returns fulfilled values in order', async () => {
  const result = await joinResourceOperations([Promise.resolve(1), Promise.resolve('two')] as const);
  assert.deepEqual(result, [1, 'two']);
});

test('joinResourceOperations surfaces an ordinary rejection when no retirement error is present', async () => {
  await assert.rejects(
    () => joinResourceOperations([Promise.resolve(1), Promise.reject(new Error('read failed'))] as const),
    /read failed/
  );
});

test('joinResourceOperations prefers ResourceRetirementError over an earlier ordinary failure', async () => {
  const retirement = new ResourceRetirementError('descriptor cleanup failed', new Error('close failed'));
  await assert.rejects(
    () => joinResourceOperations([
      Promise.reject(new Error('artifact read failed')),
      Promise.reject(retirement)
    ] as const),
    (error: unknown) => error === retirement
  );
});

test('joinResourceOperations surfaces the first ResourceRetirementError when several are present', async () => {
  const first = new ResourceRetirementError('first retirement failure', new Error('a'));
  const second = new ResourceRetirementError('second retirement failure', new Error('b'));
  await assert.rejects(
    () => joinResourceOperations([Promise.reject(first), Promise.reject(second)] as const),
    (error: unknown) => error === first
  );
});

test('CredentialFinalizationTimeError maps to STATE_TRANSITION_INVALID with a closed reason', () => {
  for (const reason of ['noncausal_time', 'expired'] as const) {
    const error = new CredentialFinalizationTimeError(reason);
    assert.equal(error.name, 'CredentialFinalizationTimeError');
    assert.equal(error.reason, reason);
    assert.equal(error.code, 'STATE_TRANSITION_INVALID');
    assert.equal(error.retryable, false);
    assert.ok(error instanceof KernelStorageError);
  }
});
