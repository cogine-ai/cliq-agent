import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CredentialFinalizationTimeError, InstalledModelAuthorizationError, KernelStorageError, ModelRetryPendingError,
  ResourceRetirementError, RunTerminalError, isKernelStorageError, joinResourceOperations, stateOperation
} from './errors.js';

test('isKernelStorageError recognizes storage errors and rejects structural lookalikes', () => {
  assert.equal(isKernelStorageError(new KernelStorageError('INVALID_REQUEST', 'bad')), true);
  assert.equal(isKernelStorageError(new RunTerminalError()), true);
  assert.equal(isKernelStorageError(new CredentialFinalizationTimeError('expired')), true);
  assert.equal(isKernelStorageError(new InstalledModelAuthorizationError()), true);
  assert.equal(isKernelStorageError(new ModelRetryPendingError(2, '2026-01-01T00:00:00.000Z')), true);
  assert.equal(isKernelStorageError(new ResourceRetirementError('cleanup', new Error('cause'))), true);
  assert.equal(isKernelStorageError(new TypeError('validation')), false);
  assert.equal(isKernelStorageError({ code: 'INVALID_REQUEST', name: 'KernelStorageError' }), false);
});

test('stateOperation maps TypeError and SyntaxError to KernelStorageError at the state seam', async () => {
  const invalid = stateOperation('INVALID_REQUEST', async () => { throw new TypeError('shape'); });
  const recovery = stateOperation('RECOVERY_REQUIRED', async () => { throw new SyntaxError('parse'); });
  const fenced = stateOperation('INVALID_REQUEST', async () => { throw new KernelStorageError('LEASE_FENCED', 'fenced'); });
  await assert.rejects(invalid(), error => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST' && error.cause instanceof TypeError);
  await assert.rejects(recovery(), error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED' && error.cause instanceof SyntaxError);
  await assert.rejects(fenced(), error => error instanceof KernelStorageError && error.code === 'LEASE_FENCED');
  const ok = stateOperation('INVALID_REQUEST', async (value: number) => value * 2);
  assert.equal(await ok(21), 42);
});

test('joinResourceOperations prefers ResourceRetirementError over other read failures', async () => {
  const retirement = new ResourceRetirementError('descriptor', new Error('close'));
  const read = new KernelStorageError('ARTIFACT_MISMATCH', 'missing');
  await assert.rejects(joinResourceOperations([
    Promise.resolve(1), Promise.reject(retirement), Promise.reject(read)
  ]), error => error === retirement);
  await assert.rejects(joinResourceOperations([
    Promise.resolve('a'), Promise.reject(read)
  ]), error => error === read);
  assert.deepEqual(await joinResourceOperations([Promise.resolve(1), Promise.resolve(2)]), [1, 2]);
});

test('fixed storage error subclasses retain their closed codes and names', () => {
  const terminal = new RunTerminalError();
  assert.equal(terminal.code, 'STATE_TRANSITION_INVALID');
  assert.equal(terminal.name, 'RunTerminalError');
  const time = new CredentialFinalizationTimeError('noncausal_time');
  assert.equal(time.reason, 'noncausal_time');
  assert.equal(time.name, 'CredentialFinalizationTimeError');
  const auth = new InstalledModelAuthorizationError();
  assert.equal(auth.name, 'InstalledModelAuthorizationError');
  const retry = new ModelRetryPendingError(3, '2026-06-01T00:00:00.000Z');
  assert.equal(retry.nextAttempt, 3);
  assert.equal(retry.code, 'MODEL_RETRY_PENDING');
});