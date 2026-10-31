import assert from 'node:assert/strict';
import test from 'node:test';

import { CredentialFinalizationTimeError, KernelStorageError } from './errors.js';
import { mapCredentialFinalizeRefusal } from './installed-control.js';

test('mapCredentialFinalizeRefusal exposes closed finalizer time diagnoses on the wire', () => {
  assert.deepEqual(mapCredentialFinalizeRefusal(new CredentialFinalizationTimeError('noncausal_time')), {
    schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'credential.finalize.noncausal_time'
  });
  assert.deepEqual(mapCredentialFinalizeRefusal(new CredentialFinalizationTimeError('expired')), {
    schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'credential.finalize.expired'
  });
});

test('mapCredentialFinalizeRefusal keeps generic credential refusals distinct from time diagnoses', () => {
  assert.deepEqual(mapCredentialFinalizeRefusal(new KernelStorageError('STATE_TRANSITION_INVALID', 'credential endpoint changed')), {
    schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'credential.finalize_refused'
  });
});
