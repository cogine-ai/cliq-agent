import assert from 'node:assert/strict';
import test from 'node:test';

import type { InstalledControlErrorV1 } from './installed-control.js';
import { decodeInstalledCredentialControlResult } from './installed-credential-client.js';

// Pure wire-data conformance only. These values create no authenticated peer,
// installed handle, credential scope or finalization authority.
test('installed credential client recognizes a closed request-id conflict as a refusal', () => {
  assert.throws(() => decodeInstalledCredentialControlResult({
    protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'REQUEST_ID_CONFLICT', retryable: false, messageCode: 'control.request_id_conflict' }
  }, 'credential.finalize'), {
    name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
    message: 'installed Supervisor refused the authenticated credential operation'
  });
});

// Literal variants from the installed server's closed error union and wire
// projections. Request-id conflict above completes the eight credential codes.
const otherRefusals = [
  { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false, messageCode: 'control.invalid_request',
    issues: [{ path: 'request', issueCode: 'invalid_request' }] },
  { schemaVersion: 1, code: 'INTERNAL', retryable: false, messageCode: 'control.internal',
    errorId: '00000000-0000-4000-8000-000000000001' },
  { schemaVersion: 1, code: 'INCOMPATIBLE_PROTOCOL', retryable: false, messageCode: 'control.incompatible_protocol',
    supportedControlRange: { min: 1, max: 1 }, supportedHeadlessRange: { min: 1, max: 1 }, upgradeAction: 'upgrade_client' },
  { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.read_rejected' },
  { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'credential.finalize_refused' },
  { schemaVersion: 1, code: 'ARTIFACT_MISMATCH', retryable: false, messageCode: 'control.read_rejected' },
  { schemaVersion: 1, code: 'UNSUPPORTED_PLATFORM', retryable: false, messageCode: 'control.read_rejected' }
] satisfies InstalledControlErrorV1[];

for (const error of otherRefusals) {
  test(`installed credential client recognizes a closed ${error.code} as a refusal`, () => {
    assert.throws(() => decodeInstalledCredentialControlResult({
      protocolVersion: 1, ok: false, method: 'credential.finalize', error
    }, 'credential.finalize'), {
      name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
      message: 'installed Supervisor refused the authenticated credential operation'
    });
  });
}

const conflict = { protocolVersion: 1, ok: false, method: 'credential.finalize',
  error: { schemaVersion: 1, code: 'REQUEST_ID_CONFLICT', retryable: false, messageCode: 'control.request_id_conflict' } };
const malformed = [
  { name: 'unknown refusal code', response: { ...conflict, error: { ...conflict.error, code: 'REMOTE_REFUSAL' } } },
  { name: 'extra response field', response: { ...conflict, payload: 'untrusted remote bytes' } },
  { name: 'extra error field', response: { ...conflict, error: { ...conflict.error, payload: 'untrusted remote bytes' } } },
  { name: 'wrong response method', response: { ...conflict, method: 'control.hello' } },
  { name: 'wrong protocol version', response: { ...conflict, protocolVersion: 2 } },
  { name: 'wrong error schema', response: { ...conflict, error: { ...conflict.error, schemaVersion: 2 } } },
  { name: 'retryable conflict', response: { ...conflict, error: { ...conflict.error, retryable: true } } },
  { name: 'empty message code', response: { ...conflict, error: { ...conflict.error, messageCode: '' } } }
];
for (const { name, response } of malformed) {
  test(`installed credential client rejects ${name}`, () => {
    assert.throws(() => decodeInstalledCredentialControlResult(response, 'credential.finalize'), TypeError);
  });
}

test('installed credential refusal diagnostics do not import remote message codes or error ids', () => {
  assert.throws(() => decodeInstalledCredentialControlResult({
    protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'INTERNAL', retryable: false,
      messageCode: 'untrusted-remote-message', errorId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }
  }, 'credential.finalize'), {
    name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
    message: 'installed Supervisor refused the authenticated credential operation'
  });
});
