import assert from 'node:assert/strict';
import test from 'node:test';

import type { InstalledControlErrorV1 } from './installed-control.js';
import { decodeInstalledCredentialControlResult } from './installed-credential-client.js';
import { KernelStorageError } from './errors.js';
import { CredentialScopeBusyError } from './installed-runtime.js';

// Pure wire-data conformance only. These values create no authenticated peer,
// installed handle, credential scope or finalization authority.
test('installed credential client preserves the fixed retryable finalizer scope-busy refusal', () => {
  assert.throws(() => decodeInstalledCredentialControlResult({
    protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'RATE_LIMITED', retryable: true,
      retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' }
  }, 'credential.finalize'), error => {
    assert(error instanceof CredentialScopeBusyError);
    assert.deepEqual(error.controlError, { schemaVersion: 1, code: 'RATE_LIMITED', retryable: true,
      retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' });
    assert.equal(Object.hasOwn(error, 'cause'), false);
    return true;
  });
});

const busyRefusal = { protocolVersion: 1, ok: false, method: 'credential.finalize',
  error: { schemaVersion: 1, code: 'RATE_LIMITED', retryable: true,
    retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' } };
for (const { name, response, method = 'credential.finalize' } of [
  { name: 'busy hello', response: { ...busyRefusal, method: 'control.hello' }, method: 'control.hello' },
  { name: 'wrong protocol', response: { ...busyRefusal, protocolVersion: 2 } },
  { name: 'wrong schema', response: { ...busyRefusal, error: { ...busyRefusal.error, schemaVersion: 2 } } },
  { name: 'nonretryable busy', response: { ...busyRefusal, error: { ...busyRefusal.error, retryable: false } } },
  { name: 'another busy reason', response: { ...busyRefusal, error: { ...busyRefusal.error, messageCode: 'untrusted-remote-message' } } },
  ...[0, 999, 1001, Number.MAX_SAFE_INTEGER, '1000', null].map(retryAfterMs => ({
    name: `unsupported busy delay ${JSON.stringify(retryAfterMs)}`,
    response: { ...busyRefusal, error: { ...busyRefusal.error, retryAfterMs } }
  })),
  { name: 'extra busy error data', response: { ...busyRefusal, error: { ...busyRefusal.error, payload: 'untrusted-remote-data' } } },
  { name: 'extra busy envelope data', response: { ...busyRefusal, payload: 'untrusted-remote-data' } }
] as Array<{ name: string; response: unknown; method?: 'control.hello' | 'credential.finalize' }>) {
  test(`installed credential client rejects ${name} instead of importing retry advice`, () => {
    assert.throws(() => decodeInstalledCredentialControlResult(response, method), TypeError);
  });
}

test('installed credential client recognizes a closed request-id conflict as a refusal', () => {
  assert.throws(() => decodeInstalledCredentialControlResult({
    protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'REQUEST_ID_CONFLICT', retryable: false, messageCode: 'control.request_id_conflict' }
  }, 'credential.finalize'), {
    name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
    message: 'installed Supervisor refused the authenticated credential operation'
  });
});

test('installed credential client diagnoses an expired finalizer refusal as terminal recovery', () => {
  assert.throws(() => decodeInstalledCredentialControlResult({
    protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false,
      messageCode: 'credential.finalize.expired' }
  }, 'credential.finalize'), {
    name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
    message: 'installed Supervisor refused expired credential finalization'
  });
});

test('installed credential client diagnoses noncausal finalizer timestamps as terminal recovery', () => {
  assert.throws(() => decodeInstalledCredentialControlResult({
    protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false,
      messageCode: 'credential.finalize.noncausal_time' }
  }, 'credential.finalize'), {
    name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
    message: 'installed Supervisor refused credential finalization because its timestamps are not causal'
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

const genericRefusal = {
  name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', retryable: false,
  message: 'installed Supervisor refused the authenticated credential operation'
};
function assertGenericRefusal(error: unknown): boolean {
  assert(error instanceof KernelStorageError);
  assert.deepEqual({ name: error.name, code: error.code, retryable: error.retryable, message: error.message }, genericRefusal);
  for (const field of ['cause', 'messageCode', 'errorId']) assert.equal(Object.hasOwn(error, field), false);
  return true;
}
const finalizerTimeCodes = ['credential.finalize.noncausal_time', 'credential.finalize.expired'] as const;
for (const messageCode of finalizerTimeCodes) {
  const response = { protocolVersion: 1, ok: false, method: 'credential.finalize',
    error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode } };
  // Each literal retains its required closed variant fields; a recognized text
  // paired with another accepted code must not claim a finalizer time diagnosis.
  for (const error of [...otherRefusals.filter(value => value.code !== 'AUTHORIZATION_REQUIRED'), conflict.error]) {
    test(`installed client ${messageCode} paired with ${error.code} remains generic`, () => {
      assert.throws(() => decodeInstalledCredentialControlResult({ ...response,
        error: { ...error, messageCode } }, 'credential.finalize'), assertGenericRefusal);
    });
  }
  test(`installed hello carrying ${messageCode} remains generic`, () => {
    assert.throws(() => decodeInstalledCredentialControlResult({ ...response,
      method: 'control.hello' }, 'control.hello'), assertGenericRefusal);
  });

  const malformedTimeRefusals = [
    { name: 'wrong protocol', value: { ...response, protocolVersion: 2 } },
    { name: 'wrong actual method', value: { ...response, method: 'control.hello' } },
    { name: 'wrong error schema', value: { ...response, error: { ...response.error, schemaVersion: 2 } } },
    { name: 'retryable response', value: { ...response, error: { ...response.error, retryable: true } } },
    { name: 'unknown wire code', value: { ...response, error: { ...response.error, code: 'REMOTE_REFUSAL' } } },
    { name: 'extra envelope field', value: { ...response, timestamp: 'untrusted-remote-data' } },
    { name: 'extra error payload', value: { ...response, error: { ...response.error, payload: 'untrusted-remote-data' } } },
    { name: 'non-string message code', value: { ...response, error: { ...response.error, messageCode: 1 } } },
    { name: 'empty message code', value: { ...response, error: { ...response.error, messageCode: '' } } },
    { name: 'oversized message code', value: { ...response, error: { ...response.error, messageCode: 'x'.repeat(129) } } },
    { name: 'noncanonical message code', value: { ...response, error: { ...response.error, messageCode: 'e\u0301' } } },
    { name: 'NUL message code', value: { ...response, error: { ...response.error, messageCode: '\u0000' } } },
    { name: 'unpaired-surrogate message code', value: { ...response, error: { ...response.error, messageCode: '\ud800' } } }
  ];
  for (const { name, value } of malformedTimeRefusals) {
    test(`installed client ${messageCode} rejects ${name} before diagnosis`, () => {
      assert.throws(() => decodeInstalledCredentialControlResult(value, 'credential.finalize'), error => {
        assert(error instanceof TypeError);
        assert.equal(Object.hasOwn(error, 'cause'), false);
        assert.equal(error.message.includes('untrusted-remote-data'), false);
        return true;
      });
    });
  }
}

for (const messageCode of ['credential.finalize.future_reason', 'untrusted\n\tmessage', '__proto__']) {
  test(`installed credential unknown canonical message code ${JSON.stringify(messageCode)} remains generic`, () => {
    assert.throws(() => decodeInstalledCredentialControlResult({
      protocolVersion: 1, ok: false, method: 'credential.finalize',
      error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode }
    }, 'credential.finalize'), assertGenericRefusal);
  });
}
