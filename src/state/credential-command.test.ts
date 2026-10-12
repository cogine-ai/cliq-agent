import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeCredentialWriteRequest, type CredentialWriteRequest } from './store.js';

// Shape-only metadata examples: neither decoding nor these values establishes
// installed authentication, producer lifetime, platform storage or authority.
const enroll = { schemaVersion: 1, kind: 'enroll', requestId: '019a0012-0000-7000-8000-0000000000af',
  credentialGrantId: 'grant', purpose: 'model_endpoint', endpointRegistrationId: 'endpoint',
  secretSubmissionId: 'submission' } satisfies CredentialWriteRequest;
const rotate = { schemaVersion: 1, kind: 'rotate', requestId: '019a0012-0000-7000-8000-0000000000b0',
  credentialGrantId: 'grant', expectedAuthorityRevision: 1, secretSubmissionId: 'rotation-submission' } satisfies CredentialWriteRequest;

test('credential write metadata accepts only the closed enroll and rotate variants', () => {
  for (const value of [enroll, rotate, { ...rotate, expectedAuthorityRevision: Number.MAX_SAFE_INTEGER - 1 },
    { ...enroll, credentialGrantId: 'é'.repeat(128), secretSubmissionId: 'é'.repeat(128), endpointRegistrationId: 'é'.repeat(2048) }])
    assert.deepEqual(decodeCredentialWriteRequest(value), value);
  for (const purpose of ['model_endpoint', 'dependency_registry', 'mcp_streamable_http'] as const)
    assert.deepEqual(decodeCredentialWriteRequest({ ...enroll, purpose }), { ...enroll, purpose });
  const plain = Object.assign(Object.create(null), rotate);
  assert.deepEqual(decodeCredentialWriteRequest(plain), rotate);
});

test('credential writes reject missing members, schema drift and non-object metadata', () => {
  for (const value of [undefined, null, false, 1, 'enroll', [], new Date(), Object.create({ ...enroll })])
    assert.throws(() => decodeCredentialWriteRequest(value), TypeError);
  for (const value of [enroll, rotate]) {
    for (const key of Object.keys(value)) {
      const missing: Record<string, unknown> = { ...value }; delete missing[key];
      assert.throws(() => decodeCredentialWriteRequest(missing), TypeError, `missing ${value.kind}.${key}`);
    }
    for (const schemaVersion of [undefined, null, '1', 0, 2])
      assert.throws(() => decodeCredentialWriteRequest({ ...value, schemaVersion }), TypeError);
    for (const kind of [undefined, null, 'read', 'revoke', 'cleanup', 'ENROLL'])
      assert.throws(() => decodeCredentialWriteRequest({ ...value, kind }), TypeError);
  }
  for (const purpose of [undefined, null, '', 'model', 'MODEL_ENDPOINT'])
    assert.throws(() => decodeCredentialWriteRequest({ ...enroll, purpose }), TypeError);
});

test('credential write metadata cannot inject authority, secret or opposite-variant fields', () => {
  const forbidden = ['ownerPrincipalId', 'principalId', 'channelIdentityRef', 'channelIdentityDigest', 'processIdentity', 'pid',
    'externalSubject', 'externalSubjectDigest', 'platformItem', 'commandCore', 'commandDigest', 'credentialTargetDigest',
    'createdAt', 'secret', 'verified', 'unknown'];
  for (const value of [enroll, rotate]) {
    for (const key of forbidden)
      assert.throws(() => decodeCredentialWriteRequest({ ...value, [key]: 'not-authority' }), TypeError, `${value.kind}.${key}`);
    assert.throws(() => decodeCredentialWriteRequest({ ...value, [Symbol('unknown')]: true }), TypeError);
    const hidden = Object.defineProperty({ ...value }, 'unknown', { value: true });
    assert.throws(() => decodeCredentialWriteRequest(hidden), TypeError);
  }
  assert.throws(() => decodeCredentialWriteRequest({ ...enroll, expectedAuthorityRevision: 1 }), TypeError);
  assert.throws(() => decodeCredentialWriteRequest({ ...rotate, purpose: 'model_endpoint' }), TypeError);
  assert.throws(() => decodeCredentialWriteRequest({ ...rotate, endpointRegistrationId: 'endpoint' }), TypeError);
});

test('credential ids are nonempty canonical bounded UTF-8 and request ids are lowercase UUIDv7', () => {
  for (const value of [enroll, rotate]) {
    const keys = ['requestId', 'credentialGrantId', 'secretSubmissionId', ...(value.kind === 'enroll' ? ['endpointRegistrationId'] : [])];
    for (const key of keys) {
      for (const invalid of [undefined, null, 1, '', 'nul\0id', 'e\u0301', '\ud800', '\udc00'])
        assert.throws(() => decodeCredentialWriteRequest({ ...value, [key]: invalid }), TypeError, `${value.kind}.${key}`);
      const oversized = 'é'.repeat(key === 'endpointRegistrationId' ? 2049 : 129);
      assert.throws(() => decodeCredentialWriteRequest({ ...value, [key]: oversized }), TypeError, `${key} byte bound`);
    }
    for (const requestId of ['019a0012-0000-4000-8000-0000000000af', '019a0012-0000-7000-c000-0000000000af',
      '019A0012-0000-7000-8000-0000000000AF', '019a00120000700080000000000000af', 'not-a-uuid'])
      assert.throws(() => decodeCredentialWriteRequest({ ...value, requestId }), TypeError, requestId);
  }
});

test('rotation expected revision is positive, safe and leaves room for the next revision', () => {
  for (const expectedAuthorityRevision of [undefined, null, false, '1', 0, -0, -1, 1.5, NaN, Infinity,
    Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, 1n])
    assert.throws(() => decodeCredentialWriteRequest({ ...rotate, expectedAuthorityRevision }), TypeError);
});

test('optional expiry uses exact canonical UTC milliseconds without a decoder clock gate', () => {
  for (const value of [enroll, rotate]) {
    for (const expiresAt of ['1970-01-01T00:00:00.000Z', '2000-02-29T12:00:00.000Z',
      '2099-01-01T00:00:00.000Z', '9999-12-31T23:59:59.999Z'])
      assert.deepEqual(decodeCredentialWriteRequest({ ...value, expiresAt }), { ...value, expiresAt });
    for (const expiresAt of [undefined, null, 1, '', '2099-01-01T00:00:00Z', '2099-01-01T00:00:00.0000Z',
      '2099-01-01T00:00:00.000+00:00', '2099-01-01T00:00:00.000z', '2099-01-01T24:00:00.000Z',
      '2099-01-01T00:00:60.000Z', '2099-02-29T00:00:00.000Z', '1969-12-31T23:59:59.999Z', '10000-01-01T00:00:00.000Z'])
      assert.throws(() => decodeCredentialWriteRequest({ ...value, expiresAt }), TypeError);
  }
});

test('decoded credential write metadata retains an immutable copy without freezing the caller', () => {
  for (const value of [enroll, rotate]) {
    const caller: Record<string, unknown> = { ...value, expiresAt: '2099-01-01T00:00:00.000Z' };
    const expected = { ...caller }, retained = decodeCredentialWriteRequest(caller);
    assert.notEqual(retained, caller); assert.deepEqual(caller, expected); assert.equal(Object.isFrozen(caller), false);
    caller.credentialGrantId = 'changed'; caller.secretSubmissionId = 'changed'; caller.kind = 'read';
    caller.expiresAt = '1970-01-01T00:00:00.000Z'; caller.expectedAuthorityRevision = 2;
    assert.deepEqual(retained, expected); assert.equal(Object.isFrozen(retained), true);
    assert.throws(() => { (retained as { credentialGrantId: string }).credentialGrantId = 'changed'; }, TypeError);
    assert.throws(() => Object.defineProperty(retained, 'unknown', { value: true }), TypeError);
    assert.deepEqual(retained, expected);
  }
});
