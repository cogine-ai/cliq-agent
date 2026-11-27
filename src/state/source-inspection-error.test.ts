import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodeInstalledControlEnvelope } from '../kernel/control-wire.js';
import { identityHash } from '../kernel/identity.js';
import { KernelStorageError } from './errors.js';
import { createSourceInspectionErrorResponse, assertSourceInspectionErrorResponse } from './source-inspection-error.js';

const inspectionId = identityHash('powerless-source-error-fixture', 'original');
const otherInspectionId = identityHash('powerless-source-error-fixture', 'other');

for (const method of ['run.submit', 'run.apply'] as const) {
  test(`${method} retains one original wire-valid internal correlation without exposing its exception`, () => {
    const response = createSourceInspectionErrorResponse(new Error('must not be copied to the response'), inspectionId, false, method);
    assert.equal(response.error.code, 'INTERNAL');
    assertSourceInspectionErrorResponse(response, inspectionId, method);
    assert.doesNotThrow(() => decodeInstalledControlEnvelope(response, method));
    const retry = createSourceInspectionErrorResponse(new Error('a different exception'), inspectionId, false, method);
    assert.deepEqual(canonicalJsonBytes(retry), canonicalJsonBytes(response));
    assert(!canonicalJsonBytes(response).toString().includes('exception'));
    assert.throws(() => assertSourceInspectionErrorResponse(response, otherInspectionId, method), { code: 'RECOVERY_REQUIRED' });
    assert.throws(() => assertSourceInspectionErrorResponse(response, inspectionId, method === 'run.submit' ? 'run.apply' : 'run.submit'),
      { code: 'RECOVERY_REQUIRED' });
  });
}

for (const [name, error, cancelled, expected] of [
  ['cancelled', new Error('not copied'), true, 'CANCEL_REQUESTED'],
  ['budget', new KernelStorageError('BUDGET_EXHAUSTED', 'not copied'), false, 'BUDGET_EXHAUSTED'],
  ['integrity', new KernelStorageError('ARTIFACT_MISMATCH', 'not copied'), false, 'ARTIFACT_MISMATCH'],
  ['type', new TypeError('not copied'), false, 'INVALID_REQUEST'],
  ['storage', new KernelStorageError('RECOVERY_REQUIRED', 'not copied'), false, 'INVALID_REQUEST'],
] as const) test(`the existing ${name} source refusal remains closed and wire-valid`, () => {
  const response = createSourceInspectionErrorResponse(error, inspectionId, cancelled, 'run.submit');
  assert.equal(response.error.code, expected);
  assertSourceInspectionErrorResponse(response, inspectionId, 'run.submit');
  assert.doesNotThrow(() => decodeInstalledControlEnvelope(response, 'run.submit'));
  assert.throws(() => assertSourceInspectionErrorResponse({ ...response, extra: true }, inspectionId, 'run.submit'),
    { code: 'RECOVERY_REQUIRED' });
  assert.throws(() => assertSourceInspectionErrorResponse({ ...response, error: { ...response.error, raw: 'not allowed' } }, inspectionId, 'run.submit'),
    { code: 'RECOVERY_REQUIRED' });
});
