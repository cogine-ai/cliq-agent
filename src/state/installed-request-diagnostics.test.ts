// Pure diagnostic data and real rejection checks. These are not an installed
// connection, native authentication, source inspection or Linux qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { beginInstalledRequestDiagnostic, classifyInstalledRequestError, decodeInstalledRequestFailure,
  observeInstalledRequestFailures, type InstalledRequestFailure } from './installed-request-diagnostics.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertCurrentControlFrame } from './control-channel.js';
import { decodeInstalledControlResponse } from '../kernel/control-wire.js';

test('request diagnosis is absent without an observer and contains each synchronous observer failure', () => {
  assert.equal(beginInstalledRequestDiagnostic('run.get'), undefined);
  const observed: InstalledRequestFailure[] = [];
  const closeThrowing = observeInstalledRequestFailures(() => { throw new Error('observer failure must stay local'); });
  const close = observeInstalledRequestFailures(value => { observed.push(value); });
  try {
    const original = new KernelStorageError('ARTIFACT_MISMATCH', 'not emitted');
    const diagnosis = beginInstalledRequestDiagnostic('run.get')!;
    diagnosis.at('pre_current'); diagnosis.failure(original); diagnosis.failure(new Error('later failure'));
    assert.deepEqual(observed, [{ method: 'run.get', boundary: 'pre_current', kind: 'kernel_storage', code: 'ARTIFACT_MISMATCH' }]);
    assert(Object.isFrozen(observed[0]));
  } finally { close(); closeThrowing(); }
  assert.equal(beginInstalledRequestDiagnostic('run.get'), undefined);
});

test('an observer registered during failure delivery waits for the next independent observation', () => {
  const seen: string[] = [];
  let closeLater: (() => void) | undefined;
  const later = () => { seen.push('later'); };
  const close = observeInstalledRequestFailures(() => {
    seen.push('original'); closeLater ??= observeInstalledRequestFailures(later);
  });
  try {
    beginInstalledRequestDiagnostic('run.get')!.failure(new TypeError('not emitted'));
    assert.deepEqual(seen, ['original']);
    beginInstalledRequestDiagnostic('run.get')!.failure(new TypeError('not emitted'));
    assert.deepEqual(seen, ['original', 'original', 'later']);
  } finally { close(); closeLater?.(); }
  assert.equal(beginInstalledRequestDiagnostic('run.get'), undefined);
});

test('real current-frame rejection and strict response rejection retain their executed boundary and original Error', () => {
  const observed: InstalledRequestFailure[] = [];
  const close = observeInstalledRequestFailures(value => { observed.push(value); });
  try {
    for (const boundary of ['pre_current', 'post_current'] as const) {
      const diagnosis = beginInstalledRequestDiagnostic('run.get')!; diagnosis.at(boundary);
      let original: unknown;
      try { assertCurrentControlFrame(undefined as never, undefined as never); }
      catch (error) { original = error; diagnosis.failure(error); }
      assert(original instanceof KernelStorageError && original.code === 'ARTIFACT_MISMATCH');
      assert.equal(observed.at(-1)!.boundary, boundary); assert.equal(observed.at(-1)!.code, 'ARTIFACT_MISMATCH');
    }
    const diagnosis = beginInstalledRequestDiagnostic('run.get')!; diagnosis.at('response_decode');
    assert.throws(() => {
      try { decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result: { method: 'run.get' } },
        { protocolVersion: 1, method: 'run.get', runId: 'missing' }); }
      catch (error) { diagnosis.failure(error); throw error; }
    }, TypeError);
    assert.deepEqual(observed.at(-1), { method: 'run.get', boundary: 'response_decode', kind: 'type_error', code: null });
  } finally { close(); }
});

test('a genuine closed business refusal is data and never emits a request exception', () => {
  const observed: InstalledRequestFailure[] = [], close = observeInstalledRequestFailures(value => { observed.push(value); });
  try {
    const diagnosis = beginInstalledRequestDiagnostic('run.get')!; diagnosis.at('response_decode');
    const response = decodeInstalledControlResponse({ protocolVersion: 1, ok: false, method: 'run.get',
      error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'run.not_found' } },
    { protocolVersion: 1, method: 'run.get', runId: 'missing' });
    assert.equal(response.ok, false); assert.deepEqual(observed, []);
  } finally { close(); }
});

test('Error classification never reads messages, causes, code accessors, proxies or foreign declarations', () => {
  let touched = 0; const getter = () => { touched++; throw new Error('must not execute'); };
  const original = new TypeError('not emitted');
  Object.defineProperties(original, { message: { get: getter }, cause: { get: getter }, code: { get: getter } });
  assert.deepEqual(classifyInstalledRequestError(original), { kind: 'type_error', code: null });
  assert.deepEqual(classifyInstalledRequestError(new Proxy(original, { get: getter, getPrototypeOf: getter })), { kind: 'non_error', code: null });
  assert.deepEqual(classifyInstalledRequestError({ name: 'KernelStorageError', code: 'RECOVERY_REQUIRED', get message() { return getter(); } }), { kind: 'non_error', code: null });
  const changed = new Error('not emitted'); Object.setPrototypeOf(changed, new Proxy({}, { getPrototypeOf: getter }));
  assert.deepEqual(classifyInstalledRequestError(changed), { kind: 'non_error', code: null });
  assert.equal(touched, 0);
  assert.deepEqual(classifyInstalledRequestError(new ResourceRetirementError('not emitted', new Error('not emitted'))), { kind: 'resource_retirement', code: null });
  const foreignCode = new KernelStorageError('NOT_FOUND', 'not emitted'); Object.defineProperty(foreignCode, 'code', { value: 'FOREIGN' });
  assert.deepEqual(classifyInstalledRequestError(foreignCode), { kind: 'error', code: null });
});

test('fixed request observations reject extra, unknown, inconsistent, accessor and proxy fields before reading them', () => {
  const original = { method: 'run.get', boundary: 'exchange', kind: 'kernel_storage', code: 'RECOVERY_REQUIRED' };
  assert.deepEqual(decodeInstalledRequestFailure(original), original);
  let touched = 0;
  for (const value of [{ ...original, body: 'untrusted' }, { ...original, method: 'foreign.method' },
    { ...original, boundary: 'permission_granted' }, { ...original, kind: 'error' }, { ...original, code: 'FOREIGN' },
    { ...original, method: 'unrecognized' }, { ...original, get code() { touched++; return 'RECOVERY_REQUIRED'; } },
    new Proxy(original, { get() { touched++; throw new Error('must not execute'); } })]) assert.throws(() => decodeInstalledRequestFailure(value), TypeError);
  assert.equal(touched, 0);
});
