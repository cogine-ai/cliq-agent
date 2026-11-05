import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeInstalledControlRequest, decodeInstalledControlResponse } from '../kernel/control-wire.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { KernelStorageError } from './errors.js';
import { SessionContextRequestLimitError, sessionContextRequestLimitRefusal } from './session-context-limit.js';

test('only the actual admission context-limit error has the fixed non-retryable wire reason', () => {
  const original = new SessionContextRequestLimitError();
  const error = sessionContextRequestLimitRefusal('run.submit', original);
  assert.deepEqual(error, { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false,
    messageCode: 'session.context_requires_compaction',
    issues: [{ path: 'sessionId', issueCode: 'session_context_requires_compaction' }] });
  assert.equal(sessionContextRequestLimitRefusal('session.compact', original), undefined);
  assert.equal(sessionContextRequestLimitRefusal(undefined, original), undefined);
  for (const other of [new KernelStorageError('INVALID_REQUEST', original.message),
    new Error(original.message), { name: original.name, code: original.code, message: original.message }]) {
    assert.equal(sessionContextRequestLimitRefusal('run.submit', other), undefined);
  }
  // Wire data only: no Store, admission, source capture or native authority.
  const response = { protocolVersion: 1, ok: false, method: 'run.submit', error };
  const core = { protocolVersion: 1, method: 'run.submit', requestId: '01900000-0000-7000-8000-000000000001',
    admissionKey: 'a'.repeat(22), sessionId: 'session', expectedContextRevision: 7, workspacePath: '/workspace',
    objective: 'inspect', model: { provider: 'ollama', model: 'test' }, policyMode: 'default', verifiers: [],
    dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [],
    allowUnverified: true } as const;
  const request = decodeInstalledControlRequest({ ...core, requestDigest: canonicalSha256(core) });
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
});
