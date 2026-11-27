import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { decodeInstalledLocalModelCommand, decodeInstalledLocalModelRequest, decodeInstalledLocalModelSummaries } from './local-model-operations.js';

test('the signed models role accepts only its fixed source or original model selector', () => {
  const enroll = { schemaVersion: 1, kind: 'enroll', manifestPath: '/home/example/offline/model-manifest.json' };
  assert.deepEqual(decodeInstalledLocalModelCommand(canonicalJsonBytes(enroll).toString('base64url')), enroll);
  assert.deepEqual(decodeInstalledLocalModelRequest({ schemaVersion: 1, kind: 'list' }), { schemaVersion: 1, kind: 'list' });
  for (const field of ['backend', 'qualified', 'endpoint', 'ownerPrincipalId', 'serviceSpecRef', 'executable', 'alias'])
    assert.throws(() => decodeInstalledLocalModelRequest({ ...enroll, [field]: 'untrusted' }));
  for (const manifestPath of ['model-manifest.json', '/home/../model-manifest.json', '/home/model.json', '/home/model-manifest.json/'])
    assert.throws(() => decodeInstalledLocalModelRequest({ ...enroll, manifestPath }));
  assert.throws(() => decodeInstalledLocalModelCommand(Buffer.from(JSON.stringify(enroll)).toString('base64url')));
  let read = false;
  const accessor = { schemaVersion: 1, get kind() { read = true; return 'list'; } };
  assert.throws(() => decodeInstalledLocalModelRequest(accessor));
  assert.equal(read, false);
});

test('model summaries carry registration state and reject service-readiness assertions', () => {
  const item = { provider: 'ollama', model: 'sample:offline', serviceId: identityHash('sample-service'), registryRevision: 1, state: 'active' };
  assert.deepEqual(decodeInstalledLocalModelSummaries([item]), [item]);
  assert.deepEqual(decodeInstalledLocalModelSummaries([]), []);
  assert.throws(() => decodeInstalledLocalModelSummaries([{ ...item, ready: true }]));
  assert.throws(() => decodeInstalledLocalModelSummaries([item, item]));
});
