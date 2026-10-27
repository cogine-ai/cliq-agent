import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeRunSubmitRequest } from './source-target.js';
import { sourceInspectionRequest } from './testing/source-inspection-fixtures.js';
import { assertInstalledDependencyRequest } from './dependency-profile.js';

test('the first installed locked request is public-only and keeps every original ceiling and managed-root selection', () => {
  const request = normalizeRunSubmitRequest(sourceInspectionRequest({
    model: { provider: 'openai-compatible', model: 'owned', endpoint: { kind: 'registered', endpointRegistrationId: 'model' }, modelCredentialGrantIds: ['model-grant'] },
    dependency: { mode: 'locked', registryEndpointIds: ['registry'], credentialGrantIds: [], allowInstallScripts: false },
  })).request;
  assert.doesNotThrow(() => assertInstalledDependencyRequest(request));
  for (const dependency of [{ ...request.dependency, registryEndpointIds: [] }, { ...request.dependency, credentialGrantIds: ['private'] }, { ...request.dependency, maxPackages: 200001 },
    { ...request.dependency, maxDownloadBytes: 21_474_836_481 }])
    assert.throws(() => assertInstalledDependencyRequest({ ...request, dependency } as typeof request));
  assert.throws(() => assertInstalledDependencyRequest({ ...request, model: { provider: 'ollama', model: 'owned' } }));
  assert.throws(() => assertInstalledDependencyRequest({ ...request, sourceIncludes: [{ path: 'node_modules', scope: 'subtree' }] }));
  assert.doesNotThrow(() => assertInstalledDependencyRequest({ ...request, dependency: { mode: 'none' } }));
});
