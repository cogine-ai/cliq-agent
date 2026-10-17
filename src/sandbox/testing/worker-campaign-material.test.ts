import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentFixture } from '../../state/testing/agent-fixtures.js';
import { disposeFixture } from '../../state/testing/fixtures.js';
import { restoreOfflineWorkerCampaignMaterial, type OfflineWorkerCampaignMaterialData } from './worker-campaign-material.js';

test('serialized worker campaign model data reopens its exact closed endpoint and credential prefix', async () => {
  const fixture = await createAgentFixture('worker-material-ipc', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const { assembly, material } = fixture.authority;
    const materialData = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(material)
      .filter(([, value]) => typeof value !== 'function')))) as OfflineWorkerCampaignMaterialData;
    const tools = material.resolveVerifiedTools(assembly.tools);
    assert.ok(tools);
    const restored = restoreOfflineWorkerCampaignMaterial({ materialData, assembly, tools });
    const expected = { provider: assembly.provider.name, model: assembly.provider.model, endpoint: assembly.provider.endpoint,
      credentialGrantRefs: assembly.provider.credentialGrantRefs, capabilitySource: materialData.capabilityEvidence.value.source };
    assert.equal(restored.verifyProviderEndpoint(expected), true);
    assert.equal(restored.verifyProviderEndpoint({ ...expected, provider: expected.provider === 'openai' ? 'ollama' : 'openai' }), false);
    assert.equal(restored.verifyProviderEndpoint({ ...expected, model: `${expected.model}-substituted` }), false);
    assert.equal(restored.verifyProviderEndpoint({ ...expected, credentialGrantRefs: [] }), false);
    assert.equal(expected.endpoint.kind, 'registered');
    if (expected.endpoint.kind !== 'registered') assert.fail('this regression requires its real closed registered endpoint DATA');
    for (const field of ['endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest'] as const) {
      assert.equal(restored.verifyProviderEndpoint({ ...expected, endpoint: { ...expected.endpoint, [field]: '0'.repeat(64) } }), false);
    }
    assert.equal(expected.capabilitySource.kind, 'signed_catalog');
    if (expected.capabilitySource.kind !== 'signed_catalog') assert.fail('this prefix retains its original signed-catalog DATA');
    assert.equal(restored.verifyProviderEndpoint({ ...expected,
      capabilitySource: { ...expected.capabilitySource, runtimeBundleRef: '0'.repeat(64) } }), false);
    // The same public retained-model loader used before the real crash child
    // can open execution. Passing here proves data closure, not native I/O.
    await fixture.store.loadAgentRun({ runId: fixture.runId, material: restored, releaseKeys: fixture.runtimeAuthority.releaseKeys });
  } finally { await disposeFixture(fixture); }
});
