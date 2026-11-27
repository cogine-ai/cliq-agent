import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { createInstalledRuntime, verifyInstalledUpgradeOriginalControl } from './installed-runtime.js';

test('readonly old-control composition rejects forged factories before caller locators', async () => {
  let touched = false;
  const foreign = new Proxy({}, { get() { touched = true; throw new Error('foreign factory'); } });
  const locator = new Proxy({}, { get() { touched = true; throw new Error('foreign locator'); } });
  await assert.rejects(verifyInstalledUpgradeOriginalControl(foreign as ReturnType<typeof createInstalledRuntime>,
    locator as unknown as string, locator as unknown as string), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(touched, false);
});

test('ordinary Node cannot enter the private original-layout control purpose', async () => {
  // No platform, keeper, receipt or native positive is manufactured here.
  await assert.rejects(async () => {
    const key = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const runtime = createInstalledRuntime({ releaseKeys: [{ keyId: 'readonly-composition-test', publicKeyPem: key }] });
    await verifyInstalledUpgradeOriginalControl(runtime, '/not-opened', 'a'.repeat(64));
  }, { code: 'UNSUPPORTED_PLATFORM' });
});
