import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledDependencySettlement, borrowInstalledDependencyTransport, loadInstalledDependencyBroker,
  assertInstalledDependencyTransportConfiguration, readInstalledDependencyTransportClosure,
  sealInstalledDependencyNpmAssets, type HeldInstalledRuntime } from './installed-runtime.js';
import type { DependencyBrokerBinding, NativeDependencySettlementFence, NativeDependencyTransport } from './dependency-broker-native.js';
import { readEndpointAuthoritySource, type HeldCredentialAuthorityLock } from './store.js';

test('dependency installed friends reject structural handles before observing caller data', () => {
  let reads = 0;
  const foreign = new Proxy({}, { get() { reads++; throw new Error('caller getter must never run'); },
    ownKeys() { reads++; throw new Error('caller keys must never run'); } });
  const binding = foreign as DependencyBrokerBinding;
  for (const input of [{}, foreign]) {
    assert.throws(() => loadInstalledDependencyBroker(input as HeldInstalledRuntime), /genuine held installed selection/u);
    assert.throws(() => sealInstalledDependencyNpmAssets(input as HeldInstalledRuntime), /genuine held installed selection/u);
    assert.throws(() => borrowInstalledDependencyTransport(input as HeldInstalledRuntime, input as NativeDependencyTransport, binding), /original installed owner/u);
    assert.throws(() => assertInstalledDependencySettlement(input as HeldInstalledRuntime, input as NativeDependencySettlementFence, binding), /original joined native owner/u);
    assert.throws(() => assertInstalledDependencyTransportConfiguration(input as HeldInstalledRuntime,
      input as NativeDependencyTransport, foreign as Buffer), /original installed configuration/u);
    assert.throws(() => readInstalledDependencyTransportClosure(input as HeldInstalledRuntime,
      input as NativeDependencyTransport, binding), /original installed owner/u);
    assert.throws(() => readEndpointAuthoritySource(input as HeldCredentialAuthorityLock, foreign as unknown as string));
  }
  assert.equal(reads, 0);
});
