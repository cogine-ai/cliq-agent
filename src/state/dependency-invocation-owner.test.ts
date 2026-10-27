import assert from 'node:assert/strict';
import test from 'node:test';
import { acknowledgeDependencyInvocation, acquireDependencyPackages, assertDependencyClaimForInvocation,
  assertDependencySettlementForInvocation, claimDependencyInvocation, closeDependencyInvocationOwner,
  readDependencyProcessInputs, registerDependencyProcess, releaseDependencyProcess, retainDependencyResultForSettlement,
  retainDependencyAcquisitionFailure, publishDependencyAcquisitionFailure, assertDependencyAcquisitionFailure,
  retainDependencyUnknownBrokerFence, markDependencyInvocationUnknown, hasDependencyProcessCustody,
  type DependencyInvocationOwner } from './dependency-invocation-owner.js';
import { assertNativeDependencyInvocation } from '../sandbox/linux-worker.js';

test('dependency claim/process/settlement reject foreign owners before caller properties', async () => {
  let accessed = 0;
  const proxy = new Proxy({}, { get() { accessed++; throw new Error('foreign'); }, ownKeys() { accessed++; throw new Error('foreign'); } });
  for (const token of [{}, proxy]) {
    const owner = token as DependencyInvocationOwner;
    assert.throws(() => claimDependencyInvocation(undefined!, undefined!, owner), /exact original invocation owner/);
    assert.throws(() => acquireDependencyPackages(undefined!, undefined!, owner), /exact original invocation owner/);
    assert.throws(() => closeDependencyInvocationOwner(undefined!, undefined!, owner), /exact original invocation owner/);
    assert.throws(() => registerDependencyProcess(undefined!, undefined!, owner, proxy as never), /exact original invocation owner/);
    assert.throws(() => assertDependencyClaimForInvocation(undefined!, undefined!, owner, proxy as never), /exact original invocation owner/);
    assert.throws(() => assertDependencySettlementForInvocation(undefined!, undefined!, owner, proxy as never), /exact original invocation owner/);
    assert.throws(() => retainDependencyResultForSettlement(undefined!, undefined!, owner, proxy as never), /exact original invocation owner/);
    await assert.rejects(readDependencyProcessInputs(undefined!, undefined!, owner), /exact original invocation owner/);
    await assert.rejects(releaseDependencyProcess(undefined!, undefined!, owner), /exact original invocation owner/);
    await assert.rejects(acknowledgeDependencyInvocation(undefined!, undefined!, owner), /exact original invocation owner/);
    await assert.rejects(retainDependencyAcquisitionFailure(undefined!, undefined!, owner), /exact original invocation owner/);
    await assert.rejects(publishDependencyAcquisitionFailure(undefined!, undefined!, owner), /exact original invocation owner/);
    await assert.rejects(retainDependencyUnknownBrokerFence(undefined!, undefined!, owner), /exact original invocation owner/);
    await assert.rejects(markDependencyInvocationUnknown(undefined!, undefined!, owner), /exact original invocation owner/);
    assert.throws(() => assertDependencyAcquisitionFailure(undefined!, undefined!, owner, proxy as never), /exact original invocation owner/);
    assert.throws(() => hasDependencyProcessCustody(undefined!, undefined!, owner), /exact original invocation owner/);
    assert.throws(() => assertNativeDependencyInvocation(proxy as never, proxy as never, proxy as never, proxy as never), /trusted.*closure|original/);
  }
  assert.equal(accessed, 0);
});
