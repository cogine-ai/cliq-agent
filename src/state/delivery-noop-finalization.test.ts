// Refusal-only ownership checks, not a fabricated verified source or native
// no-op positive. Actual directory capture remains covered at its real seam.
import assert from 'node:assert/strict';
import test from 'node:test';
import { completeOwnedNoOpDelivery, readOwnedNoOpTerminalMaterial, assertOwnedNoOpTerminalSql } from './delivery-noop-finalization.js';
import { loadRunResult } from './run-result.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

test('no-op finalization cannot borrow a structural execution, task, finalization or artifact catalog', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('structural task reached SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'withReadSignal', { get() { assert.fail('structural task reached CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const hostile = Object.defineProperty({}, 'runId', { get() { assert.fail('structural task properties were read'); } });
  await assert.rejects(completeOwnedNoOpDelivery(driver, artifacts, owner, hostile, hostile as never), /genuine|original/);
  assert.throws(() => readOwnedNoOpTerminalMaterial(driver, owner, hostile, hostile as never, hostile as never), /genuine|original/);
  assert.throws(() => assertOwnedNoOpTerminalSql(driver, owner, hostile as never, driver, ''), /genuine|original/);
  const result = loadRunResult(driver, artifacts, owner, { run: { id: 'structural' } as never, spec: {} as never, principalId: 'structural' });
  await assert.rejects(result.prepareOwnedNoOpDeliveryResult(hostile, hostile as never, hostile as never), /genuine|original/);
});
