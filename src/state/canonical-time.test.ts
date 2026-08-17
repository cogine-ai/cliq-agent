import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { advanceTimeFence, insertGenesisTimeFence, readTimeFence } from './canonical-time.js';
import { applyKernelSchema } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';

test('clock regression commits clock_regressed and does not auto-heal', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m1-time-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    driver.transaction((connection) => {
      insertGenesisTimeFence(connection, 1, '2026-08-16T12:00:00.000Z');
    });

    let outcome = 'healthy';
    driver.transaction((connection) => {
      outcome = advanceTimeFence(connection, 1, '2026-08-16T11:00:00.000Z');
    });
    assert.equal(outcome, 'clock_regressed');
    const fence = readTimeFence(driver);
    assert.equal(fence?.state, 'clock_regressed');
    assert.equal(fence?.lastAcceptedAt, '2026-08-16T12:00:00.000Z');
    assert.equal(fence?.observedWallClockAt, '2026-08-16T11:00:00.000Z');

    driver.transaction((connection) => {
      outcome = advanceTimeFence(connection, 1, '2026-08-16T13:00:00.000Z');
    });
    assert.equal(outcome, 'still_regressed');
    assert.equal(readTimeFence(driver)?.state, 'clock_regressed');
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});
