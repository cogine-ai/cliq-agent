import assert from 'node:assert/strict';
import test from 'node:test';
import { mcpRetryAdmissionData, type McpRetryAdmission } from './mcp-retry-admission.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

test('a structural retry closure or hostile token cannot create the original physical retry admission', () => {
  const driver = {} as SqliteDriver, owner = {} as StateOwnerContext;
  const hostile = new Proxy({}, { get() { throw new Error('foreign authority getter must not run'); } });
  for (const value of [{}, { reference: { ref: '0'.repeat(64), digest: '0'.repeat(64) }, assertCurrent() {} }, hostile])
    assert.throws(() => mcpRetryAdmissionData(driver, owner, value as McpRetryAdmission), /foreign MCP retry preparation owner/);
});
