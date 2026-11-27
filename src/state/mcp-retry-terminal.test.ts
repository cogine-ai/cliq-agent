import assert from 'node:assert/strict';
import test from 'node:test';
import { isMcpRetryFinalization, readMcpRetryFinalization } from './mcp-retry-terminal.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import type { ManualInvocationFinalization } from './manual-reconciliation.js';

test('the existing terminal finalization entry rejects structural retry proposals before reading their authority fields', () => {
  const driver = {} as SqliteDriver, artifacts = {} as ArtifactCatalog, owner = {} as StateOwnerContext;
  const hostile = new Proxy({}, { get() { throw new Error('untrusted proposed authority getter'); } });
  for (const value of [{}, { kind: 'mcp-retry', cut: {}, closure: { joined: true } }, hostile]) {
    assert.equal(isMcpRetryFinalization(value as ManualInvocationFinalization), false);
    assert.throws(() => readMcpRetryFinalization(driver, artifacts, owner, value as never, 'run'), /foreign MCP retry terminal finalization/);
  }
});
