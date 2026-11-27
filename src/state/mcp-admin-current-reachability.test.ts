// Missing context must stop graph discovery before any native decoder can be
// used. This test creates neither a decoder owner nor physical proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { MCP_ADMIN_CURRENT_RETIREMENT_PURPOSES, readMcpAdminCurrentRetirementEdges,
  UnsupportedMcpAdminCurrentRetirementReachability } from './mcp-admin-current-reachability.js';

test('current retirement GC requires both actual raw sources and never guesses edges from Ref-shaped keys', () => {
  const value = { format: 'cliq-mcp-admin-original-retirement-v1', originalLifecycleRef: 'a'.repeat(64), arbitraryRef: 'b'.repeat(64) };
  assert.deepEqual(MCP_ADMIN_CURRENT_RETIREMENT_PURPOSES, ['mcp_admin_current_retirement_raw', 'mcp_admin_current_retirement_projection']);
  for (const purpose of MCP_ADMIN_CURRENT_RETIREMENT_PURPOSES) {
    assert.throws(() => readMcpAdminCurrentRetirementEdges(purpose, value), UnsupportedMcpAdminCurrentRetirementReachability);
    assert.throws(() => readMcpAdminCurrentRetirementEdges(purpose, Buffer.from('inert')), UnsupportedMcpAdminCurrentRetirementReachability);
  }
});
