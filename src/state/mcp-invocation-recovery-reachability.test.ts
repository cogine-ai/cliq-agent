// Unissued data/provenance rejection only. No StateOwner, native proof, Run,
// SQLite claim, allowed-artifact graph or deletion eligibility is fabricated.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { MCP_INVOCATION_RECOVERY_RETENTION_PURPOSES, readMcpInvocationRecoveryEdges, readMcpInvocationRecoveryDependency,
  continueMcpInvocationRecoveryDependency, captureMcpInvocationRecoveryContext,
  UnsupportedMcpInvocationRecoveryReachability, type McpInvocationRecoveryContext } from './mcp-invocation-recovery-reachability.js';

test('complete-looking original MCP claim, join, source and role data cannot issue a retention parent or child context', async () => {
  const reference = canonicalSha256('inert original bytes'); let read = 0;
  const untrusted = new Proxy({}, { get() { read++; throw new Error('untrusted purported retention context getter'); } });
  const objects = [{}, { ref: reference, purpose: 'mcp.status.retirement', parent: { runId: 'original', prepared: true, claim: true, unknown: true },
    graph: { nodes: new Map(), owner: { active: true }, joined: { tokenRevoked: true, matchingActiveReleaseCount: 0 }, nativeClosure: { kind: 'linux_original_join' } } }, untrusted];
  for (const value of objects) {
    const context = value as McpInvocationRecoveryContext;
    for (const purpose of MCP_INVOCATION_RECOVERY_RETENTION_PURPOSES)
      await assert.rejects(readMcpInvocationRecoveryEdges(context, { ref: reference, purpose }), UnsupportedMcpInvocationRecoveryReachability);
    assert.throws(() => readMcpInvocationRecoveryDependency(context), UnsupportedMcpInvocationRecoveryReachability);
    assert.throws(() => continueMcpInvocationRecoveryDependency(context, { ref: reference, purpose: 'image_bytes' }), UnsupportedMcpInvocationRecoveryReachability);
  }
  assert.equal(read, 0, 'none of the unissued native/SQL/parent/child claims may be inspected or promoted');
});

test('foreign purpose and child selectors cannot run getters before a genuine original context exists', async () => {
  let inspected = 0;
  const selector = {
    get ref(): never { inspected++; throw new Error('untrusted ref getter'); },
    get purpose(): never { inspected++; throw new Error('untrusted purpose getter'); }
  };
  const context = Object.freeze({}) as McpInvocationRecoveryContext;
  await assert.rejects(readMcpInvocationRecoveryEdges(context, selector), UnsupportedMcpInvocationRecoveryReachability);
  assert.throws(() => continueMcpInvocationRecoveryDependency(context, selector), UnsupportedMcpInvocationRecoveryReachability);
  assert.equal(inspected, 0);
});

test('an old or structural source cannot begin any productive MCP retention read', async () => {
  let inspected = 0;
  const structural = new Proxy({}, { get() { inspected++; throw new Error('untrusted source getter'); } });
  type Arguments = Parameters<typeof captureMcpInvocationRecoveryContext>;
  await assert.rejects(captureMcpInvocationRecoveryContext(
    structural as Arguments[0], structural as Arguments[1], structural as Arguments[2],
    structural as Arguments[3], { runId: 'inert', expectedRunRevision: 1 }
  ), /exclusive read requires its original Store, driver, and Owner/u);
  assert.equal(inspected, 0);
});
