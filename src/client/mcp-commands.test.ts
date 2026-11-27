import assert from 'node:assert/strict';
import test from 'node:test';
import { parseClientInvocation } from './commands.js';

test('CLI and TUI parser require explicit exact manual-risk acknowledgement', () => {
  const args = ['reconcile', 'run-1', '--revision', '7', '--wait', 'a'.repeat(64)];
  const parsed = parseClientInvocation([...args, '--resolution', 'abandon_run', '--acknowledge-exact-risk'], '/workspace');
  assert.equal(parsed.kind, 'command');
  if (parsed.kind !== 'command' || parsed.command.kind !== 'request' || parsed.command.request.method !== 'run.reconcile') throw new Error('wrong request');
  assert.deepEqual(parsed.command.request.resolution, { kind: 'abandon_run', acknowledgeExactRisk: true });
  for (const suffix of [['--resolution', 'abandon_run'], ['--acknowledge-exact-risk'],
    ['--resolution', 'retry', '--acknowledge-exact-risk'], ['--resolution', 'abandon_run', '--acknowledge-exact-risk', 'false']])
    assert.throws(() => parseClientInvocation([...args, ...suffix], '/workspace'));
});

test('MCP register and refresh produce original Admin requests and no Run or effect permission', () => {
  const target = JSON.stringify({ kind: 'streamable_http', endpointRegistrationId: 'endpoint-1', credentialGrantIds: [] });
  const parsed = parseClientInvocation(['mcp', 'register', 'calendar', '--target-json', target, '--assert-stateless-per-call'], '/workspace');
  assert.equal(parsed.kind, 'command');
  if (parsed.kind !== 'command' || parsed.command.kind !== 'request' || parsed.command.request.method !== 'mcp.register') throw new Error('wrong request');
  assert.equal(parsed.command.request.assertStatelessPerCall, true);
  assert.deepEqual(parsed.command.request.toolRecovery, {});
  assert(!('runId' in parsed.command.request));
  assert.throws(() => parseClientInvocation(['mcp', 'register', 'calendar', '--target-json', target], '/workspace'));
  const refresh = parseClientInvocation(['mcp', 'refresh', 'calendar', '--revision', '1'], '/workspace');
  assert.equal(refresh.kind, 'command');
  assert.deepEqual(parseClientInvocation(['mcp', 'list'], '/workspace'), { kind: 'command', command: { kind: 'request',
    request: { protocolVersion: 1, method: 'mcp.list' } }, json: false });
});

test('the public MCP registration parser retains exact retry risk consent and signed recovery selection on the original v1 request', () => {
  const target = JSON.stringify({ kind: 'stdio', executionIdentityGrantId: 'existing-execution-identity-grant', argv: [] });
  const args = ['mcp', 'register', 'service', '--target-json', target, '--assert-stateless-per-call'];
  const selection = { update: { kind: 'retry', acknowledgeDuplicateEffectRisk: true, idempotencyKeyJsonPointer: '/request/key' },
    create: { kind: 'reconcile', bundledAdapterId: 'signed-original-bundle-adapter', idempotencyKeyJsonPointer: '/operation/key' } };
  const parsed = parseClientInvocation([...args, '--recovery-json', JSON.stringify(selection)], '/workspace');
  assert.equal(parsed.kind, 'command');
  if (parsed.kind !== 'command' || parsed.command.kind !== 'request' || parsed.command.request.method !== 'mcp.register')
    throw new Error('the original public mutation was not selected');
  assert.deepEqual(parsed.command.request.toolRecovery, selection);
  for (const field of ['runId', 'grantRef', 'adapterRef', 'profileDigest', 'nativeOwner', 'probeNonce']) assert(!Object.hasOwn(parsed.command.request, field));
  for (const recovery of [{ update: { kind: 'retry' } }, { update: { kind: 'retry', acknowledgeDuplicateEffectRisk: false } },
    { update: { kind: 'retry', acknowledgeDuplicateEffectRisk: true, retrySafe: true } },
    { create: { kind: 'reconcile', bundledAdapterId: 'adapter' } }])
    assert.throws(() => parseClientInvocation([...args, '--recovery-json', JSON.stringify(recovery)], '/workspace'));
  // Parsing is data only. The original authenticated registration still must
  // verify consent, the signed profile/registry and actual native lifecycle.
});
