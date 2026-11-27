import assert from 'node:assert/strict';
import test from 'node:test';
import { createClientApplication, type ClientUpdate } from './application.js';
import { clientMutation } from './commands.js';
import { humanResponse, initialClientView, reduceClientView } from './view.js';
import { protocolClient } from './testing/protocol.js';
import type { InstalledControlFeature, InstalledControlResponseFor } from '../control/v1.js';
import type { InstalledControlErrorV1 } from '../kernel/control-wire.js';

const request = clientMutation({ method: 'run.submit', sessionId: 'session', expectedContextRevision: 7,
  workspacePath: '/workspace', objective: 'inspect', model: { provider: 'ollama', model: 'test' }, policyMode: 'default',
  verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [],
  skillIds: [], allowUnverified: true }, true);
const error: Extract<InstalledControlErrorV1, { code: 'INVALID_REQUEST' }> = { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false,
  messageCode: 'session.context_requires_compaction',
  issues: [{ path: 'sessionId', issueCode: 'session_context_requires_compaction' }] };
const refusal = { protocolVersion: 1 as const, ok: false as const, method: 'run.submit' as const, error };

test('the actual client application displays compaction guidance once and does not resend a refused Run', async () => {
  const f = protocolClient({ 'run.submit': async () => refusal }), updates: ClientUpdate[] = [];
  const app = createClientApplication(f.session, update => { updates.push(update); });
  try {
    await app.execute({ kind: 'request', request });
    assert.deepEqual(f.calls.map(call => call.method), ['run.submit']);
    const state = updates.reduce(reduceClientView, initialClientView());
    assert.equal(state.run, undefined);
    assert.equal(state.pending, undefined);
    assert.deepEqual(state.refusal, { code: error.code, messageCode: error.messageCode });
    assert.deepEqual(state.lines, humanResponse(request, refusal));
    assert.match(state.lines.join('\n'), /session show.*complete.*session compact/u);
    assert.match(state.lines.join('\n'), /submit a new Run/u);
  } finally { await app.close(); }
  assert.equal(f.closed(), 1);
});

test('compaction guidance requires the complete fixed reason and displays the original Session as text', () => {
  assert.equal(request.method, 'run.submit');
  if (request.method !== 'run.submit') throw new Error('expected a submit request');
  const sessionId = 'original\n\u001b[31m$(untrusted)';
  const lines = humanResponse({ ...request, sessionId }, refusal);
  assert.match(lines[0]!, /original\\n\\u001b\[31m\$\(untrusted\)/u);
  assert.equal(lines.join('\n').includes('\u001b'), false);
  const others: InstalledControlResponseFor<InstalledControlFeature>[] = [
    { ...refusal, error: { ...refusal.error, messageCode: 'control.invalid_request' } },
    { ...refusal, error: { ...refusal.error, issues: [{ path: 'request', issueCode: error.issues[0].issueCode }] } },
    { ...refusal, error: { ...refusal.error, issues: [{ path: 'sessionId', issueCode: 'invalid_request' }] } },
    { ...refusal, error: { ...refusal.error, issues: [...refusal.error.issues, ...refusal.error.issues] } },
    { ...refusal, method: 'session.compact' },
  ];
  for (const response of others) assert.equal(humanResponse(request, response).length, 1);
  assert.equal(humanResponse({ protocolVersion: 1, method: 'session.get', sessionId: 'session' }, refusal).length, 1);
});
