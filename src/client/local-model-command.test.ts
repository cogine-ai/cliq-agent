// User intent and preferences only. No installed model, native boundary,
// zero-cost eligibility, tool permission or execution proof is created.
import assert from 'node:assert/strict';
import test from 'node:test';
import { modelCommand } from './model-command.js';
import { decodeClientPreferences } from './preferences.js';
import { parseClientInvocation } from './commands.js';

test('model commands preserve remote setup and explicitly separate local enrollment, reuse and retirement', () => {
  assert.deepEqual(modelCommand(['models', 'list']), { kind: 'list' });
  assert.deepEqual(modelCommand(['models', 'add', 'remote']), { kind: 'add', alias: 'remote', profileId: 'default', input: 'terminal' });
  assert.deepEqual(modelCommand(['models', 'add', 'remote', '--api-key-stdin', '--profile', 'signed']),
    { kind: 'add', alias: 'remote', profileId: 'signed', input: 'stdin' });
  assert.deepEqual(modelCommand(['models', 'add', 'local', '--manifest', '/owned/model-manifest.json']),
    { kind: 'enroll', alias: 'local', manifestPath: '/owned/model-manifest.json' });
  assert.deepEqual(modelCommand(['models', 'add', 'local', '--local', 'functiongemma-cliq:270m-q4-k-m']),
    { kind: 'local', alias: 'local', model: 'functiongemma-cliq:270m-q4-k-m' });
  assert.deepEqual(modelCommand(['models', 'retire', 'local']), { kind: 'retire', alias: 'local' });
  for (const args of [
    ['list', 'extra'], ['retire', 'local', '--profile', 'default'], ['add'], ['add', '--manifest', '/owned/model-manifest.json'],
    ['add', 'local', '--manifest'], ['add', 'local', '--local'], ['add', 'local', '--api-key', 'untrusted-input'],
    ['add', 'local', '--manifest', '/owned/model-manifest.json', '--local', 'another'],
    ['add', 'local', '--manifest', '/owned/model-manifest.json', '--api-key-stdin'],
    ['add', 'local', '--local', 'model', '--profile', 'default'],
    ['add', 'local', '--local', 'model', '--local', 'another']
  ]) assert.throws(() => modelCommand(['models', ...args]), TypeError);
});

test('local model aliases carry only model choice and cannot borrow remote endpoint, credential or backend authority', () => {
  const local = { alias: 'local', provider: 'ollama', model: 'functiongemma-cliq:270m-q4-k-m' };
  const preferences = decodeClientPreferences({ schemaVersion: 1, defaultModelAlias: 'local', modelSelections: [local,
    { alias: 'remote', provider: 'openai-compatible', model: 'remote-model', endpointRegistrationId: 'endpoint', credentialGrantId: 'credential' }] });
  const parsed = parseClientInvocation(['run', 'Inspect the code'], '/workspace', { preferences });
  assert.equal(parsed.kind, 'run');
  if (parsed.kind !== 'run') assert.fail('the actual parser must retain Run intent');
  assert.deepEqual(parsed.intent.model, { provider: 'ollama', model: local.model });
  for (const field of ['endpointRegistrationId', 'credentialGrantId', 'endpoint', 'backend', 'boundaryEvidenceRef', 'priceTableRef', 'apiKey'])
    assert.throws(() => decodeClientPreferences({ schemaVersion: 1, modelSelections: [{ ...local, [field]: 'not-authority' }] }));
  assert.throws(() => parseClientInvocation(['run', 'Inspect', '--model', 'local', '--endpoint', 'endpoint'], '/workspace', { preferences }));
  assert.throws(() => parseClientInvocation(['run', 'Inspect', '--model', 'local', '--credential-grant', 'credential'], '/workspace', { preferences }));
});
