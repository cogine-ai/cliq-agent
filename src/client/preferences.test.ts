import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { mergeBudgets } from '../kernel/control-submit.js';
import { CLIENT_PREFERENCES_BYTES, CLIENT_PREFERENCES_FILE, decodeClientPreferences, EMPTY_CLIENT_PREFERENCES,
  readClientPreferences, writeClientPreferences, type ClientPreferencesV1 } from './preferences.js';
import type { PrivateClientDirectory } from './private-files.js';

const selection = { alias: 'deepseek', provider: 'openai-compatible' as const, model: 'deepseek-flash',
  endpointRegistrationId: 'user-model-endpoint', credentialGrantId: 'user-model-credential' };
const preferences: ClientPreferencesV1 = { schemaVersion: 1, modelSelections: [selection], defaultModelAlias: selection.alias,
  budgetDefaults: mergeBudgets({ costMicros: 5_000_000 }) };

// Byte-only data adapter. Actual ownership/no-follow/fsync/join are verified by
// private-files' real Linux tests, not manufactured by this decoder regression.
function dataFile(initial?: Buffer) {
  let stored = initial;
  const calls: string[] = [];
  const directory = { async read(name: string, maximum: number) {
    assert.equal(name, CLIENT_PREFERENCES_FILE); assert.equal(maximum, CLIENT_PREFERENCES_BYTES); calls.push('read'); return stored;
  }, async replace(name: string, bytes: Uint8Array) {
    assert.equal(name, CLIENT_PREFERENCES_FILE); calls.push('replace'); stored = Buffer.from(bytes);
  } } as unknown as PrivateClientDirectory;
  return { directory, calls, bytes: () => stored };
}

test('preferences retain aliases and budgets as owned choices without capability or credential content', () => {
  const mutable = { ...preferences, modelSelections: [{ ...selection }] }, decoded = decodeClientPreferences(mutable);
  mutable.modelSelections[0]!.model = 'changed';
  assert.equal(decoded.modelSelections[0]!.model, selection.model);
  assert.equal(Object.isFrozen(decoded.modelSelections[0]), true);
  assert.equal(Object.isFrozen(decoded.budgetDefaults), true);
  for (const field of ['trust', 'policyMode', 'allow', 'grants', 'apiKey', 'caPem', 'actualProviderQualified'])
    assert.throws(() => decodeClientPreferences({ ...preferences, [field]: 'not-authority' }));
  for (const field of ['apiKey', 'credential', 'grant', 'permission', 'endpoint', 'priceTable'])
    assert.throws(() => decodeClientPreferences({ ...preferences, modelSelections: [{ ...selection, [field]: 'not-authority' }] }));
});

test('preferences reject unsupported selections, ambiguous aliases and budgets outside existing Run bounds', () => {
  const full = Array.from({ length: 32 }, (_, index) => ({ ...selection, alias: `model-${index}` }));
  assert.equal(decodeClientPreferences({ schemaVersion: 1, modelSelections: full }).modelSelections.length, 32);
  assert.throws(() => decodeClientPreferences({ schemaVersion: 1, modelSelections: [...full, { ...selection, alias: 'model-32' }] }));
  for (const changed of [
    { ...preferences, schemaVersion: 2 }, { ...preferences, modelSelections: Array(33).fill(selection) },
    { ...preferences, modelSelections: [selection, selection] }, { ...preferences, defaultModelAlias: 'missing' },
    { ...preferences, modelSelections: [{ ...selection, provider: 'ollama' }] },
    { ...preferences, modelSelections: [{ ...selection, credentialGrantId: '' }] },
    { ...preferences, budgetDefaults: { costMicros: 5_000_000 } },
    { ...preferences, budgetDefaults: { ...preferences.budgetDefaults, costMicros: 0 } },
    { ...preferences, budgetDefaults: { ...preferences.budgetDefaults, childDepth: 9 } },
    { ...preferences, budgetDefaults: { ...preferences.budgetDefaults, toolCalls: 1.1 } },
    { ...preferences, budgetDefaults: { ...preferences.budgetDefaults, newAllowance: 1 } }
  ]) assert.throws(() => decodeClientPreferences(changed));
  let reads = 0;
  const hostile = { ...preferences };
  Object.defineProperty(hostile, 'budgetDefaults', { enumerable: true, get() { reads++; return preferences.budgetDefaults; } });
  assert.throws(() => decodeClientPreferences(hostile)); assert.equal(reads, 0);
});

test('a missing preference file uses empty choices and writes canonical data only through the borrowed private directory', async () => {
  const fixture = dataFile();
  assert.equal(await readClientPreferences(fixture.directory), EMPTY_CLIENT_PREFERENCES);
  const result = await writeClientPreferences(fixture.directory, preferences);
  assert.deepEqual(fixture.bytes(), canonicalJsonBytes(result));
  assert.deepEqual(await readClientPreferences(fixture.directory), preferences);
  assert.deepEqual(fixture.calls, ['read', 'replace', 'read']);
});

test('malformed, noncanonical, oversized and invalid UTF-8 preferences fail without resetting choices', async () => {
  for (const bytes of [Buffer.from('{}'), Buffer.from(JSON.stringify(preferences, null, 2)),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), canonicalJsonBytes(preferences)]),
    Buffer.from([0xff]), Buffer.alloc(CLIENT_PREFERENCES_BYTES + 1, 0x20)]) {
    const fixture = dataFile(bytes);
    await assert.rejects(readClientPreferences(fixture.directory));
    assert.deepEqual(fixture.calls, ['read']); assert.deepEqual(fixture.bytes(), bytes);
  }
  const failure = new Error('owned file write did not complete');
  await assert.rejects(writeClientPreferences({ replace: async () => { throw failure; } } as unknown as PrivateClientDirectory, preferences),
    error => error === failure);
});
