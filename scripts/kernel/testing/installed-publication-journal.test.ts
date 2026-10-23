// Pure retained-data seam. No journal access, StateOwner, process observation,
// native resource, publication permission or physical cut is created here.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readInstalledNamespaceRetirementJournal } from './installed-publication-journal.js';

const key = 'a'.repeat(64), invocationId = 'b'.repeat(32);
const expected = { uid: 1001, pid: 2345, invocationId, key };
const frames = [
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:0:none`,
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:1:1:1:ok:100:1000:200:1100`,
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:2:1:1:ok:300:1200:400:1300`,
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:joined`,
];
const record = (MESSAGE: string) => ({ _UID: '1001', _PID: '2345', _TRANSPORT: 'stdout',
  _SYSTEMD_INVOCATION_ID: invocationId, MESSAGE });
const journal = (messages = frames) => messages.map(message => JSON.stringify(record(message))).join('\n') + '\n';

test('one exact current-process namespace group remains a closed immutable timing observation', () => {
  const result = readInstalledNamespaceRetirementJournal(journal(), expected);
  assert.deepEqual(result, { version: 1, key, kind: 'namespace', joined: true,
    slots: [null, [1, 1, 'ok', '100', '1000', '200', '1100'], [1, 1, 'ok', '300', '1200', '400', '1300']] });
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.slots));
});

test('zero fixed frames stays unobserved, while ordinary messages do not invent a timing packet', () => {
  assert.equal(readInstalledNamespaceRetirementJournal('', expected), undefined);
  assert.equal(readInstalledNamespaceRetirementJournal(journal(['ordinary Supervisor output']), expected), undefined);
  assert.deepEqual(readInstalledNamespaceRetirementJournal(journal(['ordinary Supervisor output', ...frames]), expected),
    readInstalledNamespaceRetirementJournal(journal(), expected));
});

test('missing journald invocation enrichment is allowed only with the exact trusted sender metadata', () => {
  const text = frames.map(message => {
    const { _SYSTEMD_INVOCATION_ID: _unused, ...value } = record(message); return JSON.stringify(value);
  }).join('\n');
  assert.equal(readInstalledNamespaceRetirementJournal(text, expected)!.key, key);
  for (const field of ['_UID', '_PID', '_TRANSPORT', '_SYSTEMD_INVOCATION_ID']) {
    const rows = frames.map(record); rows[0] = { ...rows[0]!, [field]: field === '_SYSTEMD_INVOCATION_ID' ? 'c'.repeat(32) : 'other' };
    assert.throws(() => readInstalledNamespaceRetirementJournal(rows.map(value => JSON.stringify(value)).join('\n'), expected));
  }
  const rows = [record('ordinary output'), ...frames.map(record)]; rows[0]!._UID = 'other';
  assert.throws(() => readInstalledNamespaceRetirementJournal(rows.map(value => JSON.stringify(value)).join('\n'), expected));
});

test('truncated, duplicated, malformed, original-kind and other-key groups cannot become namespace observations', () => {
  for (const messages of [frames.slice(0, 3), [...frames, ...frames], [...frames, 'CLIQ_PUBLICATION_RETIRE_V1:truncated'],
    frames.map(value => value.replace(':namespace:', ':original:')),
    frames.map(value => value.replace(key, 'c'.repeat(64))),
    [...frames, ...frames.map(value => value.replace(key, 'c'.repeat(64)))],
    [frames[0]!, frames[2]!, frames[1]!, frames[3]!]])
    assert.throws(() => readInstalledNamespaceRetirementJournal(journal(messages), expected));
});

test('invalid JSON, non-records and observations beyond the existing journal limits fail closed', () => {
  for (const text of ['not-json\n', 'null\n', '[]\n', '1\n', journal() + 'false\n',
    Array.from({ length: 81 }, () => JSON.stringify(record('ordinary output'))).join('\n'),
    JSON.stringify(record('x'.repeat(256 * 1024)))])
    assert.throws(() => readInstalledNamespaceRetirementJournal(text, expected));
  for (const changed of [{ ...expected, uid: 0 }, { ...expected, pid: NaN },
    { ...expected, invocationId: 'b'.repeat(31) }, { ...expected, key: 'a'.repeat(63) }])
    assert.throws(() => readInstalledNamespaceRetirementJournal(journal(), changed));
});
