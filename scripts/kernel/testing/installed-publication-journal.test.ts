// Pure retained-data seam. No journal access, StateOwner, process observation,
// native resource, publication permission or physical cut is created here.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readInstalledNamespaceRetirementJournal, readInstalledOriginalRetirementJournal } from './installed-publication-journal.js';
import * as journalReaders from './installed-publication-journal.js';

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

test('the normal-stop reader requires one original group from the captured trusted sender', () => {
  const original = frames.map(value => value.replace(':namespace:', ':original:'));
  const result = readInstalledOriginalRetirementJournal(journal(original), expected);
  assert.equal(result?.kind, 'original'); assert.equal(result.key, key);
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.slots));
});

test('a dead original sender requires its exact invocation enrichment rather than borrowing the live namespace rule', () => {
  const original = frames.map(value => value.replace(':namespace:', ':original:'));
  const text = original.map(message => {
    const { _SYSTEMD_INVOCATION_ID: _unused, ...value } = record(message); return JSON.stringify(value);
  }).join('\n');
  assert.throws(() => readInstalledOriginalRetirementJournal(text, expected));
});

test('original groups refuse foreign sender metadata, namespace reuse, duplicate groups and existing bound violations', () => {
  const original = frames.map(value => value.replace(':namespace:', ':original:'));
  assert.equal(readInstalledOriginalRetirementJournal('', expected), undefined);
  for (const field of ['_UID', '_PID', '_TRANSPORT', '_SYSTEMD_INVOCATION_ID']) {
    const rows = original.map(record); rows[0] = { ...rows[0]!, [field]: 'foreign' };
    assert.throws(() => readInstalledOriginalRetirementJournal(rows.map(value => JSON.stringify(value)).join('\n'), expected));
  }
  for (const messages of [frames, original.slice(0, 3), [...original, ...original],
    original.map(value => value.replace(key, 'c'.repeat(64))),
    Array.from({ length: 81 }, () => 'ordinary output'), ['x'.repeat(256 * 1024)]])
    assert.throws(() => readInstalledOriginalRetirementJournal(journal(messages), expected));
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

const authenticationSender = { uid: 1001, pid: 2345, invocationId };
const authenticationFrame = (ordinal: number, phase: string, elapsedNs = 0) =>
  `CLIQ_SERVER_AUTH_V1:${ordinal}:${phase}:${elapsedNs}`;
const authenticationPhases = ['publish_started', 'image_hash_completed', 'process_cas_completed',
  'principal_cas_completed', 'peer_cas_completed', 'channel_cas_completed'];

test('server authentication journal decodes only exact independent await spans as immutable inert records', () => {
  const spans = [0, 40, 0, 12, 3, 1];
  const actual = journalReaders.readInstalledServerAuthenticationJournal(journal(authenticationPhases.map((phase, index) =>
    authenticationFrame(7, phase, spans[index]))), authenticationSender);
  assert.deepEqual(actual, authenticationPhases.map((phase, index) => ({ ordinal: 7, phase, elapsedNs: spans[index] })));
  assert(Object.isFrozen(actual));
  for (const item of actual!) assert(Object.isFrozen(item));
});

test('server authentication preserves actual concurrent CAS completion order, including siblings after a failure', () => {
  const phases = ['publish_started', 'image_hash_completed', 'peer_cas_completed',
    'process_cas_failed', 'channel_cas_failed', 'principal_cas_completed'];
  const spans = [0, 9, 7, 4, 12, 2];
  const result = journalReaders.readInstalledServerAuthenticationJournal(journal(phases.map((phase, index) =>
    authenticationFrame(7, phase, spans[index]))), authenticationSender);
  assert.deepEqual(result, phases.map((phase, index) => ({ ordinal: 7, phase, elapsedNs: spans[index] })));
});

test('server authentication prefixes and interleaved ordinals never invent completion or span ordering', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  assert.equal(read('', authenticationSender), undefined);
  assert.equal(read(journal(['ordinary output', `not a marker ${authenticationFrame(1, 'publish_started')}`]), authenticationSender), undefined);
  for (let size = 1; size <= authenticationPhases.length; size++) {
    const messages = authenticationPhases.slice(0, size).map((phase, index) => authenticationFrame(1, phase, index === 0 ? 0 : 9 - index));
    const result = read(journal(messages), authenticationSender)!;
    assert.equal(result.length, size); assert.deepEqual(Object.keys(result[0]!), ['ordinal', 'phase', 'elapsedNs']);
    assert.equal(Object.hasOwn(result, 'qualified'), false);
  }
  const interleaved = [authenticationFrame(7, 'publish_started'), authenticationFrame(8, 'publish_started'),
    authenticationFrame(7, 'image_hash_completed', 2), authenticationFrame(8, 'image_hash_failed', 10),
    authenticationFrame(7, 'process_cas_completed', 1)];
  assert.deepEqual(read(journal(interleaved), authenticationSender)!.map(item => item.ordinal), [7, 8, 7, 8, 7]);
  for (let stage = 1; stage <= 5; stage++) {
    const messages = authenticationPhases.slice(0, stage).map(phase => authenticationFrame(1, phase));
    const failed = authenticationPhases[stage]!.replace('_completed', '_failed');
    messages.push(authenticationFrame(1, failed, 12));
    assert.equal(read(journal(messages), authenticationSender)!.at(-1)!.phase, failed);
    for (const extra of [authenticationFrame(1, 'publish_started'), authenticationFrame(1, failed),
      authenticationFrame(1, failed.replace('_failed', '_completed'))])
      assert.throws(() => read(journal([...messages, extra]), authenticationSender));
    if (stage === 1) for (const phase of authenticationPhases.slice(2))
      assert.throws(() => read(journal([...messages, authenticationFrame(1, phase)]), authenticationSender));
  }
});

test('server authentication permits every concurrent CAS completion order and rejects duplicate outcomes', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  const prefix = [authenticationFrame(1, 'publish_started'), authenticationFrame(1, 'image_hash_completed', 9)];
  const names = ['process_cas', 'principal_cas', 'peer_cas', 'channel_cas'];
  const orders = names.flatMap(a => names.filter(b => b !== a).flatMap(b => names.filter(c => c !== a && c !== b)
    .map(c => [a, b, c, names.find(d => d !== a && d !== b && d !== c)!])));
  assert.equal(orders.length, 24);
  for (const order of orders) for (let failed = 0; failed < 16; failed++) {
    const phases = order.map((name, index) => `${name}_${failed & (1 << index) ? 'failed' : 'completed'}`);
    const messages = [...prefix, ...phases.map((phase, index) => authenticationFrame(1, phase, 4 - index))];
    const result = read(journal(messages), authenticationSender)!;
    assert.deepEqual(result.map(item => item.phase), ['publish_started', 'image_hash_completed', ...phases]);
  }
  for (const name of names) for (const first of ['completed', 'failed']) for (const second of ['completed', 'failed'])
    assert.throws(() => read(journal([...prefix, authenticationFrame(1, name + '_' + first),
      authenticationFrame(1, name + '_' + second)]), authenticationSender));
});

test('server authentication starts cannot go backwards or omit a captured ordinal', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  for (const next of [3, 7, 9]) assert.throws(() => read(journal([
    authenticationFrame(7, 'publish_started'), authenticationFrame(next, 'publish_started'),
  ]), authenticationSender), 'the synchronous original ordinal start must not be duplicated, reversed or skipped');
});

test('server authentication rejects malformed markers, noncanonical numbers and every invalid ordinal transition', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  const started = authenticationFrame(1, 'publish_started'), first = authenticationFrame(1, 'image_hash_completed');
  for (const malformed of ['CLIQ_SERVER_AUTH_V1', 'CLIQ_SERVER_AUTH_V1:truncated', 'CLIQ_SERVER_AUTH_V1extra',
    `${started}:extra`, `${started}\n`, `${started}\r`, `${started}\r\n`, `${started} `,
    'CLIQ_SERVER_AUTH_V1:1:unknown:0', 'CLIQ_SERVER_AUTH_V1:1:publish_started:1',
    ...['0', '-1', '+1', '01', '1.0', '1e0', '9007199254740992', '12345678901234567'].map(value => `CLIQ_SERVER_AUTH_V1:${value}:publish_started:0`),
    ...['-1', '+0', '00', '1.0', '1e0', 'Infinity', 'NaN', '9007199254740992', '12345678901234567'].map(value => `CLIQ_SERVER_AUTH_V1:1:image_hash_completed:${value}`)])
    assert.throws(() => read(journal([started, malformed]), authenticationSender));
  for (const messages of [[first], [started, started], [started, first, first],
    [started, authenticationFrame(1, 'process_cas_completed')], [started, authenticationFrame(2, 'image_hash_completed')],
    [started, authenticationFrame(1, 'process_cas_failed')],
    [...authenticationPhases.map(phase => authenticationFrame(1, phase)), first]])
    assert.throws(() => read(journal(messages), authenticationSender));
  const maximum = Number.MAX_SAFE_INTEGER;
  assert.equal(read(journal([authenticationFrame(maximum, 'publish_started'),
    authenticationFrame(maximum, 'image_hash_completed', maximum)]), authenticationSender)!.at(-1)!.elapsedNs, maximum);
});

test('server authentication keeps the whole sender-bound window, exact invocation enrichment and original bounds', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  for (const field of ['_UID', '_PID', '_TRANSPORT', '_SYSTEMD_INVOCATION_ID']) {
    for (const ordinary of [false, true]) {
      const rows: Array<Record<string, unknown>> = [record(ordinary ? 'ordinary output' : authenticationFrame(1, 'publish_started'))];
      rows[0]![field] = field === '_SYSTEMD_INVOCATION_ID' ? 'c'.repeat(32) : 'foreign';
      assert.throws(() => read(rows.map(value => JSON.stringify(value)).join('\n'), authenticationSender));
      delete rows[0]![field];
      assert.throws(() => read(rows.map(value => JSON.stringify(value)).join('\n'), authenticationSender));
    }
  }
  const messages = Array.from({ length: 64 }, (_, index) => authenticationFrame(index + 1, 'publish_started'));
  assert.equal(read(journal(messages), authenticationSender)!.length, 64);
  assert.equal(read(journal([...Array(16).fill('ordinary output'), ...messages]), authenticationSender)!.length, 64);
  for (const extra of [authenticationFrame(65, 'publish_started'), 'CLIQ_SERVER_AUTH_V1:truncated'])
    assert.throws(() => read(journal([...messages, extra]), authenticationSender));
  assert.throws(() => read(journal([...Array(17).fill('ordinary output'), ...messages]), authenticationSender));
  assert.throws(() => read(journal(['x'.repeat(256 * 1024)]), authenticationSender));
  const noInvocation = { ...record(authenticationFrame(1, 'publish_started')) } as Record<string, unknown>;
  delete noInvocation._SYSTEMD_INVOCATION_ID;
  assert.throws(() => read(JSON.stringify(noInvocation), authenticationSender));
});

test('server authentication expected sender is closed data and never invokes a getter or Proxy trap', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  let calls = 0;
  const accessor = { ...authenticationSender };
  Object.defineProperty(accessor, 'pid', { enumerable: true, get() { calls++; return 2345; } });
  const hidden = { ...authenticationSender }; Object.defineProperty(hidden, 'pid', { value: 2345, enumerable: false });
  const symbol = { ...authenticationSender, [Symbol('extra')]: 0 };
  const proxy = new Proxy(authenticationSender, { ownKeys() { calls++; throw 0; }, get() { calls++; throw 0; }, getPrototypeOf() { calls++; throw 0; } });
  const boxed = { ...authenticationSender, invocationId: new String(invocationId) };
  for (const value of [accessor, hidden, symbol, proxy, boxed, { ...authenticationSender, extra: 0 }, null, [],
    { ...authenticationSender, uid: 0 }, { ...authenticationSender, uid: true }, { ...authenticationSender, pid: Infinity }])
    assert.throws(() => read(journal([authenticationFrame(1, 'publish_started')]), value as any));
  const newlineInvocation = invocationId + '\n';
  assert.throws(() => read(JSON.stringify({ ...record(authenticationFrame(1, 'publish_started')),
    _SYSTEMD_INVOCATION_ID: newlineInvocation }), { ...authenticationSender, invocationId: newlineInvocation }));
  const text = { toString() { calls++; return ''; } };
  assert.throws(() => read(text as any, authenticationSender));
  assert.equal(calls, 0);
});

test('server authentication rejects non-JSON records, duplicate keys and non-text marker fields', () => {
  const read = journalReaders.readInstalledServerAuthenticationJournal;
  for (const text of ['not-json', 'null', '[]', '1', 'false', journal([authenticationFrame(1, 'publish_started')]) + 'false\n',
    JSON.stringify(record(authenticationFrame(1, 'publish_started'))).replace('"_UID":"1001"', '"_UID":"1001","_UID":"1001"'),
    ...[null, [], {}, 1, true].map(MESSAGE => JSON.stringify({ ...record(''), MESSAGE }))])
    assert.throws(() => read(text, authenticationSender));
});
