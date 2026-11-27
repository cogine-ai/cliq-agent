// Pure retained-data seam only. These constructed rows are neither actual
// journal output nor process, native retirement, deadline or authority proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as journalReader from './installed-publication-journal.js';

const expiredProbeKey = 'a'.repeat(64), freshProbeKey = 'c'.repeat(64), invocationId = 'b'.repeat(32);
const expected = { uid: 1001, pid: 2345, invocationId, expiredProbeKey, freshProbeKey };
const frames = (key: string) => [
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:0:none`,
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:1:1:1:ok:100:1000:200:1100`,
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:2:1:1:ok:300:1200:400:1300`,
  `CLIQ_PUBLICATION_RETIRE_V1:${key}:namespace:joined`,
];
const record = (MESSAGE: string) => ({ _UID: '1001', _PID: '2345', _TRANSPORT: 'stdout',
  _SYSTEMD_INVOCATION_ID: invocationId, MESSAGE });
const journal = (messages = [...frames(expiredProbeKey), ...frames(freshProbeKey)]) =>
  messages.map(message => JSON.stringify(record(message))).join('\n') + '\n';

test('the exact expired-then-fresh namespace window yields only its two immutable ordered packets', () => {
  const packets = journalReader.readInstalledLatePublicationRetirementJournal(journal(), expected);
  assert.deepEqual(packets?.map(packet => packet.key), [expiredProbeKey, freshProbeKey]);
  assert(packets); assert(Object.isFrozen(packets));
  for (const packet of packets) {
    assert.equal(packet.kind, 'namespace'); assert.equal(packet.joined, true);
    assert(Object.isFrozen(packet)); assert(Object.isFrozen(packet.slots)); assert(Object.isFrozen(packet.slots[1]));
  }
});

test('ordinary rows remain in the one trusted window while zero fixed frames is only unobserved', () => {
  assert.equal(journalReader.readInstalledLatePublicationRetirementJournal('', expected), undefined);
  assert.equal(journalReader.readInstalledLatePublicationRetirementJournal(journal(['ordinary output']), expected), undefined);
  const messages = ['before', ...frames(expiredProbeKey), 'between', ...frames(freshProbeKey), 'after'];
  assert.deepEqual(journalReader.readInstalledLatePublicationRetirementJournal(journal(messages), expected),
    journalReader.readInstalledLatePublicationRetirementJournal(journal(), expected));
});

test('the late window cannot widen either original single-packet reader', () => {
  const oldExpected = { uid: expected.uid, pid: expected.pid, invocationId, key: expiredProbeKey };
  assert.throws(() => journalReader.readInstalledNamespaceRetirementJournal(journal(), oldExpected));
  assert.throws(() => journalReader.readInstalledOriginalRetirementJournal(journal(), oldExpected));
  assert.equal(journalReader.readInstalledNamespaceRetirementJournal(journal(frames(expiredProbeKey)), oldExpected)?.key, expiredProbeKey);
});

test('only the two expected distinct keys are accepted in expired-then-fresh group order', () => {
  const old = frames(expiredProbeKey), fresh = frames(freshProbeKey), foreign = frames('d'.repeat(64));
  for (const messages of [old, fresh, [...fresh, ...old], [...old, ...old], [...fresh, ...fresh],
    [...foreign, ...fresh], [...old, ...foreign], [...old, ...fresh, ...foreign],
    [...foreign, ...old, ...fresh], [...old, ...foreign, ...fresh], [...old, ...fresh, ...old]])
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal(messages), expected));
  for (const keys of [
    { expiredProbeKey, freshProbeKey: expiredProbeKey },
    { expiredProbeKey: 'A'.repeat(64), freshProbeKey },
    { expiredProbeKey, freshProbeKey: 'c'.repeat(63) },
    { expiredProbeKey: '', freshProbeKey },
    { expiredProbeKey, freshProbeKey: 'c'.repeat(65) },
    { expiredProbeKey: null, freshProbeKey },
    { expiredProbeKey, freshProbeKey: [freshProbeKey] },
  ]) assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal(),
    { ...expected, ...keys } as unknown as Parameters<typeof journalReader.readInstalledLatePublicationRetirementJournal>[1]));
});

test('every missing, duplicated, extra or interleaved fixed frame fails rather than returning partial packets', () => {
  const old = frames(expiredProbeKey), fresh = frames(freshProbeKey), all = [...old, ...fresh];
  for (let index = 0; index < all.length; index++) {
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal(all.filter((_, position) => position !== index)), expected));
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal([...all.slice(0, index), all[index]!, ...all.slice(index)]), expected));
    const changed = [...all]; changed[index] = changed[index]!.replace(':namespace:', ':original:');
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal(changed), expected));
  }
  for (const messages of [[...old, ...fresh.slice(0, 3)], [...old.slice(0, 3), ...fresh],
    [old[0]!, fresh[0]!, ...old.slice(1), ...fresh.slice(1)],
    [...old, fresh[0]!, fresh[2]!, fresh[1]!, fresh[3]!],
    [...old, ...fresh, 'CLIQ_PUBLICATION_RETIRE_V1:truncated']])
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal(messages), expected));
});

test('every row including ordinary output must retain the exact current sender metadata', () => {
  const messages = ['ordinary before', ...frames(expiredProbeKey), 'ordinary between', ...frames(freshProbeKey), 'ordinary after'];
  for (let index = 0; index < messages.length; index++) {
    for (const field of ['_UID', '_PID', '_TRANSPORT', '_SYSTEMD_INVOCATION_ID']) {
      const rows = messages.map(record); rows[index] = { ...rows[index]!, [field]: 'foreign' };
      assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(rows.map(row => JSON.stringify(row)).join('\n'), expected));
    }
  }
  for (const changed of [{ ...expected, uid: 0 }, { ...expected, uid: 1.5 }, { ...expected, pid: NaN },
    { ...expected, pid: -1 }, { ...expected, invocationId: 'b'.repeat(31) }])
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(journal(), changed));
});

test('the live namespace enrichment rule is unchanged and cannot become a dead-original exception', () => {
  const rows = [...frames(expiredProbeKey), ...frames(freshProbeKey)].map(message => {
    const { _SYSTEMD_INVOCATION_ID: _unused, ...value } = record(message); return value;
  });
  assert.equal(journalReader.readInstalledLatePublicationRetirementJournal(rows.map(row => JSON.stringify(row)).join('\n'), expected)?.length, 2);
  const original = rows.map(row => ({ ...row, MESSAGE: row.MESSAGE.replace(':namespace:', ':original:') }));
  assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(original.map(row => JSON.stringify(row)).join('\n'), expected));
  const mixed = rows.map((row, index) => index % 2 ? row : { ...row, _SYSTEMD_INVOCATION_ID: invocationId });
  assert.equal(journalReader.readInstalledLatePublicationRetirementJournal(mixed.map(row => JSON.stringify(row)).join('\n'), expected)?.length, 2);
});

test('the existing strict JSON, whole-window byte limit and whole-row limit remain mandatory', () => {
  const ordinary = JSON.stringify(record('ordinary output'));
  const duplicateUid = ordinary.replace('"_UID":"1001"', '"_UID":"1001","_UID":"1001"');
  for (const text of ['not-json\n', 'null\n', '[]\n', '1\n', journal() + 'false\n',
    `${duplicateUid}\n${journal()}`, `${journal()}\n${JSON.stringify(record('x'.repeat(256 * 1024)))}`,
    [...Array.from({ length: 73 }, () => ordinary), ...[...frames(expiredProbeKey), ...frames(freshProbeKey)].map(message => JSON.stringify(record(message)))].join('\n')])
    assert.throws(() => journalReader.readInstalledLatePublicationRetirementJournal(text, expected));
  const exactlyEighty = [...Array.from({ length: 72 }, () => ordinary),
    ...[...frames(expiredProbeKey), ...frames(freshProbeKey)].map(message => JSON.stringify(record(message)))].join('\n');
  assert.equal(journalReader.readInstalledLatePublicationRetirementJournal(exactlyEighty, expected)?.length, 2);
});

test('unavailable or repeated spans stay diagnostic data and never become a physical late qualification', () => {
  const messages = [...frames(expiredProbeKey), ...frames(freshProbeKey)];
  messages[1] = `CLIQ_PUBLICATION_RETIRE_V1:${expiredProbeKey}:namespace:1:1:1:unavailable`;
  messages[6] = `CLIQ_PUBLICATION_RETIRE_V1:${freshProbeKey}:namespace:2:2:3:interrupted:300:1200:400:1300`;
  const packets = journalReader.readInstalledLatePublicationRetirementJournal(journal(messages), expected);
  assert.deepEqual(packets?.[0].slots[1], [1, 1, 'unavailable']);
  assert.deepEqual(packets?.[1].slots[2], [2, 3, 'interrupted', '300', '1200', '400', '1300']);
  for (const packet of packets!) assert.deepEqual(Object.keys(packet).sort(), ['joined', 'key', 'kind', 'slots', 'version']);
});
