// Constructed pure clock/packet data only, not an actual late syscall proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as result from './installed-publication-late-result.js';

const key = 'a'.repeat(64), probeStartedAt = '2026-10-24T00:00:00.000Z', probeDeadlineAt = '2026-10-24T00:00:30.000Z';
const d = BigInt(Date.parse(probeDeadlineAt)) * 1_000_000n;
const snapshot = { version: 1, key, kind: 'namespace', joined: true,
  slots: [null, [1, 1, 'ok', '100', String(d - 1n), '200', String(d + 1n)],
    [1, 1, 'ok', '300', String(d + 2n), '400', String(d + 3n)]] };
const input = { snapshot, key, probeStartedAt, probeDeadlineAt, completedAt: '2026-10-24T00:00:30.001Z' };

test('one same-nonce continuous parent fsync must strictly cross the original UTC deadline with both actual clocks present', () => {
  assert.deepEqual(result.assessInstalledPublicationLateInterval(input), {
    diagnosticOnly: true, hit: true, parentSlot: 1, monotonicDurationNs: '100',
  });
});

test('a genuine second parent tuple can be selected without combining either parent interval', () => {
  const data = structuredClone(input);
  data.snapshot.slots[1] = [1, 1, 'unavailable'];
  data.snapshot.slots[2] = [1, 1, 'ok', '500', String(d - 5n), '750', String(d + 5n)];
  const observed = result.assessInstalledPublicationLateInterval(data);
  assert.deepEqual(observed, { diagnosticOnly: true, hit: true, parentSlot: 2, monotonicDurationNs: '250' });
  assert(Object.isFrozen(observed)); assert.equal(Object.hasOwn(observed, 'qualified'), false);
});

test('boundary equality, adjacent calls, arena-only data and unusable or repeated clocks never hit', () => {
  const noHit = { diagnosticOnly: true, hit: false, parentSlot: null, monotonicDurationNs: null };
  const rows = [
    [1, 1, 'ok', '100', String(d), '200', String(d + 1n)],
    [1, 1, 'ok', '100', String(d - 1n), '200', String(d)],
    [1, 1, 'ok', '100', String(d - 1n), '100', String(d + 1n)],
    [1, 1, 'unavailable'], [1, 1, 'interrupted', '100', String(d - 1n), '200', String(d + 1n)],
    [1, 1, 'error', '100', String(d - 1n), '200', String(d + 1n)],
    [2, 2, 'ok', '100', String(d - 1n), '200', String(d + 1n)],
    [1, 2, 'ok', '100', String(d - 1n), '200', String(d + 1n)],
  ];
  for (const row of rows) {
    const data = structuredClone(input); data.snapshot.slots[1] = row;
    assert.deepEqual(result.assessInstalledPublicationLateInterval(data), noHit);
  }
  const arenaOnly = structuredClone(input); arenaOnly.snapshot.slots[0] = arenaOnly.snapshot.slots[1];
  arenaOnly.snapshot.slots[1] = [1, 1, 'unavailable'];
  assert.deepEqual(result.assessInstalledPublicationLateInterval(arenaOnly), noHit);
  const adjacent = structuredClone(input);
  adjacent.snapshot.slots[1] = [1, 1, 'ok', '100', String(d - 2n), '200', String(d - 1n)];
  adjacent.snapshot.slots[2] = [1, 1, 'ok', '300', String(d + 1n), '400', String(d + 2n)];
  assert.deepEqual(result.assessInstalledPublicationLateInterval(adjacent), noHit);
});

test('closed parameters require the exact same namespace key, original 30-second UTC window and genuinely late immutable completion', () => {
  for (const data of [null, { ...input, extra: true }, { ...input, key: 'b'.repeat(64) },
    { ...input, completedAt: probeDeadlineAt }, { ...input, completedAt: probeStartedAt },
    { ...input, probeDeadlineAt: '2026-10-24T00:00:31.000Z' }, { ...input, completedAt: '2026-10-24 00:00:30.001' },
    { ...input, snapshot: { ...snapshot, kind: 'original' } },
    { ...input, snapshot: { ...snapshot, joined: false } },
    { ...input, snapshot: { ...snapshot, extra: true } }]) assert.throws(() => result.assessInstalledPublicationLateInterval(data));
  let reads = 0;
  const accessor = Object.defineProperty({ ...input }, 'completedAt', { enumerable: true, get() { reads++; return input.completedAt; } });
  assert.throws(() => result.assessInstalledPublicationLateInterval(accessor)); assert.equal(reads, 0);
});

test('fresh-nonce observations cannot predate any available return of the old joined task on the same host monotonic clock', () => {
  const expiredSnapshot = structuredClone(snapshot), freshSnapshot = structuredClone(snapshot);
  freshSnapshot.key = 'b'.repeat(64);
  freshSnapshot.slots[1] = [1, 1, 'ok', '400', '1', '500', '2'];
  freshSnapshot.slots[2] = [1, 1, 'ok', '500', '3', '600', '4'];
  assert.equal(result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot, freshSnapshot }), undefined);
  const early = structuredClone(freshSnapshot); early.slots[1] = [1, 1, 'ok', '399', '1', '500', '2'];
  assert.throws(() => result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot, freshSnapshot: early }),
    { name: 'AssertionError', code: 'ERR_ASSERTION', message: 'the old joined task must return before every available fresh-nonce monotonic entry' });
});

test('causal order checks every available arena or parent tuple but never invents unavailable clocks or orders realtime across tasks', () => {
  const packet = (selected: string) => ({ version: 1, key: selected, kind: 'namespace', joined: true,
    slots: [null, [1, 1, 'unavailable'], [1, 1, 'unavailable']] as (null | (number | string)[])[] });
  const expiredSnapshot = packet(key), freshSnapshot = packet('b'.repeat(64));
  assert.equal(result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot, freshSnapshot }), undefined);
  freshSnapshot.slots[1] = [1, 1, 'ok', '1', '1', '2', '2'];
  assert.equal(result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot, freshSnapshot }), undefined);
  for (const oldIndex of [0, 1, 2]) for (const freshIndex of [0, 1, 2]) {
    const old = packet(key), fresh = packet('b'.repeat(64));
    old.slots[oldIndex] = [2, 3, 'interrupted', '100', '1000', '400', '1100'];
    fresh.slots[freshIndex] = [1, 1, 'error', '399', '1', '500', '2'];
    assert.throws(() => result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot: old, freshSnapshot: fresh }),
      { code: 'ERR_ASSERTION', message: 'the old joined task must return before every available fresh-nonce monotonic entry' });
    fresh.slots[freshIndex]![3] = '400';
    assert.equal(result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot: old, freshSnapshot: fresh }), undefined);
  }
  const available = packet(key); available.slots[1] = [1, 1, 'ok', '100', '1000', '400', '1100'];
  assert.equal(result.assertInstalledPublicationLateCausalOrder({ expiredSnapshot: available, freshSnapshot: packet('b'.repeat(64)) }), undefined);
});

test('causal input remains fixed inert namespace data and cannot read accessor properties', () => {
  const expiredSnapshot = structuredClone(snapshot), freshSnapshot = { ...structuredClone(snapshot), key: 'b'.repeat(64) };
  for (const input of [null, [], { expiredSnapshot }, { expiredSnapshot, freshSnapshot, extra: true },
    { expiredSnapshot: { ...expiredSnapshot, kind: 'original' }, freshSnapshot },
    { expiredSnapshot, freshSnapshot: { ...freshSnapshot, key } },
    { expiredSnapshot, freshSnapshot: { ...freshSnapshot, joined: false } }])
    assert.throws(() => result.assertInstalledPublicationLateCausalOrder(input));
  let reads = 0;
  const getter = Object.defineProperty({ freshSnapshot }, 'expiredSnapshot', { enumerable: true,
    get() { reads++; return expiredSnapshot; } });
  assert.throws(() => result.assertInstalledPublicationLateCausalOrder(getter)); assert.equal(reads, 0);
});

const freshKey = 'b'.repeat(64), invocationId = 'c'.repeat(32);
const sender = { uid: 1001, pid: 2345, invocationId, expiredProbeKey: key, freshProbeKey: freshKey };
const frames = (selected: string) => [
  `CLIQ_PUBLICATION_RETIRE_V1:${selected}:namespace:0:none`,
  `CLIQ_PUBLICATION_RETIRE_V1:${selected}:namespace:1:1:1:ok:100:1000:200:1100`,
  `CLIQ_PUBLICATION_RETIRE_V1:${selected}:namespace:2:1:1:ok:300:1200:400:1300`,
  `CLIQ_PUBLICATION_RETIRE_V1:${selected}:namespace:joined`,
];
const journal = (messages: string[]) => messages.map(MESSAGE => JSON.stringify({ _UID: '1001', _PID: '2345',
  _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: invocationId, MESSAGE })).join('\n');

test('only the exact complete expired prefix stays explicitly incomplete until a single query contains both full groups', () => {
  const pending = result.readInstalledLatePublicationRetirementWindow(journal(frames(key)), sender);
  assert.equal(pending.phase, 'first_packet_only'); assert.equal(pending.snapshots.length, 1);
  assert(Object.isFrozen(pending)); assert.equal(Object.hasOwn(pending, 'qualified'), false);
  const complete = result.readInstalledLatePublicationRetirementWindow(journal([...frames(key), ...frames(freshKey)]), sender);
  assert.equal(complete.phase, 'complete'); assert.equal(complete.snapshots.length, 2);
  assert.equal(result.readInstalledLatePublicationRetirementWindow('', sender).phase, 'unobserved');
});

test('pending adaptation never buffers fragments, combines windows or downgrades unknown frames, keys, bounds or metadata', () => {
  for (const messages of [frames(freshKey), frames(key).slice(0, 3), [...frames(key), ...frames(freshKey).slice(0, 3)],
    [...frames(key), ...frames('d'.repeat(64))], [...frames(key), ...frames(key)],
    [...frames(key), 'CLIQ_PUBLICATION_RETIRE_V1:truncated'],
    [frames(key)[0]!, frames(freshKey)[1]!, ...frames(key).slice(2)]])
    assert.throws(() => result.readInstalledLatePublicationRetirementWindow(journal(messages), sender));
  assert.equal(result.readInstalledLatePublicationRetirementWindow(journal(frames(key)), sender).phase, 'first_packet_only');
  assert.throws(() => result.readInstalledLatePublicationRetirementWindow(journal(frames(freshKey)), sender));
  for (const changed of [{ ...sender, freshProbeKey: key }, { ...sender, freshProbeKey: 'invalid' },
    { ...sender, extra: true }, { ...sender, pid: 2346 }])
    assert.throws(() => result.readInstalledLatePublicationRetirementWindow(journal(frames(key)), changed));
  const wrongRow = JSON.parse(journal(['ordinary'])); wrongRow._UID = 'other';
  assert.throws(() => result.readInstalledLatePublicationRetirementWindow(JSON.stringify(wrongRow) + '\n' + journal(frames(key)), sender));
  assert.throws(() => result.readInstalledLatePublicationRetirementWindow(journal([...Array.from({ length: 77 }, () => 'ordinary'), ...frames(key)]), sender));
});
