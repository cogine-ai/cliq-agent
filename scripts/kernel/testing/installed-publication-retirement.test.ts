// Pure fixed-data qualification reader tests. No Run, StateOwner, native
// resource, journal access or physical retirement evidence is created here.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as retirement from './installed-publication-retirement.js';

const key = 'a'.repeat(64), prefix = 'CLIQ_PUBLICATION_RETIRE_V1:';
const frames = (selectedKey = key, kind = 'original') => [
  `${prefix}${selectedKey}:${kind}:0:none`,
  `${prefix}${selectedKey}:${kind}:1:1:1:ok:100:1000:200:1100`,
  `${prefix}${selectedKey}:${kind}:2:1:1:ok:300:1200:400:1300`,
  `${prefix}${selectedKey}:${kind}:joined`,
];

test('four ordered fixed journal messages decode one immutable core retirement packet', () => {
  const input = frames(), before = [...input];
  const packets = retirement.decodeInstalledPublicationRetirements(input);
  assert.deepEqual(packets, [{ version: 1, key, kind: 'original', joined: true,
    slots: [null, [1, 1, 'ok', '100', '1000', '200', '1100'], [1, 1, 'ok', '300', '1200', '400', '1300']] }]);
  assert.deepEqual(input, before); assert(Object.isFrozen(packets)); assert(Object.isFrozen(packets[0]));
  assert(Object.isFrozen(packets[0]!.slots)); assert(Object.isFrozen(packets[0]!.slots[1]));
});

test('only an original first parent fsync can strictly enclose the complete actor signal in both clocks', () => {
  const packet = retirement.decodeInstalledPublicationRetirements(frames())[0]!;
  assert.equal(retirement.isOriginalPublicationRetirementSignalBracket(packet, key, {
    monotonicEnterNs: '110', realtimeEnterNs: '1010', monotonicReturnNs: '120', realtimeReturnNs: '1020' }), true);
  assert.equal(retirement.isOriginalPublicationRetirementSignalBracket(packet, key, {
    monotonicEnterNs: '310', realtimeEnterNs: '1210', monotonicReturnNs: '320', realtimeReturnNs: '1220' }), true);
});

test('the stop-specific bracket selects only first parent slot one without changing the any-parent reader', () => {
  const packet = retirement.decodeInstalledPublicationRetirements(frames())[0]!;
  const first = { monotonicEnterNs: '110', realtimeEnterNs: '1010', monotonicReturnNs: '120', realtimeReturnNs: '1020' };
  const second = { monotonicEnterNs: '310', realtimeEnterNs: '1210', monotonicReturnNs: '320', realtimeReturnNs: '1220' };
  assert.equal(retirement.isOriginalPublicationFirstParentSignalBracket(packet, key, first), true);
  assert.equal(retirement.isOriginalPublicationFirstParentSignalBracket(packet, key, second), false);
  assert.equal(retirement.isOriginalPublicationRetirementSignalBracket(packet, key, second), true);
});

test('the real actor join uses its original signal start and independent unchanged two-second limit', () => {
  assert.equal(retirement.isPublicationSignalActorJoinedWithinStop({ monotonicSignalEnterNs: '110', monotonicJoinedNs: '2000000110' }), true);
  assert.equal(retirement.isPublicationSignalActorJoinedWithinStop({ monotonicSignalEnterNs: '110', monotonicJoinedNs: '2000000111' }), false);
});

test('each complete key-kind group is closed, dense, ordered, bounded and cannot be truncated or interleaved', () => {
  const fresh = frames(), other = frames('b'.repeat(64), 'namespace');
  const two = retirement.decodeInstalledPublicationRetirements([...fresh, ...other]);
  assert.equal(two.length, 2); assert.equal(two[1]!.kind, 'namespace');
  const thirtyTwo = Array.from({ length: 32 }, (_, index) => frames(index.toString(16).padStart(64, '0'))).flat();
  assert.equal(retirement.decodeInstalledPublicationRetirements(thirtyTwo).length, 32);
  for (const input of [undefined, '', [], fresh.slice(0, 3), [fresh[0], fresh[2], fresh[1], fresh[3]],
    [fresh[0], other[1], fresh[2], fresh[3]], [fresh[0], fresh[1], other[2], fresh[3]],
    [fresh[0], fresh[1], fresh[2], other[3]], [...fresh, ...fresh], [...thirtyTwo, ...other],
    [...thirtyTwo, `${prefix}truncated`], [fresh[0], fresh[1], fresh[2], `${prefix}truncated`],
    { 0: fresh[0], 1: fresh[1], 2: fresh[2], 3: fresh[3], length: 4 },
    Object.assign([...fresh], { extra: 'not-a-frame' }), [...fresh.slice(0, 3), undefined]])
    assert.throws(() => retirement.decodeInstalledPublicationRetirements(input), TypeError);
});

test('journal MESSAGE grammar rejects arbitrary text, LF, non-ASCII, excess fields and noncanonical numbers', () => {
  for (const bad of ['unrelated text', `${frames()[0]}\n`, `${frames()[0]}\r`, `${frames()[0]}é`, 'x'.repeat(256),
    `${prefix}${key}:original:0:none:extra`, `${prefix}${key}:original:joined:extra`,
    `${prefix}${key}:original:1:none`, `${prefix}${key}:original:1:0:1:ok:1:2:3:4`,
    `${prefix}${key}:original:1:01:1:ok:1:2:3:4`, `${prefix}${key}:original:1:1:01:ok:1:2:3:4`,
    `${prefix}${key}:original:1:1.0:1:ok:1:2:3:4`, `${prefix}${key}:original:1:4294967296:4294967296:unavailable`,
    `${prefix}${key}:original:1:2:1:ok:1:2:3:4`, `${prefix}${key}:original:1:1:1:ok:01:2:3:4`,
    `${prefix}${key}:original:1:1:1:ok:1:2:18446744073709551616:4`, `${prefix}${key}:original:1:1:1:unavailable:1:2:3:4`,
    `${prefix}${key}:original:1:1:1:ok`, `${prefix}${key}:original:1:1:1:ok:3:2:1:4`,
    `${prefix}${key}:original:1:1:1:ok:1:4:3:2`]) {
    const input = frames(); input[1] = bad;
    assert.throws(() => retirement.decodeInstalledPublicationRetirements(input), TypeError);
  }
  for (const field of [new String(frames()[1]), 1, null, false]) {
    const input: unknown[] = frames(); input[1] = field;
    assert.throws(() => retirement.decodeInstalledPublicationRetirements(input), TypeError);
  }
});

test('accessors, holes, hidden fields and symbols are rejected without invoking a getter', () => {
  let reads = 0;
  const getter = () => { reads++; throw new Error('untrusted getter must not run'); };
  const input = frames(); Object.defineProperty(input, '1', { get: getter, enumerable: true });
  assert.throws(() => retirement.decodeInstalledPublicationRetirements(input), TypeError);
  const holes = frames(); delete holes[1]; assert.throws(() => retirement.decodeInstalledPublicationRetirements(holes), TypeError);
  const symbol = frames(); Object.defineProperty(symbol, Symbol('hidden'), { value: true });
  assert.throws(() => retirement.decodeInstalledPublicationRetirements(symbol), TypeError);
  const hidden = frames(); Object.defineProperty(hidden, '1', { value: hidden[1], enumerable: false });
  assert.throws(() => retirement.decodeInstalledPublicationRetirements(hidden), TypeError);
  const packet = retirement.decodeInstalledPublicationRetirements(frames())[0]!;
  const signal = { monotonicEnterNs: '110', realtimeEnterNs: '1010', monotonicReturnNs: '120', realtimeReturnNs: '1020' };
  assert.throws(() => retirement.isOriginalPublicationRetirementSignalBracket(Object.defineProperty({ ...packet }, 'slots', { get: getter, enumerable: true }), key, signal), TypeError);
  assert.throws(() => retirement.isOriginalPublicationRetirementSignalBracket(packet, key, Object.defineProperty({ ...signal }, 'realtimeEnterNs', { get: getter, enumerable: true })), TypeError);
  assert.throws(() => retirement.isPublicationSignalActorJoinedWithinStop(Object.defineProperty({ monotonicJoinedNs: '120' }, 'monotonicSignalEnterNs', { get: getter, enumerable: true })), TypeError);
  assert.equal(reads, 0);
});

test('adjacent spans, one-clock overlap, non-parent slots, other keys and namespace packets cannot qualify', () => {
  const packet = retirement.decodeInstalledPublicationRetirements(frames())[0]!;
  const signal = { monotonicEnterNs: '110', realtimeEnterNs: '1010', monotonicReturnNs: '120', realtimeReturnNs: '1020' };
  assert.equal(retirement.isOriginalPublicationRetirementSignalBracket(packet, 'b'.repeat(64), signal), false);
  assert.equal(retirement.isOriginalPublicationRetirementSignalBracket({ ...packet, kind: 'namespace' }, key, signal), false);
  for (const changed of [
    { ...signal, monotonicEnterNs: '100' }, { ...signal, monotonicReturnNs: '200' },
    { ...signal, realtimeEnterNs: '1000' }, { ...signal, realtimeReturnNs: '1100' },
    { monotonicEnterNs: '200', realtimeEnterNs: '1100', monotonicReturnNs: '300', realtimeReturnNs: '1200' },
    { ...signal, realtimeEnterNs: '1301', realtimeReturnNs: '1302' },
  ]) {
    assert.equal(retirement.isOriginalPublicationRetirementSignalBracket(packet, key, changed), false);
    assert.equal(retirement.isOriginalPublicationFirstParentSignalBracket(packet, key, changed), false);
  }
  assert.equal(retirement.isOriginalPublicationRetirementSignalBracket({ ...packet,
    slots: [[1, 1, 'ok', '100', '1000', '200', '1100'], [1, 1, 'unavailable'], [1, 1, 'unavailable']] }, key, signal), false);
});

test('EINTR, repeated calls or attempts, unavailable and failed first fsync never count as a strict bracket', () => {
  const packet = retirement.decodeInstalledPublicationRetirements(frames())[0]!;
  const signal = { monotonicEnterNs: '110', realtimeEnterNs: '1010', monotonicReturnNs: '120', realtimeReturnNs: '1020' };
  for (const span of [[1, 1, 'interrupted', '100', '1000', '200', '1100'], [1, 1, 'error', '100', '1000', '200', '1100'],
    [2, 2, 'ok', '100', '1000', '200', '1100'], [1, 2, 'ok', '100', '1000', '200', '1100'], [1, 1, 'unavailable']])
  {
    assert.equal(retirement.isOriginalPublicationRetirementSignalBracket({ ...packet, slots: [null, span, [1, 1, 'unavailable']] }, key, signal), false);
    assert.equal(retirement.isOriginalPublicationFirstParentSignalBracket({ ...packet, slots: [null, span, [1, 1, 'unavailable']] }, key, signal), false);
  }
});

test('clock and actor-join inputs stay closed, canonical uint64 data rather than authority or clock coercion', () => {
  const packet = retirement.decodeInstalledPublicationRetirements(frames())[0]!;
  const signal = { monotonicEnterNs: '110', realtimeEnterNs: '1010', monotonicReturnNs: '120', realtimeReturnNs: '1020' };
  for (const bad of [{ ...signal, extra: true }, { ...signal, monotonicEnterNs: 110 }, { ...signal, monotonicEnterNs: '0110' },
    { ...signal, monotonicEnterNs: '18446744073709551616' }, { ...signal, monotonicReturnNs: '109' }, { ...signal, realtimeReturnNs: '1009' }])
  {
    assert.throws(() => retirement.isOriginalPublicationRetirementSignalBracket(packet, key, bad), TypeError);
    assert.throws(() => retirement.isOriginalPublicationFirstParentSignalBracket(packet, key, bad), TypeError);
  }
  for (const bad of [{ monotonicSignalEnterNs: '110', monotonicJoinedNs: '109' },
    { monotonicSignalEnterNs: '110', monotonicJoinedNs: '200', withinDeadline: true },
    { monotonicSignalEnterNs: '110', monotonicJoinedNs: '02' },
    { monotonicSignalEnterNs: '110', monotonicJoinedNs: '18446744073709551616' }])
    assert.throws(() => retirement.isPublicationSignalActorJoinedWithinStop(bad), TypeError);
});
