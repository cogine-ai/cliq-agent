// Pure data only. These values create no StateOwner, publication or death proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { channel } from 'node:diagnostics_channel';
import { decodePublicationRetirementSpans, noteJoinedPublicationRetirement,
  decodePublicationRetirementDiagnostic, publicationClaimRetirementDiagnosticKey,
  publicationRetirementDiagnosticKey, PUBLICATION_RETIREMENT_CHANNEL } from './publication-retirement-diagnostics.js';

test('publication retirement diagnostics decode exactly three roles and keep repeated attempts explicit', () => {
  const value = [[1, 2, 'interrupted', '100', '1000', '101', '1001'],
    [2, 2, 'error', '102', '1002', '103', '1003'], [1, 1, 'unavailable']];
  const result = decodePublicationRetirementSpans(value);
  assert.deepEqual(result, value);
  assert.notEqual(result, value);
  assert(Object.isFrozen(result));
  assert(Object.isFrozen((result as unknown[])[0]));
});

test('an initial claim diagnostic has a distinct domain and never invents a probe nonce', () => {
  const dispatch = { runId: 'run', planRef: 'plan', opId: 'op', attempt: 0, dispatchId: 'dispatch' };
  const key = publicationClaimRetirementDiagnosticKey(dispatch);
  assert.equal(key, '58ea565d808ca7204751201c3e47213744269ab8c2442ca254ca9c071b23bdaf');
  assert.notEqual(key, publicationRetirementDiagnosticKey({ ...dispatch, probeNonceDigest: '0'.repeat(64) }));
  assert.deepEqual(Object.keys(dispatch), ['runId', 'planRef', 'opId', 'attempt', 'dispatchId']);
});

test('closed diagnostic decoding refuses hidden fields, getters, missing roles, fabricated counts and regressing clocks', () => {
  const ready = () => [1, 1, 'ok', '100', '1000', '101', '1001'];
  for (const rows of [[], [ready(), ready()], [ready(), ready(), ready(), ready()], [null, null, ready()],
    [ready(), ready(), undefined], [[0, 1, 'ok', '100', '1000', '101', '1001'], ready(), ready()],
    [[2, 1, 'ok', '100', '1000', '101', '1001'], ready(), ready()],
    [[1, 1, 'ok', '100', '1000', '99', '1001'], ready(), ready()],
    [[1, 1, 'ok', '100', '1000', '101', '999'], ready(), ready()],
    [[1, 1, 'ok', '0100', '1000', '101', '1001'], ready(), ready()],
    [[1, 1, 'ok', '100', '1000', '18446744073709551616', '1001'], ready(), ready()],
    [[1, 1, 'unavailable', '100'], ready(), ready()], [[1, 1, 'unsupported'], ready(), ready()]])
    assert.throws(() => decodePublicationRetirementSpans(rows), TypeError);
  const slots = [null, ready(), ready()], packet = { version: 1, key: 'a'.repeat(64), kind: 'namespace', joined: true, slots };
  for (const value of [{ ...packet, path: '/private-path' }, { ...packet, joined: false }, { ...packet, key: 'a'.repeat(43) },
    { ...packet, nonce: 'must-not-escape' }, { ...packet, version: 2 }, { ...packet, kind: 'death_proof' }])
    assert.throws(() => decodePublicationRetirementDiagnostic(value), TypeError);
  let accessed = false;
  const getter = () => { accessed = true; throw new Error('private getter'); };
  assert.throws(() => decodePublicationRetirementDiagnostic(Object.defineProperty({ ...packet }, 'slots', { get: getter, enumerable: true })), TypeError);
  assert.throws(() => decodePublicationRetirementSpans([null, Object.defineProperty(ready(), '3', { get: getter }), ready()]), TypeError);
  const extra = ready(); Object.defineProperty(extra, Symbol('hidden'), { value: 'private' });
  assert.throws(() => decodePublicationRetirementSpans([null, extra, ready()]), TypeError);
  assert.equal(accessed, false);
});

test('the publication diagnostic emits only a fixed joined snapshot and cannot turn a read failure into execution failure', () => {
  const diagnostic = channel(PUBLICATION_RETIREMENT_CHANNEL), received: unknown[] = [];
  const subscriber = (value: unknown) => { try { received.push(value); } catch { /* Inert trusted sink only. */ } };
  let reads = 0;
  const read = () => { reads++; return { version: 1 as const, key: 'a'.repeat(64), kind: 'namespace' as const, joined: true as const,
    slots: decodePublicationRetirementSpans([null, [1, 1, 'ok', '1', '2', '3', '4'], [1, 1, 'ok', '5', '6', '7', '8']]) }; };
  noteJoinedPublicationRetirement(read); assert.equal(reads, 0);
  diagnostic.subscribe(subscriber);
  try {
    noteJoinedPublicationRetirement(read);
    assert.equal(reads, 1); assert.equal(received.length, 1); assert(Object.isFrozen(received[0]));
    assert(Buffer.byteLength(JSON.stringify(received[0])) <= 1024);
    assert.doesNotThrow(() => noteJoinedPublicationRetirement(() => { throw new Error('private raw error'); }));
    assert.equal(received.length, 1);
  } finally { diagnostic.unsubscribe(subscriber); }
});
