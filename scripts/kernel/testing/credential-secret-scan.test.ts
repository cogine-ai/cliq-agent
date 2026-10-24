import assert from 'node:assert/strict';
import test from 'node:test';
import { CredentialSecretScanError, createCredentialSecretScanner,
  copyCredentialSecretScanFailureDiagnostic, type CredentialSecretScanStats } from './credential-secret-scan.js';

// Pure scanner contracts only; these fixed bytes are not installed evidence.
const limits = { maxBytes: 4096, maxStreams: 8 };
const input = () => Buffer.from([251, 255, 0, 1]);

test('raw credential input is detected without returning its bytes', () => {
  const scanner = createCredentialSecretScanner([input()], limits);
  const stream = scanner.openStream();
  assert.throws(() => stream.scan(input()), {
    code: 'SECRET_DETECTED', message: 'credential secret scan detected forbidden bytes',
  });
  const stats = scanner.stats();
  assert.equal(stats.matched, true); assert.equal(stats.closed, true);
  assert.equal(stats.retainedNeedleBytes, 0); assert.equal(stats.retainedTailBytes, 0);
  assert(Object.values(stats).every(value => typeof value === 'number' || typeof value === 'boolean'));
});

test('stream overlap detects a raw needle split across chunks', () => {
  const scanner = createCredentialSecretScanner([input()], limits), stream = scanner.openStream();
  stream.scan(Buffer.from([251, 255]));
  assert.equal(scanner.stats().matched, false);
  assert.throws(() => stream.scan(Buffer.from([0, 1])), { code: 'SECRET_DETECTED' });
});

test('long encoded overlap survives multiple short chunks', () => {
  const scanner = createCredentialSecretScanner([input()], limits), stream = scanner.openStream();
  stream.scan(Buffer.from('[251,')); stream.scan(Buffer.from('255,')); stream.scan(Buffer.from('0,'));
  assert.throws(() => stream.scan(Buffer.from('1]')), { code: 'SECRET_DETECTED' });
});

test('independent streams never combine their partial bytes', () => {
  const scanner = createCredentialSecretScanner([input()], limits);
  const stdout = scanner.openStream(), stderr = scanner.openStream();
  stdout.scan(Buffer.from([251, 255])); stderr.scan(Buffer.from([0, 1]));
  assert.equal(scanner.stats().matched, false);
  assert.throws(() => stdout.scan(Buffer.from([0, 1])), { code: 'SECRET_DETECTED' });
  assert.equal(scanner.stats().streamsClosed, 2);
});

test('normal bytes qualify with count-only immutable statistics and close releases copied state', () => {
  const secret = input(), scanner = createCredentialSecretScanner([secret], limits);
  const first = scanner.openStream(), second = scanner.openStream();
  const chunk = new Uint8Array([7, 8, 9]); first.scan(chunk); second.scan(new Uint8Array([10, 11]));
  const before = scanner.stats();
  assert.equal(before.matched, false); assert.equal(before.bytesScanned, 5); assert.equal(before.chunksScanned, 2);
  assert(before.retainedNeedleBytes > 0); assert(before.retainedTailBytes > 0); assert(Object.isFrozen(before));
  first.close(); first.close(); assert.equal(scanner.stats().streamsClosed, 1);
  scanner.close(); scanner.close();
  const after = scanner.stats();
  assert.equal(after.closed, true); assert.equal(after.streamsClosed, 2);
  assert.equal(after.retainedNeedleBytes, 0); assert.equal(after.retainedTailBytes, 0);
  assert.equal(before.closed, false, 'previous statistics remain a copied snapshot');
  assert.equal(secret.equals(input()), true); assert.deepEqual([...chunk], [7, 8, 9]);
  assert.throws(() => second.scan(new Uint8Array()), { code: 'CLOSED' });
  assert.throws(() => scanner.openStream(), { code: 'CLOSED' });
});

test('scanner owns a copy rather than later caller mutations', () => {
  const secret = input(), scanner = createCredentialSecretScanner([secret], limits);
  secret.fill(0);
  assert.throws(() => scanner.openStream().scan(input()), { code: 'SECRET_DETECTED' });
  assert.equal(secret.every(byte => byte === 0), true);
});

test('total scan budget is shared across streams and exhaustion retires all owners', () => {
  const scanner = createCredentialSecretScanner([input()], { maxBytes: 3, maxStreams: 2 });
  const first = scanner.openStream(), second = scanner.openStream();
  first.scan(new Uint8Array([7, 8])); second.scan(new Uint8Array([9]));
  assert.throws(() => second.scan(new Uint8Array([10])), {
    code: 'LIMIT_EXCEEDED', message: 'credential secret scan exceeded its bound',
  });
  const stats = scanner.stats();
  assert.equal(stats.bytesScanned, 3); assert.equal(stats.limitExceeded, true); assert.equal(stats.closed, true);
  assert.equal(stats.retainedNeedleBytes, 0); assert.equal(stats.retainedTailBytes, 0); assert.equal(stats.streamsClosed, 2);
});

test('stream-count and single-chunk bounds cannot be bypassed', () => {
  const scanner = createCredentialSecretScanner([input()], { maxBytes: 16, maxStreams: 1 });
  scanner.openStream().close();
  assert.throws(() => scanner.openStream(), { code: 'LIMIT_EXCEEDED' });
  const chunkScan = createCredentialSecretScanner([input()], { maxBytes: 16 * 1024 * 1024, maxStreams: 1 });
  assert.throws(() => chunkScan.openStream().scan(new Uint8Array(8 * 1024 * 1024 + 1)), { code: 'LIMIT_EXCEEDED' });
  assert.equal(chunkScan.stats().bytesScanned, 0); assert.equal(chunkScan.stats().closed, true);
});

test('failure observation happens after real scanner closure and cannot replace its original error', () => {
  let observed: CredentialSecretScanError | undefined;
  const observations: CredentialSecretScanStats[] = [];
  const observerFailure = new Error('observer failure must remain private');
  const scanner = createCredentialSecretScanner([input()], { maxBytes: 16, maxStreams: 1 }, error => {
    observed = error;
    observations.push(scanner.stats());
    throw observerFailure;
  });
  scanner.openStream().close();
  assert.throws(() => scanner.openStream(), error => {
    assert.equal(error, observed, 'observation sees the exact original thrown scanner error');
    assert.notEqual(error, observerFailure, 'observer exception cannot replace the original error');
    assert(error instanceof CredentialSecretScanError, 'the original scanner class is retained');
    assert.equal(error.code, 'LIMIT_EXCEEDED', 'the original limit remains enforced');
    return true;
  });
  assert.equal(observations.length, 1, 'the failure is observed exactly once');
  const stats = observations[0]!;
  assert.equal(stats.closed, true, 'scanner closes before observation');
  assert.equal(stats.streamsOpened, stats.streamsClosed, 'all real stream owners retire before observation');
  assert.equal(stats.retainedNeedleBytes, 0, 'needles retire before observation');
  assert.equal(stats.retainedTailBytes, 0, 'tails retire before observation');
  const first = observed;
  assert.throws(() => scanner.openStream(), { code: 'CLOSED' });
  assert.equal(observed, first, 'subsequent CLOSED cannot overwrite the first failure');
});

test('fixed failure projection emits only closed copied data and never claims qualification', () => {
  const source = { diagnosticOnly: true, firstFailureStage: 'corpus',
    beforeCorpus: { streamsOpened: 4, bytesScanned: 300 }, corpusScanFailureCode: 'LIMIT_EXCEEDED' };
  const actual = copyCredentialSecretScanFailureDiagnostic(source);
  assert.deepEqual(actual, { diagnosticOnly: true, firstFailureStage: 'corpus',
    beforeCorpus: { streamsOpened: 4, bytesScanned: 300 }, corpusScanFailureCode: 'LIMIT_EXCEEDED' });
  source.beforeCorpus.bytesScanned = 400;
  assert.equal(actual.beforeCorpus!.bytesScanned, 300, 'the earlier actual snapshot remains immutable');
  assert.equal(Object.isFrozen(actual), true, 'the diagnostic is immutable data');
  assert.equal(Object.isFrozen(actual.beforeCorpus), true, 'the count snapshot is immutable data');
  assert.equal(Object.hasOwn(actual, 'qualified'), false, 'diagnosis never qualifies a phase');
});

test('closed failure data handles runtime, corpus, report and unavailable without retaining raw text', () => {
  for (const firstFailureStage of ['runtime', 'corpus', 'report', null] as const) {
    const value = copyCredentialSecretScanFailureDiagnostic({ diagnosticOnly: true, firstFailureStage,
      beforeCorpus: firstFailureStage === 'corpus' ? { streamsOpened: 4096, bytesScanned: 512 * 1024 * 1024 } : null,
      corpusScanFailureCode: null });
    assert.equal(value.firstFailureStage, firstFailureStage, 'the original fixed stage is retained without qualification');
    assert.equal(Object.hasOwn(value, 'qualified'), false, 'even unavailable is diagnosis, not success');
  }
  for (const corpusScanFailureCode of ['INVALID_INPUT', 'LIMIT_EXCEEDED', 'SECRET_DETECTED', 'CLOSED'] as const) {
    const actual = copyCredentialSecretScanFailureDiagnostic({ diagnosticOnly: true, firstFailureStage: 'runtime',
      beforeCorpus: { streamsOpened: 4096, bytesScanned: 3 }, corpusScanFailureCode });
    assert.equal(actual.corpusScanFailureCode, corpusScanFailureCode, 'only the original closed corpus code escapes');
  }
});

test('failure projection refuses malicious objects without invoking getters, Proxy traps or toJSON', () => {
  const valid = () => ({ diagnosticOnly: true, firstFailureStage: 'runtime', beforeCorpus: null, corpusScanFailureCode: null });
  let invoked = 0;
  const getter = Object.defineProperty(valid(), 'firstFailureStage', { enumerable: true, get() { invoked++; throw new Error('private raw text'); } });
  const traps: ProxyHandler<object> = {};
  for (const key of ['get', 'getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'] as const)
    traps[key] = (() => { invoked++; throw new Error('private raw text'); }) as never;
  const proxy = new Proxy(valid(), traps);
  const nestedProxy = { ...valid(), beforeCorpus: new Proxy({ streamsOpened: 0, bytesScanned: 0 }, traps) };
  for (const value of [getter, proxy, nestedProxy, { ...valid(), toJSON() { invoked++; throw new Error('private raw text'); } }]) {
    assert.throws(() => copyCredentialSecretScanFailureDiagnostic(value),
      { name: 'TypeError', message: 'invalid credential secret scan failure diagnostic' });
  }
  assert.equal(invoked, 0, 'no untrusted accessor or trap is invoked');
  const invalid: unknown[] = [null, [], 1, 'private raw text', { ...valid(), diagnosticOnly: false },
    { ...valid(), firstFailureStage: ['runtime'] }, { ...valid(), firstFailureStage: 'private raw text' },
    { ...valid(), firstFailureStage: new String('runtime') }, { ...valid(), corpusScanFailureCode: ['CLOSED'] },
    { ...valid(), corpusScanFailureCode: 'private raw text' }, { ...valid(), corpusScanFailureCode: 'CLOSED' },
    { ...valid(), firstFailureStage: 'corpus' }, { ...valid(), message: 'private raw text' },
    { ...valid(), phase: 'private raw text' }, { ...valid(), qualified: true },
    Object.assign(Object.create({ inherited: true }), valid())];
  for (const key of ['diagnosticOnly', 'firstFailureStage', 'beforeCorpus', 'corpusScanFailureCode']) {
    const value: Record<string, unknown> = valid(); delete value[key]; invalid.push(value);
  }
  for (const key of ['streamsOpened', 'bytesScanned']) {
    for (const bad of [-1, 1.5, NaN, Infinity, true, '1', null, Number.MAX_SAFE_INTEGER + 1])
      invalid.push({ ...valid(), beforeCorpus: { streamsOpened: 0, bytesScanned: 0, [key]: bad } });
  }
  invalid.push({ ...valid(), beforeCorpus: { streamsOpened: 4097, bytesScanned: 0 } },
    { ...valid(), beforeCorpus: { streamsOpened: 0, bytesScanned: 512 * 1024 * 1024 + 1 } },
    { ...valid(), beforeCorpus: { streamsOpened: 0, bytesScanned: 0, raw: 'private raw text' } });
  for (const value of invalid) {
    assert.throws(() => copyCredentialSecretScanFailureDiagnostic(value), error => {
      assert(error instanceof TypeError, 'only the fixed diagnostic TypeError escapes');
      assert.equal(error.message, 'invalid credential secret scan failure diagnostic', 'no raw data enters an error message');
      assert.equal(JSON.stringify(error).includes('private raw text'), false, 'no raw data is retained on errors');
      return true;
    });
  }
});

test('successful observed scanners do not notify or alter independent streams', () => {
  let observed = 0;
  const scanner = createCredentialSecretScanner([input()], limits, () => { observed++; });
  const first = scanner.openStream(), second = scanner.openStream();
  first.scan(Buffer.from([251, 255])); second.scan(Buffer.from([0, 1]));
  first.close(); second.close(); scanner.close();
  assert.equal(observed, 0, 'successful scans and explicit close do not notify');
  assert.equal(scanner.stats().matched, false, 'independent stream tails remain separate');
  assert.equal(scanner.stats().streamsOpened, 2, 'both independent streams remain counted');
});

test('invalid creation boundaries give only a fixed error and never retain caller data', () => {
  for (const secrets of [null, [], [new Uint8Array()], ['not bytes'], [new Uint16Array(4)],
    [new Uint8Array(65537)], [new Uint8Array(new SharedArrayBuffer(4))]]) {
    assert.throws(() => createCredentialSecretScanner(secrets as never, limits), {
      code: 'INVALID_INPUT', message: 'credential secret scan input is invalid',
    });
  }
  for (const badLimits of [null, {}, { maxBytes: 0, maxStreams: 1 }, { maxBytes: 1.5, maxStreams: 1 },
    { maxBytes: 1024 * 1024 * 1024 + 1, maxStreams: 1 }, { maxBytes: 1, maxStreams: 8193 },
    { maxBytes: 1, maxStreams: 1, filename: 'caller data must not appear' }]) {
    assert.throws(() => createCredentialSecretScanner([input()], badLimits as never), { code: 'INVALID_INPUT' });
  }
});

test('invalid stream input retires copies and excludes arbitrary input from its error', () => {
  const scanner = createCredentialSecretScanner([input()], limits), stream = scanner.openStream();
  let error: unknown;
  try { stream.scan('caller data must not appear' as never); } catch (caught) { error = caught; }
  assert(error instanceof CredentialSecretScanError);
  assert.equal(error.code, 'INVALID_INPUT'); assert.equal(error.message, 'credential secret scan input is invalid');
  assert.equal(Object.hasOwn(error, 'cause'), false);
  assert.equal(JSON.stringify(error).includes('caller data'), false);
  assert.equal(scanner.stats().closed, true); assert.equal(scanner.stats().retainedNeedleBytes, 0);
});

test('a detached byte view is invalid rather than an empty qualified chunk', () => {
  const scanner = createCredentialSecretScanner([input()], limits), stream = scanner.openStream();
  const backing = new ArrayBuffer(4), detached = new Uint8Array(backing);
  structuredClone(backing, { transfer: [backing] });
  assert.throws(() => stream.scan(detached), { code: 'INVALID_INPUT' });
  assert.equal(scanner.stats().closed, true); assert.equal(scanner.stats().bytesScanned, 0);
});

test('empty valid chunks are a no-op and cannot spend unbounded chunk counts', () => {
  const scanner = createCredentialSecretScanner([input()], limits), stream = scanner.openStream();
  try {
    stream.scan(new Uint8Array()); stream.scan(new Uint8Array());
    assert.equal(scanner.stats().chunksScanned, 0); assert.equal(scanner.stats().bytesScanned, 0);
  } finally { scanner.close(); }
});

test('all supplied secrets are copied and checked, including byte subviews', () => {
  const backing = new Uint8Array([7, 251, 255, 0, 1, 8]);
  const scanner = createCredentialSecretScanner([new Uint8Array([40, 41, 42]), backing.subarray(1, 5)], limits);
  assert.throws(() => scanner.openStream().scan(input()), { code: 'SECRET_DETECTED' });
  assert.deepEqual([...backing], [7, 251, 255, 0, 1, 8]);
});

test('secret count and combined copied-input bounds are enforced', () => {
  for (const secrets of [Array.from({ length: 33 }, input), [new Uint8Array(32769), new Uint8Array(32768)]]) {
    assert.throws(() => createCredentialSecretScanner(secrets, limits), { code: 'INVALID_INPUT' });
  }
});

test('real CAS campaign bounds accept a 512 MiB corpus and more than 256 logical streams', () => {
  const scanner = createCredentialSecretScanner([input()], { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 });
  try {
    for (let index = 0; index < 300; index++) {
      const stream = scanner.openStream(); stream.scan(new Uint8Array([7])); stream.close();
    }
    assert.equal(scanner.stats().streamsOpened, 300); assert.equal(scanner.stats().streamsClosed, 300);
    assert.equal(scanner.stats().bytesScanned, 300); assert.equal(scanner.stats().retainedTailBytes, 0);
  } finally { scanner.close(); }
  const ceiling = createCredentialSecretScanner([input()], { maxBytes: 1024 * 1024 * 1024, maxStreams: 8192 });
  ceiling.close(); assert.equal(ceiling.stats().closed, true);
});

for (const [encoding, encoded] of [
  ['lowercase hex', 'fbff0001'], ['uppercase hex', 'FBFF0001'],
  ['padded base64', '+/8AAQ=='], ['unpadded base64', '+/8AAQ'],
  ['padded base64url', '-_8AAQ=='], ['unpadded base64url', '-_8AAQ'],
  ['compact JSON decimal array', '[251,255,0,1]'],
  ['spaced JSON decimal array', '[251, 255, 0, 1]'],
  ['pretty JSON decimal array', '[\n  251,\n  255,\n  0,\n  1\n]'],
  ['strace hexadecimal bytes', '\\xfb\\xff\\x00\\x01'],
  ['uppercase strace hexadecimal bytes', '\\xFB\\xFF\\x00\\x01'],
] as const) test(`credential input encoded as ${encoding} is detected`, () => {
  const scanner = createCredentialSecretScanner([input()], limits);
  const stream = scanner.openStream();
  try {
    assert.throws(() => stream.scan(Buffer.from(`metadata:${encoded}:end`)), { code: 'SECRET_DETECTED' });
    assert.equal(scanner.stats().matched, true);
  } finally { scanner.close(); }
});
