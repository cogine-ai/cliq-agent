// Test-private byte qualification only: no filesystem, hashing, persistence,
// process evidence or authority decisions. Callers retain ownership of input.
import { types } from 'node:util';

export type CredentialSecretScanCode = 'INVALID_INPUT' | 'LIMIT_EXCEEDED' | 'SECRET_DETECTED' | 'CLOSED';
const messages: Record<CredentialSecretScanCode, string> = {
  INVALID_INPUT: 'credential secret scan input is invalid',
  LIMIT_EXCEEDED: 'credential secret scan exceeded its bound',
  SECRET_DETECTED: 'credential secret scan detected forbidden bytes',
  CLOSED: 'credential secret scan is closed',
};
export class CredentialSecretScanError extends Error {
  constructor(readonly code: CredentialSecretScanCode) {
    super(messages[code]); this.name = 'CredentialSecretScanError';
  }
}
export type CredentialSecretScanLimits = Readonly<{ maxBytes: number; maxStreams: number }>;
export type CredentialSecretScanStats = Readonly<{
  bytesScanned: number; chunksScanned: number; streamsOpened: number; streamsClosed: number;
  needleCount: number; retainedNeedleBytes: number; retainedTailBytes: number;
  matched: boolean; limitExceeded: boolean; closed: boolean;
}>;
export type CredentialSecretScanStream = Readonly<{ scan(bytes: Uint8Array): void; close(): void }>;
export type CredentialSecretScanner = Readonly<{
  openStream(): CredentialSecretScanStream; stats(): CredentialSecretScanStats; close(): void;
}>;
export type CredentialSecretScanFailureStage = 'runtime' | 'corpus' | 'report';
export type CredentialSecretScanFailureDiagnostic = Readonly<{
  diagnosticOnly: true; firstFailureStage: CredentialSecretScanFailureStage | null;
  beforeCorpus: Readonly<{ streamsOpened: number; bytesScanned: number }> | null;
  corpusScanFailureCode: CredentialSecretScanCode | null;
}>;

/** Fixed fallback data only. It cannot expose an original report, phase,
 * error or input bytes, or turn a failed scan into qualification. */
export function copyCredentialSecretScanFailureDiagnostic(input: unknown): CredentialSecretScanFailureDiagnostic {
  function invalid(): never { throw new TypeError('invalid credential secret scan failure diagnostic'); }
  const fields = (value: unknown, keys: readonly string[]): Record<string, PropertyDescriptor> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value) || types.isProxy(value)) invalid();
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Reflect.ownKeys(descriptors);
    if (names.length !== keys.length || !names.every(key => typeof key === 'string' && keys.includes(key))) invalid();
    for (const key of keys) if (!Object.hasOwn(descriptors[key]!, 'value') || !descriptors[key]!.enumerable) invalid();
    return descriptors;
  };
  const value = fields(input, ['diagnosticOnly', 'firstFailureStage', 'beforeCorpus', 'corpusScanFailureCode']);
  if (value.diagnosticOnly!.value !== true) invalid();
  const stage: unknown = value.firstFailureStage!.value, code: unknown = value.corpusScanFailureCode!.value;
  if (stage !== null && (typeof stage !== 'string' || !['runtime', 'corpus', 'report'].includes(stage))) invalid();
  if (code !== null && (typeof code !== 'string' || !Object.hasOwn(messages, code))) invalid();
  let beforeCorpus: CredentialSecretScanFailureDiagnostic['beforeCorpus'] = null;
  if (value.beforeCorpus!.value !== null) {
    const before = fields(value.beforeCorpus!.value, ['streamsOpened', 'bytesScanned']);
    const streams: unknown = before.streamsOpened!.value, bytes: unknown = before.bytesScanned!.value;
    if (typeof streams !== 'number' || !Number.isSafeInteger(streams) || streams < 0 || streams > 4096 ||
        typeof bytes !== 'number' || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > 512 * 1024 * 1024) invalid();
    beforeCorpus = Object.freeze({ streamsOpened: streams, bytesScanned: bytes });
  }
  if ((stage === 'corpus' || code !== null) && beforeCorpus === null) invalid();
  return Object.freeze({ diagnosticOnly: true, firstFailureStage: stage as CredentialSecretScanFailureStage | null,
    beforeCorpus, corpusScanFailureCode: code as CredentialSecretScanCode | null });
}
const maxSecretBytes = 65536, maxSecretCount = 32, maxChunkBytes = 8 * 1024 * 1024;
function invalid(): never { throw new CredentialSecretScanError('INVALID_INPUT'); }
function bytesInput(input: unknown): Uint8Array {
  try {
    if (!(input instanceof Uint8Array) || !ArrayBuffer.isView(input) || input.buffer instanceof SharedArrayBuffer) invalid();
    // Construction rejects detached/out-of-bounds views before they can be
    // mistaken for an empty chunk or throw an uncontrolled native message.
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  } catch { return invalid(); }
}
function checkedLimits(input: CredentialSecretScanLimits): CredentialSecretScanLimits {
  try {
    if (!input || typeof input !== 'object' || Reflect.ownKeys(input).length !== 2) invalid();
    const bytes = Object.getOwnPropertyDescriptor(input, 'maxBytes'), streams = Object.getOwnPropertyDescriptor(input, 'maxStreams');
    if (!bytes || !streams || !('value' in bytes) || !('value' in streams) ||
        !Number.isSafeInteger(bytes.value) || bytes.value <= 0 || bytes.value > 1024 * 1024 * 1024 ||
        !Number.isSafeInteger(streams.value) || streams.value <= 0 || streams.value > 8192) invalid();
    return { maxBytes: bytes.value as number, maxStreams: streams.value as number };
  } catch { return invalid(); }
}
function appendNeedles(needles: Buffer[], input: Uint8Array): void {
  const raw = Buffer.from(input); needles.push(raw);
  const hex = raw.toString('hex'), base64 = raw.toString('base64');
  const url = base64.replaceAll('+', '-').replaceAll('/', '_');
  const decimal = [...raw];
  try {
    for (const encoded of [hex, hex.toUpperCase(), base64, base64.replace(/=+$/u, ''), url, url.replace(/=+$/u, ''),
      JSON.stringify(decimal), `[${decimal.join(', ')}]`, JSON.stringify(decimal, null, 2),
      decimal.map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join(''),
      decimal.map(byte => `\\x${byte.toString(16).padStart(2, '0').toUpperCase()}`).join('')]) {
      needles.push(Buffer.from(encoded, 'ascii'));
    }
  } finally { decimal.fill(0); }
}

/** One budget covers the corpus; overlap belongs to each independent stream.
 * At most 32 nonempty inputs/64 KiB combined, 1 GiB corpus/8192 streams,
 * and 8 MiB per chunk. JSON array needles cover compact, spaced and two-space
 * pretty printing; this is not a promise about arbitrary secret encodings.
 * Failure retires all copied needles/tails. Only counts/booleans escape.
 * Buffer wiping cannot promise erasure of VM/native copies owned elsewhere. */
export function createCredentialSecretScanner(secrets: readonly Uint8Array[], inputLimits: CredentialSecretScanLimits,
  onFailure?: (error: CredentialSecretScanError) => void): CredentialSecretScanner {
  const limits = checkedLimits(inputLimits);
  const needles: Buffer[] = [];
  try {
    if (!Array.isArray(secrets) || secrets.length === 0 || secrets.length > maxSecretCount) invalid();
    let total = 0;
    for (let index = 0; index < secrets.length; index++) {
      const entry = Object.getOwnPropertyDescriptor(secrets, String(index));
      if (!entry || !('value' in entry)) invalid();
      const bytes = bytesInput(entry.value);
      if (!bytes.byteLength || bytes.byteLength > maxSecretBytes || (total += bytes.byteLength) > maxSecretBytes) invalid();
      appendNeedles(needles, bytes);
    }
  } catch {
    for (const needle of needles) needle.fill(0);
    return invalid();
  }
  const needleCount = needles.length, overlap = Math.max(...needles.map(needle => needle.length)) - 1;
  type StreamState = { tail: Buffer; closed: boolean };
  const streams = new Set<StreamState>();
  let bytesScanned = 0, chunksScanned = 0, streamsOpened = 0, streamsClosed = 0;
  let matched = false, limitExceeded = false, closed = false;
  const closeStream = (stream: StreamState) => {
    if (stream.closed) return;
    stream.tail.fill(0); stream.tail = Buffer.alloc(0); stream.closed = true;
    streams.delete(stream); streamsClosed++;
  };
  const close = () => {
    if (closed) return;
    closed = true;
    for (const stream of streams) closeStream(stream);
    for (const needle of needles) needle.fill(0);
    needles.length = 0;
  };
  const fail = (code: CredentialSecretScanCode): never => {
    if (code === 'SECRET_DETECTED') matched = true;
    if (code === 'LIMIT_EXCEEDED') limitExceeded = true;
    close();
    const error = new CredentialSecretScanError(code);
    // Test-private observation cannot change the original failure or run
    // before actual stream/needle retirement. Successful scans do no work here.
    try { onFailure?.(error); } catch { /* Preserve the original scanner error. */ }
    throw error;
  };
  const stats = (): CredentialSecretScanStats => Object.freeze({ bytesScanned, chunksScanned, streamsOpened, streamsClosed,
    needleCount, retainedNeedleBytes: needles.reduce((sum, needle) => sum + needle.length, 0),
    retainedTailBytes: [...streams].reduce((sum, stream) => sum + stream.tail.length, 0), matched, limitExceeded, closed });
  const openStream = (): CredentialSecretScanStream => {
    if (closed) throw new CredentialSecretScanError('CLOSED');
    if (streamsOpened >= limits.maxStreams) fail('LIMIT_EXCEEDED');
    const stream: StreamState = { tail: Buffer.alloc(0), closed: false };
    streams.add(stream); streamsOpened++;
    return Object.freeze({ close: () => closeStream(stream), scan(input: Uint8Array) {
      if (closed || stream.closed) throw new CredentialSecretScanError('CLOSED');
      let bytes: Uint8Array;
      try { bytes = bytesInput(input); } catch { return fail('INVALID_INPUT'); }
      if (bytes.byteLength === 0) return;
      if (bytes.byteLength > maxChunkBytes || bytes.byteLength > limits.maxBytes - bytesScanned) fail('LIMIT_EXCEEDED');
      let joined: Buffer | undefined;
      try {
        joined = Buffer.alloc(stream.tail.length + bytes.byteLength);
        stream.tail.copy(joined); joined.set(bytes, stream.tail.length);
        bytesScanned += bytes.byteLength; chunksScanned++;
        if (needles.some(needle => joined!.includes(needle))) fail('SECRET_DETECTED');
        const tail = Buffer.from(joined.subarray(Math.max(0, joined.length - overlap)));
        stream.tail.fill(0); stream.tail = tail;
      } catch (error) {
        if (error instanceof CredentialSecretScanError) throw error;
        return fail('INVALID_INPUT');
      } finally { joined?.fill(0); }
    } });
  };
  return Object.freeze({ openStream, stats, close });
}
