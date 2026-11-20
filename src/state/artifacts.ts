import { AsyncLocalStorage } from 'node:async_hooks';
import { setImmediate } from 'node:timers/promises';
import { immutableSnapshot } from '../model/immutable.js';
import type { ReleaseTrustKey } from '../policy/runtime-authority.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef, sha256Bytes } from '../kernel/identity.js';
import type { ArtifactRef } from '../kernel/types.js';
import { ContentAddressedStore } from './cas.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import type { SqliteConnection } from './sqlite-driver.js';

type ArtifactReadCache = {
  objects: Map<ContentAddressedStore, Map<ArtifactRef, Buffer>>;
  bytes: number;
  entries: number;
  closed: boolean;
};
const artifactReadCache = new AsyncLocalStorage<ArtifactReadCache>();
const MAX_READ_CACHE_BYTES = 64 * 1024 * 1024;
const MAX_READ_CACHE_ENTRIES = 8192;
const MAX_READ_CACHE_OBJECT_BYTES = 16 * 1024 * 1024;

/** One immutable graph traversal owns these verified byte copies.
 * A later traversal starts fresh. Every consumer still hashes and decodes its
 * own copy. Explicit raw, bounded and stream reads keep their original I/O. */
export async function withArtifactReadCache<T>(read: () => Promise<T>): Promise<T> {
  const cache: ArtifactReadCache = { objects: new Map(), bytes: 0, entries: 0, closed: false };
  try { return await artifactReadCache.run(cache, read); }
  finally { cache.closed = true; cache.objects.clear(); }
}

export type PublishedArtifact = {
  ref: ArtifactRef;
  mediaType: string;
  schemaKind: string;
  byteLength: number;
};

type CanonicalPublication = Readonly<{ value: unknown; schemaKind: string }>;

export class ArtifactCatalog {
  private readWidth: 1 | 4 = 4;
  private readonly trustedReleases: readonly ReleaseTrustKey[] | undefined;
  private readonly runtimeConversionTarget: string | undefined;
  constructor(private readonly cas: ContentAddressedStore, private readonly readSignal?: AbortSignal,
    trustedReleaseKeys?: readonly ReleaseTrustKey[], runtimeConversionTarget?: string) {
    this.trustedReleases = trustedReleaseKeys === undefined ? undefined : immutableSnapshot(trustedReleaseKeys);
    if (runtimeConversionTarget !== undefined) assertArtifactRef(runtimeConversionTarget);
    this.runtimeConversionTarget = runtimeConversionTarget;
  }

  /** Trust configuration from the existing trusted Supervisor composition.
   * Never populated or extended from CAS, requests or artifact declarations.
   * Signature trust alone supplies no lock, owner or execution authority. */
  releaseTrustRoots(): readonly ReleaseTrustKey[] {
    if (!this.trustedReleases) throw new KernelStorageError('RECOVERY_REQUIRED', 'signed upgrade history requires trusted release composition');
    return this.trustedReleases;
  }

  /** Same real CAS and checks, with a tighter read lifetime. This view grants
   * no authority, starts no work and cannot discard a parent's cancellation. */
  withReadSignal(signal: AbortSignal): ArtifactCatalog {
    // Reapplying the exact original signal does not tighten its lifetime.
    // Keep that identity so simultaneous real-file reads can join; distinct
    // signals still compose and can never cancel each other's parent scope.
    const lifetime = this.readSignal && this.readSignal !== signal ? AbortSignal.any([this.readSignal, signal]) : signal;
    const view = new ArtifactCatalog(this.cas, lifetime, this.trustedReleases, this.runtimeConversionTarget);
    view.readWidth = this.readWidth; return view;
  }

  /** Fixed signed-conversion data-audit context. It can only authorize parsing
   * the exact original source declared by an independently trusted target;
   * ordinary opening and the sole upgrade transaction retain their own gates. */
  withRuntimeConversionSource(targetBundleRef: string): ArtifactCatalog {
    assertArtifactRef(targetBundleRef);
    const view = new ArtifactCatalog(this.cas, this.readSignal, this.releaseTrustRoots(), targetBundleRef);
    view.readWidth = this.readWidth; return view;
  }
  runtimeConversionSourceRef(): string | undefined { return this.runtimeConversionTarget; }

  /** Same read lifetime during computation between CAS operations. This is
   * only a cancellation checkpoint, not a new scope or execution authority. */
  assertReadActive(): void {
    this.readSignal?.throwIfAborted();
    if (artifactReadCache.getStore()?.closed)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'artifact read traversal has closed');
  }

  /** Exact original cancellation identity. Every issued I/O still joins. */
  isReadCancellation(error: unknown): boolean {
    return this.readSignal?.aborted === true && error === this.readSignal.reason;
  }

  /** One lazy, fixed-width read group, not a global I/O or descriptor budget.
   * Stop dispatch on failure/cancellation, but join every issued operation so
   * a later resource-retirement failure still reaches the original owner. */
  async mapReads<T, Result>(values: readonly T[], read: (value: T, index: number) => Result | Promise<Result>): Promise<Result[]> {
    this.assertReadActive();
    const length = values.length, results = new Array<Result>(length);
    let next = 0, stopped = false;
    const run = async () => {
      while (!stopped && next < length) {
        try {
          this.assertReadActive();
          const index = next++;
          results[index] = await read(values[index]!, index);
          this.assertReadActive();
        } catch (error) { stopped = true; throw error; }
      }
    };
    await joinResourceOperations(Array.from({ length: Math.min(this.readWidth, length) }, () => run()));
    this.assertReadActive();
    return results;
  }

  /** Independent read-only histories may overlap, but their nested catalog
   * groups must not multiply the four-reader bound. Each callback uses this
   * serial view for all nested reads and awaits them before returning. Scoped
   * Byte copies share only the current traversal's lifetime. Each use
   * retains its original digest and decoder validation. */
  async mapReadGroups<T, Result>(values: readonly T[], read: (artifacts: ArtifactCatalog, value: T, index: number) => Promise<Result>): Promise<Result[]> {
    const serial = new ArtifactCatalog(this.cas, this.readSignal, this.trustedReleases, this.runtimeConversionTarget);
    serial.readWidth = 1;
    return this.mapReads(values, (value, index) => read(serial, value, index));
  }

  async publishBytes(
    bytes: Uint8Array,
    mediaType: string,
    schemaKind: string
  ): Promise<PublishedArtifact> {
    const ref = await this.cas.publish(bytes);
    return { ref, mediaType, schemaKind, byteLength: bytes.byteLength };
  }

  async publishCanonical(value: unknown, schemaKind: string): Promise<PublishedArtifact> {
    return this.publishBytes(canonicalJsonBytes(value), 'application/json', schemaKind);
  }

  /** Inert admission data only; no partial result or deferred durability. */
  async publishCanonicalPair(values: readonly [CanonicalPublication, CanonicalPublication]):
    Promise<readonly [PublishedArtifact, PublishedArtifact]> {
    if (!Array.isArray(values) || values.length !== 2) throw new TypeError('artifact publication requires exactly two objects');
    const bytes = values.map(value => canonicalJsonBytes(value.value)), kinds = values.map(value => value.schemaKind);
    const published = await this.cas.publishPair([bytes[0]!, bytes[1]!]);
    if (published.length !== 2 || published.some((item, index) => item.ref !== sha256Bytes(bytes[index]!) || item.byteLength !== bytes[index]!.length))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'admission pair differs from its complete canonical bytes');
    const result = (index: number): PublishedArtifact => ({ ...published[index]!, mediaType: 'application/json', schemaKind: kinds[index]! });
    return [result(0), result(1)];
  }

  /** Exactly three data objects share the existing four CAS boundaries. */
  async publishCanonicalTriple(values: readonly [CanonicalPublication, CanonicalPublication, CanonicalPublication]):
    Promise<readonly [PublishedArtifact, PublishedArtifact, PublishedArtifact]> {
    if (!Array.isArray(values) || values.length !== 3) throw new TypeError('artifact publication requires exactly three objects');
    const bytes = values.map(value => canonicalJsonBytes(value.value)), kinds = values.map(value => value.schemaKind);
    const published = await this.cas.publishTriple([bytes[0]!, bytes[1]!, bytes[2]!]);
    if (published.length !== 3 || published.some((item, index) => item.ref !== sha256Bytes(bytes[index]!) || item.byteLength !== bytes[index]!.length))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'admission triple differs from its complete canonical bytes');
    const result = (index: number): PublishedArtifact => ({ ...published[index]!, mediaType: 'application/json', schemaKind: kinds[index]! });
    return [result(0), result(1), result(2)];
  }

  /** Fixed four-object durability group. Every result waits for the complete
   * group's file verification and descriptor retirement, including failures. */
  async publishCanonicalFour(values: readonly [CanonicalPublication, CanonicalPublication, CanonicalPublication, CanonicalPublication]):
    Promise<readonly [PublishedArtifact, PublishedArtifact, PublishedArtifact, PublishedArtifact]> {
    if (!Array.isArray(values) || values.length !== 4) throw new TypeError('artifact publication requires exactly four objects');
    const bytes = values.map(value => canonicalJsonBytes(value.value));
    const kinds = values.map(value => value.schemaKind);
    const published = await this.cas.publishFour([bytes[0]!, bytes[1]!, bytes[2]!, bytes[3]!]);
    const result = (index: number): PublishedArtifact => ({ ...published[index]!,
      mediaType: 'application/json', schemaKind: kinds[index]! });
    return [result(0), result(1), result(2), result(3)];
  }

  async publishChunks(chunks: AsyncIterable<Uint8Array>, mediaType: string, schemaKind: string,
    maxByteCount: number): Promise<PublishedArtifact> {
    const result = await this.cas.publishChunks(chunks, maxByteCount);
    return { ref: result.ref, mediaType, schemaKind, byteLength: result.byteLength };
  }

  /** Exhaustion verifies the complete object; partially consumed chunks cannot establish authority. */
  readChunks(ref: ArtifactRef, expectedByteCount: number): AsyncIterable<Buffer> {
    assertArtifactRef(ref);
    return this.cas.readChunks(ref, expectedByteCount, this.readSignal);
  }

  async readBytes(ref: ArtifactRef): Promise<Buffer> {
    assertArtifactRef(ref);
    this.readSignal?.throwIfAborted();
    const bytes = await this.cas.read(ref, this.readSignal);
    this.readSignal?.throwIfAborted(); return bytes;
  }

  /** Small retained inputs need a ceiling before any whole-object allocation.
   * The existing full verification supplies an exact held size; the subsequent
   * exact-size stream independently verifies the entire object again. Neither
   * a stat nor the first walk replaces that consumer read or its real closes. */
  async readBoundedBytes(ref: ArtifactRef, maxByteCount: number): Promise<Buffer> {
    assertArtifactRef(ref);
    if (!Number.isSafeInteger(maxByteCount) || maxByteCount < 0) throw new TypeError('bounded artifact read requires a nonnegative safe ceiling');
    this.readSignal?.throwIfAborted();
    const verified = await this.cas.verify(ref, this.readSignal);
    this.readSignal?.throwIfAborted();
    if (verified.byteLength > maxByteCount) throw new KernelStorageError('ARTIFACT_MISMATCH', 'artifact exceeds its bounded consumer ceiling');
    const chunks: Buffer[] = [];
    for await (const chunk of this.readChunks(ref, verified.byteLength)) {
      this.readSignal?.throwIfAborted(); chunks.push(chunk);
    }
    this.readSignal?.throwIfAborted(); return Buffer.concat(chunks, verified.byteLength);
  }

  /** The v2 context head has a fixed small profile. A canonical v1 prefix
   * selects only the original historical read profile; it grants no authority
   * and the complete reader still checks exact UTF-8/JCS/schema afterwards.
   * This avoids allocating an oversized v2 object before learning its format,
   * without falsely imposing today's small-page bounds on real v1 history. */
  async readSessionContextHeadBytes(ref: ArtifactRef): Promise<Buffer> {
    assertArtifactRef(ref); this.assertReadActive();
    const verified = await this.cas.verify(ref, this.readSignal);
    this.assertReadActive();
    const chunks: Buffer[] = []; let prefix = Buffer.alloc(0), profiled = false;
    for await (const chunk of this.readChunks(ref, verified.byteLength)) {
      this.assertReadActive();
      if (!profiled) {
        const needed = Math.min(256 - prefix.length, chunk.length);
        prefix = Buffer.concat([prefix, chunk.subarray(0, needed)], prefix.length + needed);
        const legacy = /^\{"contextRevision":[1-9][0-9]{0,15},"format":"cliq-session-context-v1",/u.test(prefix.toString('latin1'));
        if (legacy || prefix.length === 256 || verified.byteLength <= 262_144) {
          if (!legacy && verified.byteLength > 262_144)
            throw new KernelStorageError('ARTIFACT_MISMATCH', 'Session v2 context head exceeds its fixed small-artifact ceiling');
          profiled = true;
        }
      }
      chunks.push(chunk);
    }
    this.assertReadActive();
    if (!profiled && verified.byteLength > 262_144)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'Session context has no supported complete profile');
    return Buffer.concat(chunks, verified.byteLength);
  }

  /** A recovery traversal can verify its own complete immutable byte copy.
   * On a miss, retain only a bounded small object after the actual CAS reader
   * has verified every byte and joined both descriptors. Large objects and
   * readers outside a traversal keep the original discard-only path. */
  async verifyBytes(ref: ArtifactRef): Promise<void> {
    assertArtifactRef(ref); this.assertReadActive();
    const bytes = await this.cachedReadBytes(ref);
    if (bytes !== undefined) {
      if (sha256Bytes(bytes) !== ref)
        throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} failed a digest rehash`);
      return;
    }
    const cache = artifactReadCache.getStore();
    const limit = cache && cache.entries < MAX_READ_CACHE_ENTRIES
      ? Math.min(MAX_READ_CACHE_OBJECT_BYTES, MAX_READ_CACHE_BYTES - cache.bytes) : undefined;
    const verified = await this.cas.verify(ref, this.readSignal, limit);
    this.assertReadActive();
    if (verified.bytes !== undefined) this.retainReadBytes(ref, verified.bytes);
  }

  /** Exact-size discard checks may hash this traversal's complete byte copy.
   * A small miss exhausts the original stream and joins before retaining it.
   * Large files and exhausted caches keep the original discard-only reader. */
  async verifyChunks(ref: ArtifactRef, expectedByteLength: number, reader: 'discard' | 'stream' = 'discard'): Promise<void> {
    assertArtifactRef(ref);
    if (!Number.isSafeInteger(expectedByteLength) || expectedByteLength < 0)
      throw new TypeError('artifact stream requires an exact nonnegative safe byte count');
    this.assertReadActive();
    const bytes = await this.cachedReadBytes(ref);
    if (bytes !== undefined) {
      if (bytes.length !== expectedByteLength) throw new Error(`artifact ${ref} has an unexpected byte count`);
      if (sha256Bytes(bytes) !== ref)
        throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} failed a digest rehash`);
      return;
    }
    const cache = artifactReadCache.getStore();
    const retain = cache && expectedByteLength <= MAX_READ_CACHE_OBJECT_BYTES && cache.entries < MAX_READ_CACHE_ENTRIES &&
      cache.bytes + expectedByteLength <= MAX_READ_CACHE_BYTES;
    if (retain || reader === 'stream') {
      const chunks: Buffer[] | undefined = retain ? [] : undefined;
      for await (const chunk of this.readChunks(ref, expectedByteLength)) chunks?.push(chunk);
      this.assertReadActive();
      if (chunks) this.retainReadBytes(ref, Buffer.concat(chunks, expectedByteLength));
      return;
    }
    await this.cas.verifyChunks(ref, expectedByteLength, this.readSignal);
    this.assertReadActive();
  }

  private async cachedReadBytes(ref: ArtifactRef): Promise<Buffer | undefined> {
    const retained = artifactReadCache.getStore()?.objects.get(this.cas)?.get(ref);
    // Cached copies retain the event-loop turn formerly supplied by real I/O,
    // so cancellation, worker maintenance and control requests can progress.
    if (retained === undefined) return undefined;
    await setImmediate(); this.assertReadActive();
    return Buffer.from(retained);
  }

  private retainReadBytes(ref: ArtifactRef, bytes: Buffer): void {
    const cache = artifactReadCache.getStore();
    if (cache && !cache.objects.get(this.cas)?.has(ref) && bytes.byteLength <= MAX_READ_CACHE_OBJECT_BYTES &&
        cache.entries < MAX_READ_CACHE_ENTRIES && cache.bytes + bytes.byteLength <= MAX_READ_CACHE_BYTES) {
      const entries = cache.objects.get(this.cas) ?? new Map<ArtifactRef, Buffer>();
      entries.set(ref, Buffer.from(bytes)); cache.objects.set(this.cas, entries);
      cache.entries++; cache.bytes += bytes.byteLength;
    }
  }

  async readCanonical<T>(ref: ArtifactRef): Promise<T> {
    assertArtifactRef(ref); this.assertReadActive();
    const bytes = await this.cachedReadBytes(ref) ?? await this.readBytes(ref);
    this.assertReadActive();
    if (sha256Bytes(bytes) !== ref) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} failed a digest rehash`);
    }
    let value: T;
    try {
      value = JSON.parse(bytes.toString('utf8')) as T;
    } catch (cause) {
      if (this.isReadCancellation(cause)) throw cause;
      throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} is not JSON`);
    }
    this.assertReadActive();
    this.retainReadBytes(ref, bytes);
    return value;
  }

  async describe(
    ref: ArtifactRef,
    mediaType: string,
    schemaKind: string
  ): Promise<PublishedArtifact> {
    const bytes = await this.readBytes(ref);
    this.readSignal?.throwIfAborted();
    return { ref, mediaType, schemaKind, byteLength: bytes.byteLength };
  }
}

export function insertArtifactMetadata(
  connection: SqliteConnection,
  artifact: PublishedArtifact,
  createdAt: string
): void {
  assertArtifactRef(artifact.ref);
  if (!Number.isSafeInteger(artifact.byteLength) || artifact.byteLength < 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'artifact byte length is not a nonnegative safe integer');
  }
  // A CAS ref identifies bytes, not a unique typed use. Preserve the first
  // descriptor verbatim; every later consumer must independently rehash and
  // decode its required schema. Labels never grant permission or authority.
  connection
    .prepare(
      `INSERT OR IGNORE INTO artifacts (ref, media_type, schema_kind, byte_length, created_at)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(artifact.ref, artifact.mediaType, artifact.schemaKind, BigInt(artifact.byteLength), createdAt);
  const stored = connection
    .prepare('SELECT byte_length FROM artifacts WHERE ref = ?')
    .get<{ byte_length: unknown }>(artifact.ref);
  if (
    stored === undefined ||
    Number(stored.byte_length) !== artifact.byteLength
  ) {
    throw new KernelStorageError(
      'ARTIFACT_MISMATCH',
      `artifact ${artifact.ref} byte length conflicts with its immutable first descriptor`
    );
  }
}
