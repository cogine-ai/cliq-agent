import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef, sha256Bytes } from '../kernel/identity.js';
import type { ArtifactRef } from '../kernel/types.js';
import { ContentAddressedStore } from './cas.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import type { SqliteConnection } from './sqlite-driver.js';

export type PublishedArtifact = {
  ref: ArtifactRef;
  mediaType: string;
  schemaKind: string;
  byteLength: number;
};

type CanonicalPublication = Readonly<{ value: unknown; schemaKind: string }>;

export class ArtifactCatalog {
  constructor(private readonly cas: ContentAddressedStore, private readonly readSignal?: AbortSignal) {}

  /** Same real CAS and checks, with a tighter read lifetime. This view grants
   * no authority, starts no work and cannot discard a parent's cancellation. */
  withReadSignal(signal: AbortSignal): ArtifactCatalog {
    return new ArtifactCatalog(this.cas, this.readSignal ? AbortSignal.any([this.readSignal, signal]) : signal);
  }

  /** Same read lifetime during computation between CAS operations. This is
   * only a cancellation checkpoint, not a new scope or execution authority. */
  assertReadActive(): void {
    this.readSignal?.throwIfAborted();
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
    await joinResourceOperations(Array.from({ length: Math.min(4, length) }, () => run()));
    this.assertReadActive();
    return results;
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

  /** Complete original-byte verification without retaining an object buffer. */
  async verifyBytes(ref: ArtifactRef): Promise<void> {
    assertArtifactRef(ref);
    this.readSignal?.throwIfAborted();
    await this.cas.verify(ref, this.readSignal);
    this.readSignal?.throwIfAborted();
  }

  async readCanonical<T>(ref: ArtifactRef): Promise<T> {
    const bytes = await this.readBytes(ref);
    this.readSignal?.throwIfAborted();
    if (sha256Bytes(bytes) !== ref) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} failed a digest rehash`);
    }
    try {
      const value = JSON.parse(bytes.toString('utf8')) as T;
      this.readSignal?.throwIfAborted(); return value;
    } catch (cause) {
      if (this.readSignal?.aborted && cause === this.readSignal.reason) throw cause;
      throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} is not JSON`);
    }
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
