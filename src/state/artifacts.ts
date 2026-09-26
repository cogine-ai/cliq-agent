import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef, sha256Bytes } from '../kernel/identity.js';
import type { ArtifactRef } from '../kernel/types.js';
import { RECOVERY_ARTIFACT_READ_CONCURRENCY } from './bounded-artifact-reads.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError } from './errors.js';
import type { SqliteConnection } from './sqlite-driver.js';

export type PublishedArtifact = {
  ref: ArtifactRef;
  mediaType: string;
  schemaKind: string;
  byteLength: number;
};

export class ArtifactCatalog {
  private activeReads = 0;
  private readonly waitingReads: Array<() => void> = [];

  constructor(private readonly cas: ContentAddressedStore) {}

  private async withReadSlot<T>(read: () => Promise<T>): Promise<T> {
    if (this.activeReads < RECOVERY_ARTIFACT_READ_CONCURRENCY) {
      this.activeReads += 1;
    } else {
      await new Promise<void>((resolve) => { this.waitingReads.push(resolve); });
    }
    try {
      return await read();
    } finally {
      const next = this.waitingReads.shift();
      if (next) next();
      else this.activeReads -= 1;
    }
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

  async readBytes(ref: ArtifactRef): Promise<Buffer> {
    assertArtifactRef(ref);
    return this.withReadSlot(() => this.cas.read(ref));
  }

  async verifyBytes(ref: ArtifactRef): Promise<{ ref: ArtifactRef; byteLength: number }> {
    assertArtifactRef(ref);
    return this.withReadSlot(() => this.cas.verify(ref));
  }

  async readCanonical<T>(ref: ArtifactRef): Promise<T> {
    const bytes = await this.readBytes(ref);
    if (sha256Bytes(bytes) !== ref) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} failed a digest rehash`);
    }
    try {
      return JSON.parse(bytes.toString('utf8')) as T;
    } catch (cause) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `artifact ${ref} is not JSON`);
    }
  }

  async describe(
    ref: ArtifactRef,
    mediaType: string,
    schemaKind: string
  ): Promise<PublishedArtifact> {
    const bytes = await this.readBytes(ref);
    return { ref, mediaType, schemaKind, byteLength: bytes.byteLength };
  }
}

export function insertArtifactMetadata(
  connection: SqliteConnection,
  artifact: PublishedArtifact,
  createdAt: string
): void {
  connection
    .prepare(
      `INSERT OR IGNORE INTO artifacts (ref, media_type, schema_kind, byte_length, created_at)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(artifact.ref, artifact.mediaType, artifact.schemaKind, BigInt(artifact.byteLength), createdAt);
  const stored = connection
    .prepare('SELECT media_type, schema_kind, byte_length FROM artifacts WHERE ref = ?')
    .get<{ media_type: string; schema_kind: string; byte_length: unknown }>(artifact.ref);
  if (
    stored === undefined ||
    stored.media_type !== artifact.mediaType ||
    stored.schema_kind !== artifact.schemaKind ||
    Number(stored.byte_length) !== artifact.byteLength
  ) {
    throw new KernelStorageError(
      'ARTIFACT_MISMATCH',
      `artifact ${artifact.ref} metadata conflicts with its first authoritative declaration`
    );
  }
}
