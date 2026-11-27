import { createHash } from 'node:crypto';
import { assertArtifactRef } from '../kernel/identity.js';
import { decodeDependencyPackageDescriptor } from '../kernel/dependency-descriptors.js';
import type { DependencyPackageDescriptorV1 } from '../kernel/dependency.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import type { NativeDependencyPackage, NativeDependencyPackageReader } from './dependency-broker-native.js';
import { ResourceRetirementError } from './errors.js';

/** Content-only consumer of an original package reader. This publishes no
 * GET/permission/physical proof. The genuine acquisition owner retains its
 * package and fence on every failure, and alone may retire them after this
 * whole publication and independent full CAS read have actually joined. */
export async function publishDependencyPackageData(artifacts: ArtifactCatalog, source: NativeDependencyPackage,
  descriptor: DependencyPackageDescriptorV1, maxPackageBytes: number, signal?: AbortSignal): Promise<PublishedArtifact> {
  descriptor = decodeDependencyPackageDescriptor(descriptor);
  if (!Number.isSafeInteger(maxPackageBytes) || maxPackageBytes < 1 || maxPackageBytes > 67_108_864 ||
      !Number.isSafeInteger(source.byteCount) || source.byteCount < 1 || source.byteCount > maxPackageBytes) throw new TypeError('dependency package exceeds its exact data ceiling');
  const byteCount = source.byteCount, digest = source.sha256; assertArtifactRef(digest);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts; reads.assertReadActive();
  let reader: NativeDependencyPackageReader | undefined, failure: { error: unknown } | undefined;
  let artifact: PublishedArtifact | undefined;
  try {
    reader = source.openReader();
    const active = reader;
    async function* chunks() {
      const hash = createHash('sha256'), integrity = createHash(descriptor.integrityAlgorithm); let count = 0;
      for (;;) {
        reads.assertReadActive(); const chunk = active.readChunk();
        if (!Buffer.isBuffer(chunk) || chunk.length > 65_536) throw new TypeError('dependency reader returned an invalid fixed chunk');
        if (!chunk.length) break;
        count += chunk.length;
        if (count > byteCount) throw new TypeError('dependency reader exceeded its complete original size');
        hash.update(chunk); integrity.update(chunk); yield Buffer.from(chunk);
      }
      active.assertComplete(); reads.assertReadActive();
      if (count !== byteCount || hash.digest('hex') !== digest || integrity.digest('base64') !== descriptor.integrityDigest)
        throw new TypeError('dependency package differs from its complete original SHA and SRI');
    }
    artifact = await artifacts.publishChunks(chunks(), 'application/octet-stream', 'cliq-integrity-package-tarball-v1', byteCount);
  } catch (error) { failure = { error }; }
  finally {
    if (reader) try { reader.close(); }
    catch (error) { throw new ResourceRetirementError('dependency package reader did not actually retire', failure ? new AggregateError([failure.error, error]) : error); }
  }
  if (failure) throw failure.error;
  if (!artifact || artifact.ref !== digest || artifact.byteLength !== byteCount) throw new TypeError('package CAS publication differs from its exact native bytes');
  // New consumer, full EOF, full CAS SHA and independent SRI; a successful
  // descriptor/rename or the native metadata alone cannot establish it.
  const integrity = createHash(descriptor.integrityAlgorithm); let count = 0;
  for await (const chunk of reads.readChunks(digest, byteCount)) { reads.assertReadActive(); count += chunk.length; integrity.update(chunk); }
  reads.assertReadActive();
  if (count !== byteCount || integrity.digest('base64') !== descriptor.integrityDigest) throw new TypeError('durable package cache failed its independent complete SRI read');
  return artifact;
}
