import { createHash } from 'node:crypto';
import { fstatSync, readSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { KernelStorageError } from './errors.js';

/** Hash a native-held image without queuing reads on a borrowed descriptor.
 * The caller owns the observation and must join this operation before closing it. */
export async function hashHeldProcessImage(imageFd: number, imageByteCount: number,
  assertHeld: () => void): Promise<string> {
  assertHeld();
  const before = fstatSync(imageFd, { bigint: true });
  if (!before.isFile() || before.size !== BigInt(imageByteCount) ||
      imageByteCount <= 0 || imageByteCount > 256 * 1024 * 1024) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'process executable image is unavailable or unbounded');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(Math.min(imageByteCount, 1024 * 1024));
  for (let offset = 0; offset < imageByteCount;) {
    await setImmediate();
    assertHeld();
    const count = readSync(imageFd, buffer, 0, Math.min(buffer.length, imageByteCount - offset), offset);
    if (count === 0) throw new KernelStorageError('ARTIFACT_MISMATCH', 'process executable image ended early');
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  const after = fstatSync(imageFd, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode ||
      before.uid !== after.uid || before.gid !== after.gid || before.nlink !== after.nlink ||
      before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'process executable image changed while hashing');
  }
  assertHeld();
  return hash.digest('hex');
}
