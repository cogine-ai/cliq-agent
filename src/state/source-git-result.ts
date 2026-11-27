import { createHash } from 'node:crypto';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { publishSourceGitArtifacts } from '../workspace/source-git-artifacts.js';
import { assertSourceGitResult, type SourceGitResult } from '../sandbox/source-git-native.js';
import type { NativeSourceGitOutputReader } from '../sandbox/linux-worker.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import type { HeldSourceGitInput } from './native-owner.js';

function mismatch(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'source Git native output differs from its complete fixed file identity'); }
function closeReader(reader: NativeSourceGitOutputReader, closed: Set<NativeSourceGitOutputReader>, operationError?: unknown): void {
  if (!closed.has(reader)) {
    closed.add(reader);
    try { reader.close(); }
    catch (error) {
      if (error instanceof ResourceRetirementError) throw error;
      throw new ResourceRetirementError('source Git output reader did not retire',
        operationError === undefined ? error : new AggregateError([operationError, error]));
    }
  }
  if (operationError instanceof ResourceRetirementError) throw operationError;
}

/** Private actual-reader adapter. Byte counters/hash are not a replacement
 * for the native source result brand, held input, whole death or retirement.
 * Even a consumer's early return closes this reader in the same generator. */
async function* sourceGitStream(reader: NativeSourceGitOutputReader, closed: Set<NativeSourceGitOutputReader>,
  ceiling: number, signal?: AbortSignal): AsyncGenerator<Buffer> {
  let failure: unknown;
  try {
    signal?.throwIfAborted(); reader.assertHeld();
    const expected = reader.identity;
    if (!Number.isSafeInteger(expected.byteCount) || expected.byteCount < 0 || expected.byteCount > ceiling ||
        typeof expected.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(expected.sha256)) return mismatch();
    const hash = createHash('sha256'); let count = 0;
    for (;;) {
      signal?.throwIfAborted(); reader.assertHeld();
      const next = reader.readChunk();
      signal?.throwIfAborted(); reader.assertHeld();
      if (next === undefined) break;
      if (!Buffer.isBuffer(next) || next.length > 65_536 || next.length < 1 || next.length > expected.byteCount - count) return mismatch();
      count += next.length; hash.update(next); yield next;
    }
    if (count !== expected.byteCount || hash.digest('hex') !== expected.sha256) return mismatch();
    signal?.throwIfAborted(); reader.assertHeld();
  } catch (error) { failure = error; throw error; }
  finally { closeReader(reader, closed, failure); }
}

// Internal byte/descriptor adapters only. Each producer independently checks
// its genuine native family before borrowing a reader; these mint no proof.
export { sourceGitStream as nativeGitOutputStream, closeReader as closeNativeGitOutputReader };

/** Same original result only. All CAS consumers join before this function
 * returns/rejects, and every native reader (including unopened siblings) is
 * then closed. The owner must still explicitly stop/retire the original
 * scope before publishing any successful capture or retirement evidence. */
export async function publishInstalledSourceGitResult(artifacts: ArtifactCatalog, input: HeldSourceGitInput,
  result: SourceGitResult, expected: Readonly<{ repositoryIdentityDigest: string; resources: SandboxResourceSpec;
    exclude: Readonly<{ grantCoreDigest: string; expectedDigest?: string }> | null }>, signal?: AbortSignal) {
  assertSourceGitResult(result, input); // private brand before any caller data/reader access
  const readers = [...Object.values(result.files), ...(result.excludeRule ? [result.excludeRule] : [])];
  const closed = new Set<NativeSourceGitOutputReader>(); let operationError: unknown;
  try {
    signal?.throwIfAborted();
    if (expected.exclude === null && result.excludeRule !== null) return mismatch();
    if (expected.exclude?.expectedDigest !== undefined && result.excludeRule === null) return mismatch();
    const maximum = expected.resources.maxSingleFileBytes;
    const published = await publishSourceGitArtifacts(artifacts, {
      inspection: sourceGitStream(result.files.inspection, closed,
        Math.min(maximum, expected.resources.maxInvocationOutputBytes), signal),
      index: sourceGitStream(result.files.index, closed, maximum, signal),
      pack: sourceGitStream(result.files.pack, closed, maximum, signal),
      packIndex: sourceGitStream(result.files.packIndex, closed, maximum, signal)
    }, { repositoryIdentityDigest: expected.repositoryIdentityDigest, resources: expected.resources }, signal);
    let exclude: { contentRef: string; sha256: string; byteCount: number } | null = null;
    if (result.excludeRule) {
      // This separate already-consumed rule grant is not sent to Git and
      // cannot authorize any other .git or ordinary source payload read.
      const reader = result.excludeRule;
      const rule = await artifacts.publishChunks(sourceGitStream(reader, closed,
        Math.min(1_048_576, maximum, expected.resources.maxInvocationOutputBytes), signal),
      'text/plain; charset=utf-8', 'cliq-ignore-rule-source-v1', reader.identity.byteCount);
      signal?.throwIfAborted();
      if (rule.ref !== reader.identity.sha256 || expected.exclude?.expectedDigest !== undefined &&
          rule.ref !== expected.exclude.expectedDigest) return mismatch();
      exclude = { contentRef: rule.ref, sha256: rule.ref, byteCount: rule.byteLength };
      return { ...published, exclude, metadata: [...published.metadata, rule] };
    }
    return { ...published, exclude };
  } catch (error) { operationError = error; throw error; }
  finally {
    const failures: unknown[] = [];
    for (const reader of readers) try { closeReader(reader, closed); } catch (error) { failures.push(error); }
    if (failures.length) {
      const retirement = failures.find(error => error instanceof ResourceRetirementError);
      if (retirement) throw retirement;
      throw new ResourceRetirementError('source Git fixed output readers did not retire',
        new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
    }
  }
}
