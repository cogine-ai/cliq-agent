// Bounded retained-byte assertions for the owned installed fixture. These
// readers supply no StateOwner, native handle, grant, or execution authority.
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import type { SandboxResourceSpec } from '../../../src/kernel/execution.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { SourceManifest, WorkspaceStateManifest } from '../../../src/kernel/types.js';
import type { ArtifactCatalog } from '../../../src/state/artifacts.js';
import { privateGitSourceHead, readGitIndexData, readPrivateGitData, type PrivateGitReader } from '../../../src/workspace/private-git-data.js';

type Reader = Omit<PrivateGitReader, 'withReadSignal'> & Pick<ArtifactCatalog, 'readCanonical' | 'assertReadActive'> & {
  withReadSignal(signal: AbortSignal): Reader;
};
const MAX_BYTES = 1_048_576;
export function installedGitDataReader(read: (ref: string) => Promise<Buffer>, signal?: AbortSignal): Reader {
  const bounded = async (ref: string, maximum: number) => {
    assert.match(ref, /^[a-f0-9]{64}$/u); assert(Number.isSafeInteger(maximum) && maximum >= 0);
    signal?.throwIfAborted(); const bytes = await read(ref); signal?.throwIfAborted();
    assert(Buffer.isBuffer(bytes) && bytes.length <= Math.min(maximum, MAX_BYTES) && sha256Bytes(bytes) === ref);
    return bytes;
  };
  return {
    assertReadActive: () => signal?.throwIfAborted(),
    readBoundedBytes: bounded,
    async readCanonical<T>(ref: string): Promise<T> {
      const bytes = await bounded(ref, MAX_BYTES), value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      assert(canonicalJsonBytes(value).equals(bytes)); return value as T;
    },
    async *readChunks(ref, expectedSize) {
      const bytes = await bounded(ref, expectedSize ?? MAX_BYTES); assert(expectedSize === undefined || bytes.length === expectedSize);
      yield bytes;
    },
    withReadSignal: selected => installedGitDataReader(read, signal ? AbortSignal.any([signal, selected]) : selected)
  };
}

/** Fixed ordinary Git fixture: file edits/verifiers/publication may not alter
 * its original private Git graph or the current captured metadata index. */
export async function assertInstalledGitState(reader: Reader, source: SourceManifest, state: WorkspaceStateManifest,
  resources: SandboxResourceSpec, expectedGit: boolean) {
  assert.equal(!!source.git, expectedGit); assert.equal(!!state.privateGitStateRef, expectedGit);
  if (!expectedGit) return;
  assert(source.git && state.privateGitStateRef);
  const expected = { repositoryIdentityDigest: source.git.repositoryIdentityDigest, resources };
  const privateGit = await readPrivateGitData(reader, state.privateGitStateRef, expected);
  const index = await readGitIndexData(reader, source.git.indexRef, expected);
  assert.equal(canonicalSha256(privateGitSourceHead(privateGit)), canonicalSha256(source.git.head));
  assert.equal(index.indexTreeObjectId, source.git.indexTreeObjectId);
  assert.equal(privateGit.index.objectFormat, index.objectFormat);
  assert.equal(privateGit.index.snapshotDigest, index.snapshotDigest);
}
