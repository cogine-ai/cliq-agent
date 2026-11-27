import { ContentAddressedStore, type ArtifactStat } from './cas.js';
import { KernelStorageError } from './errors.js';

/** Immutable install data only. No selection, StateOwner or execution grant.
 * Each fixed group reuses the original four CAS durability stages, complete
 * per-file sync/verification and joined failure cleanup. The caller retains
 * and checks the original installation directory scope around the full group. */
export async function publishInstalledCasRoots(cas: ContentAddressedStore,
  roots: readonly (readonly [string, Uint8Array])[]): Promise<readonly ArtifactStat[]> {
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 4)
    throw new TypeError('installed CAS publication requires one to four original roots');
  const inputs = roots.map(([ref, bytes]) => [ref, Buffer.from(bytes)] as const);
  const bytes = inputs.map(([, source]) => source);
  const results = bytes.length === 4 ? await cas.publishFour([bytes[0]!, bytes[1]!, bytes[2]!, bytes[3]!])
    : bytes.length === 3 ? await cas.publishTriple([bytes[0]!, bytes[1]!, bytes[2]!])
    : bytes.length === 2 ? await cas.publishPair([bytes[0]!, bytes[1]!])
    : [await cas.publishChunks((async function* () { yield bytes[0]!; })(), bytes[0]!.length)];
  for (const [index, result] of results.entries()) {
    if (result.ref !== inputs[index]![0] || result.byteLength !== inputs[index]![1].length)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed CAS publication changed its complete root identity');
  }
  return results;
}
