import type { FrozenIgnoreRulesV1 } from '../kernel/types.js';
import { mapArtifactReads } from './bounded-artifact-reads.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

/** Validate retained raw ignore files before admission or recovery trusts rules
 * derived from them. The fixed wildmatch parser is a separate source-capture
 * gate; this check makes missing, changed, or invalid UTF-8 inputs fail closed. */
export async function validateFrozenIgnoreSourceBytes(
  artifacts: ArtifactCatalog,
  rules: FrozenIgnoreRulesV1
): Promise<void> {
  const distinct = [...new Set(rules.sources.map((source) => source.contentRef))];
  await mapArtifactReads(distinct, async (ref) => {
    const bytes = await artifacts.readBytes(ref);
    if (bytes.includes(0)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source contains NUL');
    }
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source is not UTF-8');
    }
  });
}
