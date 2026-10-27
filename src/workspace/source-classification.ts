import type { FrozenIgnoreRulesV1, GitIndexSnapshotV1 } from '../kernel/types.js';
import { createFrozenIgnoreMatcher } from './frozen-ignore.js';

/** One immutable metadata classifier for capture, retained includes and later
 * result selection. It supplies no Trust, live read permission or native proof.
 * The owning reader verifies the complete original index and rule artifacts. */
export function createSourceClassifier(rules: FrozenIgnoreRulesV1 | undefined, index?: GitIndexSnapshotV1) {
  const ignored = rules ? createFrozenIgnoreMatcher(rules) : () => false;
  const paths = index?.entries.map(entry => entry.canonicalRootRelativePath) ?? [];
  const tracked = new Set(paths);
  const hasTrackedDescendant = (path: string): boolean => {
    const prefix = `${path}/`, bytes = Buffer.from(prefix);
    let left = 0, right = paths.length;
    while (left < right) {
      const middle = (left + right) >>> 1;
      if (Buffer.compare(Buffer.from(paths[middle]!),bytes) < 0) left = middle + 1;
      else right = middle;
    }
    return paths[left]?.startsWith(prefix) === true;
  };
  const classify = (entry: {path:string;kind:string}) => {
    if (!['directory','file','symlink'].includes(entry.kind)) return undefined;
    if (tracked.has(entry.path)) return 'tracked_in_git_index' as const;
    if (entry.kind === 'directory' && hasTrackedDescendant(entry.path)) return 'tracked_ancestor_in_git_index' as const;
    return !ignored(entry.path,entry.kind === 'directory') ? 'nonignored_in_root' as const : undefined;
  };
  return Object.freeze({ignored,isTracked:(path:string)=>tracked.has(path),hasTrackedDescendant,classify});
}
