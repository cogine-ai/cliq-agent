import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { WorkspaceEntryManifest } from '../kernel/types.js';
import { VerifierAuthorizationError } from './authorization-artifacts.js';

type ReadTarget = Extract<AuthorizationGrantV1['target'], { kind: 'read_scope' }>;

/** A digest constraint has exactly one supported meaning: the complete bytes
 * of one regular file. This is data validation, never a live read permit. */
export function assertSourceIncludeConstraintScope(target: ReadTarget): void {
  if (target.expectedDigest !== undefined && target.scope !== 'entry')
    throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
}

/** Capture already exhausted and joined the real file reader. Retained reads
 * use this exact original manifest, not today's tree or a child fork. */
export function assertSourceIncludeExpectedDigest(target: ReadTarget, entries: WorkspaceEntryManifest): void {
  assertSourceIncludeConstraintScope(target);
  if (target.expectedDigest === undefined) return;
  const entry = entries.entries.find(entry => entry.path === target.canonicalRootRelativePath);
  if (entry?.kind !== 'file' || entry.blobRef !== target.expectedDigest)
    throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
}
