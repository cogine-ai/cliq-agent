import { createWorkspaceCheckpoint } from '../../session/checkpoints.js';

/**
 * Create a pre-apply ghost snapshot for a transactional workspace.
 *
 * Returns the snapshot id (workspace checkpoint id) on success. Throws when the
 * provided workspace is not in a Git repository, or when the underlying ghost
 * snapshot creation fails for any other reason.
 */
export async function createApplyPreSnapshot(workspaceRealPath: string): Promise<string> {
  const ck = await createWorkspaceCheckpoint(workspaceRealPath);
  if (ck.kind === 'unavailable') {
    if (ck.reason === 'not-git') {
      throw new Error(`apply pre-snapshot requires a git repository at ${workspaceRealPath}`);
    }
    throw new Error(`apply pre-snapshot failed: ${ck.error ?? 'snapshot-failed'}`);
  }
  // git-ghost case: workspace checkpoint id is suitable as snapshot id.
  return ck.id;
}
