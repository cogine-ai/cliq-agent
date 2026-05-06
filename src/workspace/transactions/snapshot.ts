import { createWorkspaceCheckpoint, writeWorkspaceCheckpoint } from '../../session/checkpoints.js';

/**
 * Create a pre-apply ghost snapshot for a transactional workspace.
 *
 * Returns the snapshot id (workspace checkpoint id) on success. Throws when the
 * provided workspace is not in a Git repository, or when the underlying ghost
 * snapshot creation fails for any other reason.
 *
 * The checkpoint artifact is persisted to ${CLIQ_HOME}/checkpoints/<id>.json so
 * abortTx's restore-confirmed path can later locate and restore from it.
 */
export async function createApplyPreSnapshot(workspaceRealPath: string): Promise<string> {
  const ck = await createWorkspaceCheckpoint(workspaceRealPath);
  if (ck.kind === 'unavailable') {
    if (ck.reason === 'not-git') {
      throw new Error(`apply pre-snapshot requires a git repository at ${workspaceRealPath}`);
    }
    throw new Error(`apply pre-snapshot failed: ${ck.error ?? 'snapshot-failed'}`);
  }
  await writeWorkspaceCheckpoint(ck);
  return ck.id;
}
