import { assertArtifactRef } from '../kernel/identity.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest, decodeRunSpec, decodeWorkspaceState } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

export async function readRecoveryClosure(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  runId: string
): Promise<RecoveryClosureV1> {
  const run = readRun(driver, runId);
  if (run.revision < 1 || run.latestCheckpointId.length === 0) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run is missing its initial ready Checkpoint');
  }
  const latestCheckpoint = readCheckpoint(driver, run.latestCheckpointId);
  if (latestCheckpoint.runId !== run.id) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'latest Checkpoint does not belong to the Run');
  }
  if (run.revision === 1 && latestCheckpoint.basedOnRunRevision !== 0) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'initial Checkpoint must be based on virtual revision 0');
  }

  const runSpec = decodeRunSpec(await artifacts.readCanonical(run.specRef));
  if (runSpec.operation !== 'agent') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'M1 recovery only accepts agent RunSpecs');
  }
  assertArtifactRef(runSpec.objectiveRef);
  decodeContextManifest(await artifacts.readCanonical(latestCheckpoint.contextManifestRef));
  const workspaceState = decodeWorkspaceState(await artifacts.readCanonical(latestCheckpoint.workspaceStateRef));
  if (workspaceState.runId !== run.id || workspaceState.baseWorkspaceManifestRef !== runSpec.baseWorkspaceManifestRef) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'workspace state is not bound to the admitted RunSpec');
  }

  const journalCount = driver
    .prepare('SELECT count(*) AS count FROM run_journal WHERE run_id = ?')
    .get<{ count: unknown }>(run.id);
  const itemCount = driver
    .prepare('SELECT count(*) AS count FROM items WHERE run_id = ?')
    .get<{ count: unknown }>(run.id);
  const launchCount = driver
    .prepare('SELECT count(*) AS count FROM worker_launches WHERE run_id = ?')
    .get<{ count: unknown }>(run.id);
  const childCount = driver
    .prepare('SELECT count(*) AS count FROM child_allocations WHERE parent_run_id = ? OR child_run_id = ?')
    .get<{ count: unknown }>(run.id, run.id);

  if (Number(journalCount?.count ?? 0) !== 0 || Number(itemCount?.count ?? 0) !== 0) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'M1 recovery found post-checkpoint items or Journal rows');
  }
  if (Number(launchCount?.count ?? 0) !== 0 || Number(childCount?.count ?? 0) !== 0) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'M1 recovery found worker launches or child allocations');
  }

  return {
    runSpec,
    run,
    latestCheckpoint,
    items: [],
    journal: [],
    workerLaunches: [],
    childAllocations: []
  };
}
