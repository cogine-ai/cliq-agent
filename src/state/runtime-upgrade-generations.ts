import type { Run, RunAssemblyV1, WorkerLaunch, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeRunSpec } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGeneration } from './repositories/workspace-generations.js';
import { readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';

function refuse(): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', 'upgrade generation has no exact closed original worker and seal');
}

/** Historical read only. A sealed generation stays sealed: its original
 * snapshot and all-descendant death, not a rewritten phase or current path,
 * establish the dormant source accepted by schema conversion. */
export async function assertClosedUpgradeGeneration(driver: SqliteDriver, artifacts: ArtifactCatalog,
  run: Run, generation: WorkspaceGenerationStateV1, retainedWorkers: ReadonlyMap<string, WorkerLaunch>): Promise<void> {
  if (generation.runId !== run.id || !['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status) ||
      run.activeWorkerLaunchId !== undefined || !isZeroBudget(run.budgetReserved)) refuse();
  requireEqual(readRun(driver, run.id), run, 'upgrade generation original terminal Run');
  requireEqual(readRequiredWorkspaceGeneration(driver, generation.generationId), generation, 'upgrade original generation');
  if (generation.phase === 'retired') return;
  if (generation.phase !== 'sealed') refuse();

  // Do not infer absence from only this Run's supplied resource list. The
  // whole locked SQL cut must have exactly this original launch and no active
  // pointer, including preparing records in another Run.
  const references = driver.prepare(`SELECT launch_id FROM worker_launches
    WHERE COALESCE(json_extract(row_json, '$.workspaceGenerationRef'),
      json_extract(row_json, '$.preparation.generation.generationRef')) = ?`)
    .all<{ launch_id: string }>(generation.generationRef);
  if (references.length !== 1) refuse();
  const launch = retainedWorkers.get(references[0]!.launch_id);
  if (!launch || launch.runId !== run.id || launch.phase !== 'retired' || launch.retirementKind === 'preparation' ||
      launch.workspaceGenerationRef !== generation.generationRef || launch.generationWriteState !== 'sealed' ||
      !launch.activatedAt || !launch.retiredAt || launch.retiredAt !== generation.updatedAt ||
      driver.prepare('SELECT 1 FROM runs WHERE active_worker_launch_id = ? LIMIT 1').get(launch.launchId)) refuse();
  requireEqual(readRequiredWorkerLaunch(driver, launch.launchId), launch, 'upgrade original sealed worker');

  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  if (assembly.format !== 'cliq-run-assembly-v1') refuse();
  // Reuse the ordinary retained reader: full immutable file bytes, original
  // Checkpoint, snapshot, containment, inspector, death and commit freshness.
  // It neither observes current liveness nor grants execution/retirement.
  await validateRetainedWorkerSeal(driver, artifacts, { run, spec, assembly, launch, generation });
}
