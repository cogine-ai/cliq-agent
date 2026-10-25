import { openInstalledLinuxWorkerLauncher, openLinuxWorkerLauncher,
  type LinuxWorkerInstallation, type LinuxWorkerLauncher } from '../sandbox/linux-worker.js';
import type { HeldInstalledAnchor, HeldInstalledRuntime } from './installed-runtime.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { observeInstalledBrokerQuiescence, type StateStore } from './store.js';
import { openWorkerPreparationCleanupContext, readWorkerPreparationCleanupTarget, retireRetainedWorkerPreparation } from './worker-preparation.js';

/** A bounded startup inspection within the original Store admission owner.
 * There is no new runner, retry queue, execution permit or discovery ledger.
 * Missing/half/changed original births cannot become a no-attempt result. */
export async function retireAbandonedWorkerPreparations(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { store: StateStore; selected?: HeldInstalledRuntime; anchor?: HeldInstalledAnchor;
    installation?: LinuxWorkerInstallation; signal: AbortSignal }): Promise<void> {
  // Data-only Stores do not have a qualified native installer/anchor. They may
  // inspect retained metadata; this supplies no physical closure or exception
  // to the ordinary dead-preparation recovery refusal.
  if (!input.selected && !input.installation) return;
  let launcher: LinuxWorkerLauncher | undefined, primary: { error: unknown } | undefined;
  try {
    input.signal.throwIfAborted(); assertActiveStateOwner(driver, owner);
    const rows = driver.prepare("SELECT launch_id FROM worker_launches WHERE phase='preparing' ORDER BY rowid LIMIT 1001")
      .all<{ launch_id: string }>();
    if (rows.length > 1000) throw new KernelStorageError('RECOVERY_REQUIRED', 'preparation cleanup exceeds the existing active Run inventory');
    for (const row of rows) {
      input.signal.throwIfAborted();
      const launch = readRequiredWorkerLaunch(driver, row.launch_id);
      if (launch.phase !== 'preparing') throw new KernelStorageError('RECOVERY_REQUIRED', 'preparation cleanup discovery changed its original phase');
      // The original live producer remains with its own execution scope; a
      // successor never adopts it or grants another attempt.
      if (launch.supervisorInstanceId === owner.supervisorInstanceId) continue;
      const context = await openWorkerPreparationCleanupContext(driver, artifacts, owner, launch.launchId);
      const target = readWorkerPreparationCleanupTarget(driver, owner, context);
      if (!target.generation || !target.identity || !target.originalController || !target.recipe ||
          !launch.preparation.reservation || !launch.preparation.controller?.privateGitInputRef)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'abandoned preparation still lacks its complete original native prefix');
      const broker = observeInstalledBrokerQuiescence(input.store, launch.runId);
      input.signal.throwIfAborted();
      launcher ??= input.selected || input.anchor
        ? await openInstalledLinuxWorkerLauncher(input.selected!, input.anchor!) : await openLinuxWorkerLauncher(input.installation);
      const controller = await launcher.startController({ signal: input.signal });
      // The core producer owns every subsequent current-checker/input/directory
      // join and the existing single preparation retirement transaction.
      await retireRetainedWorkerPreparation(driver, artifacts, owner, context, controller, broker, input.signal);
    }
  } catch (error) {
    primary = { error };
    throw error instanceof ResourceRetirementError ? error : new ResourceRetirementError('abandoned preparation native closure remains unresolved', error);
  } finally {
    try { await launcher?.close(); }
    catch (error) { throw new ResourceRetirementError('preparation cleanup installation did not retire',
      primary ? new AggregateError([primary.error, error]) : error); }
  }
}
