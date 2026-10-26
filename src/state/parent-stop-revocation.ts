import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildAdmission } from './child-admission.js';
import { KernelStorageError } from './errors.js';
import { readRegisteredAgentStop } from './stop-registration.js';
import { readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

/** A revocation observation, not the parent's full Stop cause, resource
 * retirement, terminal state or a transferred permission. Never calls the
 * parent's RecoveryClosure: each Run independently validates its own Stop. */
export async function readParentStopRevocation(driver: SqliteDriver, artifacts: ArtifactCatalog,
  childRunId: string, sourceRef?: string) {
  const admitted = await readChildAdmission(driver, artifacts, childRunId);
  const parent = readRun(driver, admitted.parent.id), currentRef = parent.stopIntentRef;
  if (!currentRef) throw new KernelStorageError('RECOVERY_REQUIRED', 'parent revocation lost its actually registered StopIntent');
  const wanted = sourceRef ?? currentRef, intent = await readRegisteredAgentStop(artifacts, parent, wanted);
  return { parent, intent, sourceStopIntentRef: wanted, admission: admitted,
    assertUnchanged(connection: SqliteConnection) {
      for (const source of [admitted, ...admitted.ancestors]) source.assertUnchanged(connection);
      admitted.rootOrigin.assertUnchanged(connection);
      // The last no-await SQL cut must still point to the observed registered
      // chain, not merely to a Stop with the same Run or reason.
      requireEqual(readRun(connection, parent.id), parent, 'parent revocation original registered Run cut');
    } };
}
