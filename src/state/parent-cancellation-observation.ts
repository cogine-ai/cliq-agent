// A registered negative dispatch observation, never a winning Stop, proof of
// parent quiescence, child termination, permission or execution authority.
import type { RecoveryClosureV1 } from '../kernel/types.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { agentStopPriority, decodeAgentStop } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { readParentStopRevocation } from './parent-stop-revocation.js';
import { readRegisteredAgentStopChain } from './stop-registration.js';
import { readStopSourceData } from './stop-source.js';
import type { SqliteDriver } from './sqlite-driver.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `parent cancellation observation ${message}`); }
export async function readParentCancellationObservation(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1) {
  const { run } = closure, ref = run.parentCancellationRef;
  if (!ref) return undefined;
  if (!run.parentRunId || !run.cancelRequested || !run.stopIntentRef) invalid('lost its actual child dispatch fence');
  const intent = decodeAgentStop(await readCanonicalArtifact(artifacts, ref), run);
  if (intent.origin !== 'parent_cancel' || intent.sourceRunId !== run.parentRunId || intent.registeredCheckpointId === undefined ||
      intent.registeredRunRevision === undefined || intent.registeredJournalSeq === undefined) invalid('is not its complete originally registered parent intent');
  const metadata = driver.prepare('SELECT byte_length FROM artifacts WHERE ref=?').get<{byte_length:unknown}>(ref);
  if (!metadata || Number(metadata.byte_length) !== canonicalJsonBytes(intent).byteLength ||
      run.revision === intent.registeredRunRevision + 1 && run.updatedAt !== intent.createdAt) invalid('lost its actual registration metadata or first committed Run cut');
  readStopSourceData(driver, closure, intent.createdAt, intent.registeredCheckpointId, intent.registeredRunRevision, intent.registeredJournalSeq);
  const chain = await readRegisteredAgentStopChain(artifacts, run);
  if (chain.some(entry => entry.intent.registeredRunRevision === undefined)) invalid('cannot guess a missing original winner registration');
  const sameRevision = chain.find(entry => entry.intent.registeredRunRevision === intent.registeredRunRevision),
    prior = chain.find(entry => entry.intent.registeredRunRevision! < intent.registeredRunRevision!);
  if (sameRevision) {
    if (sameRevision.ref !== ref || prior && agentStopPriority(prior.intent) >= agentStopPriority(intent) ||
        intent.supersedesStopIntentRef !== prior?.ref) invalid('invented the winning parent intent or its exact predecessor');
  } else {
    if (!prior || agentStopPriority(prior.intent) <= agentStopPriority(intent) || intent.supersedesStopIntentRef !== undefined)
      invalid('losing parent observation cannot replace or supersede a higher winner');
  }
  const source = await readParentStopRevocation(driver, artifacts, run.id, intent.sourceStopIntentRef);
  if (source.parent.id !== intent.sourceRunId || source.intent.createdAt > intent.createdAt) invalid('precedes its actual registered direct-parent Stop');
  source.assertUnchanged(driver); return { ref, intent };
}
