import type { Run } from '../kernel/types.js';
import { agentStopPriority, decodeAgentStop, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';

/** Pure retained-data closure rooted at the caller's actual SQL Run cut.
 * Proves registration/replacement only, not any Stop cause or resource fact. */
export async function readRegisteredAgentStopChain(artifacts: ArtifactCatalog, run: Run) {
  if (!run.stopIntentRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'revocation lost its actually registered StopIntent');
  let ref = run.stopIntentRef, newer: AgentStopIntent | undefined;
  const chain: Array<{ ref: string; intent: AgentStopIntent }> = [];
  const seen = new Set<string>();
  for (let depth = 0; depth < 7; depth++) {
    if (seen.has(ref)) throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop registration chain is cyclic');
    seen.add(ref);
    const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, ref), run);
    if (newer && (agentStopPriority(stop) >= agentStopPriority(newer) || stop.createdAt > newer.createdAt ||
        stop.registeredRunRevision !== undefined && newer.registeredRunRevision !== undefined && stop.registeredRunRevision >= newer.registeredRunRevision))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop registration chain regressed precedence or time');
    chain.push({ ref, intent: stop });
    if (!stop.supersedesStopIntentRef) {
      return chain;
    }
    newer = stop; ref = stop.supersedesStopIntentRef;
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop registration chain exceeds its fixed precedence bound');
}

export async function readRegisteredAgentStop(artifacts: ArtifactCatalog, run: Run, requestedRef = run.stopIntentRef) {
  const chain = await readRegisteredAgentStopChain(artifacts, run), found = chain.find(entry => entry.ref === requestedRef);
  if (!found) throw new KernelStorageError('RECOVERY_REQUIRED', 'historical Stop lacks its original registered replacement chain');
  return found.intent;
}
