import type { InvocationJournalEntry } from '../kernel/types.js';
import type { ModelRetryState } from '../runtime/model-retry.js';

export type InstalledModelProgress = Readonly<{
  phase: InvocationJournalEntry['phase'];
  disposition: 'candidate_required' | 'stop_required' | undefined;
  hasDispatchClaim: boolean;
  hasSettlement: boolean;
  retry: ModelRetryState['kind'];
}>;

/** Scheduling only, never permission to create/claim a model invocation. The
 * owner validates its cut; an automatic wake also needs its original hint. */
export function selectInstalledModelProgress(attempt: InstalledModelProgress | undefined): 'prepare' | 'retry' | 'stop' | 'retain' {
  if (!attempt) return 'prepare';
  if (attempt.phase === 'completed') return attempt.disposition === 'stop_required' ? 'stop' : 'retain';
  if (attempt.phase === 'failed' && !attempt.hasDispatchClaim && attempt.hasSettlement && attempt.retry === 'ready') return 'retry';
  return 'retain';
}
