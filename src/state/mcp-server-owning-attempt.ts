// A server preparation belongs to the most recent preceding effect preparation,
// while the whole call retains the first preparation's original deadline.
// These Journal lookups are data only; they grant no execution or recovery rights.
import type { InvocationJournalEntry } from '../kernel/types.js';

export function mcpServerOwningAttempt(journal: readonly InvocationJournalEntry[], server: InvocationJournalEntry, toolRequestRef: string) {
  if (server.opKind !== 'mcp-server' || server.phase !== 'prepared') return undefined;
  const preceding = journal.filter(entry => entry.runId === server.runId && entry.opKind === 'mcp' && entry.phase === 'prepared' &&
    entry.requestRef === toolRequestRef && entry.seq < server.seq).sort((a, b) => a.seq - b.seq);
  const owning = preceding.at(-1), first = preceding[0];
  if (!owning || !first || owning.leaseEpoch !== server.leaseEpoch || owning.timestamp > server.timestamp) return undefined;
  return { owning, first };
}

export function mcpAttemptHasClaim(journal: readonly InvocationJournalEntry[], prepared: InvocationJournalEntry, throughSeq = Number.MAX_SAFE_INTEGER): boolean {
  return journal.some(entry => entry.runId === prepared.runId && entry.opId === prepared.opId && entry.attempt === prepared.attempt &&
    entry.phase === 'dispatch_claimed' && entry.seq <= throughSeq);
}
