import assert from 'node:assert/strict';
import test from 'node:test';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { mcpAttemptHasClaim, mcpServerOwningAttempt } from './mcp-server-owning-attempt.js';

const effect = (seq: number, attempt: number, leaseEpoch: number): InvocationJournalEntry => ({ runId: 'run', opId: 'effect',
  opKind: 'mcp', phase: 'prepared', requestRef: 'same-request', attempt, leaseEpoch, seq, timestamp: new Date(seq * 1000).toISOString() } as InvocationJournalEntry);
const server = (seq: number, leaseEpoch: number): InvocationJournalEntry => ({ runId: 'run', opId: `server-${seq}`,
  opKind: 'mcp-server', phase: 'prepared', attempt: 0, leaseEpoch, seq, timestamp: new Date(seq * 1000).toISOString() } as InvocationJournalEntry);
const claim = (prepared: InvocationJournalEntry, seq: number): InvocationJournalEntry => ({ ...prepared, phase: 'dispatch_claimed', seq });

test('stdio replacements bind their own exact effect attempt and retain the first whole-call preparation', () => {
  const first = effect(1, 0, 1), oldServer = server(2, 1), next = effect(7, 1, 2), replacement = server(8, 2), future = effect(11, 2, 3);
  const journal = [first, oldServer, claim(first, 3), next, replacement, claim(next, 9), future];
  assert.deepEqual(mcpServerOwningAttempt(journal, oldServer, 'same-request'), { owning: first, first });
  assert.deepEqual(mcpServerOwningAttempt(journal, replacement, 'same-request'), { owning: next, first });
  assert.equal(mcpServerOwningAttempt(journal, { ...replacement, leaseEpoch: 1 }, 'same-request'), undefined);
  assert.equal(mcpServerOwningAttempt(journal, replacement, 'different-request'), undefined);
  assert.equal(mcpServerOwningAttempt(journal, { ...replacement, runId: 'other' }, 'same-request'), undefined);
  assert.equal(mcpServerOwningAttempt(journal, { ...replacement, timestamp: first.timestamp }, 'same-request'), undefined);
});

test('a local pre-effect closure neither erases its exact claim nor mistakes older/future claims for its own', () => {
  const first = effect(1, 0, 1), next = effect(7, 1, 2), journal = [first, claim(first, 3), next, claim(next, 12)];
  assert.equal(mcpAttemptHasClaim(journal, next), true);
  assert.equal(mcpAttemptHasClaim(journal, next, 10), false);
  assert.equal(mcpAttemptHasClaim(journal, next, 12), true);
  assert.equal(mcpAttemptHasClaim(journal, { ...next, attempt: 2 }), false);
  assert.equal(mcpAttemptHasClaim(journal, { ...next, runId: 'other' }), false);
});
