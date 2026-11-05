// Pure retained-data projection: this creates no Run, StateOwner, native
// no-release proof, request or permission. Physical qualification is separate.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import type { ToolRequestV1 } from '../kernel/tool-authorization.js';
import { planMcpNoReleaseResult } from './mcp-execution.js';

test('a delayed positive MCP failure result retains its original attempt, error and zero-charge settlement', () => {
  const request = { runId: 'run', opId: 'op', batchItemId: 'batch', callId: 'call', callIndex: 0, toolName: 'mcp__server__effect' } as ToolRequestV1;
  const failed = { runId: 'run', opId: 'op', opKind: 'mcp', phase: 'failed', attempt: 1, requestRef: canonicalSha256(request),
    errorRef: canonicalSha256('real original positive failure'), budgetSettlementRef: canonicalSha256('real original zero-consumption settlement'),
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: '2026-11-04T00:00:00.000Z' } as InvocationJournalEntry;
  const before = structuredClone(failed), createdAt = '2026-11-04T00:00:02.000Z';
  const result = planMcpNoReleaseResult(request, failed, createdAt);
  assert.equal(result.item.outcome, 'error'); assert.equal(result.item.createdAt, createdAt); assert.equal(result.item.opId, failed.opId);
  const payload = JSON.parse(Buffer.from(result.artifacts[1]!.bytes).toString('utf8'));
  assert.equal(payload.attempt, 1); assert.equal(payload.code, 'TOOL_EXECUTION_FAILED');
  assert.equal(payload.journalErrorRef, failed.errorRef); assert.equal(payload.diagnosticRef, failed.errorRef);
  assert.deepEqual(failed, before, 'result publication neither changes the settlement nor creates a second charge');
  for (const changed of [{ ...failed, phase: 'unknown' }, { ...failed, requestRef: canonicalSha256('substitute') },
    { ...failed, budgetSettlementRef: undefined }, { ...failed, errorRef: undefined }, { ...failed, opId: 'other' }])
    assert.throws(() => planMcpNoReleaseResult(request, changed as InvocationJournalEntry, createdAt));
  assert.throws(() => planMcpNoReleaseResult(request, failed, '2026-11-03T23:59:59.999Z'));
});
