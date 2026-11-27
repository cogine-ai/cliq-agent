import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeMcpKnownUnusableResponse } from './mcp.js';
import { decodeBrokerInvocationAmbiguity } from './broker-ambiguity.js';

// Closed audit data only. These examples cannot create an original native
// receipt, safe-event screening, creator death, or settlement authority.
const ref = 'a'.repeat(64);

test('known-unusable audit keeps honest prefix/event/tail metadata without claiming unsafe bytes are retained', () => {
  const core = {
    schemaVersion: 1, format: 'cliq-mcp-known-unusable-response-v1', phase: 'tools_call', expectedId: 3,
    safeMessageRef: ref, safeMessageDigest: ref, safeMessageBytes: 100,
    mediaType: 'text/event-stream', termination: 'sse_response_event', rawFinitePrefixBytes: 1000,
    rawFinitePrefixDigest: ref, responseEventEndOffset: 1000, receivedTailBytes: 0,
    reason: 'full_capture_no_echo_refused'
  };
  const audit = (change: Record<string, unknown> = {}) => {
    const value = { ...core, ...change };
    return { ...value, auditDigest: canonicalSha256(value) };
  };
  assert.equal(decodeMcpKnownUnusableResponse(audit()).receivedTailBytes, 0,
    'an unsafe comment before the safe matching event need not have an after-event tail');
  assert.equal(decodeMcpKnownUnusableResponse(audit({ responseEventEndOffset: 900, receivedTailBytes: 100 })).receivedTailBytes, 100);
  for (const change of [
    { rawResponseRef: ref }, { unsafePrefixBytes: 'omitted unsafe data' },
    { phase: 'initialize' }, { expectedId: 2 }, { receivedTailBytes: 1 },
    { rawFinitePrefixBytes: 1_048_577, responseEventEndOffset: 1_048_577 },
    { safeMessageDigest: 'b'.repeat(64) }
  ]) {
    assert.throws(() => decodeMcpKnownUnusableResponse(audit(change)));
  }
});

test('successor creator-death references are paired and remain restricted to the original MCP ambiguity purpose', () => {
  const core = {
    schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1', runId: 'run', frontierRef: ref, frontierDigest: ref,
    opId: 'mcp-effect', opKind: 'mcp', attempt: 0, dispatchId: 'dispatch', dispatchJournalSeq: 2,
    operationRequestRef: ref, operationRequestDigest: ref, operationTargetRef: ref, operationTargetDigest: ref,
    claimingSupervisorInstanceId: 'original-owner', claimingStateOwnerEpoch: 1,
    inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: '2026-11-01T00:00:00.000Z',
    ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: ref,
    failureCode: 'response_stream_interrupted', durableTerminalResultAbsent: true
  };
  const evidence = (change: Record<string, unknown> = {}) => {
    const value = { ...core, ...change, evidenceDigest: '' };
    value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
    return value;
  };
  assert.equal(decodeBrokerInvocationAmbiguity(evidence()).creatorProcessDeathEvidenceRef, undefined);
  assert.equal(decodeBrokerInvocationAmbiguity(evidence({ creatorProcessDeathEvidenceRef: ref,
    creatorProcessDeathEvidenceDigest: ref })).creatorProcessDeathEvidenceRef, ref);
  for (const change of [
    { creatorProcessDeathEvidenceRef: ref }, { creatorProcessDeathEvidenceDigest: ref },
    { opKind: 'model', creatorProcessDeathEvidenceRef: ref, creatorProcessDeathEvidenceDigest: ref },
    { opKind: 'tool', creatorProcessDeathEvidenceRef: ref, creatorProcessDeathEvidenceDigest: ref }
  ]) {
    assert.throws(() => decodeBrokerInvocationAmbiguity(evidence(change)));
  }
});
