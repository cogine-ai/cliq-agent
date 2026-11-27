// Retry planning and retained closure data only. Neither function creates a
// native join, releases a request or proves an external operation failed.
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertBoundedJsonValue } from './json.js';
import type { InvocationJournalEntry } from './types.js';
import { immutableSnapshot } from '../model/immutable.js';

export type McpHttpRetryClaimBindingData = Readonly<{
  runId: string; opId: string; attempt: number; dispatchId: string; dispatchJournalSeq: number;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string; grantRef: string; grantDigest: string;
  registryRef: string; manifestDigest: string; toolContractDigest: string; batchItemId: string; callId: string; callIndex: number;
  supervisorInstanceId: string; stateOwnerEpoch: number; workerLaunchId: string; leaseEpoch: number;
  brokerFenceTokenDigest: string; deadlineMs: number;
}>;
export type McpHttpRetryClaimIdentityV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-http-retry-claim-identity-v1'; binding: McpHttpRetryClaimBindingData; identityDigest: string;
}>;
/** Persisted before a new HTTP retry-profile claim. Its original native
 * binding/deadline are data only; live publication still asserts the native
 * opaque owner inside the original claim transaction. */
export function decodeMcpHttpRetryClaimIdentity(value: unknown): McpHttpRetryClaimIdentityV1 {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP HTTP retry original claim identity');
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'binding', 'identityDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-http-retry-claim-identity-v1') throw new TypeError('foreign MCP HTTP retry claim identity');
  const binding = controlWireRecord(data.binding, ['runId', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq', 'requestRef', 'requestDigest',
    'targetRef', 'targetDigest', 'grantRef', 'grantDigest', 'registryRef', 'manifestDigest', 'toolContractDigest', 'batchItemId', 'callId', 'callIndex',
    'supervisorInstanceId', 'stateOwnerEpoch', 'workerLaunchId', 'leaseEpoch', 'brokerFenceTokenDigest', 'deadlineMs']);
  for (const name of ['runId', 'opId', 'dispatchId', 'batchItemId', 'callId', 'supervisorInstanceId', 'workerLaunchId']) controlWireText(binding[name], 512);
  for (const [name, member] of Object.entries(binding)) if (name.endsWith('Ref') || name.endsWith('Digest')) controlWireRef(member);
  for (const name of ['attempt', 'callIndex']) controlWireInteger(binding[name]);
  for (const name of ['dispatchJournalSeq', 'stateOwnerEpoch', 'leaseEpoch', 'deadlineMs']) controlWireInteger(binding[name], 1);
  if (controlWireRef(data.identityDigest) !== digestOmitting(data, 'identityDigest')) throw new TypeError('MCP HTTP retry claim identity does not rehash');
  return immutableSnapshot(data) as McpHttpRetryClaimIdentityV1;
}

export type McpJoinedDispatchData = Readonly<{
  kind: 'mcp_http_owner_joined'; purpose: 'run'; brokerFenceTokenDigest: string;
  networkStarted: boolean; requestStarted: boolean; setupReleased: boolean; effectReleased: boolean;
  completedStages: readonly string[]; tokenRevoked: true; matchingActiveReleaseCount: 0; networkJoined: true; tasksJoined: true;
}> | Readonly<{
  kind: 'mcp_stdio_owner_joined'; purpose: 'run'; releaseFenceTokenDigest: string;
  execReleased: true; setupReleased: true; effectReleased: boolean; completedStages: readonly string[];
  tokenRevoked: true; matchingActiveReleaseCount: 0; processJoined: true; pipesJoined: true; tasksJoined: true; outputCustodyRetired: true;
}>;
export type McpRetryDispatchClosureV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-retry-dispatch-closure-v1'; runId: string; opId: string; attempt: number; nextAttempt: number;
  preparedJournalSeq: number; dispatchId: string; dispatchJournalSeq: number; unknownJournalSeq: number;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string; grantRef: string; grantDigest: string;
  registryRef: string; manifestDigest: string; toolContractDigest: string; brokerFenceTokenDigest: string;
  unknownEvidenceRef: string; unknownEvidenceDigest: string; budgetSettlementRef: string;
  originalClaimIdentity: Readonly<{ kind: 'stdio_instance' | 'http_retry_binding'; ref: string; digest: string }>;
  claimingSupervisorInstanceId: string; claimingStateOwnerEpoch: number;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; inspectorStateOwnerEpoch: number;
  callDeadlineMs: number; observedAt: string; evidenceDigest: string;
}> & (Readonly<{ kind: 'original_native_joined'; joined: McpJoinedDispatchData }> |
  Readonly<{ kind: 'broker_process_domain_dead'; deathEvidenceRef: string; deathEvidenceDigest: string }>);
export function decodeMcpJoinedDispatchData(value: unknown): McpJoinedDispatchData {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP original joined dispatch');
  const kind = (value as {kind?: unknown} | null)?.kind, stdio = kind === 'mcp_stdio_owner_joined';
  const data = controlWireRecord(value, ['kind', 'purpose', 'setupReleased', 'effectReleased', 'completedStages', 'tokenRevoked',
    'matchingActiveReleaseCount', 'tasksJoined', ...(stdio ? ['releaseFenceTokenDigest', 'execReleased', 'processJoined', 'pipesJoined', 'outputCustodyRetired']
      : ['brokerFenceTokenDigest', 'networkStarted', 'requestStarted', 'networkJoined'])]);
  if (data.purpose !== 'run' || !['mcp_stdio_owner_joined', 'mcp_http_owner_joined'].includes(kind as string) ||
      data.tokenRevoked !== true || data.matchingActiveReleaseCount !== 0 || data.tasksJoined !== true ||
      typeof data.effectReleased !== 'boolean' || typeof data.setupReleased !== 'boolean')
    throw new TypeError('MCP original dispatch has no complete irreversible joined/revoked domain');
  controlWireRef(data[stdio ? 'releaseFenceTokenDigest' : 'brokerFenceTokenDigest']);
  if (stdio ? data.execReleased !== true || data.setupReleased !== true || data.processJoined !== true || data.pipesJoined !== true || data.outputCustodyRetired !== true
    : data.networkJoined !== true || typeof data.networkStarted !== 'boolean' || typeof data.requestStarted !== 'boolean' ||
      data.requestStarted && !data.networkStarted || data.effectReleased && !data.setupReleased)
    throw new TypeError('MCP original dispatch loses complete transport-specific resource closure');
  const stages = ['initialize', 'initialized', 'tools_list', 'tools_call'];
  if (!Array.isArray(data.completedStages) || data.completedStages.length > stages.length ||
      data.completedStages.some((stage, index) => stage !== stages[index])) throw new TypeError('MCP joined dispatch changes original complete stage prefix');
  return immutableSnapshot(data) as McpJoinedDispatchData;
}
export function decodeMcpRetryDispatchClosure(value: unknown): McpRetryDispatchClosureV1 {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP retry dispatch closure');
  const kind = (value as {kind?: unknown} | null)?.kind;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'nextAttempt', 'preparedJournalSeq',
    'dispatchId', 'dispatchJournalSeq', 'unknownJournalSeq', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef', 'grantDigest',
    'registryRef', 'manifestDigest', 'toolContractDigest', 'brokerFenceTokenDigest', 'unknownEvidenceRef', 'unknownEvidenceDigest', 'budgetSettlementRef',
    'originalClaimIdentity',
    'claimingSupervisorInstanceId', 'claimingStateOwnerEpoch', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'inspectorStateOwnerEpoch',
    'callDeadlineMs', 'observedAt', 'evidenceDigest', 'kind', ...(kind === 'original_native_joined' ? ['joined'] : ['deathEvidenceRef', 'deathEvidenceDigest'])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-retry-dispatch-closure-v1') throw new TypeError('foreign MCP retry dispatch closure');
  for (const name of ['runId', 'opId', 'dispatchId', 'claimingSupervisorInstanceId']) controlWireText(data[name]);
  for (const [name, member] of Object.entries(data)) if (name.endsWith('Ref') || name.endsWith('Digest')) controlWireRef(member);
  const attempt = controlWireInteger(data.attempt), next = controlWireInteger(data.nextAttempt, 1);
  const prepared = controlWireInteger(data.preparedJournalSeq, 1), claim = controlWireInteger(data.dispatchJournalSeq, prepared + 1);
  controlWireInteger(data.unknownJournalSeq, claim + 1);
  controlWireInteger(data.callDeadlineMs, 1);
  const source = controlWireRecord(data.originalClaimIdentity, ['kind', 'ref', 'digest']);
  if (source.kind !== 'stdio_instance' && source.kind !== 'http_retry_binding') throw new TypeError('MCP retry closure lacks original transport-specific claim identity');
  controlWireRef(source.ref); controlWireRef(source.digest);
  const claiming = controlWireInteger(data.claimingStateOwnerEpoch, 1), inspecting = controlWireInteger(data.inspectorStateOwnerEpoch, claiming);
  if (next !== attempt + 1) throw new TypeError('MCP retry closure changes original contiguous attempts');
  if (kind === 'original_native_joined') {
    const joined = decodeMcpJoinedDispatchData(data.joined), token = joined.kind === 'mcp_stdio_owner_joined' ? joined.releaseFenceTokenDigest : joined.brokerFenceTokenDigest;
    if (inspecting !== claiming || token !== data.brokerFenceTokenDigest || (joined.kind === 'mcp_stdio_owner_joined') !== (source.kind === 'stdio_instance'))
      throw new TypeError('MCP retry joined receipt substitutes original owner/token/claim identity');
  } else if (kind !== 'broker_process_domain_dead' || inspecting <= claiming) throw new TypeError('MCP retry successor closure requires a strictly newer real inspector');
  parseCanonicalTime(controlWireText(data.observedAt));
  if (data.evidenceDigest !== digestOmitting(data, 'evidenceDigest')) throw new TypeError('MCP retry dispatch closure does not rehash');
  return immutableSnapshot(data) as McpRetryDispatchClosureV1;
}
export type McpRetryState = Readonly<{ dispatchedAttempts: number }> & (
  Readonly<{ kind: 'ready'; nextAttempt: number }> | Readonly<{ kind: 'backoff'; nextAttempt: number; notBefore: string }> |
  Readonly<{ kind: 'pending'; attempt: number; phase: 'prepared' | 'dispatch_claimed' }> |
  Readonly<{ kind: 'completed'; attempt: number }> |
  Readonly<{ kind: 'exhausted' | 'deadline'; attempt: number; lastPhase: 'failed' | 'unknown' }>);
export type McpRetryTerminalCause = Readonly<{ failureKind: 'retry_unknown_exhausted' }> |
  Readonly<{ failureKind: 'mcp_call_resource_exhausted'; resource: 'server_launch_capacity'; used: number; limit: number }>;
/** A failed replacement which never claimed cannot erase the last real
 * effect's outcome. Full provenance is still checked by the owning reader. */
export function mcpRetryLastClaimedTerminal(entries: readonly InvocationJournalEntry[]): InvocationJournalEntry | undefined {
  const claim = entries.filter(entry => entry.opKind === 'mcp' && entry.phase === 'dispatch_claimed').at(-1);
  if (!claim) return undefined;
  const terminal = entries.filter(entry => entry.opId === claim.opId && entry.attempt === claim.attempt).at(-1);
  return terminal && ['completed', 'failed', 'unknown'].includes(terminal.phase) ? terminal : undefined;
}
/** Decision data only. The owning finalization independently reads the full
 * original Journal, signed lifecycle and positive native dispatch closure. */
export function mcpRetryTerminalCause(state: McpRetryState, highestPhase: InvocationJournalEntry['phase'],
  launchCapacity?: Readonly<{ used: number; limit: number }>,
  originalDeadline?: Readonly<{ sampledAt: string; deadlineMs: number }>): McpRetryTerminalCause | undefined {
  if (launchCapacity && (!Number.isSafeInteger(launchCapacity.used) || !Number.isSafeInteger(launchCapacity.limit) ||
      launchCapacity.used < 0 || launchCapacity.limit < 1 || launchCapacity.limit > 3 || launchCapacity.used > launchCapacity.limit))
    throw new TypeError('MCP call changes its original bounded server launch capacity');
  if (highestPhase !== 'unknown') return undefined;
  const unclaimed = state.kind === 'pending' && state.phase === 'prepared';
  if (originalDeadline && (!Number.isSafeInteger(originalDeadline.deadlineMs) || originalDeadline.deadlineMs < 0))
    throw new TypeError('MCP retry terminal changes its original native deadline');
  if (state.kind === 'exhausted' || state.kind === 'deadline' || unclaimed && originalDeadline &&
      parseCanonicalTime(originalDeadline.sampledAt) >= originalDeadline.deadlineMs) return { failureKind: 'retry_unknown_exhausted' };
  if (launchCapacity && (state.kind === 'ready' || state.kind === 'backoff' || unclaimed) && launchCapacity.used === launchCapacity.limit)
    return { failureKind: 'mcp_call_resource_exhausted', resource: 'server_launch_capacity', used: launchCapacity.used, limit: launchCapacity.limit };
  return undefined;
}
/** Only a separately verified positive failure may become an ordinary error
 * result. UNKNOWN always retains its independent truthful terminal carrier. */
export function mcpRetryPositiveFailureAction(state: McpRetryState, highestPhase: InvocationJournalEntry['phase'], stopped: boolean,
  launchCapacity?: Readonly<{ used: number; limit: number }>): 'retry' | 'result' {
  mcpRetryTerminalCause(state, 'failed', launchCapacity); // Reproduce the original closed capacity bounds.
  if (highestPhase !== 'failed' || !['ready', 'backoff', 'exhausted', 'deadline'].includes(state.kind))
    throw new TypeError('MCP ordinary retry error requires its actual settled positive failure');
  return stopped || state.kind === 'exhausted' || state.kind === 'deadline' || launchCapacity !== undefined && launchCapacity.used === launchCapacity.limit
    ? 'result' : 'retry';
}
/** Full CAS/native provenance is checked by the owning consumer. This pure
 * plan only reproduces literal capacity, contiguous attempts and real-time
 * backoff; it cannot turn an UNKNOWN into a negative effect result. */
export function mcpRetryState(policy: Readonly<{ maxDispatchedAttempts: number; postAttemptDelaysMs: readonly number[] }>,
  entries: readonly InvocationJournalEntry[], now: string, callDeadlineMs: number): McpRetryState {
  if (policy.maxDispatchedAttempts !== 3 || canonicalSha256(policy.postAttemptDelaysMs) !== canonicalSha256([500, 2000]) ||
      !Number.isSafeInteger(callDeadlineMs) || callDeadlineMs < 0) throw new TypeError('MCP retry changes frozen policy or original call deadline');
  const sampled = parseCanonicalTime(now), first = entries[0];
  if (!first) return { kind: 'ready', nextAttempt: 0, dispatchedAttempts: 0 };
  let count = 0, settledAt: number | undefined, lastSeq = 0, lastTime = -Infinity;
  const attempts: InvocationJournalEntry[][] = [];
  for (const entry of entries) {
    const at = parseCanonicalTime(entry.timestamp);
    if (entry.opKind !== 'mcp' || entry.replayClass !== 'retry' || entry.runId !== first.runId || entry.opId !== first.opId ||
        entry.target !== first.target || entry.requestRef !== first.requestRef || entry.idempotencyKey !== first.idempotencyKey ||
        entry.seq <= lastSeq || at < lastTime) throw new TypeError('MCP retry mixes original operation/request or Journal order');
    lastSeq = entry.seq; lastTime = at;
    if (entry.phase === 'prepared') {
      const prior = attempts.at(-1), final = prior?.at(-1);
      if (entry.attempt !== attempts.length || count >= 3 || final && (!['failed', 'unknown'].includes(final.phase) || !final.budgetSettlementRef) ||
          settledAt !== undefined && at < settledAt + (policy.postAttemptDelaysMs[count - 1] ?? 0) || at >= callDeadlineMs)
        throw new TypeError('MCP retry overtakes settlement, capacity, original deadline or literal backoff');
      if (final?.phase === 'unknown' && (!entry.evidenceRef || !entry.evidenceDigest)) throw new TypeError('MCP retry preparation lacks original dispatch closure');
      attempts.push([entry]);
    } else {
      const attempt = attempts[entry.attempt], previous = attempt?.at(-1);
      if (!attempt || !previous || entry.attempt !== attempts.length - 1 || entry.grantRef !== attempt[0]?.grantRef)
        throw new TypeError('MCP retry phase has no sole current original prepared owner');
      if (entry.phase === 'dispatch_claimed') {
        if (attempt.length !== 1 || count >= 3 || at >= callDeadlineMs) throw new TypeError('MCP retry has repeated or deadline-expired claim');
        count++;
      } else {
        if (!['completed', 'failed', 'unknown'].includes(entry.phase) || !entry.budgetSettlementRef ||
            previous.phase !== 'dispatch_claimed' && !(previous.phase === 'prepared' && entry.phase === 'failed'))
          throw new TypeError('MCP retry has no closed original settlement');
        if (entry.phase === 'unknown' && (!entry.evidenceRef || !entry.evidenceDigest || canonicalSha256(entry.budgetDelta) !== canonicalSha256(attempt[0]?.budgetDelta)))
          throw new TypeError('MCP retry UNKNOWN loses original whole-once charge');
        if (previous.phase === 'dispatch_claimed') settledAt = at;
      }
      attempt.push(entry);
    }
  }
  const final = attempts.at(-1)?.at(-1);
  if (!final) throw new TypeError('MCP retry Journal has no prepared owner');
  if (final.phase === 'prepared' || final.phase === 'dispatch_claimed') return { kind: 'pending', dispatchedAttempts: count, attempt: final.attempt, phase: final.phase };
  if (final.phase === 'completed') return { kind: 'completed', dispatchedAttempts: count, attempt: final.attempt };
  if (final.phase !== 'failed' && final.phase !== 'unknown') throw new TypeError('MCP retry has no supported terminal phase');
  if (count >= 3 || sampled >= callDeadlineMs) return { kind: count >= 3 ? 'exhausted' : 'deadline', dispatchedAttempts: count, attempt: final.attempt, lastPhase: final.phase };
  const notBefore = settledAt === undefined ? undefined : settledAt + (policy.postAttemptDelaysMs[count - 1] ?? 0);
  return notBefore !== undefined && sampled < notBefore ? { kind: 'backoff', dispatchedAttempts: count, nextAttempt: final.attempt + 1, notBefore: new Date(notBefore).toISOString() }
    : { kind: 'ready', dispatchedAttempts: count, nextAttempt: final.attempt + 1 };
}
