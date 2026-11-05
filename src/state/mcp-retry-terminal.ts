// The ordinary unique terminal transaction owns this finalization. An unused
// result does not mutate the original UNKNOWN, once-settled budget or claim.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeRetryUnknownCancelledResult, retryUnknownHasLaterClaim, type RetryUnknownCancelledResult } from '../kernel/retry-unknown.js';
import { mcpRetryTerminalCause, mcpRetryLastClaimedTerminal, type McpRetryTerminalCause } from '../kernel/mcp-retry.js';
import type { RetryUnknownExhaustionEvidenceV1, McpCallResourceExhaustionEvidenceV1 } from '../kernel/stop.js';
import type { RecoveryClosureV1, RunAssemblyV1, ToolResultItem, TerminalDetail } from '../kernel/types.js';
import type { ToolRequestV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { recordAgentStopPredecessor, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import type { HeldInstalledRuntime } from './installed-runtime.js';
import { prepareMcpRetryTerminalClosure, readMcpRetryJournalHistory, validateMcpRetryTerminalHistory, type McpRetryTerminalClosure } from './mcp-retry-admission.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readStopSourceData } from './stop-source.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import type { SqliteDriver } from './sqlite-driver.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
declare const finalizationBrand: unique symbol;
export type McpRetryFinalization = Readonly<{ readonly [finalizationBrand]: true }>;
type Plan = Readonly<{ driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; cut: RecoveryClosureV1;
  closure: McpRetryTerminalClosure; request: ToolRequestV1; unknown: RecoveryClosureV1['journal'][number];
  result: RetryUnknownCancelledResult; inspectorIdentityRef: string; inspectorIdentityDigest: string; inspectorArtifact: PlannedArtifact; observedAt: string;
  cause: McpRetryTerminalCause }>;
const plans = new WeakMap<object, Plan>();
function exhaustionCause(history: Awaited<ReturnType<typeof readMcpRetryJournalHistory>>): Plan['cause'] {
  const original = mcpRetryLastClaimedTerminal(history.entries);
  const cause = original && mcpRetryTerminalCause(history.state, original.phase, history.launchCapacity,
    history.deadline === undefined ? undefined : { sampledAt: history.sampledAt, deadlineMs: history.deadline });
  if (!cause) invalid('MCP UNKNOWN retains real original dispatch and server launch capacity');
  return cause;
}
export function isMcpRetryFinalization(value: import('./manual-reconciliation.js').ManualInvocationFinalization | McpRetryFinalization): value is McpRetryFinalization {
  return plans.has(value);
}
export function readMcpRetryFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  value: McpRetryFinalization, runId: string): Plan {
  const plan = plans.get(value);
  if (!plan || plan.driver !== driver || plan.artifacts !== artifacts || plan.owner !== owner || plan.cut.run.id !== runId)
    invalid('foreign MCP retry terminal finalization');
  return plan;
}
export async function prepareMcpRetryFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  installedRuntime: HeldInstalledRuntime, runId: string, expectedRunRevision: number, signal?: AbortSignal): Promise<McpRetryFinalization> {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts; reads.assertReadActive();
  const cut = immutableSnapshot(await readRecoveryClosure(driver, reads, runId));
  if (cut.run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'MCP retry terminal original Run revision changed');
  if (cut.runSpec.operation !== 'agent' || cut.run.status !== 'queued' || cut.run.activeWorkerLaunchId || cut.run.waitingOnRef ||
      cut.run.stopIntentRef || cut.run.cancelRequested || cut.run.nextStep !== 'tool' || !cut.run.frontierRef)
    invalid('MCP retry exhaustion requires its exact productive worker-free unresolved original call');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(reads, cut.runSpec.assemblyRef);
  const candidates = cut.journal.filter(entry => entry.opKind === 'mcp' && entry.replayClass === 'retry' && entry.phase === 'unknown' &&
    !retryUnknownHasLaterClaim(cut.journal, entry));
  if (candidates.length !== 1) invalid('MCP retry exhaustion has no sole highest wholly settled original UNKNOWN');
  const unknown = candidates[0]!, history = await readMcpRetryJournalHistory(driver, reads, assembly, cut.journal, unknown.opId, sampleCanonicalNow());
  const cause = exhaustionCause(history);
  const request = await readCanonicalArtifact<ToolRequestV1>(reads, unknown.requestRef);
  if (request.frontierRef !== cut.run.frontierRef) invalid('MCP retry exhaustion changes its actual still-unanswered original frontier');
  const closure = await prepareMcpRetryTerminalClosure(driver, artifacts, owner, installedRuntime, cut, true, signal);
  const original = closure.abandonedRetryInvocations.find(entry => entry.unknownJournalSeq === unknown.seq);
  if (!original) invalid('MCP retry exhaustion has no positive original dispatch closure');
  const active = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(active);
  const inspectorArtifact = planCanonicalArtifact(inspector, inspector.format), observedAt = sampleCanonicalNow();
  const result = decodeRetryUnknownCancelledResult({ schemaVersion: 1, kind: 'retry_unknown_cancelled', ...original,
    message: 'Run stopped without using the ambiguous result' });
  reads.assertReadActive(); const token = Object.freeze({}) as McpRetryFinalization;
  plans.set(token, { driver, artifacts, owner, cut, closure, request, unknown, result,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, inspectorArtifact, observedAt, cause });
  return token;
}
/** These inert plans become durable only in the one terminal transaction,
 * so failed/stale preparation cannot strand an immutable failure intent. */
export function stageMcpRetryFinalization(plan: Plan, createdAt: string) {
  const { cut, request, result } = plan;
  if (createdAt < plan.observedAt || parseCanonicalTime(createdAt) - parseCanonicalTime(plan.observedAt) > 5_000)
    invalid('MCP retry actual terminal closure is stale before its original projection');
  const { artifact: resultArtifact, item } = planMcpRetryCancelledItem(request, result, createdAt);
  const core = { schemaVersion: 1 as const, format: 'cliq-runtime-failure-evidence-v1' as const, runId: cut.run.id,
    frontierRef: request.frontierRef, frontierDigest: request.frontierRef, failingOpId: request.opId,
    inspectorIdentityRef: plan.inspectorIdentityRef, inspectorIdentityDigest: plan.inspectorIdentityDigest,
    observedAt: plan.observedAt, ...plan.cause,
    retryUnknownResultRef: resultArtifact.ref, retryUnknownResultDigest: resultArtifact.ref };
  const failure: RetryUnknownExhaustionEvidenceV1 | McpCallResourceExhaustionEvidenceV1 = { ...core, evidenceDigest: canonicalSha256(core) };
  const failureArtifact = planCanonicalArtifact(failure, failure.format);
  const intent = recordAgentStopPredecessor({ schemaVersion: 1, runId: cut.run.id, createdAt, origin: 'runtime', targetStatus: 'failed',
    reason: 'runtime_failed', runtimeSubtype: 'runtime', failingOpId: request.opId,
    runtimeFailureRef: failureArtifact.ref, runtimeFailureDigest: failure.evidenceDigest }, undefined,
  cut.latestCheckpoint.id, cut.run.revision, cut.journal.length) as AgentStopIntent;
  return { intent, item, artifacts: [resultArtifact, failureArtifact, plan.inspectorArtifact] };
}

export function planMcpRetryCancelledItem(request: ToolRequestV1, value: RetryUnknownCancelledResult, createdAt: string) {
  const result = decodeRetryUnknownCancelledResult(value); parseCanonicalTime(createdAt);
  if (request.opId !== result.opId) invalid('MCP retry cancelled result changes its exact original request');
  const artifact = planCanonicalArtifact(result, 'cliq-retry-unknown-cancelled-result-v1');
  const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result', itemId: identityHash('cliq-tool-result-item-v1', request.runId,
    request.batchItemId, request.callId), runId: request.runId, batchItemId: request.batchItemId, callId: request.callId, index: request.callIndex,
    opId: request.opId, outcome: 'cancelled', resultRef: artifact.ref, createdAt };
  return { item, artifact };
}

export async function readMcpRetryExhaustionCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, observedAt: string,
  resultRef: string, resultDigest: string, sourceCheckpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number) {
  const result = decodeRetryUnknownCancelledResult(await readCanonicalArtifact(artifacts, resultRef));
  if (canonicalSha256(result) !== resultDigest) invalid('MCP retry failure substitutes its original terminal result');
  const source = readStopSourceData(driver, cut, observedAt, sourceCheckpointId, sourceRunRevision, registeredJournalSeq);
  const unknown = source.journal.find(entry => entry.seq === result.unknownJournalSeq);
  if (!unknown || unknown.opId !== result.opId || unknown.attempt !== result.attempt || unknown.phase !== 'unknown' ||
      unknown.opKind !== 'mcp' || unknown.replayClass !== 'retry' || unknown.budgetSettlementRef !== result.budgetSettlementRef ||
      retryUnknownHasLaterClaim(source.journal, unknown))
    invalid('MCP retry failure has no exact unused highest original UNKNOWN');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, cut.runSpec.assemblyRef);
  const history = await readMcpRetryJournalHistory(driver, artifacts, assembly, source.journal, unknown.opId, observedAt);
  const cause = exhaustionCause(history);
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, unknown.requestRef);
  if (!cut.run.terminalDetailRef) invalid('MCP retry failure is not owned by the unique completed terminal transaction');
  const detail = await readCanonicalArtifact<TerminalDetail>(artifacts, cut.run.terminalDetailRef);
  const original = (await validateMcpRetryTerminalHistory(driver, artifacts, cut, detail)).find(entry => entry.unknownJournalSeq === unknown.seq);
  requireEqual(original, { opId: result.opId, attempt: result.attempt, unknownJournalSeq: result.unknownJournalSeq,
    budgetSettlementRef: result.budgetSettlementRef, dispatchFenceOrDeathEvidenceRef: result.dispatchFenceOrDeathEvidenceRef }, 'MCP retry original terminal dispatch closure');
  return { frontierRef: request.frontierRef, frontierDigest: request.frontierRef, failingOpId: request.opId,
    ...cause, retryUnknownResultRef: resultRef, retryUnknownResultDigest: resultDigest };
}

export async function validateMcpRetryCancelledItem(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  detail: TerminalDetail, item: ToolResultItem) {
  if (item.outcome !== 'cancelled' || !item.opId || !['failed', 'cancelled'].includes(cut.run.status) || item.createdAt !== detail.createdAt)
    invalid('MCP retry cancelled item is not a terminal-only unused result');
  const result = decodeRetryUnknownCancelledResult(await readCanonicalArtifact(artifacts, item.resultRef));
  const original = (await validateMcpRetryTerminalHistory(driver, artifacts, cut, detail)).find(entry => entry.unknownJournalSeq === result.unknownJournalSeq);
  requireEqual(original, { opId: result.opId, attempt: result.attempt, unknownJournalSeq: result.unknownJournalSeq,
    budgetSettlementRef: result.budgetSettlementRef, dispatchFenceOrDeathEvidenceRef: result.dispatchFenceOrDeathEvidenceRef }, 'MCP retry exact cancelled result closure');
  const unknown = cut.journal.find(entry => entry.seq === result.unknownJournalSeq)!;
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, unknown.requestRef);
  if (item.opId !== request.opId || item.batchItemId !== request.batchItemId || item.callId !== request.callId || item.index !== request.callIndex ||
      item.itemId !== identityHash('cliq-tool-result-item-v1', cut.run.id, request.batchItemId, request.callId) || item.runId !== cut.run.id ||
      cut.journal.some(entry => entry.opId === result.opId && entry.attempt > result.attempt && entry.phase === 'dispatch_claimed'))
    invalid('MCP retry terminal result changes its original highest unanswered provider call');
}
