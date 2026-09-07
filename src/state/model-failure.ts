import { digestOmitting, modelOperationId, parseCanonicalTime } from '../kernel/identity.js';
import type { ModelResponseFailureEvidenceV1 } from '../kernel/stop.js';
import type { RecoveryClosureV1, RunAssemblyV1, RunFrontier, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import type { ModelRequestV1, NormalPromptProjectionV1 } from '../model/request.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import type { ModelUnusableResponseV1 } from '../protocol/agent-ir.js';
import { validateUnusableModelResponse } from '../runtime/continuation.js';
import { stopInvocationHistory, type ModelFailureStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { isZeroBudget } from './invariants.js';
import { readStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

type Inspector = { inspectorIdentityRef: string; inspectorIdentityDigest: string };

/** Only positively received normal responses with a settled history. Unknowns require their own external closure. */
async function readModelFailureCause(artifacts: ArtifactCatalog, cut: RecoveryClosureV1, observedAt: string) {
  const { run, journal, latestCheckpoint: checkpoint } = cut;
  if (run.waitingReason || !isZeroBudget(run.budgetReserved)) return undefined;
  const history = [...stopInvocationHistory(journal).values()];
  if (history.some(({ entry, hasClaim }) => !['model', 'tool'].includes(entry.opKind) ||
      (entry.phase !== 'completed' && (entry.phase !== 'failed' || hasClaim)))) return undefined;
  const latest = history.filter(({ entry }) => entry.opKind === 'model').at(-1)?.entry;
  if (latest?.phase !== 'completed') return undefined;
  const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, latest.requestRef);
  if (request.kind !== 'normal') return undefined; // Compaction retains its dedicated StopIntent as primary evidence.
  const response = await readCanonicalArtifact<ModelUnusableResponseV1>(artifacts, latest.resultRef!);
  if (response.format !== 'cliq-model-unusable-response-v1') return undefined;
  validateUnusableModelResponse(request, latest.requestRef, response);
  const projection = await readCanonicalArtifact<NormalPromptProjectionV1>(artifacts, request.promptProjectionRef);
  const frontierRef = projection.frontierDigest;
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, frontierRef);
  if (frontier.kind !== 'agent' || frontier.phase !== 'model_turn' || frontier.compactionPlanRef !== undefined ||
      latest.opId !== modelOperationId(run.id, frontier) || (run.frontierRef !== undefined && run.frontierRef !== frontierRef) ||
      projection.contextManifestRef !== checkpoint.contextManifestRef || frontier.contextItemSeq !== checkpoint.runItemSeq ||
      cut.items.length !== checkpoint.runItemSeq || response.observedAt > latest.timestamp || latest.timestamp > observedAt) {
    throw new TypeError('model failure does not own the current normal-model frontier and checkpoint');
  }
  if ((await artifacts.readBytes(response.observedResponse.bytesRef)).byteLength !== response.observedResponse.byteCount) {
    throw new TypeError('model failure response byte count mismatch');
  }
  return { frontierRef, frontierDigest: frontierRef, failingOpId: latest.opId,
    failureKind: 'model_unusable_response' as const, unusableResponseRef: latest.resultRef!, unusableResponseDigest: response.unusableDigest };
}

/** The state owner observes its Journal now and constructs the wrapper; callers supply no reason or evidence artifact. */
export async function prepareModelFailureStop(artifacts: ArtifactCatalog, owner: StateOwnerContext, assembly: RunAssemblyV1,
  cut: RecoveryClosureV1, identity: Inspector, observedAt: string) {
  if (assembly.mcpServers.length) return undefined;
  const cause = await readModelFailureCause(artifacts, cut, observedAt);
  if (!cause) return undefined;
  await readSupervisorInspector(artifacts, owner, assembly, { ...identity, observedAt });
  const evidence: ModelResponseFailureEvidenceV1 = { schemaVersion: 1, format: 'cliq-runtime-failure-evidence-v1',
    runId: cut.run.id, ...cause, ...identity, observedAt, evidenceDigest: '' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
  const artifact = await artifacts.publishCanonical(evidence, evidence.format);
  const inspector = await artifacts.describe(identity.inspectorIdentityRef, 'application/json', 'cliq-supervisor-inspector-identity-v1');
  const intent: ModelFailureStopIntent = { schemaVersion: 1, runId: cut.run.id, createdAt: observedAt, origin: 'runtime',
    targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'runtime', failingOpId: cause.failingOpId,
    runtimeFailureRef: artifact.ref, runtimeFailureDigest: evidence.evidenceDigest };
  return { intent, metadata: [artifact, inspector] };
}

/** Historical evidence stays valid after restart; freshness is relative to its original stop commit, not recovery time. */
export async function validateModelFailureStop(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, intent: ModelFailureStopIntent) {
  const evidence = await readCanonicalArtifact<ModelResponseFailureEvidenceV1>(artifacts, intent.runtimeFailureRef);
  if (!exactKeys(evidence, ['schemaVersion', 'format', 'runId', 'frontierRef', 'frontierDigest', 'failingOpId',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'failureKind', 'unusableResponseRef', 'unusableResponseDigest']) ||
      evidence.schemaVersion !== 1 || evidence.format !== 'cliq-runtime-failure-evidence-v1' || evidence.runId !== cut.run.id ||
      evidence.evidenceDigest !== intent.runtimeFailureDigest || digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest ||
      evidence.failingOpId !== intent.failingOpId || evidence.observedAt > intent.createdAt ||
      parseCanonicalTime(intent.createdAt) - parseCanonicalTime(evidence.observedAt) > 5_000) {
    throw new TypeError('runtime stop has no exact fresh model failure evidence');
  }
  const cause = await readModelFailureCause(artifacts, cut, evidence.observedAt);
  if (!cause) throw new TypeError('runtime stop has no settled unusable model response');
  requireEqual(evidence, { schemaVersion: 1, format: evidence.format, runId: cut.run.id, ...cause,
    inspectorIdentityRef: evidence.inspectorIdentityRef, inspectorIdentityDigest: evidence.inspectorIdentityDigest,
    observedAt: evidence.observedAt, evidenceDigest: evidence.evidenceDigest }, 'runtime model failure cause');
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, evidence.inspectorIdentityRef);
  const owner = readStateOwner(driver, inspector.stateOwnerEpoch);
  if (!owner || owner.acquiredAt > evidence.observedAt || (owner.state === 'terminal' && owner.releasedAt < intent.createdAt)) {
    throw new TypeError('model failure inspector was not the state owner at stop commit');
  }
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, cut.runSpec.assemblyRef);
  if (assembly.mcpServers.length) throw new TypeError('model failure stop lacks MCP closure');
  await readSupervisorInspector(artifacts, owner, assembly, evidence);
}
