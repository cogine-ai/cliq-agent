import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyScriptApprovalRequest, decodeDependencyScriptPolicyEvidence } from '../kernel/dependency-script-approval.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { agentStopCause, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readDependencyScriptDenialCause } from './dependency-script-approval.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStopSourceData } from './stop-source.js';

/** The original registered policy/decision supplies the source locator. A
 * current policy disposition, template or arbitrary Error cannot replace it. */
export async function validateDependencyScriptStop(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, intent: Extract<AgentStopIntent, { origin: 'policy_deny' }> & { subjectKind: 'dependency_install_scripts' }) {
  const original = readStopSourceData(driver, cut, intent.createdAt, intent.registeredCheckpointId,
    intent.registeredRunRevision, intent.registeredJournalSeq);
  const evidence = decodeDependencyScriptPolicyEvidence(await readCanonicalArtifact(artifacts, intent.policyChannelEvidenceRef));
  const request = decodeDependencyScriptApprovalRequest(await readCanonicalArtifact(artifacts, evidence.requestRef));
  if (intent.opId !== request.opId || evidence.opId !== request.opId || evidence.runId !== cut.run.id ||
      evidence.requestDigest !== request.requestDigest || evidence.targetRef !== request.targetRef ||
      evidence.targetDigest !== request.targetDigest || original.journal.some(row => row.opId === request.opId))
    throw new TypeError('dependency script Stop substitutes its original undispatched consent');
  const cause = await readDependencyScriptDenialCause(driver, artifacts, cut.run.id, { observedAt: intent.createdAt,
    retained: { candidateItemId: request.candidateItemId, sourceCheckpointId: request.sourceCheckpointId,
      dependencyPlanRef: request.dependencyPlanRef, resultSourceRef: request.resultSourceRef,
      policyChannelEvidenceRef: intent.policyChannelEvidenceRef } });
  if (!cause || cause.opId !== intent.opId || cause.policyChannelEvidenceRef !== intent.policyChannelEvidenceRef ||
      cause.policyChannelEvidenceDigest !== intent.policyChannelEvidenceDigest)
    throw new TypeError('dependency script Stop has no complete original policy or registered decision denial');
  requireEqual(evidence, cause.evidence, 'dependency script Stop original policy bytes');
  requireEqual(canonicalSha256(cause.request), evidence.requestRef, 'dependency script Stop original request bytes');
  requireEqual(agentStopCause(intent), { schemaVersion: 1, runId: cut.run.id, createdAt: intent.createdAt,
    origin: 'policy_deny', subjectKind: 'dependency_install_scripts', targetStatus: 'failed', reason: 'runtime_failed',
    opId: cause.opId, policyChannelEvidenceRef: cause.policyChannelEvidenceRef,
    policyChannelEvidenceDigest: cause.policyChannelEvidenceDigest }, 'dependency script Stop reproduced cause');
  cause.assertUnchanged(driver);
}
