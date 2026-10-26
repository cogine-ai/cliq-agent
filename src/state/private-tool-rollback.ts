import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { InvocationJournalEntry, Checkpoint, WorkspaceGenerationStateV1,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationRetirementEvidenceV1, ToolResultItem, ToolResultPayloadV1, ToolResultModelContentV1,
  RecoveryClosureV1, RunAssemblyV1, WorkerRecoveryEvidenceV1 } from '../kernel/types.js';
import type { ToolRequestV1, ToolTargetV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import { exactKeys, requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeBuiltinEditContainmentPlan, decodeBuiltinEditSandboxLaunchSpec, decodeBuiltinScriptSandboxLaunchSpec } from './execution-closure.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readCheckpoint } from './rows.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { BUILTIN_SCRIPT_TOOL_NAMES, decodeToolExecutionIdentity, assertBuiltinScriptGuest } from '../tools/execution-identity.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import type { ToolContractManifestV1 } from '../kernel/types.js';
import { loadToolContracts } from '../tools/input-contract.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { decodeGuestToolchainManifest, guestToolchainMembers } from './guest-toolchain.js';
import { assertBuiltinScriptResources } from './tool-runtime-authority.js';

/** Closed retained evidence, never an execution or native retirement permit. */
export type PrivateToolRollbackV1 = {
  schemaVersion: 1; format: 'cliq-private-tool-rollback-v1'; code: 'TOOL_EXECUTION_FAILED';
  failureKind: 'private_effect_rolled_back'; runId: string; opId: string; attempt: number; dispatchId: string;
  preparedJournalSeq: number; claimJournalSeq: number; unknownJournalSeq: number;
  requestRef: string; targetRef: string; grantRef: string; sandboxLaunchSpecRef: string;
  workerLaunchId: string; leaseEpoch: number; generationRef: string; generationIdentityDigest: string;
  checkpointId: string; workspaceStateRef: string; quarantineEvidenceRef: string; quarantineEvidenceDigest: string;
  retirementEvidenceRef: string; retirementEvidenceDigest: string; inspectorIdentityRef: string; inspectorIdentityDigest: string;
  observedAt: string; evidenceDigest: string;
};

export function hasOnlySettledPrivateToolUnknowns(journal: readonly InvocationJournalEntry[]): boolean {
  const latest = new Map<string, InvocationJournalEntry>();
  for (const entry of journal) latest.set(`${entry.opId}:${entry.attempt}`, entry);
  const open = [...latest.values()].filter(entry => ['prepared', 'dispatch_claimed', 'unknown'].includes(entry.phase));
  if (open.length !== 1) return false;
  const unknown = open[0]!, prepared = journal.find(entry => entry.opId === unknown.opId && entry.attempt === unknown.attempt && entry.phase === 'prepared');
  // Candidate classification only. The original fixed recipe and its entire
  // retained closure are independently checked before any rollback commit.
  return !!prepared && prepared.opKind === 'tool' && ['manual', 'retry'].includes(prepared.replayClass) &&
    unknown.phase === 'unknown' && !!unknown.budgetSettlementRef && canonicalSha256(unknown.budgetDelta) === canonicalSha256(prepared.budgetDelta);
}

export function planPrivateRollbackResult(request: ToolRequestV1, evidence: PrivateToolRollbackV1, createdAt: string) {
  const evidenceRef = canonicalSha256(evidence);
  const core = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
    callId: request.callId, index: request.callIndex, toolName: request.toolName, outcome: 'error' as const,
    content: { code: 'TOOL_EXECUTION_FAILED', failureKind: 'private_effect_rolled_back' } };
  const model: ToolResultModelContentV1 = { ...core, contentDigest: canonicalSha256(core) };
  const modelPlan = planCanonicalArtifact(model, model.format);
  const payload: ToolResultPayloadV1 = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: request.runId,
    batchItemId: request.batchItemId, callId: request.callId, index: request.callIndex, toolName: request.toolName,
    modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest, outcome: 'error', code: 'TOOL_EXECUTION_FAILED',
    diagnosticRef: evidenceRef, diagnosticDigest: evidence.evidenceDigest, opId: request.opId, attempt: evidence.attempt,
    journalErrorRef: evidenceRef, journalErrorDigest: evidence.evidenceDigest, payloadDigest: '' };
  payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
  const result = planCanonicalArtifact(payload, payload.format);
  const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', request.runId, request.batchItemId, request.callId), runId: request.runId,
    batchItemId: request.batchItemId, callId: request.callId, index: request.callIndex, opId: request.opId,
    outcome: 'error', resultRef: result.ref, createdAt };
  return { item, artifacts: [modelPlan, result] };
}

export function decodePrivateToolRollback(value: PrivateToolRollbackV1): PrivateToolRollbackV1 {
  if (!exactKeys(value, ['schemaVersion', 'format', 'code', 'failureKind', 'runId', 'opId', 'attempt', 'dispatchId',
    'preparedJournalSeq', 'claimJournalSeq', 'unknownJournalSeq', 'requestRef', 'targetRef', 'grantRef', 'sandboxLaunchSpecRef',
    'workerLaunchId', 'leaseEpoch', 'generationRef', 'generationIdentityDigest', 'checkpointId', 'workspaceStateRef',
    'quarantineEvidenceRef', 'quarantineEvidenceDigest', 'retirementEvidenceRef', 'retirementEvidenceDigest',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest']) || value.schemaVersion !== 1 ||
      value.format !== 'cliq-private-tool-rollback-v1' || value.code !== 'TOOL_EXECUTION_FAILED' ||
      value.failureKind !== 'private_effect_rolled_back' || value.evidenceDigest !== digestOmitting(value, 'evidenceDigest') ||
      [value.runId, value.opId, value.dispatchId, value.workerLaunchId, value.checkpointId].some(id => typeof id !== 'string' || !id) ||
      !Number.isSafeInteger(value.attempt) || value.attempt < 0 ||
      [value.preparedJournalSeq, value.claimJournalSeq, value.unknownJournalSeq, value.leaseEpoch].some(seq => !Number.isSafeInteger(seq) || seq < 1) ||
      value.claimJournalSeq <= value.preparedJournalSeq || value.unknownJournalSeq <= value.claimJournalSeq)
    throw new TypeError('private rollback has no closed original invocation evidence');
  for (const ref of [value.requestRef, value.targetRef, value.grantRef, value.sandboxLaunchSpecRef, value.generationRef,
    value.generationIdentityDigest, value.workspaceStateRef, value.quarantineEvidenceRef, value.quarantineEvidenceDigest,
    value.retirementEvidenceRef, value.retirementEvidenceDigest, value.inspectorIdentityRef, value.inspectorIdentityDigest, value.evidenceDigest])
    assertArtifactRef(ref);
  parseCanonicalTime(value.observedAt);
  return value;
}

/** Validate the original claim's fixed private-only recipe. No Run projection,
 * new grant or productive branded launch is constructed for a fenced worker. */
export async function readPrivateRollbackClaim(artifacts: ArtifactCatalog, prepared: InvocationJournalEntry,
  claim: InvocationJournalEntry, unknown: InvocationJournalEntry, generation: WorkspaceGenerationStateV1) {
  if (prepared.opKind !== 'tool' || !['manual', 'retry'].includes(prepared.replayClass) || prepared.phase !== 'prepared' ||
      claim.phase !== 'dispatch_claimed' || unknown.phase !== 'unknown' || !unknown.budgetSettlementRef ||
      claim.opId !== prepared.opId || claim.attempt !== prepared.attempt || unknown.opId !== prepared.opId ||
      unknown.attempt !== prepared.attempt || !prepared.grantRef || !claim.sandboxLaunchSpecRef)
    throw new TypeError('private rollback requires one original fully charged private tool unknown');
  requireEqual(unknown.budgetDelta, prepared.budgetDelta, 'private rollback original pessimistic charge');
  return readPrivateBuiltinClaim(artifacts, prepared, claim, generation);
}

/** Original fixed builtin data only. This neither reopens a native scope nor
 * changes a possibly dispatched Journal entry into a retryable operation. */
export async function readPrivateBuiltinClaim(artifacts: ArtifactCatalog, prepared: InvocationJournalEntry,
  claim: InvocationJournalEntry, generation: Pick<WorkspaceGenerationStateV1, 'generationRef'>) {
  if (prepared.opKind !== 'tool' || prepared.phase !== 'prepared' || claim.phase !== 'dispatch_claimed' ||
      claim.opId !== prepared.opId || claim.attempt !== prepared.attempt || claim.runId !== prepared.runId ||
      !prepared.grantRef || !claim.sandboxLaunchSpecRef)
    throw new TypeError('private builtin result requires its original prepared and permanent claim');
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef);
  const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, prepared.grantRef);
  const execution = decodeToolExecutionIdentity(target.execution), script = execution.kind === 'builtin_script';
  if (!script && (execution.kind !== 'builtin' || request.toolName !== 'edit' || execution.adapterId !== 'edit' || prepared.replayClass !== 'manual') ||
      script && (!BUILTIN_SCRIPT_TOOL_NAMES.some(name => name === request.toolName) ||
        prepared.replayClass !== (request.toolName === 'bash' ? 'manual' : 'retry')))
    throw new TypeError('private rollback requires its original fixed native builtin recipe');
  const launchBytes = await readCanonicalArtifact(artifacts, claim.sandboxLaunchSpecRef);
  const spec = script ? decodeBuiltinScriptSandboxLaunchSpec(launchBytes) : decodeBuiltinEditSandboxLaunchSpec(launchBytes);
  const plan = decodeBuiltinEditContainmentPlan(await readCanonicalArtifact(artifacts, spec.containmentPlanRef));
  const expectedOwner = { kind: 'run_invocation', runId: prepared.runId, intendedLeaseEpoch: prepared.leaseEpoch,
    workerLaunchId: spec.owner.workerLaunchId, opId: prepared.opId, attempt: prepared.attempt, dispatchId: claim.dispatchId };
  requireEqual(spec.owner, expectedOwner, 'private rollback original edit owner');
  requireEqual(plan.owner, expectedOwner, 'private rollback original edit plan');
  requireEqual(plan.filesystemBinding, { kind: 'run-generation', generationRef: generation.generationRef }, 'private rollback effect domain');
  if (request.requestDigest !== digestOmitting(request, 'requestDigest') || target.targetDigest !== digestOmitting(target, 'targetDigest') ||
      grant.grantDigest !== digestOmitting(grant, 'grantDigest') || request.runId !== prepared.runId || request.opId !== prepared.opId ||
      target.toolName !== request.toolName || grant.requestRef !== prepared.requestRef || grant.targetRef !== prepared.target ||
      grant.subject.replayClass !== prepared.replayClass ||
      spec.requestRef !== prepared.requestRef || spec.requestDigest !== request.requestDigest || spec.targetRef !== prepared.target ||
      spec.targetDigest !== target.targetDigest || spec.operationGrantRef !== prepared.grantRef ||
      spec.filesystem.kind !== 'run_generation' || spec.filesystem.generationRef !== generation.generationRef ||
      spec.filesystem.access !== (!script || request.toolName === 'bash' ? 'read_write' : 'read_only') || plan.planDigest !== spec.containmentPlanDigest ||
      plan.parentContainmentRef !== spec.parentWorkerContainmentRef)
    throw new TypeError('private rollback substitutes its fixed original request or private generation');
  if (!script) {
    if (execution.kind !== 'builtin' || spec.executable.kind !== 'runtime_bundle' || spec.executable.executableId !== 'edit' ||
        spec.executable.executableDigest !== execution.adapterCodeDigest)
      throw new TypeError('private rollback substitutes its original edit executable');
  } else {
    const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, request.assemblyRef));
    const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
    const contract = manifest.entries.find(entry => entry.name === request.toolName);
    if (manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
        target.toolManifestRef !== assembly.tools.manifestRef || target.toolManifestDigest !== assembly.tools.manifestDigest ||
        !contract || contract.replayClass !== prepared.replayClass || canonicalSha256(contract) !== target.toolContractDigest)
      throw new TypeError('private script rollback substitutes its complete original tool contract');
    requireEqual(contract.execution, execution, 'private script rollback execution');
    const inputSchema = await readCanonicalArtifact(artifacts, contract.inputSchemaRef);
    const call = await readCanonicalArtifact<ToolCallInputV1>(artifacts, request.inputRef);
    const resolver = loadToolContracts([{ ...contract, inputSchema }]);
    const projected = resolver.projectInvocation({ callId: call.callId, index: call.index, toolName: call.toolName, input: call.value! });
    if (projected.kind !== 'tool' || call.toolName !== request.toolName || call.disposition !== 'resolved' ||
        call.inputDigest !== request.inputDigest || call.inputDigest !== digestOmitting(call, 'inputDigest'))
      throw new TypeError('private script rollback has no exact normalized original call');
    requireEqual(projected.invocation.input, call.value, 'private rollback original normalized input');
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
    const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
    const scriptEntry = bundle.entries.find(entry => entry.entryId === execution.adapterId);
    if (bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest || bundle.manifestDigest !== canonicalSha256(core) ||
        !scriptEntry || scriptEntry.role !== 'tool_adapter' || scriptEntry.executable || scriptEntry.version !== execution.adapterVersion ||
        scriptEntry.relativePath !== 'adapters/builtin-tools.mjs' || scriptEntry.digest !== execution.adapterCodeDigest ||
        scriptEntry.byteCount < 1 || scriptEntry.byteCount > 1_048_576 ||
        assembly.runtime.guestToolchainManifestRef !== execution.guestToolchainManifestRef ||
        assembly.runtime.guestToolchainManifestDigest !== execution.guestToolchainManifestDigest)
      throw new TypeError('private rollback substitutes its original signed script and runtime');
    const guest = decodeGuestToolchainManifest(await readCanonicalArtifact(artifacts, execution.guestToolchainManifestRef));
    const members = guestToolchainMembers(bundle, execution.guestToolchainManifestRef, guest);
    assertBuiltinScriptResources(guest.guestImageByteCount, spec.resources);
    assertBuiltinScriptGuest(guest, [request.toolName]);
    if (guest.manifestDigest !== execution.guestToolchainManifestDigest || guest.node.digest !== execution.executableDigest ||
        guest.node.canonicalGuestPath !== execution.executionPath || guest.node.logicalName !== execution.toolId)
      throw new TypeError('private rollback substitutes its original guest Node identity');
    requireEqual(spec.executable, { kind: 'guest_toolchain', guestToolchainManifestRef: execution.guestToolchainManifestRef,
      guestToolchainManifestDigest: execution.guestToolchainManifestDigest, toolId: execution.toolId, role: 'tool',
      executionPath: execution.executionPath, executableDigest: execution.executableDigest }, 'private rollback exact executable');
    requireEqual(spec.runtime, { ...spec.runtime, runtimeBundleRef: assembly.runtime.runtimeBundleRef,
      runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest, toolchain: { kind: 'guest_toolchain',
        guestToolchainManifestRef: execution.guestToolchainManifestRef, guestToolchainManifestDigest: execution.guestToolchainManifestDigest,
        guestImageRef: guest.guestImageRef, guestImageDigest: guest.guestImageDigest } }, 'private rollback original runtime closure');
    for (const entry of [scriptEntry, ...members])
      for await (const _chunk of artifacts.readChunks(entry.digest, entry.byteCount)) { /* Complete original bytes; no current install. */ }
  }
  return { request, spec };
}

/** The common recovery graph independently verifies the whole quarantine,
 * native death, retirement and historical inspector graph before returning. */
export async function validatePrivateToolRollback(artifacts: ArtifactCatalog, input: {
  prepared: InvocationJournalEntry; claim: InvocationJournalEntry; unknown: InvocationJournalEntry; failed: InvocationJournalEntry;
  generations: WorkspaceGenerationStateV1[]; checkpoints: Checkpoint[];
}) {
  const { prepared, claim, unknown, failed } = input;
  const evidence = decodePrivateToolRollback(await readCanonicalArtifact<PrivateToolRollbackV1>(artifacts, failed.errorRef!));
  const generation = input.generations.find(row => row.generationRef === evidence.generationRef);
  const checkpoint = input.checkpoints.find(row => row.id === evidence.checkpointId);
  if (!generation || !checkpoint || generation.phase !== 'quarantined' || checkpoint.runId !== prepared.runId ||
      evidence.runId !== prepared.runId || evidence.opId !== prepared.opId || evidence.attempt !== prepared.attempt ||
      evidence.dispatchId !== claim.dispatchId || evidence.leaseEpoch !== claim.leaseEpoch ||
      evidence.preparedJournalSeq !== prepared.seq || evidence.claimJournalSeq !== claim.seq || evidence.unknownJournalSeq !== unknown.seq ||
      evidence.requestRef !== prepared.requestRef || evidence.targetRef !== prepared.target || evidence.grantRef !== prepared.grantRef ||
      evidence.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || evidence.generationIdentityDigest !== generation.generationIdentityDigest ||
      evidence.workspaceStateRef !== checkpoint.workspaceStateRef || failed.phase !== 'failed' ||
      failed.evidenceRef !== failed.errorRef || failed.evidenceDigest !== evidence.evidenceDigest ||
      failed.budgetSettlementRef !== unknown.budgetSettlementRef || evidence.observedAt < unknown.timestamp ||
      failed.timestamp < evidence.observedAt)
    throw new TypeError('private rollback substitutes its immutable original unknown, charge or last ready Checkpoint');
  const { request, spec } = await readPrivateRollbackClaim(artifacts, prepared, claim, unknown, generation);
  const quarantine = await readCanonicalArtifact<WorkspaceGenerationQuarantineEvidenceV1>(artifacts, evidence.quarantineEvidenceRef);
  const retirement = await readCanonicalArtifact<WorkspaceGenerationRetirementEvidenceV1>(artifacts, evidence.retirementEvidenceRef);
  if (spec.owner.workerLaunchId !== evidence.workerLaunchId || generation.quarantineEvidenceRef !== evidence.quarantineEvidenceRef ||
      quarantine.reason !== 'worker_recovery' || quarantine.evidenceDigest !== evidence.quarantineEvidenceDigest ||
      quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest') ||
      retirement.fromPhase !== 'quarantined' || retirement.quarantineEvidenceRef !== evidence.quarantineEvidenceRef ||
      retirement.evidenceDigest !== evidence.retirementEvidenceDigest || retirement.evidenceDigest !== digestOmitting(retirement, 'evidenceDigest') ||
      retirement.generationRef !== generation.generationRef || retirement.inspectorIdentityRef !== evidence.inspectorIdentityRef ||
      retirement.inspectorIdentityDigest !== evidence.inspectorIdentityDigest || retirement.observedAt > evidence.observedAt)
    throw new TypeError('private rollback lacks its original positive physical retirement graph');
  const recovery = await readCanonicalArtifact<WorkerRecoveryEvidenceV1>(artifacts, quarantine.workerRecoveryEvidenceRef);
  if (recovery.oldWorkerLaunchId !== evidence.workerLaunchId || recovery.oldLeaseEpoch !== evidence.leaseEpoch ||
      recovery.processContainmentRef !== spec.parentWorkerContainmentRef || recovery.workspaceGenerationRef !== generation.generationRef ||
      recovery.observedAt > retirement.observedAt || checkpoint.createdAt > unknown.timestamp)
    throw new TypeError('private rollback substitutes its original physical worker or preceding ready Checkpoint');
  return { evidence, request };
}

export async function validatePrivateToolRollbackHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  closure: RecoveryClosureV1): Promise<ReadonlySet<number>> {
  const verified = new Set<number>();
  for (const failed of closure.journal.filter(entry => entry.opKind === 'tool' && entry.phase === 'failed' &&
    ['manual', 'retry'].includes(entry.replayClass))) {
    const entries = closure.journal.filter(entry => entry.opId === failed.opId && entry.attempt === failed.attempt);
    const prepared = entries.find(entry => entry.phase === 'prepared'), claim = entries.find(entry => entry.phase === 'dispatch_claimed'),
      unknown = entries.find(entry => entry.phase === 'unknown');
    if (!prepared || !claim || !unknown) continue;
    const evidence = decodePrivateToolRollback(await readCanonicalArtifact<PrivateToolRollbackV1>(artifacts, failed.errorRef!));
    const generation = closure.workspaceGenerations.find(row => row.generationRef === evidence.generationRef);
    if (!generation || generation.phase !== 'retired') throw new TypeError('terminal private rollback has no physically retired original generation');
    const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, closure.runSpec.assemblyRef);
    const { source } = await readRetiredGenerationSource(driver, artifacts, { run: closure.run, spec: closure.runSpec, assembly, generation });
    await validatePrivateToolRollback(artifacts, { prepared, claim, unknown, failed, generations: [source],
      checkpoints: [readCheckpoint(driver, evidence.checkpointId)] });
    verified.add(failed.seq);
  }
  return verified;
}
