import { canonicalSha256 } from '../../kernel/canonical.js';
import { planArtifactBytes, planCanonicalArtifact, type PlannedArtifact } from '../../kernel/artifact-plan.js';
import { assertArtifactRef, digestOmitting, identityHash, modelOperationId as modelOpId, sha256Bytes } from '../../kernel/identity.js';
import type {
  Run, RunAssemblyV1, RunFrontier, ContextManifest, ContinuationItem, ToolContractManifestV1, RunContextCompactionPlan, ToolBatchItem
} from '../../kernel/types.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { mapArtifactReads } from '../bounded-artifact-reads.js';
import type { ModelAttemptResult } from '../../model/model-session.js';
import type { ModelUnusableResponseV1 } from '../../protocol/agent-ir.js';
import { loadToolContracts } from '../../tools/input-contract.js';
import { validateRunAssembly, type RunAssemblyValidationMaterial } from '../../model/run-assembly.js';
import { estimatePromptTokens, projectModelVisiblePrompt, type ModelRequestV1, type NormalPromptProjectionV1 } from '../../model/request.js';
import { planModelContinuation, validateModelTurn, validateUnusableModelResponse, type ModelContinuationPlan } from '../../runtime/continuation.js';
import { assertSameModelOperation, modelRetryState, type ModelRetryState } from '../../runtime/model-retry.js';
import { contextSourceDigest, planContextCompaction, replaceCompactedPrefix, validateContextItems, type ContextItem } from '../../runtime/context-compaction.js';
import { loadInstructionText, projectNormalContext, readCanonicalArtifact, readModelContext, readModelTurnMaterial } from '../agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from '../artifacts.js';
import { decodeContextManifest, decodeRunSpec } from '../decoders.js';
import { KernelStorageError, ModelRetryPendingError, stateOperation } from '../errors.js';
import { sampleCanonicalNow } from '../canonical-time.js';
import { readHighestPreparedAttempt, readInvocationAttempt, readOperationJournal } from '../repositories/journal.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { readCheckpoint, readRun, ZERO_BUDGET } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import type { StateOwnerContext } from '../state-owner.js';
import { prepareValidatedInvocation, readModelRetryHistory, settleValidatedInvocation, type SettleInvocationInput } from './invocation.js';
import { loadToolContinuation } from './tool.js';
import { readToolCut } from '../tool-cut.js';
import type { ReleaseTrustKey } from '../../policy/runtime-authority.js';

export type LoadAgentRunInput = {
  runId: string;
  material: RunAssemblyValidationMaterial;
  /**
   * Trusted Supervisor release roots, never worker/Run/repository-controlled. Required for tool authority
   * and to load any Run with retained policy decisions, even for read-only tool projections;
   * omission in that case fails with RECOVERY_REQUIRED because those decisions must be replayed.
   */
  releaseKeys?: readonly ReleaseTrustKey[];
};
export type AgentRunState = Awaited<ReturnType<typeof loadAgentRun>>;

async function publishPlans(artifacts: ArtifactCatalog, plans: readonly PlannedArtifact[]): Promise<PublishedArtifact[]> {
  return Promise.all(plans.map(async (plan) => {
    const bytes = plan.bytes;
    if (sha256Bytes(bytes) !== plan.ref) throw new TypeError('planned artifact bytes do not rehash');
    return artifacts.publishBytes(bytes, plan.mediaType, plan.schemaKind);
  }));
}

const agentCut = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, revision: number) => {
  const run = readRun(driver, runId);
  if (run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'agent Run revision changed');
  if (!run.frontierRef || run.nextStep !== 'agent') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run is not at an agent frontier');
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  if (frontier.kind !== 'agent' || !['model_turn', 'context_compaction'].includes(frontier.phase) ||
      (frontier.phase === 'context_compaction') !== (frontier.compactionPlanRef !== undefined)) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model attempt requires an exact agent frontier');
  }
  const highest = readHighestPreparedAttempt(driver, runId, modelOpId(runId, frontier));
  const last = highest && readInvocationAttempt(driver, runId, highest.opId, highest.attempt).at(-1);
  if (last?.phase === 'completed') {
    const root = await readCanonicalArtifact<{ format: string; stopReason?: string }>(artifacts, last.resultRef!);
    throw new AgentHandoffPendingError(frontier.phase === 'model_turn' && root.format === 'cliq-agent-model-turn-v1' && root.stopReason === 'end'
      ? 'candidate_required' : 'stop_required', last.resultRef!);
  }
  const checkpoint = readCheckpoint(driver, run.latestCheckpointId);
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const latestItem = Number(driver.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?')
    .get<{ seq: unknown }>(runId)?.seq);
  if (checkpoint.runId !== runId || context.throughItemSeq !== checkpoint.runItemSeq || latestItem !== checkpoint.runItemSeq ||
      frontier.contextItemSeq !== context.throughItemSeq) throw new TypeError('agent frontier is not at the current ready context checkpoint');
  const items = await readContextItems(driver, artifacts, runId, context.throughItemSeq);
  validateContextItems(context, items);
  return { run, frontier, checkpoint, context, items };
});

async function readContextItems(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, through: number): Promise<ContextItem[]> {
  const rows = driver.prepare('SELECT item_seq, item_id, kind, payload_ref FROM items WHERE run_id = ? AND item_seq <= ? ORDER BY item_seq')
    .all<{ item_seq: unknown; item_id: string; kind: string; payload_ref: string }>(runId, BigInt(through));
  return mapArtifactReads(rows, async (row) => {
    const item = await readCanonicalArtifact<ContinuationItem>(artifacts, row.payload_ref);
    if (item.itemId !== row.item_id || item.kind !== row.kind) throw new TypeError('context item does not match its owner row');
    return { itemSeq: Number(row.item_seq), itemRef: row.payload_ref, item };
  });
}

export class AgentContextExhaustedError extends KernelStorageError {
  constructor(readonly evidenceRef: string, readonly evidence: Extract<ReturnType<typeof planContextCompaction>, { kind: 'exhausted' }>['evidence']) {
    super('STATE_TRANSITION_INVALID', 'context_window_exhausted: no safe whole-prefix compaction is possible');
  }
}

export class AgentHandoffPendingError extends KernelStorageError {
  constructor(readonly disposition: 'candidate_required' | 'stop_required', readonly evidenceRef: string,
    readonly reason?: 'model_retry_exhausted') {
    super('AGENT_HANDOFF_PENDING', `${reason ?? 'completed model observation'} requires ${disposition}`);
  }
}

function requireRetryReady(retry: ModelRetryState): number {
  if (retry.kind === 'backoff') throw new ModelRetryPendingError(retry.nextAttempt, retry.notBefore);
  if (retry.kind === 'exhausted') throw new AgentHandoffPendingError('stop_required', retry.evidenceRef, 'model_retry_exhausted');
  if (retry.kind !== 'ready') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'current model attempt must settle before replacement');
  return retry.nextAttempt;
}

function appendItems(connection: SqliteConnection, run: Run, items: ContinuationItem[], refs: string[], throughItemSeq: number): void {
  items.forEach((item, index) => connection.prepare(
    'INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, NULL, ?, ?, ?, ?, ?)'
  ).run(item.itemId, run.id, BigInt(throughItemSeq + index + 1), item.kind, refs[index]!, item.createdAt));
}

/** A loaded authority handle only: every mutable Run/frontier/Journal value is read from SQLite on each operation. */
export const loadAgentRun = stateOperation('RECOVERY_REQUIRED', async function loadAgentRun(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: LoadAgentRunInput
) {
  const runId = input.runId;
  const releaseKeys = input.releaseKeys === undefined ? undefined : immutableSnapshot(input.releaseKeys);
  const material = Object.fromEntries(Object.entries(input.material).map(([key, value]) =>
    [key, typeof value === 'function' ? value : immutableSnapshot(value)])) as RunAssemblyValidationMaterial;
  const recovered = await readRecoveryClosure(driver, artifacts, runId);
  const admittedRun = recovered.run;
  const spec = immutableSnapshot(decodeRunSpec(await readCanonicalArtifact(artifacts, admittedRun.specRef)));
  if (spec.operation !== 'agent') throw new TypeError('delivery Runs cannot load a model');
  const assembly = immutableSnapshot(await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef));
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
  const exactKeys = (value: object, keys: string[]) => Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-tool-contracts-v1' ||
      !exactKeys(manifest, ['schemaVersion', 'format', 'entries', 'manifestDigest']) ||
      manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
      new Set(manifest.entries.map((entry) => entry.name)).size !== manifest.entries.length) {
    throw new TypeError('Run tool manifest does not match its retained assembly');
  }
  const contracts = immutableSnapshot(await mapArtifactReads(manifest.entries, async (entry) => {
    const output = entry.outputSchemaRef !== undefined;
    if (!exactKeys(entry, ['name', 'version', 'description', 'access', 'inputSchemaRef', 'inputSchemaDigest', 'replayClass', 'execution',
      ...(output ? ['outputSchemaRef', 'outputSchemaDigest'] : [])]) || typeof entry.version !== 'string' || !entry.version ||
        !['read', 'write', 'exec', 'plan', 'control'].includes(entry.access)) throw new TypeError('invalid frozen tool contract schema');
    const execution = entry.execution;
    if (execution.kind === 'builtin') {
      if (!exactKeys(execution, ['kind', 'adapterId', 'adapterVersion', 'adapterCodeDigest']) ||
          !['manual', 'retry'].includes(entry.replayClass) || typeof execution.adapterId !== 'string' || !execution.adapterId ||
          typeof execution.adapterVersion !== 'string' || !execution.adapterVersion) throw new TypeError('invalid builtin execution contract');
      assertArtifactRef(execution.adapterCodeDigest);
    } else if (execution.kind === 'mcp') {
      if (!exactKeys(execution, ['kind', 'registrationId', 'registryRevisionRef', 'registryManifestDigest', 'serverToolName', 'toolContractDigest']) ||
          typeof execution.serverToolName !== 'string' || !execution.serverToolName || !assembly.mcpServers.some((server) =>
            server.registrationId === execution.registrationId && server.registryRevisionRef === execution.registryRevisionRef &&
            server.manifestDigest === execution.registryManifestDigest)) throw new TypeError('tool contract differs from the frozen MCP registration');
      assertArtifactRef(execution.toolContractDigest);
    } else throw new TypeError('unknown tool execution contract');
    const schema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
    if (canonicalSha256(schema) !== entry.inputSchemaDigest) throw new TypeError('tool input schema digest mismatch');
    if (output && canonicalSha256(await readCanonicalArtifact(artifacts, entry.outputSchemaRef!)) !== entry.outputSchemaDigest) {
      throw new TypeError('tool output schema digest mismatch');
    }
    return { ...entry, inputSchema: schema };
  }));
  const tools = contracts.map((entry) => ({ name: entry.name, description: entry.description, inputSchemaRef: entry.inputSchemaRef,
    inputSchemaDigest: entry.inputSchemaDigest, inputSchema: entry.inputSchema, replayClass: entry.replayClass }));
  const validated = validateRunAssembly({ assemblyRef: spec.assemblyRef, assembly, admittedAt: admittedRun.createdAt,
    deadlineAt: admittedRun.deadlineAt, maxRunCostMicros: spec.budgets.costMicros, runSpecCredentialGrantRefs: spec.credentialGrantRefs,
    material: { ...material, resolveVerifiedTools: (reference) => {
      const verified = material.resolveVerifiedTools(reference);
      return verified !== null && canonicalSha256(verified) === canonicalSha256(tools) ? tools : null;
    } } });
  if (!validated.ok) throw new TypeError(`${validated.code}: ${validated.reason}`);
  const { model } = validated;
  const systemInstruction = await loadInstructionText(artifacts, assembly);
  const toolContracts = loadToolContracts(contracts);
  const { resolveToolInput } = toolContracts;
  const project = (run: Run, context: ContextManifest, contextRef: string) => projectNormalContext({
    artifacts, run, spec, assembly, context, contextRef, systemInstruction, tools
  });
  const compactionSource = stateOperation('RECOVERY_REQUIRED', async (run: Run, planRef: string) => {
    const plan = await readCanonicalArtifact<RunContextCompactionPlan>(artifacts, planRef);
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, plan.sourceContextManifestRef));
    const items = await readContextItems(driver, artifacts, runId, context.throughItemSeq);
    const projection = await readModelContext({ artifacts, run, spec, assembly, context, systemInstruction, tools });
    const reproduced = planContextCompaction({ context, contextRef: plan.sourceContextManifestRef, items, projection,
      policy: assembly.context, createdAt: plan.createdAt });
    if (reproduced.kind !== 'compact' || canonicalSha256(reproduced.plan) !== planRef) {
      throw new TypeError('compaction plan cannot be reproduced from retained context and frozen policy');
    }
    return reproduced;
  });
  const reproduceRequest = stateOperation('RECOVERY_REQUIRED', async (run: Run, request: ModelRequestV1) => {
    if (run.specRef !== admittedRun.specRef || run.deadlineAt !== admittedRun.deadlineAt || run.createdAt !== admittedRun.createdAt) {
      throw new TypeError('loaded model authority no longer belongs to this Run');
    }
    const invocation = { runId, opId: request.opId, attempt: request.attempt };
    if (request.kind === 'context_compaction') {
      if (!request.compactionPlanRef) throw new TypeError('compaction request requires a retained plan');
      const source = await compactionSource(run, request.compactionPlanRef);
      return model.prepare({ kind: 'context_compaction', invocation, compactionPlanRef: request.compactionPlanRef,
        sourceContextUtf8: source.sourceContextUtf8 });
    }
    const projection = await readCanonicalArtifact<NormalPromptProjectionV1>(artifacts, request.promptProjectionRef);
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, projection.contextManifestRef));
    validateContextItems(context, await readContextItems(driver, artifacts, runId, context.throughItemSeq));
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, projection.frontierDigest);
    if (frontier.kind !== 'agent' || frontier.phase !== 'model_turn' || frontier.contextItemSeq !== context.throughItemSeq ||
        request.opId !== modelOpId(runId, frontier)) throw new TypeError('retained projection differs from its model frontier');
    const reproduced = await project({ ...run, revision: projection.basedOnRunRevision, frontierRef: projection.frontierDigest },
      context, projection.contextManifestRef);
    if (canonicalSha256(reproduced) !== request.promptProjectionRef) throw new TypeError('retained projection differs from its durable sources');
    return model.prepare({ kind: 'normal', invocation, projectionRef: request.promptProjectionRef, projection });
  });
  for (const entry of recovered.journal.filter((entry) => entry.opKind === 'model' && entry.phase === 'prepared')) {
    const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, entry.requestRef);
    const reproduced = await reproduceRequest(admittedRun, request);
    if (reproduced.requestRef !== entry.requestRef) throw new TypeError('retained native request cannot be reproduced');
    const completed = recovered.journal.find((result) => result.opId === entry.opId && result.attempt === entry.attempt && result.phase === 'completed');
    if (completed?.resultRef) {
      const root = await readCanonicalArtifact<{ format: string }>(artifacts, completed.resultRef);
      if (root.format === 'cliq-agent-model-turn-v1') {
        const material = await readModelTurnMaterial(artifacts, completed.resultRef);
        validateModelTurn(request, material, resolveToolInput);
        if (request.kind === 'normal') {
          const modelItemId = identityHash('cliq-model-turn-item-v1', runId, entry.opId, String(entry.attempt));
          const row = recovered.items.find((row) => row.itemId === modelItemId);
          if (!row) throw new TypeError('completed model turn has no durable continuation item');
          const plan = planModelContinuation({ request, turnRef: completed.resultRef, material, throughItemSeq: row.itemSeq - 1,
            createdAt: completed.timestamp, resolveToolInput });
          for (const [index, item] of plan.items.entries()) {
            if (recovered.items[row.itemSeq - 1 + index]?.payloadRef !== canonicalSha256(item)) {
              throw new TypeError('durable model continuation differs from its normalized response');
            }
          }
        }
      }
    }
  }

  const toolContinuation = await loadToolContinuation(driver, artifacts, owner, {
    run: admittedRun, spec, assembly, contracts, resolveToolInput, releaseKeys
  });
  return Object.freeze({
    ...toolContinuation,
    model,
    resolveToolInput,
    /** Read the current durable call. This projection is neither a grant nor permission to dispatch it. */
    readToolInvocation: stateOperation('RECOVERY_REQUIRED', async () => {
      const selected = await readToolCut(driver, artifacts, runId, resolveToolInput);
      if (selected.run.specRef !== admittedRun.specRef || selected.run.deadlineAt !== admittedRun.deadlineAt ||
          selected.run.createdAt !== admittedRun.createdAt) throw new TypeError('loaded tool authority no longer belongs to this Run');
      const input = selected.call;
      return immutableSnapshot({ run: selected.run, frontier: selected.frontier, batchItemId: selected.batch.itemId,
        ...toolContracts.projectInvocation({ callId: input.callId, index: input.index, toolName: input.toolName, input: input.value! }) });
    }),
    /** Rehydrate the exact durable attempt; a dispatch_claimed/settled entry is never permission to resend it. */
    readModelAttempt: stateOperation('RECOVERY_REQUIRED', async () => {
      const closure = await readRecoveryClosure(driver, artifacts, runId);
      if (!closure.run.frontierRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal Run has no model frontier');
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, closure.run.frontierRef!);
      if (frontier.kind !== 'agent') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run is not at a model frontier');
      const opId = modelOpId(runId, frontier);
      const entry = closure.journal.filter((entry) => entry.opId === opId && entry.phase === 'prepared').at(-1);
      if (!entry) return undefined;
      const state = closure.journal.filter((next) => next.opId === opId && next.attempt === entry.attempt).at(-1)!;
      const retry = modelRetryState(assembly.retry.model, closure.journal.filter((next) => next.opId === opId), sampleCanonicalNow());
      const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, entry.requestRef);
      const prepared = await reproduceRequest(closure.run, request);
      if (prepared.requestRef !== entry.requestRef) throw new TypeError('retained model request cannot be reproduced');
      let disposition: 'candidate_required' | 'stop_required' | undefined;
      if (state.phase === 'completed') {
        const root = await readCanonicalArtifact<{ format: string; stopReason?: string }>(artifacts, state.resultRef!);
        disposition = request.kind === 'normal' && root.format === 'cliq-agent-model-turn-v1' && root.stopReason === 'end'
          ? 'candidate_required' : 'stop_required';
      }
      if (retry.kind === 'exhausted') disposition = 'stop_required';
      return { run: closure.run, entry, state, prepared, disposition, retry: immutableSnapshot(retry) };
    }),
    prepareModel: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; leaseEpoch: number }) => {
      const { expectedRunRevision, leaseEpoch } = input;
      const cut = await agentCut(driver, artifacts, runId, expectedRunRevision);
      if (cut.run.specRef !== admittedRun.specRef || cut.run.deadlineAt !== admittedRun.deadlineAt || cut.run.createdAt !== admittedRun.createdAt) {
        throw new TypeError('loaded model authority no longer belongs to this Run');
      }
      const projection = await project(cut.run, cut.context, cut.checkpoint.contextManifestRef);
      const selection = cut.frontier.phase === 'context_compaction' ? await compactionSource(cut.run, cut.frontier.compactionPlanRef!)
        : planContextCompaction({ context: cut.context, contextRef: cut.checkpoint.contextManifestRef, items: cut.items,
          projection, policy: assembly.context, createdAt: sampleCanonicalNow() });
      if (selection.kind === 'exhausted') {
        const evidence = planCanonicalArtifact(selection.evidence, selection.evidence.format);
        await publishPlans(artifacts, [evidence]);
        throw new AgentContextExhaustedError(evidence.ref, immutableSnapshot(selection.evidence));
      }
      const compaction = selection.kind === 'compact' ? selection : undefined;
      const planArtifact = compaction ? planCanonicalArtifact(compaction.plan, 'cliq-run-context-compaction-plan-v1') : undefined;
      if (compaction && compaction.plan.sourceContextManifestRef !== cut.checkpoint.contextManifestRef) {
        throw new TypeError('compaction frontier no longer matches its source checkpoint');
      }
      const frontier: Extract<RunFrontier, { kind: 'agent' }> = planArtifact
        ? { ...cut.frontier, phase: 'context_compaction', compactionPlanRef: planArtifact.ref } : cut.frontier;
      const frontierPlan = planCanonicalArtifact(frontier, 'cliq-run-frontier-v1');
      const opId = modelOpId(runId, frontier);
      const history = await readModelRetryHistory(driver, artifacts, runId, opId);
      const attempt = requireRetryReady(modelRetryState(assembly.retry.model, history, sampleCanonicalNow()));
      const projectionArtifact = planCanonicalArtifact(projection, projection.format);
      const prepared = compaction ? model.prepare({ kind: 'context_compaction', invocation: { runId, opId, attempt },
        compactionPlanRef: planArtifact!.ref, sourceContextUtf8: compaction.sourceContextUtf8 })
        : model.prepare({ kind: 'normal', invocation: { runId, opId, attempt }, projectionRef: projectionArtifact.ref, projection });
      if (history.length) assertSameModelOperation(await readCanonicalArtifact<ModelRequestV1>(artifacts, history[0]!.requestRef), prepared.request);
      const metadata = await publishPlans(artifacts, [projectionArtifact, frontierPlan, ...(planArtifact ? [planArtifact] : []), ...prepared.artifacts]);
      const admitted = await prepareValidatedInvocation(driver, artifacts, owner, {
        runId, expectedRunRevision, leaseEpoch, opId, opKind: 'model',
        target: assembly.provider.model, requestRef: prepared.requestRef, replayClass: 'retry',
        reservation: { modelTokens: prepared.request.reservation.modelTokens, costMicros: prepared.request.reservation.costMicros,
          toolCalls: 0, repairAttempts: 0 }
      }, { metadata, validate: (connection, run, actualAttempt) => {
        if (actualAttempt !== attempt || run.frontierRef !== cut.run.frontierRef || run.latestCheckpointId !== cut.run.latestCheckpointId) {
          throw new KernelStorageError('REVISION_CONFLICT', 'model request no longer matches its state cut');
        }
        if (requireRetryReady(modelRetryState(assembly.retry.model, readOperationJournal(connection, runId, opId), sampleCanonicalNow())) !== attempt) {
          throw new KernelStorageError('REVISION_CONFLICT', 'model retry history changed before reservation');
        }
      }, commit(connection) {
        connection.prepare('UPDATE runs SET frontier_ref = ? WHERE id = ?').run(frontierPlan.ref, runId);
      } });
      return { ...admitted, prepared, projection };
    }),
    completeModel: stateOperation('INVALID_REQUEST', async (input: Omit<SettleInvocationInput, 'runId'> & { result: ModelAttemptResult }) => {
      // Snapshot before the first await; planned byte getters cannot swap data during CAS publication.
      const { opId, attempt, expectedRunRevision } = input;
      const plans = input.result.artifacts.map((plan) => planArtifactBytes(plan.bytes, plan.mediaType, plan.schemaKind));
      const result = input.result.kind === 'usable'
        ? { kind: 'usable' as const, ref: input.result.turnRef }
        : { kind: 'unusable' as const, ref: input.result.responseRef };
      const entries = readInvocationAttempt(driver, runId, opId, attempt);
      const prepared = entries.find((entry) => entry.phase === 'prepared');
      if (prepared?.opKind !== 'model') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model completion has no matching prepared Journal entry');
      const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
      const cut = await agentCut(driver, artifacts, runId, expectedRunRevision);
      if (request.kind !== (cut.frontier.phase === 'model_turn' ? 'normal' : 'context_compaction') ||
          request.compactionPlanRef !== cut.frontier.compactionPlanRef || request.runId !== runId || request.opId !== opId || request.attempt !== attempt ||
          opId !== modelOpId(runId, cut.frontier) || readHighestPreparedAttempt(driver, runId, opId)?.attempt !== attempt) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model completion does not match the current frontier or highest attempt');
      }
      const replayed = await reproduceRequest(cut.run, request);
      if (replayed.requestRef !== prepared.requestRef || canonicalSha256(prepared.budgetDelta) !== canonicalSha256({
        modelTokens: request.reservation.modelTokens, costMicros: request.reservation.costMicros, toolCalls: 0, repairAttempts: 0
      })) throw new KernelStorageError('RECOVERY_REQUIRED', 'retained request or reservation cannot be reproduced from its loaded authority');
      await publishPlans(artifacts, plans);
      const material = result.kind === 'usable' ? await readModelTurnMaterial(artifacts, result.ref) : undefined;
      const resultMetadata: PublishedArtifact[] = [];
      if (material === undefined) {
        const unusable = await readCanonicalArtifact<ModelUnusableResponseV1>(artifacts, result.ref);
        validateUnusableModelResponse(request, prepared.requestRef, unusable);
        const bytes = await artifacts.readBytes(unusable.observedResponse.bytesRef);
        if (bytes.byteLength !== unusable.observedResponse.byteCount) throw new TypeError('unusable observation byte count mismatch');
        resultMetadata.push(await artifacts.describe(result.ref, 'application/json', unusable.format),
          await artifacts.describe(unusable.observedResponse.bytesRef, 'application/octet-stream', 'cliq-observed-model-response-bytes-v1'));
      } else {
        resultMetadata.push(await artifacts.describe(result.ref, 'application/json', material.turn.format),
          await artifacts.describe(material.turn.textRef, 'application/json', material.text.format));
        for (const [index, input] of material.inputs.entries()) {
          resultMetadata.push(await artifacts.describe(material.turn.toolCalls[index]!.inputRef, 'application/json', input.value.format),
            await artifacts.describe(input.value.observedInputRef, 'application/json', input.observed.format));
          if (input.value.diagnosticRef) {
            const diagnostic = await readCanonicalArtifact<{ format: string; diagnosticDigest: string }>(artifacts, input.value.diagnosticRef);
            if (diagnostic.format !== 'cliq-tool-input-diagnostic-v1' || diagnostic.diagnosticDigest !== input.value.diagnosticDigest ||
                digestOmitting(diagnostic, 'diagnosticDigest') !== diagnostic.diagnosticDigest) throw new TypeError('tool diagnostic does not rehash');
            resultMetadata.push(await artifacts.describe(input.value.diagnosticRef, 'application/json', diagnostic.format));
          }
        }
      }
      if (material?.turn.stopReason === 'cancelled' && material.turn.abortStopIntentRef !== cut.run.stopIntentRef) {
        throw new TypeError('cancelled model turn does not match a persisted StopIntent');
      }
      const compaction = request.kind === 'context_compaction' ? await compactionSource(cut.run, request.compactionPlanRef!) : undefined;
      if (compaction && compaction.plan.sourceContextManifestRef !== cut.checkpoint.contextManifestRef) {
        throw new TypeError('compaction completion no longer matches its source checkpoint');
      }
      let disposition!: ModelContinuationPlan['disposition'];
      const settled = await settleValidatedInvocation(driver, artifacts, owner, { opId, attempt, expectedRunRevision, runId }, {
        phase: 'completed', resultRef: result.ref, consumed: ZERO_BUDGET
      }, async ({ run, settlement }) => {
        if (run.frontierRef !== cut.run.frontierRef || run.latestCheckpointId !== cut.run.latestCheckpointId) {
          throw new KernelStorageError('REVISION_CONFLICT', 'model continuation state changed');
        }
        let plan: ModelContinuationPlan;
        if (material === undefined) plan = { items: [], artifacts: [], disposition: 'stop_required' };
        else if (compaction) {
          validateModelTurn(request, material, resolveToolInput);
          const { compactionPlanRef: _, ...normalFrontier } = cut.frontier;
          plan = { artifacts: [], disposition: 'context_compacted', items: [{ schemaVersion: 1, kind: 'context_compaction',
            itemId: identityHash('cliq-run-compaction-item-v1', runId, opId, String(attempt)), runId,
            planRef: request.compactionPlanRef!, modelOpId: opId, modelAttempt: attempt,
            summaryRef: material.turn.textRef, summaryDigest: material.text.textDigest,
            coveredFromItemSeq: 1, coveredThroughItemSeq: compaction.plan.compactThroughItemSeq,
            sourceItemsDigest: compaction.plan.sourceItemsDigest, createdAt: settlement.settledAt }],
            frontier: { ...normalFrontier, phase: 'model_turn', contextItemSeq: cut.context.throughItemSeq + 1 } };
        } else plan = planModelContinuation({ request, turnRef: result.ref, material,
          throughItemSeq: cut.context.throughItemSeq, createdAt: settlement.settledAt, resolveToolInput });
        let itemPlans = plan.items.map((item) => planCanonicalArtifact(item, `cliq-${item.kind.replaceAll('_', '-')}-item-v1`));
        let context = compaction && material
          ? replaceCompactedPrefix(cut.context, compaction.plan, { itemId: plan.items[0]!.itemId,
              summaryRef: material.turn.textRef, summaryDigest: material.text.textDigest })
          : structuredClone(cut.context);
        plan.items.forEach((item, index) => {
          const seq = cut.context.throughItemSeq + index + 1;
          context.segments.push(item.kind === 'model_turn' || item.kind === 'tool_result'
            ? { kind: 'raw', fromItemSeq: seq, throughItemSeq: seq, items: [{ itemSeq: seq, itemRef: itemPlans[index]!.ref }] }
            : { kind: 'excluded_control', fromItemSeq: seq, throughItemSeq: seq,
                sourceItemsDigest: contextSourceDigest([{ itemSeq: seq, itemRef: itemPlans[index]!.ref, item }]) });
        });
        context.throughItemSeq += plan.items.length;
        context.projectionDigest = digestOmitting(context, 'projectionDigest');
        let contextPlan = planCanonicalArtifact(context, context.format);
        validateContextItems(context, [...cut.items, ...plan.items.map((item, index) => ({
          item, itemSeq: cut.context.throughItemSeq + index + 1, itemRef: itemPlans[index]!.ref
        }))]);
        if (compaction && material) {
          const before = await project(run, cut.context, cut.checkpoint.contextManifestRef);
          const after = await project(run, context, contextPlan.ref);
          if (estimatePromptTokens(projectModelVisiblePrompt(after, assembly.provider.negotiation.mode)) >=
              estimatePromptTokens(projectModelVisiblePrompt(before, assembly.provider.negotiation.mode))) {
            // A shape-valid but ineffective summary is still an executed, fully charged response.
            // Leave the old context intact and hand the completed attempt to the stop reducer.
            plan = { items: [], artifacts: [], disposition: 'stop_required' };
            itemPlans = [];
            context = structuredClone(cut.context);
            contextPlan = planCanonicalArtifact(context, context.format);
          }
        }
        disposition = plan.disposition;
        const frontierPlan = plan.frontier === undefined ? undefined : planCanonicalArtifact(plan.frontier, 'cliq-run-frontier-v1');
        const metadata = await publishPlans(artifacts, [...itemPlans, ...plan.artifacts, contextPlan, ...(frontierPlan ? [frontierPlan] : [])]);
        const checkpointId = identityHash('cliq-continuation-checkpoint-v1', runId, result.ref, contextPlan.ref);
        return { metadata: [...resultMetadata, ...metadata], commit(connection, currentRun, entry) {
          appendItems(connection, currentRun, plan.items, itemPlans.map((item) => item.ref), cut.context.throughItemSeq);
          connection.prepare(`INSERT INTO checkpoints (id, schema_version, run_id, based_on_run_revision, run_item_seq,
            context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'auto')`)
            .run(checkpointId, runId, BigInt(currentRun.revision), BigInt(context.throughItemSeq), contextPlan.ref,
              BigInt(entry.seq), cut.checkpoint.workspaceStateRef, settlement.settledAt);
          connection.prepare('UPDATE runs SET latest_checkpoint_id = ?, frontier_ref = ?, next_step = ? WHERE id = ?')
            .run(checkpointId, frontierPlan?.ref ?? currentRun.frontierRef!, plan.frontier?.kind ?? currentRun.nextStep, runId);
        } };
      });
      return { ...settled, disposition, ...(disposition === 'stop_required' && compaction ? {
        failure: { kind: 'context_compaction_failed' as const, compactionPlanRef: request.compactionPlanRef!, modelOpId: opId,
          attempt, evidenceRef: result.ref }
      } : {}) };
    })
  });
});
