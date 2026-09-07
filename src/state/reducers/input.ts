import { canonicalSha256 } from '../../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../../kernel/identity.js';
import type { ContinuationItem, ControlApplicationResponseV1, ControlResultV1, Run, RunAssemblyV1, RunFrontier, RunSpec } from '../../kernel/types.js';
import type { InputWait, RunInput, UserInputItem } from '../../kernel/user-input.js';
import type { ToolCheckpointProof } from '../../kernel/tool-authorization.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ResolveToolInput } from '../../model/attempt.js';
import { exactKeys, requireEqual } from '../../policy/runtime-authority.js';
import { inputRequestDigest, planInputReply, planInputWait } from '../../runtime/user-input.js';
import type { ToolInputAuthority } from '../../tools/input-contract.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from '../artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { readRetainedControlChannelClosure, validateControlChannelClosure } from '../control-channel.js';
import { prepareContinuationCommit } from '../continuation-commit.js';
import { KernelStorageError, stateOperation } from '../errors.js';
import { validateUserInputRecovery } from '../input-recovery.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { nextJournalSequence } from '../repositories/journal.js';
import { insertControlRequest, readCheckpoint, readControlRequest, readRun } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { prepareToolCheckpoint } from '../tool-checkpoint.js';
import { readToolCut, type ToolCut } from '../tool-cut.js';
import { appendRunStateEvent, requireHealthyFence } from './invocation.js';

type Response = Extract<ControlApplicationResponseV1, { ok: true }> & { result: Extract<ControlResultV1, { method: 'run.input' }> };

/** Internal to the loaded Run; no mutable Run, prompt or reply is cached between calls. */
export async function loadInputContinuation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, authority: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; principalId: string; resolveToolInput: ResolveToolInput;
  contracts: readonly ToolInputAuthority[];
  assertAuthority: () => Promise<void>;
}) {
  const { run: admitted, spec, assembly, principalId, resolveToolInput } = authority;
  const runId = admitted.id;
  const contract = authority.contracts.find((entry) => entry.name === 'request_input' && entry.access === 'control' && entry.execution.kind === 'builtin');
  const assertInputCall = (selected: ToolCut) => {
    if (!contract || selected.call.toolName !== contract.name || selected.call.inputSchemaRef !== contract.inputSchemaRef ||
        selected.call.inputSchemaDigest !== contract.inputSchemaDigest) throw new TypeError('current call is not the frozen builtin request_input');
  };
  const cut = async (revision?: number) => {
    const selected = await readToolCut(driver, artifacts, runId, resolveToolInput);
    if (selected.run.specRef !== admitted.specRef || selected.run.deadlineAt !== admitted.deadlineAt || selected.run.createdAt !== admitted.createdAt) throw new TypeError('input authority no longer belongs to this Run');
    if (revision !== undefined && selected.run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'input Run revision changed');
    return selected;
  };
  const recover = async () => {
    // The public closure also works after the tool batch has advanced to an agent frontier.
    const closure = await readRecoveryClosure(driver, artifacts, runId);
    const items = new Map(await Promise.all(closure.items.map(async (row) => [row.itemId,
      await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef)] as const)));
    const checkpoints = driver.prepare('SELECT id FROM checkpoints WHERE run_id = ? ORDER BY based_on_run_revision, created_at, id')
      .all<{ id: string }>(runId).map(({ id }) => readCheckpoint(driver, id));
    return validateUserInputRecovery({ artifacts, run: closure.run, spec, items, journal: closure.journal, checkpoints });
  };
  async function verifyReply(itemRef: string, recovered?: Awaited<ReturnType<typeof recover>>) {
    recovered ??= await recover();
    const value = recovered.find(({ reply }) => reply?.itemRef === itemRef);
    if (!value?.reply) throw new TypeError('input response has no committed input owner');
    const { reply, proof } = value;
    const command = reply.command;
    if (command.principalId !== principalId) throw new TypeError('input reply principal does not own this Run');
    const row = driver.prepare("SELECT request_digest, channel_identity_ref, channel_identity_digest, response_ref, committed_at FROM control_requests WHERE principal_id = ? AND method = 'run.input' AND request_id = ?")
      .get<{ request_digest: string; channel_identity_ref: string; channel_identity_digest: string; response_ref: string; committed_at: string }>(principalId, command.requestId);
    if (!row || row.request_digest !== reply.payload.requestDigest || row.channel_identity_ref !== command.channelIdentityRef ||
        row.channel_identity_digest !== command.channelIdentityDigest || row.committed_at !== reply.item.createdAt) throw new TypeError('input reply has no exact authenticated control-row owner');
    await readRetainedControlChannelClosure(artifacts, owner, command);
    const response = await readCanonicalArtifact<Response>(artifacts, row.response_ref);
    const snapshot = response.result.snapshot;
    if (response.protocolVersion !== 1 || response.ok !== true || response.result.method !== 'run.input' || response.result.inputItemRef !== itemRef ||
        snapshot.schemaVersion !== 1 || snapshot.operation !== 'agent' || snapshot.latestRunItemSeq !== reply.checkpoint.runItemSeq ||
        snapshot.run.id !== runId || snapshot.run.sessionId !== admitted.sessionId || snapshot.run.specRef !== admitted.specRef ||
        snapshot.run.latestCheckpointId !== reply.checkpointId || snapshot.run.updatedAt !== reply.item.createdAt ||
        snapshot.run.revision !== command.expectedRunRevision + 1 || snapshot.run.status !== 'queued' || snapshot.run.waitingOnRef !== undefined ||
        snapshot.run.activeWorkerLaunchId !== undefined) throw new TypeError('input response substitutes its committed snapshot');
    const frontier = await readCanonicalArtifact<Extract<RunFrontier, { kind: 'tool' }>>(artifacts, proof.wait.frontierRef);
    if (snapshot.run.frontierRef !== canonicalSha256(nextFrontier(frontier, reply.item, snapshot.latestRunItemSeq))) throw new TypeError('input response substitutes its continuation');
    return response;
  }
  function nextFrontier(frontier: Extract<RunFrontier, { kind: 'tool' }>, item: UserInputItem, itemSeq: number): RunFrontier {
    return frontier.nextCallIndex + 1 < frontier.orderedCallIds.length ? { ...frontier, nextCallIndex: frontier.nextCallIndex + 1 }
      : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', runId, item.batchItemId),
          contextItemSeq: itemSeq, cause: 'input' };
  }
  function assertCut(connection: SqliteConnection, selected: ToolCut, now: string) {
    assertActiveStateOwner(connection, owner);
    const run = readRun(connection, runId);
    const seq = Number(connection.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?').get<{ seq: unknown }>(runId)?.seq);
    if (run.revision !== selected.run.revision || run.status !== selected.run.status || run.waitingOnRef !== selected.run.waitingOnRef ||
        run.frontierRef !== selected.run.frontierRef || run.latestCheckpointId !== selected.checkpoint.id || seq !== selected.context.throughItemSeq ||
        nextJournalSequence(connection, runId) - 1 !== (selected.journal.at(-1)?.seq ?? 0) ||
        run.cancelRequested || run.stopIntentRef || now >= run.deadlineAt) throw new KernelStorageError('REVISION_CONFLICT', 'input Run is stopped, expired or changed');
    if (connection.prepare("SELECT 1 FROM worker_launches WHERE run_id = ? AND phase != 'retired' AND launch_id != ? LIMIT 1")
      .get(runId, run.activeWorkerLaunchId ?? '')) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'input wait cannot retain a pending worker launch');
    return run;
  }
  if (driver.prepare("SELECT 1 FROM items WHERE run_id = ? AND kind = 'input_request' LIMIT 1").get(runId) || admitted.waitingReason === 'input') {
    await authority.assertAuthority();
    const recovered = await recover();
    for (const { reply } of recovered) if (reply) await verifyReply(reply.itemRef, recovered);
  }
  return {
    async plan(selected: ToolCut) {
      assertInputCall(selected);
      const proof = planInputWait(selected.run, selected.batch.itemId, selected.call, sampleCanonicalNow());
      for (const artifact of proof.artifacts) await artifacts.publishBytes(artifact.bytes, artifact.mediaType, artifact.schemaKind);
      return immutableSnapshot({ disposition: 'input_required' as const, run: selected.run, waitingOnRef: proof.waitingOnRef,
        checkpointId: proof.checkpointId, prompt: proof.prompt, promptText: proof.request.prompt });
    },
    waitForInput: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; waitingOnRef: string; checkpoint?: ToolCheckpointProof }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'waitingOnRef', ...(input.checkpoint === undefined ? [] : ['checkpoint'])])) throw new TypeError('unknown input wait field');
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision);
      assertInputCall(selected);
      const wait = await readCanonicalArtifact<InputWait>(artifacts, input.waitingOnRef);
      const proof = planInputWait(selected.run, selected.batch.itemId, selected.call, wait.createdAt);
      requireEqual(wait, proof.wait, 'planned input wait');
      if (input.waitingOnRef !== proof.waitingOnRef || !['running', 'queued'].includes(selected.run.status) ||
          parseCanonicalTime(wait.createdAt) < parseCanonicalTime(admitted.createdAt) || wait.createdAt >= admitted.deadlineAt) throw new TypeError('input wait does not name the current Run cut');
      let seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
      if (selected.run.activeWorkerLaunchId) {
        if (!input.checkpoint || !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']) ||
            input.checkpoint.workspaceStateRef !== selected.checkpoint.workspaceStateRef) throw new TypeError('input wait requires retirement proof over the unchanged workspace');
        seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: selected.run, spec, assembly, checkpointId: proof.checkpointId,
          observedAt: wait.createdAt, postEffect: input.checkpoint });
      } else if (selected.run.status !== 'queued' || input.checkpoint !== undefined) throw new TypeError('only a worker-free queued Run can wait without a seal');
      const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items, items: [proof.item],
        frontier: selected.frontier, checkpointId: proof.checkpointId, workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: proof.artifacts });
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      driver.transaction((connection) => {
        const now = sampleCanonicalNow();
        const run = assertCut(connection, selected, now);
        outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
        if (outcome !== 'healthy') return;
        if (now < wait.createdAt) throw new TypeError('input wait precedes its prompt');
        for (const artifact of [...plan.metadata, ...(seal?.metadata ?? [])]) insertArtifactMetadata(connection, artifact, now);
        seal?.commit(connection, run, now);
        plan.commit(connection, run, nextJournalSequence(connection, runId) - 1, now);
        connection.prepare("UPDATE runs SET status = 'waiting', waiting_reason = 'input', waiting_on_ref = ?, revision = revision + 1, updated_at = ? WHERE id = ?")
          .run(input.waitingOnRef, now, runId);
        updated = readRun(connection, runId);
        appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(outcome);
      return immutableSnapshot({ run: updated, waitingOnRef: input.waitingOnRef });
    }),
    submitInput: stateOperation('INVALID_REQUEST', async (input: RunInput) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision', 'waitingOnRef', 'input'])) throw new TypeError('unknown run.input field');
      await authority.assertAuthority();
      const digest = inputRequestDigest(runId, input);
      if (input.principalId !== principalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'input caller does not own this Run');
      const channel = await validateControlChannelClosure(artifacts, owner, input);
      const replay = async () => {
        const row = readControlRequest(driver, principalId, 'run.input', input.requestId);
        if (!row) return undefined;
        if (row.requestDigest !== digest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.input requestId was reused with different bytes');
        const response = await readCanonicalArtifact<Response>(artifacts, row.responseRef);
        requireEqual(response, await verifyReply(response.result.inputItemRef), 'replayed input response');
        return immutableSnapshot({ replayed: true, run: response.result.snapshot.run, response });
      };
      const existing = await replay();
      if (existing) return existing;
      const selected = await cut(input.expectedRunRevision);
      if (selected.run.status !== 'waiting' || selected.run.waitingReason !== 'input' || selected.run.waitingOnRef !== input.waitingOnRef ||
          selected.run.activeWorkerLaunchId) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'run.input requires its exact worker-free input wait');
      const wait = await readCanonicalArtifact<InputWait>(artifacts, input.waitingOnRef);
      const proof = planInputWait({ ...selected.run, revision: wait.createdFromRevision }, selected.batch.itemId, selected.call, wait.createdAt);
      requireEqual(wait, proof.wait, 'current input wait');
      for (let retry = 0; retry < 8; retry++) {
        const now = sampleCanonicalNow();
        const reply = planInputReply(proof, input, now);
        const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items, items: [reply.item, reply.result],
          frontier: nextFrontier(selected.frontier, reply.item, selected.context.throughItemSeq + 2), checkpointId: reply.checkpointId,
          workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: reply.artifacts });
        const { waitingOnRef: _wait, waitingReason: _reason, ...current } = selected.run;
        const next: Run = { ...current, ...plan.runUpdate, status: 'queued', revision: current.revision + 1, updatedAt: now };
        const response: Response = { protocolVersion: 1, ok: true, result: { method: 'run.input', inputItemRef: reply.itemRef,
          snapshot: { schemaVersion: 1, operation: 'agent', run: next, latestRunItemSeq: plan.throughItemSeq } } };
        const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-application-response-v1');
        let outcome: TimeFenceAdvance | undefined, committed = false;
        driver.transaction((connection) => {
          assertActiveStateOwner(connection, owner);
          if (readControlRequest(connection, principalId, 'run.input', input.requestId)) return;
          const sampled = sampleCanonicalNow(), fence = readTimeFence(connection);
          if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'input canonical time fence is missing');
          if (sampled < now || sampled < fence.lastAcceptedAt) { outcome = advanceTimeFence(connection, owner.ownerEpoch, sampled); return; }
          if (now < fence.lastAcceptedAt) return;
          const run = assertCut(connection, selected, sampled);
          outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
          if (outcome !== 'healthy') return;
          for (const artifact of [...channel.metadata, ...plan.metadata, responseArtifact]) insertArtifactMetadata(connection, artifact, now);
          plan.commit(connection, run, nextJournalSequence(connection, runId) - 1, now);
          connection.prepare("UPDATE runs SET status = 'queued', waiting_reason = NULL, waiting_on_ref = NULL, revision = revision + 1, updated_at = ? WHERE id = ?")
            .run(now, runId);
          requireEqual(readRun(connection, runId), next, 'committed input snapshot');
          appendRunStateEvent(connection, next, now);
          insertControlRequest(connection, { principalId, method: 'run.input', requestId: input.requestId, requestDigest: digest,
            channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, responseRef: responseArtifact.ref, committedAt: now });
          committed = true;
        });
        requireHealthyFence(outcome);
        if (committed) return immutableSnapshot({ replayed: false, run: next, response });
        const result = await replay();
        if (result) return result;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'input control cut kept changing');
    })
  };
}
