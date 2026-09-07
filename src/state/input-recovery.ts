import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunAssemblyV1, RunFrontier, RunSpec, ToolContractManifestV1 } from '../kernel/types.js';
import type { InputWait, RunInput, UserInputPayloadV1 } from '../kernel/user-input.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { planInputReply, planInputWait } from '../runtime/user-input.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { toolOperationId } from '../policy/tool-policy.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';

type InputCut = { artifacts: ArtifactCatalog; run: Run; spec: RunSpec; items: Map<string, ContinuationItem>;
  journal: InvocationJournalEntry[]; checkpoints: Checkpoint[] };

/** Replay from retained native input, not from the prompt/response artifacts' assertions about themselves. */
export async function validateUserInputRecovery(cut: InputCut) {
  const { artifacts, run, spec, journal } = cut;
  const items = [...cut.items.values()];
  const requests = items.filter((item) => item.kind === 'input_request');
  const replies = items.filter((item) => item.kind === 'user_input');
  const inputResults = [];
  for (const item of items) if (item.kind === 'tool_result' && item.outcome === 'executed') {
    const payload = await readCanonicalArtifact<{ source?: string }>(artifacts, item.resultRef);
    if (payload.source === 'user_input') inputResults.push(item);
  }
  if (!requests.length && !replies.length && run.waitingReason !== 'input') {
    if (inputResults.length) throw new TypeError('input result has no owning authenticated input');
    return [];
  }
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
  if (manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) throw new TypeError('input tool manifest mismatch');
  const entry = manifest.entries.find((entry) => entry.name === 'request_input');
  if (!entry || entry.execution.kind !== 'builtin' || entry.access !== 'control') throw new TypeError('input wait has no frozen builtin control contract');
  const resolver = loadToolContracts([{ ...entry, inputSchema: await readCanonicalArtifact(artifacts, entry.inputSchemaRef) }]);
  const seenCalls = new Set<string>(), seenReplies = new Set<string>();
  const recovered = [];
  for (const item of requests) {
    const batch = cut.items.get(item.batchItemId);
    const call = batch?.kind === 'assistant_tool_batch' ? batch.calls[item.index] : undefined;
    const opId = toolOperationId(run.id, item.batchItemId, item.callId);
    const position = items.indexOf(item);
    if (!call || call.callId !== item.callId || call.toolName !== 'request_input' || seenCalls.has(opId) ||
        journal.some((entry) => entry.opId === opId) ||
        items.slice(0, position).filter((prior) => prior.kind === 'tool_result' && prior.batchItemId === item.batchItemId).length !== item.index) {
      throw new TypeError('input request is not the first result-less control call');
    }
    seenCalls.add(opId);
    const input = await readCanonicalArtifact<ToolCallInputV1>(artifacts, call.inputRef);
    if (input.inputDigest !== call.inputDigest || digestOmitting(input, 'inputDigest') !== call.inputDigest ||
        input.callId !== item.callId || input.index !== item.index || input.toolName !== 'request_input' ||
        input.inputSchemaRef !== entry.inputSchemaRef || input.inputSchemaDigest !== entry.inputSchemaDigest || input.disposition !== 'resolved') {
      throw new TypeError('input request substitutes its retained native call');
    }
    if (resolver.projectInvocation({ callId: input.callId, index: input.index, toolName: input.toolName, input: input.value! }).kind !== 'input') {
      throw new TypeError('input request is not a control invocation');
    }
    const matches = replies.filter((reply) => reply.inputRequestItemId === item.itemId);
    if (matches.length > 1) throw new TypeError('input request has duplicate replies');
    const reply = matches[0];
    const payload = reply && await readCanonicalArtifact<UserInputPayloadV1>(artifacts, reply.inputRef);
    const frontier: RunFrontier = { schemaVersion: 1, kind: 'tool', batchItemId: item.batchItemId,
      orderedCallIds: batch!.kind === 'assistant_tool_batch' ? batch!.calls.map((call) => call.callId) : [], nextCallIndex: item.index };
    const stopped = run.stopIntentRef && ['failed', 'cancelled'].includes(run.status) && !reply;
    const historicWaits = stopped ? cut.checkpoints.filter((checkpoint) => checkpoint.runItemSeq === position + 1).map((checkpoint) => ({ checkpoint,
      proof: planInputWait({ id: run.id, revision: checkpoint.basedOnRunRevision, frontierRef: canonicalSha256(frontier) }, item.batchItemId, input, item.createdAt)
    })).filter(({ checkpoint, proof }) => checkpoint.id === proof.checkpointId) : [];
    if (stopped && historicWaits.length !== 1) throw new TypeError('stopped input has no unique retained wait checkpoint');
    const waitRef = payload?.waitingSubjectRef ?? (run.waitingReason === 'input' ? run.waitingOnRef : historicWaits[0]?.proof.waitingOnRef);
    if (!waitRef) throw new TypeError('input request has no retained wait owner');
    const wait = await readCanonicalArtifact<InputWait>(artifacts, waitRef);
    const proof = planInputWait({ id: run.id, revision: wait.createdFromRevision, frontierRef: canonicalSha256(frontier) }, item.batchItemId, input, item.createdAt);
    requireEqual(wait, proof.wait, 'retained input wait');
    requireEqual(item, proof.item, 'retained input request');
    if (waitRef !== proof.waitingOnRef || !Number.isSafeInteger(wait.createdFromRevision) || wait.createdFromRevision < 1 ||
        parseCanonicalTime(wait.createdAt) < parseCanonicalTime(run.createdAt) || wait.createdAt >= run.deadlineAt) throw new TypeError('input wait lifetime or revision mismatch');
    for (const artifact of proof.artifacts) {
      if (!(await artifacts.readBytes(artifact.ref)).equals(Buffer.from(artifact.bytes))) throw new TypeError('input artifact differs from its original call');
    }
    await artifacts.readBytes(wait.frontierRef);
    const checkpoint = cut.checkpoints.find((checkpoint) => checkpoint.id === proof.checkpointId);
    const prior = cut.checkpoints.filter((checkpoint) => checkpoint.basedOnRunRevision < wait.createdFromRevision).at(-1);
    if (!checkpoint || !prior || checkpoint.basedOnRunRevision !== wait.createdFromRevision || checkpoint.createdAt < wait.createdAt ||
        checkpoint.runItemSeq !== position + 1 || prior.runItemSeq !== position || checkpoint.journalSeq !== prior.journalSeq ||
        checkpoint.workspaceStateRef !== prior.workspaceStateRef) throw new TypeError('input wait has no atomic unchanged-workspace checkpoint');
    if (!reply || !payload) {
      if (stopped) {
        const result = items[position + 1];
        if (result?.kind !== 'tool_result' || result.outcome !== 'cancelled' || result.batchItemId !== item.batchItemId ||
            result.callId !== item.callId || result.index !== item.index) throw new TypeError('stopped input has no ordered cancellation result');
        recovered.push({ proof, checkpoint });
        continue;
      }
      if (run.status !== 'waiting' || run.waitingReason !== 'input' || run.waitingOnRef !== waitRef || run.activeWorkerLaunchId ||
          (run.stopIntentRef ? run.revision < wait.createdFromRevision + 1 : run.revision !== wait.createdFromRevision + 1) || run.latestCheckpointId !== checkpoint.id || run.frontierRef !== wait.frontierRef ||
          run.nextStep !== 'tool' || position !== items.length - 1) throw new TypeError('unanswered input does not own the current worker-free wait');
      recovered.push({ proof, checkpoint });
      continue;
    }
    const command: RunInput = { principalId: payload.principalId, channelIdentityRef: payload.channelIdentityRef,
      channelIdentityDigest: payload.channelIdentityDigest, requestId: payload.requestId, expectedRunRevision: payload.expectedRunRevision,
      waitingOnRef: payload.waitingSubjectRef, input: payload.inputKind === 'text'
        ? { kind: 'text', value: payload.value as string } : { kind: 'json', value: payload.value } };
    const result = planInputReply(proof, command, reply.createdAt);
    requireEqual(payload, result.payload, 'retained user input payload');
    requireEqual(reply, result.item, 'retained user input item');
    const replyPosition = items.indexOf(reply);
    requireEqual(items[replyPosition + 1], result.result, 'input ordered tool result');
    if (replyPosition !== position + 1 || reply.createdAt >= run.deadlineAt) throw new TypeError('input reply overtakes its wait or deadline');
    for (const artifact of result.artifacts) {
      if (!(await artifacts.readBytes(artifact.ref)).equals(Buffer.from(artifact.bytes))) throw new TypeError('input response artifact differs from its normalized value');
    }
    const replyCheckpoint = cut.checkpoints.find((checkpoint) => checkpoint.id === result.checkpointId);
    if (!replyCheckpoint || replyCheckpoint.basedOnRunRevision !== wait.createdFromRevision + 1 ||
        replyCheckpoint.createdAt !== reply.createdAt || replyCheckpoint.runItemSeq !== replyPosition + 2 ||
        replyCheckpoint.journalSeq !== checkpoint.journalSeq || replyCheckpoint.workspaceStateRef !== checkpoint.workspaceStateRef) {
      throw new TypeError('input reply has no atomic continuation checkpoint');
    }
    seenReplies.add(reply.itemId);
    recovered.push({ proof, checkpoint, reply: { ...result, command, checkpoint: replyCheckpoint } });
  }
  if (replies.some((reply) => !seenReplies.has(reply.itemId))) throw new TypeError('user input has no owning request');
  if (run.waitingReason === 'input' && !recovered.some(({ proof, reply }) => !reply && proof.waitingOnRef === run.waitingOnRef)) {
    throw new TypeError('input wait has no owning request item');
  }
  for (const item of inputResults) {
    if (!recovered.some(({ reply }) => reply && canonicalSha256(reply.result) === canonicalSha256(item))) {
      throw new TypeError('input result has no owning authenticated input');
    }
  }
  return recovered;
}
