import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertArtifactRef, assertRequestId, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import type { Run, ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { InputPromptV1, InputRequestItem, InputResponseSchemaV1, InputWait, RunInput,
  UserInputItem, UserInputModelContentV1, UserInputPayloadV1 } from '../kernel/user-input.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { requestInputContract, validateUserInput, type RequestInput } from '../tools/request-input.js';

export const inputWaitCheckpointId = (waitRef: string) => identityHash('cliq-input-wait-checkpoint-v1', waitRef);
export const inputReplyCheckpointId = (itemRef: string) => identityHash('cliq-input-reply-checkpoint-v1', itemRef);

export function inputRequestDigest(runId: string, input: RunInput): string {
  assertRequestId(input.requestId);
  assertArtifactRef(input.waitingOnRef);
  if (!Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1 ||
      !input.input || !['text', 'json'].includes(input.input.kind) || Object.keys(input.input).length !== 2 ||
      !Object.hasOwn(input.input, 'value')) throw new TypeError('invalid run.input request');
  assertBoundedJsonValue(input.input.value, 'user input');
  if (canonicalJsonBytes(input.input.value).byteLength > 1_048_576) throw new TypeError('user input exceeds its model-content byte bound');
  return canonicalSha256({ protocolVersion: 1, method: 'run.input', runId, requestId: input.requestId,
    expectedRevision: input.expectedRunRevision, waitingOnRef: input.waitingOnRef, input: input.input });
}

/** Pure artifact plans from one already validated native call; State owns publication and the wait commit. */
export function planInputWait(run: Pick<Run, 'id' | 'revision' | 'frontierRef'>, batchItemId: string, call: ToolCallInputV1, createdAt: string) {
  parseCanonicalTime(createdAt);
  const parsed = requestInputContract.parseInput(call.value);
  if (call.toolName !== 'request_input' || call.disposition !== 'resolved' || !parsed ||
      canonicalSha256(parsed.input) !== canonicalSha256(call.value)) throw new TypeError('input wait requires the exact normalized request_input call');
  const request: RequestInput = parsed.input;
  const textCore = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: request.prompt, byteCount: Buffer.byteLength(request.prompt) };
  const text = planCanonicalArtifact({ ...textCore, textDigest: canonicalSha256(textCore) }, textCore.format);
  const schemaCore = request.responseKind === 'json' ? { schemaVersion: 1 as const, format: 'cliq-input-response-schema-v1' as const,
    dialect: 'https://json-schema.org/draft/2020-12/schema' as const, schema: request.responseSchema } : undefined;
  const schema = schemaCore && planCanonicalArtifact({ ...schemaCore, schemaDigest: canonicalSha256(schemaCore) } satisfies InputResponseSchemaV1, schemaCore.format);
  const core = { schemaVersion: 1 as const, format: 'cliq-input-prompt-v1' as const, runId: run.id,
    batchItemId, callId: call.callId, index: call.index, promptTextRef: text.ref, promptTextDigest: canonicalSha256(textCore),
    maximumResponseBytes: request.maximumResponseBytes,
    ...(schema ? { responseKind: 'json' as const, responseSchemaRef: schema.ref, responseSchemaDigest: canonicalSha256(schemaCore) }
      : { responseKind: 'text' as const }) };
  const prompt: InputPromptV1 = { ...core, promptDigest: canonicalSha256(core) };
  const promptPlan = planCanonicalArtifact(prompt, prompt.format);
  const item: InputRequestItem = { schemaVersion: 1, kind: 'input_request',
    itemId: identityHash('cliq-input-request-item-v1', run.id, batchItemId, call.callId), runId: run.id,
    batchItemId, callId: call.callId, index: call.index, promptRef: promptPlan.ref, promptDigest: prompt.promptDigest, createdAt };
  const wait: InputWait = { schemaVersion: 1, kind: 'input', runId: run.id, createdFromRevision: run.revision,
    createdAt, frontierRef: run.frontierRef!, inputRequestItemId: item.itemId, batchItemId, callId: call.callId };
  const waitPlan = planCanonicalArtifact(wait, 'cliq-waiting-subject-v1');
  return { wait, waitingOnRef: waitPlan.ref, checkpointId: inputWaitCheckpointId(waitPlan.ref), item, prompt, request,
    artifacts: [text, ...(schema ? [schema] : []), promptPlan, waitPlan] };
}

export function planInputReply(proof: ReturnType<typeof planInputWait>, input: RunInput, createdAt: string) {
  const requestDigest = inputRequestDigest(proof.wait.runId, input);
  if (input.waitingOnRef !== proof.waitingOnRef || input.expectedRunRevision !== proof.wait.createdFromRevision + 1 ||
      parseCanonicalTime(createdAt) < parseCanonicalTime(proof.wait.createdAt)) throw new TypeError('input does not match its current wait');
  assertArtifactRef(input.channelIdentityRef);
  assertArtifactRef(input.channelIdentityDigest);
  const byteCount = validateUserInput(proof.request, input.input);
  const modelCore = { schemaVersion: 1 as const, format: 'cliq-user-input-model-content-v1' as const,
    inputKind: input.input.kind, value: input.input.value };
  const model: UserInputModelContentV1 = { ...modelCore, contentDigest: canonicalSha256(modelCore) };
  const modelPlan = planCanonicalArtifact(model, model.format);
  const { runId, batchItemId, callId, index, promptRef, promptDigest } = proof.item;
  const payloadCore = { schemaVersion: 1 as const, format: 'cliq-user-input-payload-v1' as const,
    runId, batchItemId, callId, index, inputRequestItemId: proof.item.itemId, promptRef, promptDigest,
    principalId: input.principalId, byteCount, modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest,
    waitingSubjectRef: input.waitingOnRef, requestId: input.requestId, requestDigest, expectedRunRevision: input.expectedRunRevision,
    channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest,
    ...(input.input.kind === 'text' ? { inputKind: 'text' as const, value: input.input.value }
      : { inputKind: 'json' as const, value: input.input.value }) };
  const payload: UserInputPayloadV1 = { ...payloadCore, payloadDigest: canonicalSha256(payloadCore) };
  const payloadPlan = planCanonicalArtifact(payload, payload.format);
  const item: UserInputItem = { schemaVersion: 1, kind: 'user_input',
    itemId: identityHash('cliq-user-input-item-v1', runId, proof.item.itemId), runId, batchItemId, callId, index,
    inputRequestItemId: proof.item.itemId, promptRef, promptDigest, inputRef: payloadPlan.ref, inputDigest: payload.payloadDigest,
    modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest, principalId: input.principalId, createdAt };
  const itemRef = canonicalSha256(item);
  const resultContentCore = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
    callId, index, toolName: 'request_input', outcome: 'executed' as const, content: input.input.value };
  const resultContent: ToolResultModelContentV1 = { ...resultContentCore, contentDigest: canonicalSha256(resultContentCore) };
  const contentPlan = planCanonicalArtifact(resultContent, resultContent.format);
  if (canonicalJsonBytes(resultContent.content).byteLength > 1_048_576) throw new TypeError('input exceeds the model tool-result byte bound');
  const resultCore = { schemaVersion: 1 as const, format: 'cliq-tool-result-payload-v1' as const,
    runId, batchItemId, callId, index, toolName: 'request_input', outcome: 'executed' as const, source: 'user_input' as const,
    inputItemRef: itemRef, inputRef: payloadPlan.ref, inputDigest: payload.payloadDigest,
    modelContentRef: contentPlan.ref, modelContentDigest: resultContent.contentDigest };
  const resultPayload: ToolResultPayloadV1 = { ...resultCore, payloadDigest: canonicalSha256(resultCore) };
  const resultPlan = planCanonicalArtifact(resultPayload, resultPayload.format);
  const result: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', runId, batchItemId, callId), runId, batchItemId, callId, index,
    outcome: 'executed', resultRef: resultPlan.ref, createdAt };
  return { item, itemRef, payload, result, checkpointId: inputReplyCheckpointId(itemRef),
    artifacts: [modelPlan, payloadPlan, contentPlan, resultPlan] };
}
