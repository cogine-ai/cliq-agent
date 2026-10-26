import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { controlWireInteger, controlWireRecord, controlWireRef } from '../kernel/control-wire-data.js';
import type { RunSnapshotV1 } from '../kernel/types.js';
import { verifyModelText } from '../model/attempt.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import type { InstalledControlSession } from '../control/session.js';
import type { InstalledControlRequestV1, InstalledControlResponseFor, InstalledControlFeature } from '../control/v1.js';
type ArtifactReader = Pick<InstalledControlSession, 'artifact'>;
type PresentationClient = ArtifactReader & { readRun(request: Extract<InstalledControlRequestV1, { method: 'run.get' }>): Promise<InstalledControlResponseFor<InstalledControlFeature>> };

export type WaitingPresentation = Readonly<{ waitingOnRef: string; text: string;
  responseKind?: 'text' | 'json'; maximumResponseBytes?: number; responseSchema?: unknown }>;
export async function readClientJson(app: ArtifactReader, ref: string, signal?: AbortSignal): Promise<unknown> {
  controlWireRef(ref);
  const bytes = await app.artifact(ref, { maxBytes: 64 * 1024 * 1024, signal });
  signal?.throwIfAborted();
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('client artifact is not canonical JSON');
  return value;
}
async function modelText(app: ArtifactReader, ref: string, signal?: AbortSignal): Promise<string> {
  const value = await readClientJson(app, ref, signal) as ModelTextV1;
  verifyModelText(value); return value.utf8;
}
/** Exact referenced data for a human decision, never an approval/recovery
 * permit. Every actual mutation still goes through its owning reducer. */
export async function readWaitingPresentation(app: PresentationClient, snapshot: RunSnapshotV1,
  signal?: AbortSignal): Promise<WaitingPresentation> {
  const run = snapshot.run;
  if (run.status !== 'waiting' || !run.waitingOnRef) throw new TypeError('there is no captured wait to present');
  const value = await readClientJson(app, run.waitingOnRef, signal);
  if (run.waitingReason !== 'input') {
    if (run.waitingReason === 'approval') {
      const wait = controlWireRecord(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject']);
      if (wait.schemaVersion !== 1 || wait.kind !== 'approval' || wait.runId !== run.id || wait.frontierRef !== run.frontierRef)
        throw new TypeError('approval presentation differs from its captured Run');
      controlWireInteger(wait.createdFromRevision, 1, run.revision - 1);
      const subject = wait.subject as Record<string, unknown>;
      let text = canonicalJsonBytes(subject).toString('utf8');
      if (subject && typeof subject === 'object' && typeof subject.policyChannelEvidenceRef === 'string') {
        const evidence = await readClientJson(app, subject.policyChannelEvidenceRef, signal) as Record<string, unknown>;
        if (evidence.runId !== run.id || evidence.evidenceDigest !== subject.policyChannelEvidenceDigest ||
            digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest)
          throw new TypeError('approval presentation substitutes its original evidence');
        text = canonicalJsonBytes(evidence).toString('utf8');
      }
      return { waitingOnRef: run.waitingOnRef, text };
    }
    return { waitingOnRef: run.waitingOnRef, text: canonicalJsonBytes(value).toString('utf8') };
  }
  const wait = controlWireRecord(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef',
    'inputRequestItemId', 'batchItemId', 'callId']);
  if (wait.schemaVersion !== 1 || wait.kind !== 'input' || wait.runId !== run.id || wait.frontierRef !== run.frontierRef)
    throw new TypeError('input presentation differs from its captured Run');
  controlWireInteger(wait.createdFromRevision, 1, run.revision - 1);
  const response = await app.readRun({ protocolVersion: 1, method: 'run.get', runId: run.id,
    afterItemSeq: Math.max(0, snapshot.latestRunItemSeq - 1), itemLimit: 1, journalLimit: 1, checkpointLimit: 1 });
  if (!response || !response.ok || response.result.method !== 'run.get' || response.result.snapshot.run.waitingOnRef !== run.waitingOnRef)
    throw new TypeError('input wait changed while reading its original request');
  const row = response.result.items.find(item => item.itemId === wait.inputRequestItemId);
  if (!row) throw new TypeError('input wait does not own the last committed input request');
  const request = controlWireRecord(await readClientJson(app, row.payloadRef, signal), ['schemaVersion', 'kind', 'itemId', 'runId',
    'batchItemId', 'callId', 'index', 'promptRef', 'promptDigest', 'createdAt']);
  if (request.schemaVersion !== 1 || request.kind !== 'input_request' || request.itemId !== row.itemId || request.runId !== run.id ||
      request.batchItemId !== wait.batchItemId || request.callId !== wait.callId) throw new TypeError('input request presentation differs');
  const promptData = await readClientJson(app, controlWireRef(request.promptRef), signal) as Record<string, unknown>;
  const prompt = controlWireRecord(promptData, ['schemaVersion', 'format', 'runId', 'batchItemId', 'callId', 'index', 'promptTextRef',
    'promptTextDigest', 'maximumResponseBytes', 'promptDigest', 'responseKind'], promptData.responseKind === 'json' ? ['responseSchemaRef', 'responseSchemaDigest'] : []);
  if (prompt.schemaVersion !== 1 || prompt.format !== 'cliq-input-prompt-v1' || prompt.runId !== run.id || prompt.batchItemId !== request.batchItemId ||
      prompt.callId !== request.callId || prompt.index !== request.index || prompt.promptDigest !== request.promptDigest ||
      digestOmitting(prompt, 'promptDigest') !== prompt.promptDigest || !['text', 'json'].includes(prompt.responseKind as string))
    throw new TypeError('input prompt presentation substitutes the original prompt');
  const maximumResponseBytes = controlWireInteger(prompt.maximumResponseBytes, 1, 1_048_576);
  const textValue = await readClientJson(app, controlWireRef(prompt.promptTextRef), signal) as ModelTextV1;
  verifyModelText(textValue);
  if (textValue.textDigest !== prompt.promptTextDigest) throw new TypeError('input prompt text differs');
  let responseSchema: unknown;
  if (prompt.responseKind === 'json') {
    const schema = controlWireRecord(await readClientJson(app, controlWireRef(prompt.responseSchemaRef), signal),
      ['schemaVersion', 'format', 'dialect', 'schema', 'schemaDigest']);
    if (schema.schemaVersion !== 1 || schema.format !== 'cliq-input-response-schema-v1' || schema.dialect !== 'https://json-schema.org/draft/2020-12/schema' ||
        schema.schemaDigest !== prompt.responseSchemaDigest || digestOmitting(schema, 'schemaDigest') !== schema.schemaDigest)
      throw new TypeError('input response schema differs');
    responseSchema = schema.schema;
  }
  return { waitingOnRef: run.waitingOnRef, text: textValue.utf8, responseKind: prompt.responseKind as 'text' | 'json', maximumResponseBytes,
    ...(responseSchema === undefined ? {} : { responseSchema }) };
}

/** Committed transcript data only. Control/legacy bodies are never rendered
 * as model messages. An unsupported item remains an explicit reference. */
export async function readRunItemPresentation(app: ArtifactReader,
  expected: { runId: string; itemId: string; payloadRef: string }, signal?: AbortSignal): Promise<string> {
  const item = await readClientJson(app, expected.payloadRef, signal) as Record<string, unknown>;
  if (item.schemaVersion !== 1 || item.runId !== expected.runId || item.itemId !== expected.itemId || typeof item.kind !== 'string')
    throw new TypeError('transcript item differs from its committed row');
  if (item.kind === 'model_turn' || item.kind === 'assistant_tool_batch')
    return `Assistant: ${await modelText(app, controlWireRef(item.textRef), signal)}`;
  if (item.kind === 'tool_result') {
    const payload = await readClientJson(app, controlWireRef(item.resultRef), signal) as Record<string, unknown>;
    if (payload.schemaVersion !== 1 || payload.format !== 'cliq-tool-result-payload-v1' || payload.runId !== expected.runId || payload.callId !== item.callId ||
        payload.batchItemId !== item.batchItemId || payload.index !== item.index || payload.outcome !== item.outcome || digestOmitting(payload, 'payloadDigest') !== payload.payloadDigest)
      throw new TypeError('tool result presentation substitutes its source');
    const content = controlWireRecord(await readClientJson(app, controlWireRef(payload.modelContentRef), signal),
      ['schemaVersion', 'format', 'callId', 'index', 'toolName', 'outcome', 'content', 'contentDigest']);
    if (content.schemaVersion !== 1 || content.format !== 'cliq-tool-result-model-content-v1' || content.callId !== item.callId ||
        content.index !== item.index || content.toolName !== payload.toolName || content.outcome !== item.outcome || content.contentDigest !== payload.modelContentDigest ||
        digestOmitting(content, 'contentDigest') !== content.contentDigest) throw new TypeError('tool model content presentation differs');
    return `${String(content.toolName)} · ${String(content.outcome)}: ${canonicalJsonBytes(content.content).toString('utf8')}`;
  }
  return `${item.kind} · ${expected.itemId}`;
}
