import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { RunSnapshotV1 } from '../kernel/types.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { planInputReply, planInputWait } from '../runtime/user-input.js';
import { ContentAddressedStore } from '../state/cas.js';
import type { ClientApplication } from './actions.js';
import { readWaitingPresentation, readRunItemPresentation } from './artifacts.js';

// Real CAS and production artifact plans, with inert protocol responses only.
// This consumer fixture creates no accepted Run, StateOwner or native proof.
const at = '2026-10-26T00:00:00.000Z', ref = 'a'.repeat(64);
function snapshot(waitingOnRef: string): RunSnapshotV1 {
  return { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 1, run: { id: 'run', sessionId: 'session', specRef: ref,
    status: 'waiting', nextStep: 'tool', waitingReason: 'input', waitingOnRef, frontierRef: ref, revision: 2, leaseEpoch: 0,
    latestCheckpointId: 'checkpoint', budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0, cancelRequested: false,
    createdAt: at, updatedAt: at, deadlineAt: '2026-10-27T00:00:00.000Z' } };
}
async function fixture() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-client-presentation-'));
  const root = path.join(home, 'objects'); await mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root);
  const call: ToolCallInputV1 = { schemaVersion: 1, format: 'cliq-tool-call-input-v1', observedInputRef: ref, observedInputDigest: ref, inputDigest: ref, inputSchemaRef: ref, inputSchemaDigest: ref, toolName: 'request_input', disposition: 'resolved', callId: 'call', index: 0,
    value: { prompt: 'Choose a count.\nUse the original schema.', responseKind: 'json', maximumResponseBytes: 1_048_576,
      responseSchema: { type: 'object', properties: { count: { type: 'integer' } }, required: ['count'], additionalProperties: false } } };
  const proof = planInputWait({ id: 'run', revision: 1, frontierRef: ref }, 'batch', call, at);
  for (const artifact of proof.artifacts) assert.equal(await cas.publish(artifact.bytes), artifact.ref);
  const itemRef = await cas.publish(canonicalJsonBytes(proof.item));
  let current = snapshot(proof.waitingOnRef);
  const app = {
    artifact: async (digest: string, options: { maxBytes: number; signal?: AbortSignal }) => {
      const bytes = await cas.read(digest, options.signal); assert(bytes.length <= options.maxBytes); return bytes;
    },
    readRun: async (request: any) => {
      assert.equal(request.method, 'run.get'); assert.equal(request.afterItemSeq, 0); assert.equal(request.itemLimit, 1);
      return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: current,
        items: [{ itemId: proof.item.itemId, itemSeq: 1, kind: 'input_request', payloadRef: itemRef }] } };
    }
  } as unknown as ClientApplication;
  return { home, cas, proof, app, itemRef, setCurrent(value: RunSnapshotV1) { current = value; } };
}

test('input presentation reads the original production CAS graph, semantic schema digest and full response limit', async () => {
  const f = await fixture();
  try {
    const view = await readWaitingPresentation(f.app, snapshot(f.proof.waitingOnRef));
    assert.equal(view.text, f.proof.request.prompt); assert.equal(view.responseKind, 'json');
    assert.equal(view.maximumResponseBytes, 1_048_576);
    assert.equal(canonicalJsonBytes(view.responseSchema).toString(), canonicalJsonBytes(f.proof.request.responseSchema).toString());
    assert.notEqual(f.proof.prompt.responseSchemaRef, f.proof.prompt.responseSchemaDigest);
    f.setCurrent(snapshot(ref));
    await assert.rejects(readWaitingPresentation(f.app, snapshot(f.proof.waitingOnRef)), /wait changed/u);
  } finally { await rm(f.home, { recursive: true, force: true }); }
});

test('changed semantic prompt links and foreign committed items cannot be shown as the original question', async () => {
  const f = await fixture();
  try {
    const original = f.app.artifact;
    const changed = { ...f.proof.prompt, runId: 'other' }; changed.promptDigest = digestOmitting(changed, 'promptDigest');
    const changedRef = await f.cas.publish(canonicalJsonBytes(changed));
    const reader = { ...f.app, artifact: (digest: string, options: any) => original(digest === f.proof.item.promptRef ? changedRef : digest, options) };
    await assert.rejects(readWaitingPresentation(reader, snapshot(f.proof.waitingOnRef)), /prompt presentation/u);
    await assert.rejects(readRunItemPresentation(f.app, { runId: 'foreign', itemId: f.proof.item.itemId, payloadRef: f.itemRef }), /committed row/u);
    const aborted = new AbortController(); aborted.abort();
    await assert.rejects(readWaitingPresentation(f.app, snapshot(f.proof.waitingOnRef), aborted.signal), { name: 'AbortError' });
  } finally { await rm(f.home, { recursive: true, force: true }); }
});

test('committed model text is readable while legacy and control bodies remain only explicit item references', async () => {
  const f = await fixture();
  try {
    const text = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: 'Actual answer.', byteCount: 14, textDigest: '' };
    text.textDigest = digestOmitting(text, 'textDigest');
    const textRef = await f.cas.publish(canonicalJsonBytes(text));
    const item = { schemaVersion: 1, kind: 'model_turn', runId: 'run', itemId: 'answer', textRef };
    const itemRef = await f.cas.publish(canonicalJsonBytes(item));
    assert.equal(await readRunItemPresentation(f.app, { runId: 'run', itemId: 'answer', payloadRef: itemRef }), 'Assistant: Actual answer.');
    const legacy = { ...item, kind: 'legacy', text: 'must not enter transcript' };
    assert.equal(await readRunItemPresentation(f.app, { runId: 'run', itemId: 'answer', payloadRef: await f.cas.publish(canonicalJsonBytes(legacy)) }), 'legacy · answer');
    assert.equal(canonicalSha256(item), itemRef);
  } finally { await rm(f.home, { recursive: true, force: true }); }
});


test('tool transcript binds the original batch and model tool name across actual production result artifacts', async () => {
  const f = await fixture();
  try {
    const plan = planInputReply(f.proof, { principalId: 'principal', requestId: '019a1d00-0000-7000-8000-000000000001', expectedRunRevision: 2,
      waitingOnRef: f.proof.waitingOnRef, channelIdentityRef: ref, channelIdentityDigest: ref,
      input: { kind: 'json', value: { count: 1 } } }, at);
    for (const artifact of plan.artifacts) await f.cas.publish(artifact.bytes);
    const present = async (item: typeof plan.result) => readRunItemPresentation(f.app,
      { runId: 'run', itemId: item.itemId, payloadRef: await f.cas.publish(canonicalJsonBytes(item)) });
    assert.equal(await present(plan.result), 'request_input · executed: {"count":1}');
    const payload = await f.cas.read(plan.result.resultRef).then(bytes => JSON.parse(bytes.toString('utf8')));
    const foreignBatch = { ...payload, batchItemId: 'another-batch' };
    foreignBatch.payloadDigest = digestOmitting(foreignBatch, 'payloadDigest');
    await assert.rejects(present({ ...plan.result, resultRef: await f.cas.publish(canonicalJsonBytes(foreignBatch)) }), /source/u);
    const content = await f.cas.read(payload.modelContentRef).then(bytes => JSON.parse(bytes.toString('utf8')));
    const foreignName = { ...content, toolName: 'another-tool' };
    foreignName.contentDigest = digestOmitting(foreignName, 'contentDigest');
    const changed = { ...payload, modelContentRef: await f.cas.publish(canonicalJsonBytes(foreignName)), modelContentDigest: foreignName.contentDigest };
    changed.payloadDigest = digestOmitting(changed, 'payloadDigest');
    await assert.rejects(present({ ...plan.result, resultRef: await f.cas.publish(canonicalJsonBytes(changed)) }), /content/u);
  } finally { await rm(f.home, { recursive: true, force: true }); }
});
