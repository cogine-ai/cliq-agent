// Original client data only. Displaying this wait neither releases a child nor
// proves ownership, completion, permission, settlement or physical quiescence.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef,
  controlWireText, decodeWireRun } from '../kernel/control-wire-data.js';
import { parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { RunSnapshotV1 } from '../kernel/types.js';

type Reader = { artifact(ref: string, options: { maxBytes: number; signal?: AbortSignal }): Promise<Buffer> };
export async function readChildWaitingPresentation(app: Reader, snapshot: RunSnapshotV1, value: unknown, signal?: AbortSignal) {
  signal?.throwIfAborted(); assertControlWireJson(snapshot); assertControlWireJson(value);
  const run = Object.freeze({ ...decodeWireRun(snapshot.run) });
  const wait = controlWireRecord(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject']);
  if (snapshot.operation !== 'agent' || run.status !== 'waiting' || run.waitingReason !== 'child' || !run.waitingOnRef ||
      canonicalSha256(wait) !== run.waitingOnRef || wait.schemaVersion !== 1 || wait.kind !== 'child' ||
      wait.runId !== run.id || wait.frontierRef !== run.frontierRef)
    throw new TypeError('child presentation differs from its captured wait');
  controlWireInteger(wait.createdFromRevision, 1, run.revision - 1);
  const createdAt = controlWireText(wait.createdAt); parseCanonicalTime(createdAt);
  if (createdAt < run.createdAt || createdAt > run.updatedAt) throw new TypeError('child wait time differs from its captured Run');
  const raw = controlWireRecord(wait.subject, ['kind', 'waitSetRef'], ['awaitBatchItemId', 'awaitCallId', 'awaitCallIndex',
    'modelTurnItemId', 'observedStopIntentRef', 'stopIntentRef', 'interruptedWaitRef', 'awaitOrigin']);
  const kind = raw.kind;
  if (!['await_tool', 'finalize_settlement', 'stop_settlement'].includes(kind as string)) throw new TypeError('unknown child wait purpose');
  const subject = controlWireRecord(raw, ['kind', 'waitSetRef', ...(kind === 'await_tool' ? ['awaitBatchItemId', 'awaitCallId', 'awaitCallIndex']
    : kind === 'finalize_settlement' ? ['modelTurnItemId'] : ['stopIntentRef'])], kind === 'finalize_settlement' ? ['observedStopIntentRef']
    : kind === 'stop_settlement' ? ['interruptedWaitRef', 'awaitOrigin'] : []);
  const setRef = controlWireRef(subject.waitSetRef);
  for (const key of ['stopIntentRef', 'interruptedWaitRef', 'observedStopIntentRef']) if (Object.hasOwn(subject, key)) controlWireRef(subject[key]);
  for (const key of ['awaitBatchItemId', 'awaitCallId', 'modelTurnItemId']) if (Object.hasOwn(subject, key)) controlWireText(subject[key]);
  if (kind === 'await_tool') controlWireInteger(subject.awaitCallIndex);
  if (Object.hasOwn(subject, 'awaitOrigin')) {
    const origin = controlWireRecord(subject.awaitOrigin, ['batchItemId', 'callId', 'callIndex']);
    controlWireText(origin.batchItemId); controlWireText(origin.callId); controlWireInteger(origin.callIndex);
  }
  const bytes = await app.artifact(setRef, { maxBytes: 1_048_576, signal }); signal?.throwIfAborted();
  if (bytes.length > 1_048_576 || sha256Bytes(bytes) !== setRef) throw new TypeError('child wait lost its complete original set bytes');
  const data = parseJsonStrict(new TextDecoder('utf8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!canonicalJsonBytes(data).equals(bytes)) throw new TypeError('child wait set is not canonical JSON');
  const set = controlWireRecord(data, ['schemaVersion', 'parentRunId', 'purpose', 'childRunIds']);
  const { waitSetRef: _setRef, observedStopIntentRef: _observedStop, ...purpose } = subject;
  if (set.schemaVersion !== 1 || set.parentRunId !== run.id || canonicalSha256(set.purpose) !== canonicalSha256(purpose) ||
      !Array.isArray(set.childRunIds) || set.childRunIds.length < 1 || set.childRunIds.length > 64)
    throw new TypeError('child wait set substitutes its parent, purpose or ordered handles');
  const children = set.childRunIds.map(value => controlWireText(value));
  if (new Set(children).size !== children.length || children.includes(run.id)) throw new TypeError('child wait set has invalid handles');
  return Object.freeze({ waitingOnRef: run.waitingOnRef,
    text: `${kind === 'stop_settlement' ? 'Stopping child tasks' : 'Waiting for child tasks'} (${children.length}):\n` +
      children.map(id => `  ${JSON.stringify(id)}`).join('\n') });
}
