import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { RunSubmitRequest } from '../../../src/kernel/control-submit.js';
import type { ArtifactDescriptorV1, SessionContextProjection } from '../../../src/kernel/types.js';
import type { SessionHandoffV1 } from '../../../src/kernel/session-continuity.js';
import { controlWireRecord, controlWireInteger } from '../../../src/kernel/control-wire-data.js';

type Data = Record<string, any>;
type Inputs = Readonly<{
  send(request: Data): Promise<Data>; readCas(ref: string): Promise<Buffer>; closeClient(): Promise<void>;
  parentSessionId: string; submission: Omit<RunSubmitRequest, 'requestId' | 'requestDigest' | 'admissionKey' | 'sessionId' | 'expectedContextRevision' | 'objective'>;
  registerSubmission(request: Data): void; counts(): readonly [number, number, number]; providerHealthy(): boolean;
  enableResume(summaryUtf8: string, retainedUtf8: string): void;
  verifyResult(cut: Data, session: Data): Promise<unknown>;
}>;
const accepted = (reply: Data, method: string): Data => { assert.equal(reply.protocolVersion, 1); assert.equal(reply.ok, true); assert.equal(reply.result.method, method); return reply.result; };
const mutation = (core: Data) => ({ ...core, requestDigest: canonicalSha256(core) });
const sessionGet = (sessionId: string) => ({ protocolVersion: 1, method: 'session.get', sessionId });
const objective = 'Continue the compacted Session as a new Run without editing any file.';
export function assertInstalledSessionResumeBudget(value: unknown, expected: { modelTokens: number; costMicros: number; toolCalls: number; repairAttempts: number }): void {
  const data = controlWireRecord(value, ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts']);
  for (const field of ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts']) controlWireInteger(data[field]);
  assert.deepEqual(canonicalJsonBytes(data), canonicalJsonBytes(expected));
}

/** Genuine installed consumer only. This adds no StateOwner, permission,
 * resource proof or alternate execution recipe; every new effect goes through
 * the existing authenticated public admission and physical result verifier. */
export async function qualifyInstalledSessionContinuity(input: Inputs): Promise<Readonly<Data>> {
  const beforeCounts = input.counts(); assert.equal(beforeCounts[0], 4); assert(input.providerHealthy());
  const parentCut = accepted(await input.send(sessionGet(input.parentSessionId)), 'session.get'), parent = parentCut.snapshot.session;
  const projection = parseJsonStrict((await input.readCas(parent.contextProjectionRef)).toString('utf8')) as SessionContextProjection;
  assert.equal(projection.sessionId, parent.id); assert.equal(projection.contextRevision, parent.contextRevision);
  assert.equal(projection.projectionDigest, digestOmitting(projection, 'projectionDigest'));
  const raw = projection.segments[0]; assert(raw && raw.kind === 'raw' && raw.fromItemSeq === 1 && raw.items.length > 0);
  const retained = raw.items[0]!;
  const compact = mutation({ protocolVersion: 1, method: 'session.compact', requestId: '019a0012-0000-7000-8000-000000000900',
    sessionId: parent.id, expectedContextRevision: parent.contextRevision, fromItemSeq: raw.fromItemSeq, throughItemSeq: raw.throughItemSeq,
    summaryMarkdown: 'Installed Session continuity\r\nPreserve the original completed work.', retainedItemIds: [retained.itemId] });
  const compactReply = await input.send(compact), compacted = accepted(compactReply, 'session.compact').snapshot.session;
  assert.equal(compacted.contextRevision, parent.contextRevision + 1); assert.equal(compacted.latestItemSeq, parent.latestItemSeq + 1);
  assert.deepEqual(await input.send(compact), compactReply);
  const fork = mutation({ protocolVersion: 1, method: 'session.fork', requestId: '019a0012-0000-7000-8000-000000000901',
    admissionKey: randomBytes(32).toString('base64url'), sessionId: parent.id, expectedContextRevision: compacted.contextRevision,
    throughItemSeq: raw.throughItemSeq, name: 'Installed Session continuation' });
  const forkReply = await input.send(fork), child = accepted(forkReply, 'session.fork').snapshot.session;
  assert.equal(child.parentSessionId, parent.id); assert.equal(child.forkedThroughItemSeq, raw.throughItemSeq);
  assert.equal(child.contextRevision, 1); assert.equal(child.latestItemSeq, raw.throughItemSeq); assert.notEqual(child.id, parent.id);
  const childCut = accepted(await input.send(sessionGet(child.id)), 'session.get');
  assert.deepEqual(childCut.items, parentCut.items.filter((item: Data) => item.itemSeq <= raw.throughItemSeq));
  const handoffRequest = { protocolVersion: 1, method: 'session.handoff.create', sessionId: child.id, expectedContextRevision: child.contextRevision };
  const handoffReply = await input.send(handoffRequest), descriptors = accepted(handoffReply, 'session.handoff.create');
  const download = async (descriptor: ArtifactDescriptorV1): Promise<Buffer> => {
    const chunks: Buffer[] = []; let offset = 0;
    assert(descriptor.sizeBytes > 0 && descriptor.sizeBytes <= 1048576);
    for (;;) {
      const reply = accepted(await input.send({ protocolVersion: 1, method: 'artifact.get', digest: descriptor.ref, offset, length: 65536 }), 'artifact.get');
      assert.deepEqual(reply.artifact, descriptor); assert.equal(reply.offset, offset);
      const bytes = Buffer.from(reply.bytesBase64, 'base64'); assert.equal(bytes.toString('base64'), reply.bytesBase64);
      assert(bytes.length <= 65536); assert.equal(reply.nextOffset, offset + bytes.length); offset = reply.nextOffset; chunks.push(bytes);
      assert.equal(reply.eof, offset === descriptor.sizeBytes); if (reply.eof) break; assert(bytes.length > 0);
    }
    const bytes = Buffer.concat(chunks, offset); assert.equal(sha256Bytes(bytes), descriptor.digest); assert.equal(descriptor.ref, descriptor.digest);
    assert.deepEqual(bytes, await input.readCas(descriptor.ref)); return bytes;
  };
  const json = await download(descriptors.json), markdown = await download(descriptors.markdown), handoff = parseJsonStrict(json.toString('utf8')) as SessionHandoffV1;
  assert.deepEqual(canonicalJsonBytes(handoff), json); assert.equal(handoff.handoffDigest, digestOmitting(handoff, 'handoffDigest'));
  assert.equal(handoff.contextProjectionRef, child.contextProjectionRef); assert.equal(handoff.contextRevision, 1); assert.equal(handoff.throughItemSeq, raw.throughItemSeq);
  assert.deepEqual(handoff.entries.map(entry => entry.sourceKind), ['summary', 'run_terminal']); assert.deepEqual(handoff.excludedRanges, []);
  assert.equal(handoff.entries[0]!.contentUtf8, 'Installed Session continuity\nPreserve the original completed work.');
  assert.equal(handoff.entries[1]!.sourceRef, retained.payloadRef);
  assert(markdown.toString('utf8').includes('    Installed Session continuity\n    Preserve the original completed work.\n'));
  assert.deepEqual(await input.send(handoffRequest), handoffReply);
  const listRequest = { protocolVersion: 1, method: 'session.list', workspacePath: input.submission.workspacePath, limit: 1 };
  const list = accepted(await input.send(listRequest), 'session.list'); assert.equal(list.sessions.length, 1); assert.equal(typeof list.nextCursor, 'string');
  const pageRequest = { ...listRequest, cursor: list.nextCursor }, page = await input.send(pageRequest);
  accepted(page, 'session.list');
  await input.closeClient();
  assert.deepEqual(await input.send(compact), compactReply); assert.deepEqual(await input.send(fork), forkReply);
  assert.deepEqual(await input.send(handoffRequest), handoffReply); assert.deepEqual(await input.send(pageRequest), page);
  assert.deepEqual(input.counts(), beforeCounts, 'context operations and explicit reconnect cannot dispatch a provider request');
  const observed = accepted(await input.send(sessionGet(child.id)), 'session.get').snapshot.session;
  const resume = mutation({ ...input.submission, requestId: '019a0012-0000-7000-8000-000000000902', admissionKey: randomBytes(32).toString('base64url'),
    sessionId: child.id, expectedContextRevision: observed.contextRevision, objective });
  input.registerSubmission(resume); input.enableResume(handoff.entries[0]!.contentUtf8, handoff.entries[1]!.contentUtf8);
  const admittedReply = await input.send(resume), admitted = accepted(admittedReply, 'run.submit').snapshot.run;
  assert.notEqual(admitted.id, (parseJsonStrict(handoff.entries[1]!.contentUtf8) as Data).runId); assert.equal(admitted.sessionId, child.id); assert.equal(admitted.status, 'queued');
  const by = Date.now() + 90000; let cut: Data;
  for (;;) {
    assert(Date.now() < by, 'new resumed Run did not finish within its original integration deadline'); assert(input.providerHealthy());
    cut = accepted(await input.send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }), 'run.get');
    if (cut.snapshot.run.status === 'completed_unverified') break;
    assert(['queued', 'running', 'waiting'].includes(cut.snapshot.run.status)); await delay(50);
  }
  assert.equal(cut.snapshot.run.leaseEpoch, 1); assert.equal(cut.snapshot.run.activeWorkerLaunchId, undefined);
  assertInstalledSessionResumeBudget(cut.snapshot.run.budgetConsumed, { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
  assertInstalledSessionResumeBudget(cut.snapshot.run.budgetReserved, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
  assert.deepEqual(cut.journal.map((entry: Data) => [entry.opKind, entry.phase]), [['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed']]);
  assert.equal(cut.highWaterJournalSeq, 3); assert.equal(cut.nextJournalSeq, 3);
  const prepared = parseJsonStrict((await input.readCas(cut.journal[0].requestRef)).toString('utf8')) as Data;
  const prompt = parseJsonStrict((await input.readCas(prepared.promptProjectionRef)).toString('utf8')) as Data;
  assert.deepEqual(prompt.messages.filter((message: Data) => message.sourceKind === 'session_summary' || message.sourceKind === 'session_terminal')
    .map((message: Data) => message.contentUtf8), handoff.entries.map(entry => entry.contentUtf8));
  const resultProof = await input.verifyResult(cut, child);
  assert(resultProof !== undefined);
  assert.deepEqual(await input.send(resume), admittedReply); assert.deepEqual(await input.send(compact), compactReply); assert.deepEqual(await input.send(fork), forkReply);
  assert.deepEqual(input.counts(), beforeCounts.map(value => value + 1)); assert(input.providerHealthy());
  return Object.freeze({ qualified: true, contextOnlyOperationsPreservedOriginalCounts: true, summaryAndRetainedTerminalReachedProvider: true,
    deterministicHandoffDownloadedAndRehashed: true, frozenListPageSurvivedExplicitReconnect: true, firstResponsesReplayed: true,
    newRunId: admitted.id, originalProviderRequests: beforeCounts[0], additionalProviderRequests: 1, newJournalEntries: 3,
    uniqueTerminalPublicationAndPhysicalRetirement: resultProof !== undefined, fullI1Qualified: false });
}

export const installedSessionResumeObjective = objective;
