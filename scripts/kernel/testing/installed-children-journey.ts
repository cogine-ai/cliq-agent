// The existing installed campaign owns the HTTPS endpoint, public client and
// service lifecycle. This module only adds its two closed ordinary-child cases;
// it cannot create Store/native authority or bypass public admission.
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeRunResult, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import type { InstalledWorkerIdentityInspection, InstalledWorkerRetirementInspection } from './installed-worker-lease.js';

export const INSTALLED_CHILDREN_PROFILE = 'verifier_eight_plus_children_merge_restart_and_cancel_v1';
export const INSTALLED_CHILD_CASES = ['ordinary_children', 'ordinary_children_cancel'] as const;
export type InstalledChildCase = typeof INSTALLED_CHILD_CASES[number];
type ChildEvidenceBase = { qualified: true; runId: string; childRunId: string;
  ordinarySingleWorkerScheduling: true; physicalParallelismQualified: false; independentGenerationsAndLeases: true;
  completeLocalJournalAndAccounting: true; settledExactlyOnce: true; oneRootSessionTerminal: true;
  originalHostUnchanged: true; exactAdmissionReplay: true; actualVerifierQualified: false };
export type InstalledChildEvidence = ChildEvidenceBase & (
  { kind: 'ordinary_children'; resultRef: string; childResultRef: string; parentPosts: 3; childPosts: 3;
    originalWorkersRetired: 6; publicArtifactDownloads: 4; uniquePublicArtifacts: 3;
    nonemptyMerge: true; workerFreeRestart: true; exactInputReplay: true; parentCancellationPropagated: false }
  | { kind: 'ordinary_children_cancel'; resultRef: null; childResultRef: null; parentPosts: 2; childPosts: 1;
    originalWorkersRetired: 3; publicArtifactDownloads: 0; uniquePublicArtifacts: 0;
    nonemptyMerge: false; workerFreeRestart: false; exactInputReplay: false; parentCancellationPropagated: true });
const objective = (kind: InstalledChildCase) => `Owned installed child parent: ${kind}.`;
const childObjective = (kind: InstalledChildCase) => `Owned installed child task: ${kind}.`;
const prompt = 'Release the owned child after parent await and restart checks.';
const summary = 'Owned child nonempty patch complete.';
const call = (id: string, name: string, value: unknown) => ({ id, type: 'function', function: { name, arguments: JSON.stringify(value) } });
const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
export function installedChildDelegateCall(kind: InstalledChildCase) {
  assert(INSTALLED_CHILD_CASES.includes(kind));
  return call('owned-child-delegate', 'delegate', {
    objective: childObjective(kind), mode: 'mutating', context: { source: 'parent_current', additionalArtifactRefs: [] },
    requestedBudgets: { wallTimeMs: 300000, modelTokens: 200000, costMicros: 1000000, toolCalls: 5,
      repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
    capabilities: { builtinToolNames: ['edit', 'read', 'request_input'], registeredMcpServerIds: [], allowShell: false, allowSourceWrite: true },
    verifierMode: 'none', allowUnverifiedHelper: true });
}
type Data = Record<string, any>;
type State = { runId?: string; childRunId?: string; parentPosts: number; childPosts: number;
  identities: InstalledWorkerIdentityInspection[] };
type Reader = (ref: string) => Promise<Buffer>;

async function canonical(readCas: Reader, ref: string): Promise<Data> {
  const bytes = await readCas(ref); assert.equal(sha256Bytes(bytes), ref);
  const data = parseJsonStrict(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  assert(canonicalJsonBytes(data).equals(bytes)); return data as Data;
}

export function createInstalledChildrenResponder(input: { model: string; before: string; after: string; expectedParentTools(): readonly string[];
  readCas: Reader; readCut(runId: string): Promise<Data>; observeWorker(runId: string): Promise<InstalledWorkerIdentityInspection> }) {
  const states = new Map<InstalledChildCase, State>();
  const items = async (cut: Data) => Promise.all(cut.items.map((row: Data) => canonical(input.readCas, row.payloadRef)));
  const selectChild = async (state: State) => {
    assert(state.runId); const cut = await input.readCut(state.runId), handles = (await items(cut)).filter(item => item.kind === 'child_handle');
    assert.equal(handles.length, 1); assert.equal(handles[0].runId, state.runId);
    if (state.childRunId) assert.equal(handles[0].childRunId, state.childRunId);
    state.childRunId = handles[0].childRunId; assert.notEqual(state.childRunId, state.runId); return state.childRunId!;
  };
  return {
    begin(kind: InstalledChildCase) { assert(!states.has(kind)); states.set(kind, { parentPosts: 0, childPosts: 0, identities: [] }); },
    bind(kind: InstalledChildCase, runId: string) { const state = states.get(kind)!; assert(state && !state.runId); state.runId = runId; },
    state(kind: InstalledChildCase) { const state = states.get(kind); assert(state); return state; },
    selectChild,
    objective,
    async respond(body: Data): Promise<Data | undefined> {
      const matches = INSTALLED_CHILD_CASES.flatMap(kind => {
        const isChild = body.messages.some((message: Data) => message.role === 'user' && message.content === childObjective(kind));
        const isParent = body.messages.some((message: Data) => message.role === 'user' && message.content === objective(kind));
        return isChild || isParent ? [{ kind, isChild }] : [];
      });
      if (!matches.length) return undefined;
      assert.equal(matches.length, 1); const { kind, isChild } = matches[0]!, state = states.get(kind); assert(state);
      const by = Date.now() + 5000;
      while (!state.runId) { assert(Date.now() < by); await delay(10); }
      const runId = isChild ? await selectChild(state) : state.runId;
      const ordinal = isChild ? ++state.childPosts : ++state.parentPosts;
      assert(ordinal <= (kind === 'ordinary_children' ? 3 : isChild ? 1 : 2), 'a child model claim cannot resend');
      assert.deepEqual(body.tools.map((tool: Data) => tool.function.name), isChild ? ['edit', 'read', 'request_input'] : input.expectedParentTools());
      const identity = await input.observeWorker(runId); assert.equal(identity.runId, runId); state.identities.push(identity);
      let calls: Data[] | undefined;
      if (!isChild && ordinal === 1) calls = [installedChildDelegateCall(kind)];
      else if (!isChild && ordinal === 2) {
        const id = await selectChild(state);
        const replies = body.messages.filter((message: Data) => message.role === 'tool' && message.tool_call_id === 'owned-child-delegate');
        assert.equal(replies.length, 1); assert(replies[0].content.includes(id));
        calls = [call('owned-child-await', 'await_children', { childRunIds: [id] })];
      } else if (isChild && ordinal === 1) calls = [call('owned-child-input', 'request_input', {
        prompt, responseKind: 'text', maximumResponseBytes: 128 })];
      else if (isChild && ordinal === 2) {
        assert(body.messages.some((message: Data) => message.role === 'tool' && message.tool_call_id === 'owned-child-input' && message.content.includes('owned child release')));
        calls = [call('owned-child-edit', 'edit', { path: 'example.txt', old_text: input.before, new_text: input.after })];
      } else if (isChild) {
        assert(body.messages.some((message: Data) => message.role === 'tool' && message.tool_call_id === 'owned-child-edit'));
      } else {
        const replies = body.messages.filter((message: Data) => message.role === 'tool' && message.tool_call_id === 'owned-child-await');
        assert.equal(replies.length, 1); const result = parseJsonStrict(replies[0].content) as Data;
        assert.equal(result.results.length, 1); assert.equal(result.results[0].childRunId, state.childRunId);
        assert.equal(result.results[0].summary, summary); assert.equal(result.merge.outcome, 'merged');
        assert.equal(Object.hasOwn(result, 'waitSetRef'), false); assert.equal(Object.hasOwn(result, 'childResultItemIds'), false);
      }
      return { id: `owned-${kind}-${isChild ? 'child' : 'parent'}-${ordinal}`, object: 'chat.completion', model: input.model,
        choices: [{ index: 0, finish_reason: calls ? 'tool_calls' : 'stop', message: calls ? { role: 'assistant', content: '', tool_calls: calls }
          : { role: 'assistant', content: isChild ? summary : 'Owned parent child merge complete.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
    },
  };
}

export async function runInstalledChildCase(input: { kind: InstalledChildCase; responder: ReturnType<typeof createInstalledChildrenResponder>;
  submit(objective: string): Promise<{ request: Data; response: Data; run: Data; sessionId: string; hostIdentity: unknown }>;
  send(body: Data, method: string, timeout?: number): Promise<Data>; sendFrame(body: Data, timeout?: number): Promise<Data>;
  request(body: Data): Data; nextId(): string; readCas: Reader;
  restart(cuts: readonly Data[], by: number): Promise<void>; download(cut: Data): Promise<void>;
  inspectRetired(identity: InstalledWorkerIdentityInspection): Promise<InstalledWorkerRetirementInspection>;
  assertHostUnchanged(identity: unknown): Promise<void>; mark(phase: string): void }): Promise<InstalledChildEvidence> {
  const { responder, kind } = input; input.mark(kind); responder.begin(kind);
  const admitted = await input.submit(responder.objective(kind)); responder.bind(kind, admitted.run.id);
  const state = responder.state(kind), by = Date.now() + 90000;
  let restarted = false, inputReplayed = false, cancelled = false, stoppedResponse: Data | undefined;
  let parent!: Data, child: Data | undefined;
  for (;;) {
    parent = await input.send({ protocolVersion: 1, method: 'run.get', runId: admitted.run.id }, 'run.get');
    if (!state.childRunId && parent.items.some((row: Data) => row.kind === 'child_handle')) await responder.selectChild(state);
    if (state.childRunId) child = await input.send({ protocolVersion: 1, method: 'run.get', runId: state.childRunId }, 'run.get');
    if (child && parent.snapshot.run.status === 'waiting' && parent.snapshot.run.waitingReason === 'child' &&
        child.snapshot.run.status === 'waiting' && child.snapshot.run.waitingReason === 'input' && !cancelled && !inputReplayed) {
      assert.equal(parent.snapshot.run.activeWorkerLaunchId, undefined); assert.equal(child.snapshot.run.activeWorkerLaunchId, undefined);
      const wait = await canonical(input.readCas, child.snapshot.run.waitingOnRef); assert.equal(wait.kind, 'input');
      const requestRow = child.items.find((row: Data) => row.itemId === wait.inputRequestItemId); assert(requestRow);
      const requestItem = await canonical(input.readCas, requestRow.payloadRef), actualPrompt = await canonical(input.readCas, requestItem.promptRef);
      assert.equal((await canonical(input.readCas, actualPrompt.promptTextRef)).utf8, prompt);
      if (kind === 'ordinary_children') {
        await input.restart([parent, child], by); restarted = true;
        assert.deepEqual(await input.sendFrame(admitted.request, 30000), admitted.response);
        const frame = input.request({ protocolVersion: 1, method: 'run.input', requestId: input.nextId(), runId: state.childRunId,
          expectedRevision: child.snapshot.run.revision, waitingOnRef: child.snapshot.run.waitingOnRef,
          input: { kind: 'text', value: 'owned child release' } });
        const response = await input.sendFrame(frame); assert.equal(response.ok, true);
        assert.deepEqual(await input.sendFrame(frame), response); inputReplayed = true;
      } else {
        const frame = input.request({ protocolVersion: 1, method: 'run.cancel', requestId: input.nextId(), runId: admitted.run.id,
          expectedRevision: parent.snapshot.run.revision });
        stoppedResponse = await input.sendFrame(frame); assert.equal(stoppedResponse.ok, true);
        assert.deepEqual(await input.sendFrame(frame), stoppedResponse); cancelled = true;
      }
    }
    if (child && ['completed_unverified', 'cancelled', 'failed', 'succeeded'].includes(parent.snapshot.run.status) &&
        ['completed_unverified', 'cancelled', 'failed', 'succeeded'].includes(child.snapshot.run.status)) break;
    assert(Date.now() < by, 'ordinary child closure did not reach its two genuine terminals within the original 90 seconds');
    await delay(50);
  }
  assert(child); const root = parent.snapshot.run, helper = child.snapshot.run;
  assert.equal(helper.parentRunId, root.id); assert.equal(helper.sessionId, root.sessionId);
  assert.equal(root.activeWorkerLaunchId, undefined); assert.equal(helper.activeWorkerLaunchId, undefined);
  assert.equal(root.waitingOnRef, undefined); assert.equal(helper.waitingOnRef, undefined);
  const parentItems = await Promise.all(parent.items.map((row: Data) => canonical(input.readCas, row.payloadRef)));
  const childItems = await Promise.all(child.items.map((row: Data) => canonical(input.readCas, row.payloadRef)));
  assert.equal(parentItems.filter(item => item.kind === 'child_handle').length, 1);
  assert.equal(parentItems.filter(item => item.kind === 'child_result').length, 1);
  assert.equal(childItems.filter(item => item.kind === 'user_input').length, kind === 'ordinary_children' ? 1 : 0);
  const expectedLocal = kind === 'ordinary_children' ? ['child_admission', 'child_await', 'child_merge'] : ['child_admission', 'child_await'];
  for (const local of expectedLocal) {
    const rows = parent.journal.filter((row: Data) => row.opKind === local);
    assert.deepEqual(rows.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    assert(rows.every((row: Data) => row.attempt === 0 && row.leaseEpoch === 0 && !row.sandboxLaunchSpecRef && !row.brokerFenceTokenDigest));
    assert.equal(rows[0].budgetDelta.toolCalls, 1); assert.equal(rows[1].budgetDelta.toolCalls, 0); assert.equal(rows[2].budgetDelta.toolCalls, 1);
    if (local === 'child_await') assert(rows.every((row: Data) => !row.grantRef));
    const settlement = await canonical(input.readCas, rows[2].budgetSettlementRef);
    assert.equal(settlement.settlementDigest, digestOmitting(settlement, 'settlementDigest'));
    assert.equal(settlement.consumed.toolCalls, 1); assert.equal(settlement.terminalJournalSeq, rows[2].seq);
  }
  for (const cut of [parent, child]) {
    assert(cut.journal.every((row: Data) => row.phase !== 'unknown'));
    assert.equal(cut.journal.filter((row: Data) => row.opKind === 'verifier').length, 0);
    assert.equal(canonicalSha256(cut.snapshot.run.budgetReserved), canonicalSha256(zero));
    const claims = cut.journal.filter((row: Data) => row.opKind === 'model' && row.phase === 'dispatch_claimed');
    assert.equal(claims.length, cut === parent ? state.parentPosts : state.childPosts);
    assert.equal(new Set(claims.map((row: Data) => row.dispatchId)).size, claims.length);
  }
  const parentIdentities = state.identities.filter(identity => identity.runId === root.id), childIdentities = state.identities.filter(identity => identity.runId === helper.id);
  assert.equal(parentIdentities.length, state.parentPosts); assert.equal(childIdentities.length, state.childPosts);
  assert(parentIdentities.length > 0 && childIdentities.length > 0);
  for (const left of parentIdentities) for (const right of childIdentities) {
    assert.notEqual(left.launchId, right.launchId); assert.notEqual(left.workspaceGenerationRef, right.workspaceGenerationRef);
    assert.notEqual(left.workerIdentityDigest, right.workerIdentityDigest);
  }
  const retirements = await Promise.all([...new Map(state.identities.map(identity => [identity.launchId, identity])).values()].map(input.inspectRetired));
  assert.equal(retirements.length, kind === 'ordinary_children' ? 6 : 3);
  const session = await input.send({ protocolVersion: 1, method: 'session.get', sessionId: admitted.sessionId }, 'session.get');
  const terminalItems = await Promise.all(session.items.map((row: Data) => canonical(input.readCas, row.payloadRef)));
  assert.equal(terminalItems.filter(item => item.kind === 'run_terminal' && item.runId === root.id).length, 1);
  assert.equal(terminalItems.filter(item => item.kind === 'run_terminal' && item.runId === helper.id).length, 0);
  if (kind === 'ordinary_children') {
    assert(restarted && inputReplayed && !cancelled); assert.equal(state.parentPosts, 3); assert.equal(state.childPosts, 3);
    assert.equal(root.status, 'completed_unverified'); assert.equal(helper.status, 'completed_unverified');
    const result = decodeRunResult(await canonical(input.readCas, root.resultRef)), childResult = decodeRunResult(await canonical(input.readCas, helper.resultRef));
    const merged = parentItems.filter(item => item.kind === 'child_merge_result'); assert.equal(merged.length, 1); assert.equal(merged[0].outcome, 'merged');
    const item = parentItems.find(item => item.kind === 'child_result')!; assert(item.patchManifestRef);
    const patch = await canonical(input.readCas, item.patchManifestRef); assert.equal(patch.childRunId, helper.id);
    assert.equal(patch.operations.length, 1); assert.equal(patch.operations[0].path, 'example.txt'); assert.equal(patch.operations[0].kind, 'modify');
    const diff = decodeWorkspaceDiff(await canonical(input.readCas, result.diffRef)); assert.equal(diff.operations.length, 1);
    assert.equal(diff.operations[0]!.path, 'example.txt'); assert.equal(result.baseSourceRef, childResult.baseSourceRef);
    assert.equal(result.resultSourceRef, childResult.resultSourceRef); assert.equal(result.diffRef, childResult.diffRef);
    assert.notEqual(root.resultRef, helper.resultRef);
    assert.equal(root.budgetConsumed.modelTokens, 6 * 36864); assert.equal(helper.budgetConsumed.modelTokens, 3 * 36864);
    assert.equal(root.budgetConsumed.toolCalls, 4); assert.equal(helper.budgetConsumed.toolCalls, 1);
    assert.equal(child.journal.filter((row: Data) => row.opKind === 'tool' && row.phase === 'dispatch_claimed').length, 1);
    await input.download(child); await input.download(parent);
  } else {
    assert(cancelled && !restarted && !inputReplayed && stoppedResponse); assert.equal(state.parentPosts, 2); assert.equal(state.childPosts, 1);
    assert.equal(root.status, 'cancelled'); assert.equal(root.terminalReason, 'cancelled_by_user');
    assert.equal(helper.status, 'cancelled'); assert.equal(helper.terminalReason, 'parent_cancelled'); assert(helper.parentCancellationRef);
    const revocation = await canonical(input.readCas, helper.parentCancellationRef);
    assert.equal(revocation.origin, 'parent_cancel'); assert.equal(revocation.sourceRunId, root.id); assert.equal(revocation.sourceStopIntentRef, root.stopIntentRef);
    assert.equal(helper.stopIntentRef, helper.parentCancellationRef);
    assert.equal(root.budgetConsumed.modelTokens, 3 * 36864); assert.equal(helper.budgetConsumed.modelTokens, 36864);
    assert.equal(root.budgetConsumed.toolCalls, 2); assert.equal(helper.budgetConsumed.toolCalls, 0);
    assert.equal(parent.journal.some((row: Data) => row.opKind === 'child_merge'), false);
    assert.equal(child.journal.some((row: Data) => row.opKind === 'tool'), false);
    for (const cut of [parent, child]) for (const method of ['run.result', 'run.diff']) {
      const unavailable = await input.sendFrame({ protocolVersion: 1, method, runId: cut.snapshot.run.id });
      assert.equal(unavailable.ok, false); assert.equal(unavailable.error.code, 'RESULT_UNAVAILABLE');
    }
  }
  for (const cut of [parent, child]) {
    assert.equal(cut.snapshot.run.budgetConsumed.costMicros, 0); assert.equal(cut.snapshot.run.budgetConsumed.repairAttempts, 0);
    assert.deepEqual(await input.send({ protocolVersion: 1, method: 'run.get', runId: cut.snapshot.run.id }, 'run.get'), cut);
  }
  assert.deepEqual(await input.sendFrame(admitted.request, 30000), admitted.response);
  await input.assertHostUnchanged(admitted.hostIdentity);
  const common = { qualified: true, runId: root.id as string, childRunId: helper.id as string,
    ordinarySingleWorkerScheduling: true, physicalParallelismQualified: false,
    independentGenerationsAndLeases: true, completeLocalJournalAndAccounting: true, settledExactlyOnce: true,
    oneRootSessionTerminal: true, originalHostUnchanged: true, exactAdmissionReplay: true,
    actualVerifierQualified: false } as const;
  return kind === 'ordinary_children' ? { ...common, kind, resultRef: root.resultRef, childResultRef: helper.resultRef,
    parentPosts: 3, childPosts: 3, originalWorkersRetired: 6, publicArtifactDownloads: 4, uniquePublicArtifacts: 3, nonemptyMerge: true, workerFreeRestart: true,
    exactInputReplay: true, parentCancellationPropagated: false }
    : { ...common, kind, resultRef: null, childResultRef: null, parentPosts: 2, childPosts: 1, originalWorkersRetired: 3,
      publicArtifactDownloads: 0, uniquePublicArtifacts: 0, nonemptyMerge: false, workerFreeRestart: false, exactInputReplay: false, parentCancellationPropagated: true };
}
