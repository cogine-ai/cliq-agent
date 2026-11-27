// Fixed fixture-owner decisions over the installed entry and authenticated v1
// UDS. This module creates no Store, SQL writer, native proof or live grant.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chown, lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeDeliveryPlan, decodeDeliveryTerminalProjectionEvidence } from '../../../src/kernel/publication.js';
import { decodeRunResult, decodeVerificationClosure } from '../../../src/state/result-artifacts.js';
import { decodeSourceManifest, decodeWorkspaceEntries } from '../../../src/state/decoders.js';
import { readVerifierWaitingPresentation } from '../../../src/client/verifier-presentation.js';
import { decodeAgentStop } from '../../../src/runtime/stop.js';
import { decodeVerifierSkipItem } from '../../../src/state/verifier-artifacts.js';
import { INSTALLED_PERMISSION_CASES, INSTALLED_PERMISSION_PROFILE, decodeInstalledPermissionReport,
  type InstalledPermissionCase, type InstalledPermissionCaseResult } from './installed-permission-result.js';

type Data = Record<string, any>;
type Response = { protocolVersion: 1; ok: boolean; result?: Data; error?: Data };
type Reader = (ref: string) => Promise<Buffer>;
const BEFORE = 'before the owned ordinary permission edit\n';
const BAD = 'first owned candidate fails its required assertion\n';
const AFTER = 'after the owned ordinary permission repair\n';
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const objective = (kind: InstalledPermissionCase) => `Owned ordinary permission case: ${kind}. Change only example.txt; keep check.test.mjs unchanged.`;
const repair = (kind: InstalledPermissionCase) => kind === 'default_repair' || kind === 'template_repair';
const template = (kind: InstalledPermissionCase) => kind === 'template_repair' || kind === 'template_retry';
const signed = (core: Data) => ({ ...core, requestDigest: canonicalSha256(core) });
const same = (left: unknown, right: unknown) => assert.equal(canonicalSha256(left), canonicalSha256(right));
const accepted = (response: Response, method: string): Data => {
  assert.equal(response.protocolVersion, 1); assert.equal(response.ok, true, 'fixed ordinary permission request refused');
  assert.equal(response.result?.method, method); return response.result!;
};
async function object(read: Reader, ref: string): Promise<Data> {
  assert.match(ref, /^[0-9a-f]{64}$/u); const bytes = await read(ref); assert(bytes.length <= 1_048_576);
  assert.equal(sha256Bytes(bytes), ref);
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert(canonicalJsonBytes(value).equals(bytes)); return value as Data;
}
const identity = async (filename: string) => {
  const info = await lstat(filename, { bigint: true }); assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1n);
  return Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'].map(key => [key, info[key as keyof typeof info]!.toString()]));
};

/** The owned HTTPS server invokes this after its original body/secret scan.
 * Literal objectives and bounded ordinals select the entire fixed response. */
export function createInstalledPermissionResponder(model: string, expectedTools: () => readonly string[]) {
  const states = new Map<InstalledPermissionCase, { posts: number }>();
  return {
    begin(kind: InstalledPermissionCase) { assert(!states.has(kind)); states.set(kind, { posts: 0 }); },
    posts(kind: InstalledPermissionCase) { const state = states.get(kind); assert(state); return state.posts; },
    respond(body: Data): Data | undefined {
      const matches = INSTALLED_PERMISSION_CASES.filter(kind => body.messages.some((message: Data) => message.role === 'user' && message.content === objective(kind)));
      if (!matches.length) return;
      assert.equal(matches.length, 1); const kind = matches[0]!, state = states.get(kind); assert(state);
      assert.deepEqual(body.tools.map((tool: Data) => tool.function.name), expectedTools());
      const ordinal = ++state.posts; assert(ordinal <= (repair(kind) ? 4 : 2), 'a completed permission model claim must never resend');
      const editing = ordinal === 1 || repair(kind) && ordinal === 3;
      if (ordinal > 1) assert.equal(body.messages.filter((message: Data) => message.role === 'tool' &&
        message.tool_call_id === `owned-permission-edit-${ordinal % 2 === 0 ? ordinal - 1 : 1}`).length, 1);
      if (ordinal === 3) assert(body.messages.some((message: Data) => typeof message.content === 'string' &&
        message.content.includes('Verifier "node-tests" failed an assertion (exit 1). Revise the candidate and try again.')));
      return { id: `owned-permission-${kind}-${ordinal}`, object: 'chat.completion', model,
        choices: [{ index: 0, finish_reason: editing ? 'tool_calls' : 'stop', message: editing ? { role: 'assistant', content: '',
          tool_calls: [{ id: `owned-permission-edit-${ordinal}`, type: 'function', function: { name: 'edit', arguments: JSON.stringify({
            path: 'example.txt', old_text: ordinal === 1 ? BEFORE : BAD, new_text: repair(kind) && ordinal === 1 ? BAD : AFTER }) } }] }
          : { role: 'assistant', content: 'The owned private candidate is ready for its exact Node check.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
    }
  };
}

export type InstalledPermissionContext = {
  workspaceRoot: string; cliqHome: string; uid: number; gid: number; model: Data; guestToolchainManifestId: string;
  send(frame: Data, timeout?: number): Promise<Response>; nextId(): string; readCas: Reader; download: Reader;
  reconnect(): Promise<void>; restart(): Promise<void>; assertWorkerFree(runId: string, cut: Data): Promise<void>;
  assertVerifierEvidence(cut: Data, kind: InstalledPermissionCase, files: readonly { path: string; before: string; after: string }[]): Promise<void>;
  assertDeliveryEvidence(cut: Data, sourceCut: Data, files: ReadonlyMap<string, string>, local: boolean): Promise<void>;
  assertConsumedDeliveryGrant(cut: Data, grantId: string): Promise<void>;
  responder: ReturnType<typeof createInstalledPermissionResponder>; mark(phase: string): void;
};

export async function runInstalledPermissionCases(context: InstalledPermissionContext) {
  const send = async (core: Data, timeout = 30000) => accepted(await context.send(core, timeout), String(core.method));
  const get = (runId: string) => send({ protocolVersion: 1, method: 'run.get', runId });
  const read = (ref: string) => object(context.readCas, ref);
  const createIdentity = async () => (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(), decision: {
    kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: context.guestToolchainManifestId, toolId: 'node' } } }))).grant;
  const execution = async (verifier: Data, maxima: number, ttlMs?: number) => {
    const { executionGrantId: _ignored, ...core } = verifier;
    return (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(),
      ...(ttlMs === undefined ? {} : { ttlMs }), decision: { kind: 'verifier_execution', verifierId: verifier.id,
        verifierRequestDigest: canonicalSha256(core), executionIdentityGrantId: verifier.identityReadGrantId,
        maxCandidateGenerations: maxima, maxAttemptsPerCandidate: (verifier.retries ?? 0) + 1 } }))).grant;
  };
  const approve = async (cut: Data, decision: 'allow' | 'deny') => {
    const run = cut.snapshot.run, frame = signed({ protocolVersion: 1, method: 'run.approve', requestId: context.nextId(),
      runId: run.id, expectedRevision: run.revision, waitingOnRef: run.waitingOnRef, decision,
      ...(decision === 'allow' ? { ttlMs: 30000 } : {}) });
    const response = await context.send(frame); accepted(response, 'run.approve');
    assert.deepEqual(await context.send(frame), response, 'exact approval replay must preserve the original response');
    return { frame, response };
  };
  const wait = async (cut: Data, kind: 'verifier_launch' | 'tool_call' | 'delivery_plan', candidateFiles?: ReadonlyMap<string, string>) => {
    const run = cut.snapshot.run; assert.equal(run.status, 'waiting'); assert.equal(run.waitingReason, 'approval');
    assert.equal(run.activeWorkerLaunchId, undefined); same(run.budgetReserved, ZERO);
    await context.assertWorkerFree(run.id, cut);
    const value = await read(run.waitingOnRef); assert.equal(value.kind, 'approval'); assert.equal(value.runId, run.id);
    assert.equal(value.frontierRef, run.frontierRef); assert.equal(value.subject.kind, kind);
    const evidence = await read(value.subject.policyChannelEvidenceRef);
    assert.equal(evidence.evidenceDigest, digestOmitting(evidence, 'evidenceDigest'));
    assert.equal(evidence.effectiveDisposition, 'ask'); assert.equal(evidence.runId, run.id);
    assert.equal(evidence.frontierRef, run.frontierRef); assert.equal(evidence.opId, value.subject.opId);
    const request = await read(evidence.requestRef), target = await read(evidence.targetRef);
    assert.equal(request.requestDigest, digestOmitting(request, 'requestDigest'));
    assert.equal(target.targetDigest, digestOmitting(target, 'targetDigest'));
    assert.equal(request.targetRef, evidence.targetRef); assert.equal(request.targetDigest, target.targetDigest);
    if (kind === 'verifier_launch') {
      await readVerifierWaitingPresentation({ artifact: async (ref, options) => { const bytes = await context.download(ref); assert(bytes.length <= options.maxBytes); return bytes; } }, cut.snapshot, value);
      assert.equal(value.subject.verifierId, 'node-tests'); assert.equal(value.subject.verifierIndex, 0);
      const command = await read(target.commandRef); same(command.argv, ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })));
      assert.equal(command.cwd, '.'); assert.equal(target.candidateItemId, value.subject.candidateItemId);
      assert(candidateFiles); const source = decodeSourceManifest(await read(target.resultSourceRef));
      const entries = decodeWorkspaceEntries(await read(source.entriesRef));
      assert.equal(source.manifestDigest, target.sourceDigest); assert.equal(entries.treeDigest, source.treeDigest);
      assert.equal(entries.entries.length, candidateFiles.size);
      for (const entry of entries.entries) {
        assert.equal(entry.kind, 'file'); if (entry.kind !== 'file') throw new Error('owned candidate changed a fixed file kind');
        const expected = candidateFiles.get(entry.path); assert(expected !== undefined);
        assert.equal(entry.mode, 0o644); assert.equal(entry.size, Buffer.byteLength(expected));
        assert.equal(entry.blobRef, sha256Bytes(Buffer.from(expected))); assert((await context.download(entry.blobRef)).equals(Buffer.from(expected)));
      }
    } else if (kind === 'tool_call') {
      assert.equal(value.subject.toolName, 'edit'); assert.equal(value.subject.callIndex, 0); assert.equal(request.toolName, 'edit');
      const input = await read(request.inputRef); assert.equal(input.disposition, 'resolved'); assert.equal(input.toolName, 'edit');
      assert.equal(input.value.path, 'example.txt');
      assert(input.value.old_text === BEFORE && input.value.new_text === BAD || input.value.old_text === BAD && input.value.new_text === AFTER);
      assert.equal(value.subject.callId, `owned-permission-edit-${input.value.old_text === BEFORE ? 1 : 3}`);
    } else {
      const plan = decodeDeliveryPlan(await read(value.subject.deliveryPlanRef));
      assert.equal(plan.deliveryRunId, run.id); assert.equal(plan.forwardOperations.length, 1); assert.equal(plan.abortOperations.length, 0);
      const operation = plan.forwardOperations[0]!; assert.equal(operation.path, 'example.txt'); assert.equal(operation.kind, 'replace');
      assert.equal(operation.expected.kind, 'file'); assert.equal(operation.desired.kind, 'file');
      if (operation.expected.kind !== 'file' || operation.desired.kind !== 'file') throw new Error('fixed permission publication has no complete file pair');
      assert((await context.download(operation.expected.digest)).equals(Buffer.from(BEFORE)));
      assert((await context.download(operation.desired.digest)).equals(Buffer.from(AFTER)));
    }
    return value;
  };
  const review = async (cut: Data, files: ReadonlyMap<string, string>) => {
    const run = cut.snapshot.run, result = decodeRunResult(await read(run.resultRef)), closure = decodeVerificationClosure(await read(result.verificationClosureRef));
    assert.equal(result.runId, run.id); assert.equal(closure.runId, run.id); assert.equal(closure.resultSourceRef, result.resultSourceRef);
    for (const method of ['run.result', 'run.diff']) {
      const value = await send({ protocolVersion: 1, method, runId: run.id }), descriptor = method === 'run.result' ? value.result : value.diff;
      const bytes = await context.download(descriptor.ref); assert.equal(bytes.length, descriptor.sizeBytes); assert.equal(sha256Bytes(bytes), descriptor.ref);
      assert.equal(descriptor.ref, method === 'run.result' ? run.resultRef : result.diffRef);
    }
    const source = decodeSourceManifest(await read(result.resultSourceRef)), entries = decodeWorkspaceEntries(await read(source.entriesRef));
    assert.equal(source.treeDigest, entries.treeDigest); assert.equal(entries.entries.length, files.size);
    for (const entry of entries.entries) {
      assert.equal(entry.kind, 'file'); if (entry.kind !== 'file') throw new Error('fixed permission review contains another entry kind');
      const expected = files.get(entry.path); assert(expected !== undefined); const bytes = await context.download(entry.blobRef);
      assert.equal(bytes.length, entry.size); assert.equal(sha256Bytes(bytes), entry.blobRef); assert(bytes.equals(Buffer.from(expected)));
    }
    assert.deepEqual(await get(run.id), cut, 'result inspection must not advance the Run'); return { result, closure };
  };
  type Source = { cut: Data; submit: Data; response: Response; workspace: string; files: Map<string, string>; verifier: Data; executionGrantId?: string };
  const sources = new Map<InstalledPermissionCase, Source>(), results: InstalledPermissionCaseResult[] = [];
  let restarted = false, wrongChecked = false;
  for (const kind of INSTALLED_PERMISSION_CASES) {
    context.mark(`permission_${kind}`); const workspace = path.join(context.workspaceRoot, `permission-${kind}`);
    await mkdir(workspace, { mode: 0o700 }); await chown(workspace, context.uid, context.gid);
    const check = kind === 'template_retry'
      ? "import test from 'node:test';test('owned bounded timeout',async()=>await new Promise(resolve=>setTimeout(resolve,60000)));\n"
      : "import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';test('owned exact private edit',async()=>assert.equal(await readFile(new URL('./example.txt',import.meta.url),'utf8')," + JSON.stringify(AFTER) + "));\n";
    for (const [name, text] of [['example.txt', BEFORE], ['check.test.mjs', check]]) {
      const filename = path.join(workspace, name!); await writeFile(filename, text!, { flag: 'wx', mode: 0o644 }); await chown(filename, context.uid, context.gid);
    }
    const host = await identity(path.join(workspace, 'example.txt'));
    const workspaceId = sha256Bytes(Buffer.from(workspace)), trustDirectory = path.join(context.cliqHome, 'workspaces', workspaceId);
    await mkdir(trustDirectory, { recursive: true, mode: 0o700 });
    for (const directory of [path.dirname(trustDirectory), trustDirectory]) await chown(directory, context.uid, context.gid);
    const trust = path.join(trustDirectory, 'trust.json'); await writeFile(trust, canonicalJsonBytes({ version: 1, workspaceId,
      workspaceRealPath: workspace, decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trust, context.uid, context.gid);
    const session = (await send(signed({ protocolVersion: 1, method: 'session.create', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
      workspacePath: workspace, name: 'Owned ordinary permission' }))).snapshot.session;
    const grant = await createIdentity(); assert.equal(grant.state, 'active');
    const verifier: Data = { id: 'node-tests', version: '1', required: kind !== 'advisory_skip', executable: { kind: 'toolchain', toolId: 'node' },
      argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })), cwd: '.', env: {},
      writableEphemeralPaths: [], identityReadGrantId: grant.grantId, timeoutMs: kind === 'template_retry' ? 1000 : 10000,
      retries: kind === 'template_retry' ? 1 : 0, outputLimitBytes: 65536 };
    if (template(kind)) verifier.executionGrantId = (await execution(verifier, repair(kind) ? 2 : 1)).grantId;
    const mode = kind === 'default_repair' ? 'default' : 'accept-edits';
    const submit = signed({ protocolVersion: 1, method: 'run.submit', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
      sessionId: session.id, expectedContextRevision: session.contextRevision, workspacePath: workspace, objective: objective(kind), model: context.model,
      policyMode: mode, budgets: { wallTimeMs: kind === 'waiting_deadline' ? 60000 : 300000, modelTokens: 2000000, costMicros: 10000000,
        toolCalls: 1000, repairAttempts: repair(kind) ? 1 : 0, childDepth: 0, childConcurrency: 1 }, verifiers: [verifier], dependency: { mode: 'none' },
      sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: kind === 'advisory_skip' });
    context.responder.begin(kind); const response = await context.send(submit, 30000), admitted = accepted(response, 'run.submit').snapshot.run;
    const by = Date.now() + 90000, seen = new Set<string>(), candidates = new Set<string>(); let approvals = 0, edits = 0, workerFreeWaits = 0;
    let cut: Data, denial: { frame: Data; response: Response } | undefined;
    for (;;) {
      cut = await get(admitted.id); const run = cut.snapshot.run;
      assert(Date.now() < by, 'ordinary permission terminal observation exceeded the original 90-second source window');
      if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) break;
      if (run.status === 'waiting' && run.waitingReason === 'approval') {
        const waiting = await read(run.waitingOnRef); assert(['tool_call', 'verifier_launch'].includes(waiting.subject.kind));
        if (!seen.has(run.waitingOnRef)) {
          seen.add(run.waitingOnRef); workerFreeWaits++;
          await wait(cut, waiting.subject.kind, new Map([['check.test.mjs', check],
            ['example.txt', repair(kind) && candidates.size === 0 ? BAD : AFTER]]));
          if (waiting.subject.kind === 'tool_call') { assert.equal(kind, 'default_repair'); await approve(cut, 'allow'); edits++; }
          else {
            assert(!template(kind), 'an exact consumed template must not unexpectedly ask');
            assert(!candidates.has(waiting.subject.candidateItemId), 'a single exact approval cannot silently authorize another wait'); candidates.add(waiting.subject.candidateItemId);
            if (kind === 'default_repair' && !restarted) {
              await context.reconnect(); assert.deepEqual(await get(run.id), cut);
              await context.restart(); assert.deepEqual(await get(run.id), cut); restarted = true;
              for (const fields of [{ expectedRevision: run.revision - 1, waitingOnRef: run.waitingOnRef },
                { expectedRevision: run.revision, waitingOnRef: 'a'.repeat(64) }]) {
                const refused = await context.send(signed({ protocolVersion: 1, method: 'run.approve', requestId: context.nextId(), runId: run.id,
                  ...fields, decision: 'allow', ttlMs: 30000 })); assert.equal(refused.ok, false);
                assert(['REVISION_CONFLICT', 'INVALID_REQUEST'].includes(refused.error?.code)); assert.deepEqual(await get(run.id), cut);
              }
              wrongChecked = true;
            }
            if (kind === 'waiting_cancel') {
              const frame = signed({ protocolVersion: 1, method: 'run.cancel', requestId: context.nextId(), runId: run.id, expectedRevision: run.revision });
              const response = await context.send(frame); accepted(response, 'run.cancel'); denial = { frame, response };
            }
            else if (kind !== 'waiting_deadline') {
              const decision = kind === 'required_deny' || kind === 'advisory_skip' ? 'deny' : 'allow';
              const selected = await approve(cut, decision); if (decision === 'allow') approvals++; else denial = selected;
            }
          }
        }
      }
      assert(Date.now() < by, 'ordinary permission case exceeded the original 90-second source window'); await delay(kind === 'waiting_deadline' ? 200 : 100);
    }
    const run = cut.snapshot.run, claims = cut.journal.filter((row: Data) => row.opKind === 'verifier' && row.phase === 'dispatch_claimed');
    const items = await Promise.all(cut.items.map((row: Data) => read(row.payloadRef))), candidateCount = items.filter(value => value.kind === 'final_candidate').length;
    const expected = kind === 'advisory_skip' ? 'completed_unverified' : kind === 'required_deny' || kind === 'waiting_cancel' ? 'cancelled'
      : kind === 'template_retry' || kind === 'waiting_deadline' ? 'failed' : 'succeeded';
    assert.equal(run.status, expected); same(run.budgetReserved, ZERO); await context.assertWorkerFree(run.id, cut);
    if (kind === 'required_deny' || kind === 'waiting_cancel') {
      assert.equal(run.terminalReason, 'cancelled_by_user'); assert(denial);
      const stop = decodeAgentStop(await read(run.stopIntentRef), run); assert.equal(stop.origin, 'user_cancel');
      if (stop.origin !== 'user_cancel') throw new Error('owned cancellation lost its original user decision');
      assert.equal(stop.requestId, denial.frame.requestId);
    }
    if (kind === 'waiting_deadline') { assert.equal(run.terminalReason, 'budget_exhausted'); assert(run.updatedAt >= run.deadlineAt); }
    if (kind === 'template_retry') assert.equal(run.terminalReason, 'verifier_infrastructure_failed');
    assert.equal(claims.length, repair(kind) || kind === 'template_retry' ? 2 : kind === 'accept_edits_pass' ? 1 : 0);
    if (claims.length) await context.assertVerifierEvidence(cut, kind, [
      { path: 'check.test.mjs', before: check, after: check }, { path: 'example.txt', before: BEFORE, after: AFTER }]);
    if (kind === 'advisory_skip') {
      const skips = items.filter(value => value.kind === 'verifier_skip').map(decodeVerifierSkipItem); assert.equal(skips.length, 1); assert.equal(skips[0]!.outcome, 'skipped_by_user');
      assert(denial); assert.equal(skips[0]!.decisionRef, denial.response.result!.decisionRef);
      assert.equal(items.filter(value => value.kind === 'verifier_result').length, 0);
    }
    if (kind === 'required_deny' || kind === 'advisory_skip') {
      assert(denial); const policies = items.filter(value => value.kind === 'policy_decision' && value.subjectKind === 'verifier_launch');
      assert.equal(policies.length, 1); const policy = policies[0]!;
      assert.equal(policy.decisionSource, 'interactive_approval'); assert.equal(policy.decision, 'deny');
      assert.equal(policy.decisionRef, denial.response.result!.decisionRef); assert.equal(policy.waitingSubjectRef, denial.frame.waitingOnRef);
      assert.equal(policy.denialOutcome.kind, kind === 'required_deny' ? 'stop_intent' : 'advisory_verifier_skipped');
      if (kind === 'required_deny') assert.equal(policy.denialOutcome.stopIntentRef, run.stopIntentRef);
      else assert.equal(policy.denialOutcome.verifierSkipItemRef, canonicalSha256(items.find(value => value.kind === 'verifier_skip')));
    }
    const files = new Map([['check.test.mjs', check], ['example.txt', AFTER]]);
    if (run.resultRef) { const reviewed = await review(cut, files);
      if (kind === 'advisory_skip') assert.equal(reviewed.result.verificationReceiptRefs.length, 0); }
    else for (const method of ['run.result', 'run.diff']) { const unavailable = await context.send({ protocolVersion: 1, method, runId: run.id });
      assert.equal(unavailable.ok, false); assert.equal(unavailable.error?.code, 'RESULT_UNAVAILABLE'); assert.equal(unavailable.error?.retryable, false); }
    assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), BEFORE); assert.deepEqual(await identity(path.join(workspace, 'example.txt')), host);
    assert.deepEqual(await context.send(submit, 30000), response); assert.deepEqual(await get(run.id), cut);
    sources.set(kind, { cut, submit, response, workspace, files, verifier, ...(verifier.executionGrantId ? { executionGrantId: verifier.executionGrantId } : {}) });
    results.push({ kind, mode, status: run.status, modelPosts: context.responder.posts(kind), verifierClaims: claims.length,
      verifierApprovals: approvals, editApprovals: edits, workerFreeWaits, candidateCount,
      originalHostUnchanged: true, originalAdmissionReplayed: true, allRecordedWorkersRetired: true });
    await context.reconnect(); assert.deepEqual(await get(run.id), cut);
  }
  const templated = sources.get('template_repair')!, source = sources.get('accept_edits_pass')!;
  // An original one-use template cannot enter a new root or Delivery.
  const session = (await send({ protocolVersion: 1, method: 'session.get', sessionId: templated.cut.snapshot.run.sessionId })).snapshot.session;
  const { requestDigest: _old, ...oldCore } = templated.submit;
  const reused = await context.send(signed({ ...oldCore, requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: session.contextRevision }), 30000);
  assert.equal(reused.ok, false); assert.equal(reused.error?.code, 'AUTHORIZATION_REQUIRED');
  const applyCore = (entry: Source, ids: string[] = []) => signed({ protocolVersion: 1, method: 'run.apply', requestId: context.nextId(),
    admissionKey: randomBytes(32).toString('base64url'), sourceRunId: entry.cut.snapshot.run.id, expectedRunResultRef: entry.cut.snapshot.run.resultRef,
    budgets: { wallTimeMs: 300000, toolCalls: 1000 }, ...(ids.length ? { verifierExecutionGrantIds: ids } : {}) });
  const borrowed = await context.send(applyCore(templated, [templated.executionGrantId!]), 30000);
  assert.equal(borrowed.ok, false); assert.equal(borrowed.error?.code, 'AUTHORIZATION_REQUIRED');
  // A fresh explicit grant is consumed at admission even when the candidate
  // later inherits verification; its original authorization is never refunded.
  const identityGrant = await createIdentity(), rebound = { ...source.verifier, identityReadGrantId: identityGrant.grantId };
  const fresh = await execution(rebound, 1), inheritedApply = applyCore(source, [fresh.grantId]);
  const inheritedResponse = await context.send(inheritedApply, 30000), inheritedRun = accepted(inheritedResponse, 'run.apply').snapshot.run;
  const consumed = await send(signed({ protocolVersion: 1, method: 'authorization.revoke', requestId: context.nextId(), grantId: fresh.grantId }));
  assert.equal(consumed.disposition, 'already_consumed'); assert.equal(consumed.grant.useCount, 1);
  const finishDelivery = async (runId: string, entry: Source, local: boolean) => {
    const by = Date.now() + 90000, seen = new Set<string>(); let publication = false, verifier = false, terminal: Data;
    for (;;) {
      terminal = await get(runId); const run = terminal.snapshot.run;
      assert(Date.now() < by, 'ordinary permission Delivery terminal observation exceeded its original 90-second window');
      if (['succeeded', 'failed', 'cancelled', 'completed_unverified'].includes(run.status)) break;
      if (run.status === 'waiting' && run.waitingReason === 'approval') {
        const waiting = await read(run.waitingOnRef);
        if (seen.has(run.waitingOnRef)) { assert(Date.now() < by); await delay(200); continue; }
        seen.add(run.waitingOnRef);
        if (waiting.subject.kind === 'verifier_launch') {
          assert(local && !verifier && !publication); await wait(terminal, 'verifier_launch', entry.files);
          assert.equal(terminal.journal.filter((row: Data) => row.opKind === 'verifier' && row.phase === 'dispatch_claimed').length, 0,
            'the source Run approval never authorizes Delivery'); await approve(terminal, 'allow'); verifier = true;
        } else {
          assert.equal(waiting.subject.kind, 'delivery_plan'); assert(!publication && (!local || verifier));
          await wait(terminal, 'delivery_plan'); await approve(terminal, 'allow'); publication = true;
        }
      }
      assert(Date.now() < by, 'ordinary permission Delivery exceeded its original 90-second window'); await delay(200);
    }
    assert.equal(terminal.snapshot.run.status, 'succeeded'); assert(publication && verifier === local);
    assert.equal(terminal.journal.filter((row: Data) => row.opKind === 'verifier' && row.phase === 'dispatch_claimed').length, local ? 1 : 0);
    await context.assertWorkerFree(runId, terminal); await context.assertDeliveryEvidence(terminal, entry.cut, entry.files, local);
    const reviewed = await review(terminal, entry.files); assert(reviewed.result.deliveryTerminalProjectionEvidenceRef);
    const projection = decodeDeliveryTerminalProjectionEvidence(await read(reviewed.result.deliveryTerminalProjectionEvidenceRef));
    assert.equal(projection.selectedBranch, 'forward_finalize'); assert.equal(projection.observedSourceRef, reviewed.result.resultSourceRef);
    if (!local) assert.equal(reviewed.closure.verification.kind, 'inherited_verified');
    assert.deepEqual((await readdir(entry.workspace)).sort(), [...entry.files.keys()].sort());
    for (const [name, text] of entry.files) assert.equal(await readFile(path.join(entry.workspace, name), 'utf8'), text);
    return terminal;
  };
  const inheritedCut = await finishDelivery(inheritedRun.id, source, false);
  await context.assertConsumedDeliveryGrant(inheritedCut, fresh.grantId);
  assert.deepEqual(await context.send(inheritedApply, 30000), inheritedResponse); assert.deepEqual(await get(inheritedRun.id), inheritedCut);
  // Merge adds an owner-created A-only file before capture; source approval
  // cannot stand in for this distinct result's verifier or publication.
  const merged = sources.get('default_repair')!, note = path.join(merged.workspace, 'owner-note.txt');
  await writeFile(note, 'owned A-only permission note\n', { flag: 'wx', mode: 0o644 }); await chown(note, context.uid, context.gid);
  merged.files.set('owner-note.txt', 'owned A-only permission note\n'); const noteIdentity = await identity(note);
  const mergeApply = applyCore(merged), mergeResponse = await context.send(mergeApply, 30000), mergeRun = accepted(mergeResponse, 'run.apply').snapshot.run;
  await finishDelivery(mergeRun.id, merged, true); assert.deepEqual(await identity(note), noteIdentity);
  assert.deepEqual(await context.send(mergeApply, 30000), mergeResponse);
  // Real wall-clock expiry, no fake clock, process pause or DB mutation. The
  // distinct approval→claim cut remains explicitly unqualified below.
  const expiryIdentity = await createIdentity(), expiryVerifier = { ...source.verifier, identityReadGrantId: expiryIdentity.grantId }, expiring = await execution(expiryVerifier, 1, 30000);
  while (Date.now() <= Date.parse(expiring.expiresAt)) await delay(50);
  const expiryRequest = signed({ ...oldCore, requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
    sessionId: source.cut.snapshot.run.sessionId, expectedContextRevision: (await send({ protocolVersion: 1, method: 'session.get', sessionId: source.cut.snapshot.run.sessionId })).snapshot.session.contextRevision,
    workspacePath: source.workspace, budgets: { ...oldCore.budgets, repairAttempts: 0 }, verifiers: [{ ...expiryVerifier, executionGrantId: expiring.grantId }] });
  const expired = await context.send(expiryRequest, 30000); assert.equal(expired.ok, false); assert.equal(expired.error?.code, 'AUTHORIZATION_REQUIRED');
  const boundIdentity = await createIdentity(), boundVerifier = { ...source.verifier, identityReadGrantId: boundIdentity.grantId }, wrongBound = await execution(boundVerifier, 2);
  const { requestDigest: _expiredDigest, ...expiryCore } = expiryRequest;
  const wrong = await context.send(signed({ ...expiryCore, requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
    verifiers: [{ ...boundVerifier, executionGrantId: wrongBound.grantId }] }), 30000);
  assert.equal(wrong.ok, false); assert.equal(wrong.error?.code, 'AUTHORIZATION_REQUIRED');
  return decodeInstalledPermissionReport({ diagnosticOnly: true, qualified: true, profile: INSTALLED_PERMISSION_PROFILE, cases: results,
    exactWaitReconnectAndRestart: restarted, duplicateAndWrongRefChecked: wrongChecked, sourceApprovalNotBorrowedByDelivery: true,
    independentVerifierAndPublicationApproval: true, actualMergedWorkspaceApplied: true, inheritedDeliveryNoLocalVerifier: true,
    explicitUnusedInheritedGrantConsumed: true, consumedGrantCannotEnterAnotherRun: true, authorizationExpiryBeforeAdmission: true,
    wrongTemplateBoundsRefused: true, actualProviderQualified: false, realTtyQualified: false, approvalExpiryBeforeClaimQualified: false,
    exactClaimStopCutQualified: false, allCrashCutsQualified: false, wholeI1Qualified: false });
}
