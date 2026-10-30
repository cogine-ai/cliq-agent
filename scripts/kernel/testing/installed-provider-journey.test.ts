import assert from 'node:assert/strict';
import test from 'node:test';
import { runSnapshot, sessionSnapshot, ref, at } from '../../../src/client/testing/protocol.js';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import { parseClientInvocation } from '../../../src/client/commands.js';
import type { InstalledControlRequestV1 } from '../../../src/control/v1.js';
import type { RunSnapshotV1 } from '../../../src/kernel/types.js';
import { PROVIDER_JOURNEY_FILES, InstalledProviderJourneyError, runInstalledProviderJourney, runInstalledDailyProviderJourney,
  type InstalledProviderJourneyContext, type InstalledProviderJourneyInput } from './installed-provider-journey.js';

// Powerless public-protocol data only. These cases do not create an installed
// client, accepted Run, grant, process, model request or native death evidence.
const input: InstalledProviderJourneyInput = {
  workspacePath: '/owned/workspace', model: { provider: 'openai-compatible', model: 'inert-wire-model',
    endpoint: { kind: 'registered', endpointRegistrationId: 'inert-endpoint' }, modelCredentialGrantIds: ['inert-credential'] },
  budgets: { wallTimeMs: 300_000, modelTokens: 20_000, costMicros: 100_000, toolCalls: 16, repairAttempts: 1, childDepth: 0, childConcurrency: 1 },
  guestToolchainManifestId: 'inert-guest', endpointIdentityDigest: ref
};
const snapshot = (): RunSnapshotV1 => ({ ...runSnapshot(), run: { ...runSnapshot().run, sessionId: sessionSnapshot().session.id } });
function fixture(handler?: (request: InstalledControlRequestV1) => unknown | Promise<unknown>) {
  const calls: InstalledControlRequestV1[] = [], artifacts: string[] = [];
  let reconnects = 0;
  const context: InstalledProviderJourneyContext = {
    async send(request, timeoutMs) {
      assert.equal(timeoutMs, 30_000); calls.push(request);
      if (request.method === 'session.create') return { protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } };
      if (request.method === 'authorization.create') return { protocolVersion: 1, ok: true, result: { method: 'authorization.create', grant: {
        schemaVersion: 1, grantId: 'inert-verifier-identity', state: 'active', targetKind: 'execution_identity_read', purpose: 'verifier',
        targetDigest: ref, useCount: 0, rowVersion: 1, createdAt: at, expiresAt: '2026-10-27T00:00:00.000Z'
      } } };
      if (handler) return handler(request);
      throw new Error('this inert protocol has no model or executor');
    },
    async artifact(ref) { artifacts.push(ref); throw new Error('no real artifacts exist in this protocol test'); },
    async reconnect() { reconnects++; },
    async observeWorkspace() { return { paths: ['check.test.mjs', 'math.mjs'], math: Buffer.from(PROVIDER_JOURNEY_FILES['math.mjs']),
      test: Buffer.from(PROVIDER_JOURNEY_FILES['check.test.mjs']) }; }
  };
  return { context, calls, artifacts, reconnects: () => reconnects };
}
const refusedAt = (stage: InstalledProviderJourneyError['stage']) => (error: unknown) => {
  assert(error instanceof InstalledProviderJourneyError); assert.equal(error.stage, stage);
  assert.equal(Object.hasOwn(error, 'cause'), false); return true;
};

test('the complete tiny workspace is checked before any public admission or model preparation', async () => {
  const f = fixture(), original = f.context.observeWorkspace;
  await assert.rejects(runInstalledProviderJourney(input, { ...f.context, observeWorkspace: async () => ({ ...await original(), paths: ['math.mjs'] }) }), refusedAt('workspace'));
  assert.equal(f.calls.length, 0); assert.equal(f.artifacts.length, 0);
});

test('one explicit admission freezes the real-model budget and required original Node test, and transport loss is never retried', async () => {
  const failure = 'untrusted provider text must not escape';
  const f = fixture(request => { assert.equal(request.method, 'run.submit'); throw new Error(failure); });
  await assert.rejects(runInstalledProviderJourney(input, f.context), error => {
    refusedAt('admission')(error); assert(!String(error).includes(failure)); return true;
  });
  assert.deepEqual(f.calls.map(request => request.method), ['session.create', 'authorization.create', 'run.submit']);
  const request = f.calls[2]; assert(request?.method === 'run.submit');
  assert.deepEqual(request.model, input.model); assert.deepEqual(request.budgets, input.budgets); assert.equal(request.allowUnverified, false);
  assert.equal(request.verifiers.length, 1); assert.equal(request.verifiers[0]!.required, true);
  assert.deepEqual(request.verifiers[0]!.argv.map(arg => arg.value), ['--test', '--test-concurrency=1', 'check.test.mjs']);
  assert.equal(request.verifiers[0]!.executable.kind, 'toolchain'); assert.equal(request.verifiers[0]!.identityReadGrantId, 'inert-verifier-identity');
  assert.equal(request.maxChangedPaths, 1); assert.deepEqual(request.dependency, { mode: 'none' });
  assert.equal(f.reconnects(), 0);
});

test('an authoritative admission refusal cannot become a replacement Run or an application', async () => {
  const f = fixture(() => ({ protocolVersion: 1, ok: false, method: 'run.submit',
    error: { schemaVersion: 1, code: 'MODEL_COST_UNKNOWN', retryable: false, messageCode: 'control.model_cost_unknown' } }));
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt('admission'));
  assert.equal(f.calls.filter(request => request.method === 'run.submit').length, 1);
  assert.equal(f.calls.some(request => request.method === 'run.apply'), false); assert.equal(f.artifacts.length, 0);
});

test('normal daily admission uses the actual alias, explicit fixed check and budgets without a hidden protocol mutation or retry', async () => {
  const f = fixture(); let commands = 0;
  const budgets = { ...input.budgets, modelTokens: 20_000_000, costMicros: 5_000_000 };
  await assert.rejects(runInstalledDailyProviderJourney({ workspacePath: input.workspacePath,
    model: { provider: 'openai-compatible', model: input.model.model }, modelAlias: 'owned-daily', budgets,
    endpointIdentityDigest: input.endpointIdentityDigest }, { ...f.context,
    async command(argv, timeout) {
      commands++; assert.equal(timeout, 30_000); assert.equal(argv[0], 'run');
      assert(argv.includes('--trust-workspace') && argv.includes('--detach') && argv.includes('--json'));
      const invocation = parseClientInvocation(argv.filter(flag => flag !== '--trust-workspace'), '/unused', {
        guestToolchainManifestId: input.guestToolchainManifestId, preferences: { schemaVersion: 1, modelSelections: [{ alias: 'owned-daily',
          provider: 'openai-compatible', model: input.model.model, endpointRegistrationId: 'existing-endpoint', credentialGrantId: 'existing-credential' }] } });
      assert.equal(invocation.kind, 'run'); if (invocation.kind !== 'run') throw new Error('run expected');
      assert.equal(invocation.intent.workspacePath, input.workspacePath); assert.deepEqual(invocation.intent.budgets, budgets);
      assert.equal(invocation.intent.policyMode, 'yolo'); assert.equal(invocation.intent.allowUnverified, false);
      assert.deepEqual(invocation.nodeCheck, { path: 'check.test.mjs', guestToolchainManifestId: input.guestToolchainManifestId });
      assert.deepEqual(invocation.intent.verifiers, []); assert.equal(invocation.intent.maxChangedPaths, 1);
      assert.equal(invocation.intent.maxChangedBytes, 65_536);
      throw new Error('lost command response is not permission to invent or resend an admission');
    }, async verifySource() { throw new Error('no real verifier evidence exists in this protocol test'); }
  }), refusedAt('admission'));
  assert.equal(commands, 1); assert.equal(f.calls.length, 0); assert.equal(f.artifacts.length, 0); assert.equal(f.reconnects(), 0);
});

test('UNKNOWN reconciliation remains an explicit failed journey without auto-probe, permission or dispatch', async () => {
  const f = fixture(request => {
    if (request.method === 'run.submit') return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } };
    assert.equal(request.method, 'run.get'); const waiting = snapshot();
    waiting.run.status = 'waiting'; waiting.run.waitingReason = 'reconciliation'; waiting.run.waitingOnRef = ref;
    return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: waiting, items: [], journal: [], checkpoints: [],
      highWaterItemSeq: 0, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }),
      nextItemSeq: 0, nextJournalSeq: 0 } };
  });
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt('execution'));
  assert.deepEqual(f.calls.map(request => request.method), ['session.create', 'authorization.create', 'run.submit', 'run.get']);
  assert.equal(f.reconnects(), 0); assert.equal(f.artifacts.length, 0);
});

function terminalPage(request: Extract<InstalledControlRequestV1, { method: 'run.get' }>, changeSecondPage: boolean, deferredCheckpoints = false) {
  const queued = snapshot(), { frontierRef: _frontier, ...run } = queued.run;
  const terminal: RunSnapshotV1 = { ...queued, latestRunItemSeq: 202, run: { ...run, revision: 2, status: 'succeeded', nextStep: null,
    terminalReason: 'verified', resultRef: ref } };
  const start = request.afterItemSeq ?? 0, length = Math.min(request.itemLimit ?? 100, 202 - start);
  const cursor = encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' });
  const checkpoint = { schemaVersion: 1, id: 'checkpoint', runId: 'run', basedOnRunRevision: 1, contextManifestRef: ref, workspaceStateRef: ref,
    runItemSeq: 0, journalSeq: 0, reason: 'initial', createdAt: at };
  const reachedCheckpoints = !deferredCheckpoints || start + length === 202;
  if (changeSecondPage && start === 100) terminal.run.revision = 3;
  return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: terminal,
    items: Array.from({ length }, (_, index) => ({ schemaVersion: 1, itemId: `inert-item-${start + index + 1}`, itemSeq: start + index + 1,
      payloadRef: ref, payloadDigest: ref, createdAt: at })), journal: [], checkpoints: request.checkpointCursor || !reachedCheckpoints ? [] : [checkpoint],
    highWaterItemSeq: 202, highWaterJournalSeq: 0, highWaterCheckpointCursor: cursor,
    nextItemSeq: start + length, nextJournalSeq: 0, ...(reachedCheckpoints ? { nextCheckpointCursor: cursor } : {}) } };
}

for (const changeSecondPage of [false, true]) test(`terminal inspection ${changeSecondPage ? 'refuses a changed cut' : 'collects all original pages without a turn-count assumption'}`, async () => {
  const f = fixture(request => {
    if (request.method === 'run.submit') return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } };
    assert(request.method === 'run.get'); return terminalPage(request, changeSecondPage);
  });
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt(changeSecondPage ? 'execution' : 'result'));
  const gets = f.calls.filter((request): request is Extract<InstalledControlRequestV1, { method: 'run.get' }> => request.method === 'run.get');
  assert.deepEqual(gets.map(request => request.afterItemSeq), changeSecondPage ? [0, 0, 100] : [0, 0, 100, 200]);
  assert.equal(f.calls.some(request => request.method === 'run.apply'), false);
  assert.equal(f.artifacts.length, changeSecondPage ? 0 : 1);
});

test('a full item/Journal page cannot skip original checkpoints by substituting the high-water cursor', async () => {
  const f = fixture(request => {
    if (request.method === 'run.submit') return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } };
    assert(request.method === 'run.get'); return terminalPage(request, false, true);
  });
  // Reaching result-artifact inspection proves the complete original cut was
  // collected. This inert fixture has no artifacts or native/runtime authority.
  await assert.rejects(runInstalledProviderJourney(input, f.context), refusedAt('result'));
  const gets = f.calls.filter((request): request is Extract<InstalledControlRequestV1, { method: 'run.get' }> => request.method === 'run.get');
  assert.deepEqual(gets.map(request => request.afterItemSeq), [0, 0, 100, 200]);
  assert(gets.every(request => request.checkpointCursor === undefined), 'no checkpoint has been consumed when these requests are sent');
  assert.equal(f.artifacts.length, 1); assert.equal(f.calls.some(request => request.method === 'run.apply'), false);
});
