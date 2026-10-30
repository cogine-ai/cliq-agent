import assert from 'node:assert/strict';
import test from 'node:test';
import { runSnapshot, sessionSnapshot, ref, at } from '../../../src/client/testing/protocol.js';
import { encodeControlCheckpointCursor } from '../../../src/kernel/control-wire.js';
import type { InstalledControlRequestV1 } from '../../../src/control/v1.js';
import type { RunSnapshotV1 } from '../../../src/kernel/types.js';
import { PROVIDER_JOURNEY_FILES, InstalledProviderJourneyError, runInstalledProviderJourney,
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

function terminalPage(request: Extract<InstalledControlRequestV1, { method: 'run.get' }>, changeSecondPage: boolean) {
  const queued = snapshot(), { frontierRef: _frontier, ...run } = queued.run;
  const terminal: RunSnapshotV1 = { ...queued, latestRunItemSeq: 202, run: { ...run, revision: 2, status: 'succeeded', nextStep: null,
    terminalReason: 'verified', resultRef: ref } };
  const start = request.afterItemSeq ?? 0, length = Math.min(request.itemLimit ?? 100, 202 - start);
  const cursor = encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' });
  const checkpoint = { schemaVersion: 1, id: 'checkpoint', runId: 'run', basedOnRunRevision: 1, contextManifestRef: ref, workspaceStateRef: ref,
    runItemSeq: 0, journalSeq: 0, reason: 'initial', createdAt: at };
  if (changeSecondPage && start === 100) terminal.run.revision = 3;
  return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: terminal,
    items: Array.from({ length }, (_, index) => ({ schemaVersion: 1, itemId: `inert-item-${start + index + 1}`, itemSeq: start + index + 1,
      payloadRef: ref, payloadDigest: ref, createdAt: at })), journal: [], checkpoints: request.checkpointCursor ? [] : [checkpoint],
    highWaterItemSeq: 202, highWaterJournalSeq: 0, highWaterCheckpointCursor: cursor,
    nextItemSeq: start + length, nextJournalSeq: 0, nextCheckpointCursor: cursor } };
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
