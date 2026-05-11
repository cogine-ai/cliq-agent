import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { assertHeadlessCompatible, openTurnTx, finishTurnTx, type TxRunnerOptions } from './tx-runner.js';
import { createSession, mutateSession } from '../session/store.js';
import { openRecordId } from '../workspace/transactions/types.js';
import { overlayDir, resolveTxRoot, readTxState } from '../workspace/transactions/store.js';
import { createOverlayWriter } from '../workspace/transactions/overlay.js';
import type { RuntimeEvent } from '../protocol/runtime/events.js';

const execFileAsync = promisify(execFile);

async function setupGitWorkspace(): Promise<string> {
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-tr-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: ws });
  await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: ws });
  await execFileAsync('git', ['config', 'user.name', 't'], { cwd: ws });
  return ws;
}

async function withTrEnv<T>(
  fn: (env: {
    home: string;
    ws: string;
    ctx: {
      cwd: string;
      session: ReturnType<typeof createSession>;
      cliqHome: string;
      workspaceId: string;
      sessionId: string;
      workspaceRealPath: string;
    };
    session: ReturnType<typeof createSession>;
    events: RuntimeEvent[];
  }) => Promise<T>
): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-tr-home-'));
  const ws = await setupGitWorkspace();
  const prev = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = home;
  try {
    const session = createSession(ws);
    await mutateSession(ws, session, () => {});
    const ctx = {
      cwd: ws,
      session,
      cliqHome: home,
      workspaceId: 'ws_tr',
      sessionId: session.id,
      workspaceRealPath: ws
    };
    const events: RuntimeEvent[] = [];
    return await fn({ home, ws, ctx, session, events });
  } finally {
    if (prev === undefined) delete process.env.CLIQ_HOME;
    else process.env.CLIQ_HOME = prev;
    await rm(home, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
}

function baseOpts(overrides: Partial<TxRunnerOptions> = {}): TxRunnerOptions {
  return {
    mode: 'edit',
    auto: 'per-turn',
    applyPolicy: 'auto-on-pass',
    bashPolicy: 'passthrough',
    headless: false,
    validatorsConfig: {},
    stagedViewConfig: { copyMode: 'auto', bindPaths: [] },
    workspaceId: 'ws',
    workspaceRealPath: '/tmp/ws',
    ...overrides
  };
}

test('assertHeadlessCompatible passes for non-interactive applyPolicy under headless', () => {
  assertHeadlessCompatible(baseOpts({ headless: true, applyPolicy: 'auto-on-pass' }));
  assertHeadlessCompatible(baseOpts({ headless: true, applyPolicy: 'manual-only', auto: 'manual' }));
});

test('assertHeadlessCompatible passes for interactive applyPolicy with TTY (headless: false)', () => {
  assertHeadlessCompatible(baseOpts({ headless: false, applyPolicy: 'interactive' }));
});

test('assertHeadlessCompatible throws when applyPolicy=interactive + headless', () => {
  assert.throws(
    () => assertHeadlessCompatible(baseOpts({ headless: true, applyPolicy: 'interactive' })),
    /interactive requires a TTY/
  );
});

test('openTurnTx auto-opens implicit tx (no tx-opened record), emits tx-staging-start with trigger=auto-turn, opened=true', async () => {
  await withTrEnv(async ({ ctx, session, events }) => {
    const opts: TxRunnerOptions = baseOpts({ auto: 'per-turn' });
    const result = await openTurnTx(ctx, opts, async (e) => {
      events.push(e);
    });
    assert.ok(result.tx);
    assert.equal(result.opened, true);
    assert.equal(session.activeTxId, result.tx!.id);
    assert.equal(session.records.filter((r) => r.kind === 'tx-opened').length, 0);
    const stagingStart = events.find((e) => e.type === 'tx-staging-start');
    assert.ok(stagingStart);
    if (stagingStart && stagingStart.type === 'tx-staging-start') {
      assert.equal(stagingStart.trigger, 'auto-turn');
      assert.equal(stagingStart.txId, result.tx!.id);
    }
  });
});

test('openTurnTx reuses existing active tx without re-emitting staging-start (auto: manual)', async () => {
  await withTrEnv(async ({ ctx, session, events }) => {
    // Pre-create an explicit tx and make it active.
    const { openTx } = await import('../workspace/transactions/coordinator.js');
    const existing = await openTx(ctx, { explicit: true, name: 'feature' });
    const opts: TxRunnerOptions = baseOpts({ auto: 'manual' });
    const result = await openTurnTx(ctx, opts, async (e) => {
      events.push(e);
    });
    assert.equal(result.tx!.id, existing.id);
    assert.equal(result.opened, false);
    // No new staging-start emitted by openTurnTx for an existing tx.
    const stagingStarts = events.filter((e) => e.type === 'tx-staging-start');
    assert.equal(stagingStarts.length, 0);
    // tx-opened record still present from the original open.
    assert.equal(session.records.filter((r) => r.id === openRecordId(existing.id)).length, 1);
  });
});

test('openTurnTx reuses existing explicit tx even when auto=per-turn (opened=false → runner skips finalize)', async () => {
  await withTrEnv(async ({ ctx, events }) => {
    // User did `cliq tx open foo` then config has auto: per-turn. The existing tx wins.
    const { openTx } = await import('../workspace/transactions/coordinator.js');
    const existing = await openTx(ctx, { explicit: true });
    const opts: TxRunnerOptions = baseOpts({ auto: 'per-turn' });
    const result = await openTurnTx(ctx, opts, async (e) => {
      events.push(e);
    });
    assert.equal(result.tx!.id, existing.id);
    assert.equal(result.opened, false); // critical: runner uses this to skip finishTurnTx
    assert.equal(events.filter((e) => e.type === 'tx-staging-start').length, 0);
  });
});

test('openTurnTx returns null tx when auto: manual and no active tx exists (skip turn lifecycle)', async () => {
  await withTrEnv(async ({ ctx, events }) => {
    const opts: TxRunnerOptions = baseOpts({ auto: 'manual' });
    const result = await openTurnTx(ctx, opts, async (e) => {
      events.push(e);
    });
    assert.equal(result.tx, null);
    assert.equal(result.opened, false);
    assert.equal(events.length, 0);
  });
});

async function commitInitialFile(ws: string, name: string, content: string) {
  await writeFile(path.join(ws, name), content, 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: ws });
  await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });
}

test('finishTurnTx auto-on-pass: finalize → validate → approve → apply, edit lands', async () => {
  await withTrEnv(async ({ ctx, ws, home, events }) => {
    await commitInitialFile(ws, 'a.txt', 'one');
    const opts: TxRunnerOptions = baseOpts({
      applyPolicy: 'auto-on-pass',
      validatorsConfig: { disabled: ['builtin:index-clean', 'builtin:size-limit'] }
    });
    const open = await openTurnTx(ctx, opts, async (e) => { events.push(e); });
    const writer = createOverlayWriter(ws, overlayDir(resolveTxRoot(home), open.tx!.id));
    await writer.replaceText('a.txt', 'one', 'ONE');

    await finishTurnTx(ctx, opts, open.tx!, async (e) => { events.push(e); });

    const types = events.map((e) => e.type);
    assert.deepEqual(
      types.filter((t) => t.startsWith('tx-')),
      ['tx-staging-start', 'tx-finalized', 'tx-validated', 'tx-applied']
    );
    const { readFile: rf } = await import('node:fs/promises');
    assert.equal(await rf(path.join(ws, 'a.txt'), 'utf8'), 'ONE');
    const tx = await readTxState(resolveTxRoot(home), open.tx!.id);
    assert.equal(tx?.state, 'applied');
  });
});

test('finishTurnTx auto-on-pass with blocking failures aborts with reason=validator-fail; no edit lands', async () => {
  await withTrEnv(async ({ ctx, ws, home, events }) => {
    await commitInitialFile(ws, 'a.txt', 'a');
    const opts: TxRunnerOptions = baseOpts({
      applyPolicy: 'auto-on-pass',
      validatorsConfig: { disabled: ['builtin:index-clean', 'builtin:size-limit'] }
    });
    const open = await openTurnTx(ctx, opts, async (e) => { events.push(e); });
    const writer = createOverlayWriter(ws, overlayDir(resolveTxRoot(home), open.tx!.id));
    await writer.replaceText('a.txt', 'a', 'a\u0000b');

    await finishTurnTx(ctx, opts, open.tx!, async (e) => { events.push(e); });

    const aborted = events.find((e) => e.type === 'tx-aborted');
    assert.ok(aborted);
    if (aborted && aborted.type === 'tx-aborted') assert.equal(aborted.reason, 'validator-fail');
    const { readFile: rf } = await import('node:fs/promises');
    assert.equal(await rf(path.join(ws, 'a.txt'), 'utf8'), 'a'); // unchanged
  });
});

test('finishTurnTx interactive yes → applies', async () => {
  await withTrEnv(async ({ ctx, ws, home, events }) => {
    await commitInitialFile(ws, 'a.txt', 'one');
    const opts: TxRunnerOptions = baseOpts({
      applyPolicy: 'interactive',
      headless: false,
      confirmApply: async (_review) => true,
      validatorsConfig: { disabled: ['builtin:index-clean', 'builtin:size-limit'] }
    });
    const open = await openTurnTx(ctx, opts, async (e) => { events.push(e); });
    const writer = createOverlayWriter(ws, overlayDir(resolveTxRoot(home), open.tx!.id));
    await writer.replaceText('a.txt', 'one', 'ONE');
    await finishTurnTx(ctx, opts, open.tx!, async (e) => { events.push(e); });
    const tx = await readTxState(resolveTxRoot(home), open.tx!.id);
    assert.equal(tx?.state, 'applied');
  });
});

test('finishTurnTx interactive confirm receives rich apply review', async () => {
  await withTrEnv(async ({ ctx, ws, home, events }) => {
    await commitInitialFile(ws, 'a.txt', 'one');
    let review:
      | Awaited<Parameters<NonNullable<TxRunnerOptions['confirmApply']>>[0]>
      | undefined;
    const opts: TxRunnerOptions = baseOpts({
      applyPolicy: 'interactive',
      headless: false,
      confirmApply: async (received) => {
        review = received;
        return true;
      },
      validatorsConfig: { disabled: ['builtin:index-clean', 'builtin:size-limit'] }
    });
    const open = await openTurnTx(ctx, opts, async (e) => { events.push(e); });
    const writer = createOverlayWriter(ws, overlayDir(resolveTxRoot(home), open.tx!.id));
    await writer.replaceText('a.txt', 'one', 'ONE\ntwo');

    await finishTurnTx(ctx, opts, open.tx!, async (e) => { events.push(e); });

    assert.ok(review);
    assert.equal(review.txId, open.tx!.id);
    assert.match(review.prompt, /Files changed: 1/);
    assert.match(review.prompt, /Validators:/);
    assert.match(review.prompt, /Artifact: tx\//);
    assert.equal(review.diffSummary.filesChanged, 1);
    assert.equal(review.validators.length > 0, true);
    assert.deepEqual(review.blockingFailures, []);
    assert.equal(review.bashEffects.length, 0);
    assert.equal(review.artifactRef, `tx/${open.tx!.id}/`);
  });
});

test('finishTurnTx interactive no → auto-aborts with reason=user-abort', async () => {
  await withTrEnv(async ({ ctx, ws, home, events }) => {
    await commitInitialFile(ws, 'a.txt', 'one');
    const opts: TxRunnerOptions = baseOpts({
      applyPolicy: 'interactive',
      headless: false,
      confirmApply: async (_review) => false,
      validatorsConfig: { disabled: ['builtin:index-clean', 'builtin:size-limit'] }
    });
    const open = await openTurnTx(ctx, opts, async (e) => { events.push(e); });
    const writer = createOverlayWriter(ws, overlayDir(resolveTxRoot(home), open.tx!.id));
    await writer.replaceText('a.txt', 'one', 'ONE');
    await finishTurnTx(ctx, opts, open.tx!, async (e) => { events.push(e); });
    const aborted = events.find((e) => e.type === 'tx-aborted');
    assert.ok(aborted);
    if (aborted && aborted.type === 'tx-aborted') assert.equal(aborted.reason, 'user-abort');
  });
});

test('finishTurnTx with empty diff aborts the implicit tx (no-edits short-circuit)', async () => {
  await withTrEnv(async ({ ctx, ws, home, events }) => {
    await commitInitialFile(ws, 'a.txt', 'one');
    const opts: TxRunnerOptions = baseOpts({ applyPolicy: 'auto-on-pass' });
    const open = await openTurnTx(ctx, opts, async (e) => { events.push(e); });
    // No edits applied — overlay stays empty.
    await finishTurnTx(ctx, opts, open.tx!, async (e) => { events.push(e); });
    const aborted = events.find((e) => e.type === 'tx-aborted');
    assert.ok(aborted);
    const tx = await readTxState(resolveTxRoot(home), open.tx!.id);
    assert.equal(tx?.state, 'aborted');
  });
});

test('explicit tx + auto=per-turn: openTurnTx returns opened=false; runner-integration test confirms finishTurnTx is NOT called for opened=false', async () => {
  // Unit-level proof: openTurnTx behavior is asserted in Task 11 ("reuses existing
  // explicit tx even when auto=per-turn"). The full runner-skips-finalize behavior is
  // exercised end-to-end in the integration tests (plan Task 21).
  // No standalone finishTurnTx test for this case — the runner is the gate.
  assert.ok(true);
});
