import * as assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';

import {
  createWorkspaceTrustContext,
  evaluateWorkspaceTrustForNonInteractive,
  parseCliqTrustWorkspaceEnv,
  readPersistedWorkspaceTrust,
  workspaceTrustRecordPath,
  WorkspaceTrustError,
  writePersistedWorkspaceTrust
} from './trust.js';

const cleanup: string[] = [];

after(async () => {
  await Promise.all(cleanup.map((dir) => rm(dir, { recursive: true, force: true })));
});

test('parseCliqTrustWorkspaceEnv accepts trust synonyms', () => {
  assert.equal(parseCliqTrustWorkspaceEnv({ CLIQ_TRUST_WORKSPACE: 'TRUSTED' }), 'trust');
  assert.equal(parseCliqTrustWorkspaceEnv({ CLIQ_TRUST_WORKSPACE: '1' }), 'trust');
});

test('parseCliqTrustWorkspaceEnv accepts deny synonyms', () => {
  assert.equal(parseCliqTrustWorkspaceEnv({ CLIQ_TRUST_WORKSPACE: 'untrusted' }), 'deny');
});

test('parseCliqTrustWorkspaceEnv rejects ambiguous values', () => {
  assert.throws(() => parseCliqTrustWorkspaceEnv({ CLIQ_TRUST_WORKSPACE: 'wat' }), WorkspaceTrustError);
});

test('evaluateWorkspaceTrustForNonInteractive is fail-closed when nothing is persisted', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-trust-ws-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-trust-home-'));
  cleanup.push(cwd, home);

  const ctx = await createWorkspaceTrustContext(cwd, home);
  const verdict = await evaluateWorkspaceTrustForNonInteractive(ctx, {});
  assert.equal(verdict.ok, false);
  if (!verdict.ok) {
    assert.match(verdict.message, /non-interactive/);
  }
});

test('env trust bypasses persisted denial without overwriting the persisted record', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-trust-ws-env-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-trust-home-env-'));
  cleanup.push(cwd, home);
  const ctx = await createWorkspaceTrustContext(cwd, home);
  await writePersistedWorkspaceTrust(ctx, 'denied');

  const verdict = await evaluateWorkspaceTrustForNonInteractive(ctx, { CLIQ_TRUST_WORKSPACE: 'trust' });
  assert.deepEqual(verdict, { ok: true as const, source: 'env' });

  assert.equal(await readPersistedWorkspaceTrust(ctx), 'denied');
});

test('persisted trusted decision unlocks non-interactive evaluation', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-trust-ws-ok-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-trust-home-ok-'));
  cleanup.push(cwd, home);

  const ctx = await createWorkspaceTrustContext(cwd, home);
  await mkdir(path.dirname(workspaceTrustRecordPath(ctx)), { recursive: true });
  await writeFile(
    workspaceTrustRecordPath(ctx),
    JSON.stringify({
      version: 1,
      workspaceId: ctx.workspaceId,
      workspaceRealPath: ctx.workspaceRealPath,
      decision: 'trusted',
      decidedAt: '2026-05-15T00:00:00Z'
    }),
    'utf8'
  );

  const verdict = await evaluateWorkspaceTrustForNonInteractive(ctx, {});
  assert.deepEqual(verdict, { ok: true as const, source: 'persisted' });
});
