import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { SYSTEM_PROMPT } from '../prompt/system.js';
import { createSession, ensureSession, sessionPath } from './store.js';

test('createSession starts without a seeded system record', () => {
  const session = createSession('/tmp/workspace');
  assert.deepEqual(session.records, []);
  assert.equal(session.cwd, '/tmp/workspace');
});

test('ensureSession creates the persisted file when missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-'));
  const session = await ensureSession(cwd);
  const raw = JSON.parse(await readFile(sessionPath(cwd), 'utf8')) as { records: Array<{ kind: string }> };

  assert.deepEqual(session.records, []);
  assert.deepEqual(raw.records, []);
});

test('ensureSession migrates legacy tool status when present', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-'));
  await import('node:fs/promises').then(({ mkdir, writeFile }) =>
    mkdir(path.join(cwd, '.cliq'), { recursive: true }).then(() =>
      writeFile(
        path.join(cwd, '.cliq', 'session.json'),
        JSON.stringify({
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
          messages: [{ role: 'tool', name: 'bash', status: 'error', content: 'TOOL_RESULT bash ERROR' }]
        })
      )
    )
  );

  const session = await ensureSession(cwd);
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(toolRecord?.kind, 'tool');
  assert.equal(toolRecord?.status, 'error');
});

test('ensureSession strips the legacy seeded system prompt during migration', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-migrate-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 2,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 0 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: SYSTEM_PROMPT
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.deepEqual(session.records, []);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession preserves non-system records when stripping the legacy seeded prompt', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-migrate-preserve-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 2,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 2 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: SYSTEM_PROMPT
          },
          {
            id: 'usr_1',
            ts: '2026-04-01T00:00:01.000Z',
            kind: 'user',
            role: 'user',
            content: 'inspect the repo'
          },
          {
            id: 'ast_1',
            ts: '2026-04-01T00:00:02.000Z',
            kind: 'assistant',
            role: 'assistant',
            content: '{"message":"done"}',
            action: { message: 'done' }
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.deepEqual(
      session.records.map((record) => record.kind),
      ['user', 'assistant']
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession rejects malformed sessions and recreates a valid session', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-malformed-'));
  await import('node:fs/promises').then(({ mkdir, writeFile }) =>
    mkdir(path.join(cwd, '.cliq'), { recursive: true }).then(() =>
      writeFile(path.join(cwd, '.cliq', 'session.json'), JSON.stringify({ records: [] }))
    )
  );

  const session = await ensureSession(cwd);

  assert.equal(session.version > 0, true);
  assert.equal(Array.isArray(session.records), true);
  assert.deepEqual(session.records, []);
});
