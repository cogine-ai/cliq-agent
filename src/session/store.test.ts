import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { SYSTEM_PROMPT } from '../prompt/system.js';
import { createSession, ensureSession, sessionPath } from './store.js';

test('createSession seeds a system record', () => {
  const session = createSession('/tmp/workspace');
  assert.equal(session.records[0]?.kind, 'system');
  assert.equal(session.records[0]?.content, SYSTEM_PROMPT);
  assert.equal(session.cwd, '/tmp/workspace');
});

test('ensureSession creates the persisted file when missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-'));
  const session = await ensureSession(cwd);
  const raw = JSON.parse(await readFile(sessionPath(cwd), 'utf8')) as { records: Array<{ kind: string }> };

  assert.equal(session.records.length > 0, true);
  assert.equal(raw.records[0]?.kind, 'system');
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
  assert.equal(session.records[0]?.kind, 'system');
});
