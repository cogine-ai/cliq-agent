import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createSession, ensureSession, sessionPath } from './store.js';

test('createSession seeds a system record', () => {
  const session = createSession('/tmp/workspace');
  assert.equal(session.records[0]?.kind, 'system');
  assert.equal(session.cwd, '/tmp/workspace');
});

test('ensureSession creates the persisted file when missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-'));
  const session = await ensureSession(cwd);
  const raw = JSON.parse(await readFile(sessionPath(cwd), 'utf8')) as { records: Array<{ kind: string }> };

  assert.equal(session.records.length > 0, true);
  assert.equal(raw.records[0]?.kind, 'system');
});
