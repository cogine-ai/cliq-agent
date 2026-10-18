import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { prepareSupervisorSeaCarrier, SUPERVISOR_SEA_NODE_VERSION } from './supervisor-sea-builder.js';

test('carrier preparation refuses an existing extraction directory without adopting or changing it', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-existing-carrier-'));
  try {
    const name = `node-v${SUPERVISOR_SEA_NODE_VERSION}-${process.platform}-${process.arch}`;
    const nodeRoot = path.join(fixture, name);
    await mkdir(nodeRoot, { mode: 0o700 });
    const sentinel = path.join(nodeRoot, 'existing-data');
    await writeFile(sentinel, 'existing carrier directory must remain untouched\n', { flag: 'wx', mode: 0o400 });
    const rootBefore = await lstat(nodeRoot, { bigint: true });
    const fileBefore = await lstat(sentinel, { bigint: true });
    // Existing local source is deliberately not an archive. The fresh-root
    // precondition must refuse before reading it, downloading, or extracting.
    await assert.rejects(prepareSupervisorSeaCarrier(fixture, fileURLToPath(import.meta.url)),
      /carrier extraction directory must not already exist/);
    assert.deepEqual(await lstat(nodeRoot, { bigint: true }), rootBefore);
    assert.deepEqual(await lstat(sentinel, { bigint: true }), fileBefore);
    assert.equal(await readFile(sentinel, 'utf8'), 'existing carrier directory must remain untouched\n');
    assert.deepEqual(await readdir(fixture), [name]);
    assert.deepEqual(await readdir(nodeRoot), ['existing-data']);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
