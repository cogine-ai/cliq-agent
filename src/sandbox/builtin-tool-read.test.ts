import assert from 'node:assert/strict';
import test from 'node:test';
import { constants } from 'node:fs';
import { link, mkdir, mkdtemp, open, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { builtinToolInputBytes, decodeBuiltinReadOutput, decodeBuiltinToolInput, type BuiltinScriptTool } from './builtin-tool-data.js';
import { readBuiltinTool } from './builtin-tool-read.js';

// Real owned descriptors and bytes only. No StateOwner/Run/native authority or
// installation qualification is created by this filesystem component.
async function fixture(operation: (root: Awaited<ReturnType<typeof open>>, dir: string) => Promise<void>) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-io-'));
  const root = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await operation(root, dir); } finally { await root.close(); await rm(dir, { recursive: true, force: true }); }
}
const limits = { maxSingleFileBytes: 268_435_456, maxInvocationOutputBytes: 67_108_864 };
async function call(root: Awaited<ReturnType<typeof open>>, tool: BuiltinScriptTool, input: Record<string, unknown>) {
  const capsule = decodeBuiltinToolInput(builtinToolInputBytes(tool, input, limits));
  return decodeBuiltinReadOutput(await readBuiltinTool(root, capsule), capsule);
}
test('fixed read/search uses actual owned bytes, line ranges and canonical complete output', { skip: process.platform !== 'linux' }, async () => {
  await fixture(async (root, dir) => {
    await writeFile(path.join(dir, 'alpha.txt'), 'first\nsecond needlé\nthird\n');
    await mkdir(path.join(dir, 'sub')); await writeFile(path.join(dir, 'sub/needle.txt'), 'needlé\n');
    const read = await call(root, 'read', { path: 'alpha.txt', start_line: 2, end_line: 2 });
    assert.equal(read.complete, true); assert.equal((read.content as { text: string }).text, '2| second needlé');
    const outside = await call(root, 'read', { path: 'alpha.txt', start_line: 200 });
    assert.equal((outside.content as { text: string }).text, '');
    const matches = await call(root, 'grep', { path: '.', pattern: 'needlé' });
    assert.equal(matches.complete, true); assert.equal((matches.content as unknown[]).length, 2);
    const found = await call(root, 'find', { path: '.', name: 'needle' });
    assert.deepEqual(found.content, ['sub/needle.txt']);
    const before = (await readdir('/proc/self/fd')).length;
    for (let i = 0; i < 12; i++) await call(root, 'grep', { path: '.', pattern: 'needlé' });
    assert.equal((await readdir('/proc/self/fd')).length, before, 'all actual child descriptors joined');
  });
});
test('fixed search excludes Git metadata and reports unreadable or unsupported leaves without traversing them', { skip: process.platform !== 'linux' }, async () => {
  await fixture(async (root, dir) => {
    await writeFile(path.join(dir, 'plain'), 'needle'); await link(path.join(dir, 'plain'), path.join(dir, 'hard'));
    await symlink('/etc', path.join(dir, 'escape')); await mkdir(path.join(dir, '.git'));
    await writeFile(path.join(dir, '.git/private'), 'needle'); await writeFile(path.join(dir, 'invalid'), Buffer.from([0xff, 0xfe]));
    await writeFile(path.join(dir, 'large'), 'x'.repeat(64_001));
    const result = await call(root, 'grep', { path: '.', pattern: 'needle' });
    assert.equal(result.complete, false);
    for (const reason of ['hardlink', 'symlink', 'invalid_utf8', 'file_limit']) assert(result.reasons.includes(reason as never));
    assert.deepEqual(result.content, []);
    await assert.rejects(call(root, 'read', { path: 'escape/passwd' }));
    await assert.rejects(call(root, 'read', { path: 'hard' }));
    await assert.rejects(call(root, 'read', { path: '.git/private' }));
  });
});
test('fixed traversal and output ceilings produce a genuine partial prefix, with no descriptor leak', { skip: process.platform !== 'linux' }, async () => {
  await fixture(async (root, dir) => {
    for (let i = 0; i < 205; i++) await writeFile(path.join(dir, `entry-${String(i).padStart(3, '0')}`), '');
    const result = await call(root, 'ls', { path: '.' });
    assert.equal((result.content as unknown[]).length, 200); assert.equal(result.complete, false); assert(result.reasons.includes('match_limit'));
    let current = dir;
    for (let i = 0; i < 14; i++) { current = path.join(current, 'nested'); await mkdir(current); }
    await writeFile(path.join(current, 'target'), 'needle');
    const deep = await call(root, 'find', { path: '.', name: 'target' });
    assert.equal(deep.complete, false); assert(deep.reasons.includes('depth_limit')); assert.deepEqual(deep.content, []);
  });
});
