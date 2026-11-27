// Ordinary inert data only. The signed Linux Git child and real cgroup
// campaign independently establish physical verification; this test cannot.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { inflateSync } from 'node:zlib';
import { open, readFile, type FileHandle } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import ts from 'typescript';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { workerCampaignSandboxProfile } from '../../../src/sandbox/testing/worker-campaign-fixture.js';
import { decodeSourceGitInspectionOutput } from '../../../src/workspace/source-git-output.js';
import { normalizeGitIndex } from '../../../src/workspace/git-index.js';
import { missingOriginalProcStat, preparingGitNativeInputData } from './preparing-git-native.js';

test('a real original proc-stat descriptor reports ESRCH after its owned task has exited',
  { skip: process.platform !== 'linux', timeout: 5000 }, async t => {
    const child = spawn(process.execPath, ['-e', "process.stdout.write('ready\\n'); process.stdin.once('end',()=>process.exit(0)); process.stdin.resume()"],
      { stdio: ['pipe', 'pipe', 'pipe'] });
    const exited = once(child, 'exit'); let handle: FileHandle | undefined;
    t.after(async () => {
      await handle?.close();
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await exited; child.stdout.destroy(); child.stderr.destroy(); child.stdin.destroy();
    });
    await once(child.stdout, 'data'); assert(child.pid);
    handle = await open(`/proc/${child.pid}/stat`, 'r');
    const before = await handle.read(Buffer.alloc(256), 0, 256, 0); assert(before.bytesRead > 0);
    child.stdin.end(); assert.deepEqual(await exited, [0, null]);
    await assert.rejects(handle.read(Buffer.alloc(256), 0, 256, 0), error => {
      assert.equal((error as NodeJS.ErrnoException).code, 'ESRCH'); assert(missingOriginalProcStat(error)); return true;
    });
  });

test('proc-stat absence classification never accepts unreadability or a caller success record', () => {
  for (const code of ['ENOENT', 'ESRCH'])
    assert(missingOriginalProcStat(Object.assign(new Error('fixed proc-stat absence'), { code })));
  for (const code of ['EACCES', 'EPERM', 'EIO', 'EBADF'])
    assert.equal(missingOriginalProcStat(Object.assign(new Error('fixed proc-stat refusal'), { code })), false);
  assert.equal(missingOriginalProcStat({ code: 'ESRCH' }), false);
});

test('the original driver retains real HELLO birth before preparation and still requires the later native refusal', async () => {
  // Source wiring only. Actual READY, original exit and successor retirement
  // remain the independent real Linux campaign, never mocked authority here.
  const text = await readFile(new URL('./preparing-git-native.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('preparing-git-native.ts', text, ts.ScriptTarget.Latest, true);
  const original = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'nativeOriginalReadyExit');
  assert(original?.body);
  const statements = original.body.statements.map(node => node.getText(source));
  const birth = statements.findIndex(value => value.startsWith('const controllerBirth = readNativeControllerPreparationBirth('));
  const opening = statements.findIndex(value => value.includes('await controller.openPreparingGit('));
  const ready = statements.findIndex(value => value.includes('scope.createBlocked();'));
  const observedReady = statements.findIndex(value => value.includes('await wait(() => scope.pollReady()'));
  const refused = statements.findIndex(value => value.startsWith('assert.throws(') && value.includes('readNativeControllerPreparationBirth'));
  assert(birth >= 0 && birth < opening && opening < ready && ready < observedReady && observedReady < refused);
  assert.match(statements[refused]!, /code: 'RECOVERY_REQUIRED'/u);
  assert.match(statements.find(value => value.startsWith('const report:'))!, /controller: controllerBirth/u);
});

test('native preparing campaign retains a nonempty self-consistent ordinary pack/index closure without host Git', () => {
  const repositoryIdentityDigest = 'a'.repeat(64), resources = workerCampaignSandboxProfile({ maxOpenFiles: 128 }).resources;
  const [bytes, index, pack, idx] = preparingGitNativeInputData(repositoryIdentityDigest, resources);
  const metadata = decodeSourceGitInspectionOutput(bytes, { repositoryIdentityDigest, resources });
  const sha256 = (value: Buffer) => createHash('sha256').update(value).digest('hex');
  assert.equal(metadata.index.sha256, sha256(index)); assert.equal(metadata.pack.sha256, sha256(pack));
  assert.equal(metadata.pack.indexSha256, sha256(idx)); assert.equal(metadata.index.byteCount, index.length);
  assert.equal(metadata.pack.byteCount, pack.length); assert.equal(metadata.pack.indexByteCount, idx.length);
  assert.equal(pack.subarray(0, 12).toString('hex'), '5041434b0000000200000001');
  const body = inflateSync(pack.subarray(13, pack.length - 20)); assert.deepEqual(body, Buffer.from('before\n'));
  const object = createHash('sha1').update(`blob ${body.length}\0`).update(body).digest();
  assert.deepEqual(metadata.pack.objectIds, [object.toString('hex')]); assert.equal(pack[12], 0x30 | body.length);
  assert.deepEqual(pack.subarray(-20), createHash('sha1').update(pack.subarray(0, -20)).digest());
  assert.deepEqual(idx.subarray(-40, -20), pack.subarray(-20));
  assert.deepEqual(idx.subarray(-20), createHash('sha1').update(idx.subarray(0, -20)).digest());
  assert.equal(idx.subarray(0, 8).toString('hex'), 'ff744f6300000002'); assert.equal(idx.readUInt32BE(8 + 255 * 4), 1);
  assert.deepEqual(idx.subarray(1032, 1052), object); assert.equal(idx.readUInt32BE(1056), 12);
  const normalized = normalizeGitIndex(index, 'sha1', { maxBytes: resources.maxSingleFileBytes, maxEntries: 100_000 });
  assert(normalized.canonicalBytes.equals(index)); assert.deepEqual(normalized.entries, metadata.index.entries);
  assert.equal(normalized.indexTreeObjectId, metadata.index.indexTreeObjectId);
  assert.equal(canonicalSha256(metadata), sha256(bytes));
});
