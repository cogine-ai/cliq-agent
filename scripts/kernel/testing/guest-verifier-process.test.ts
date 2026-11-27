// Real owned Linux proc/cgroup reads only. This is not a signed guest launch,
// StateOwner, cancellation, namespace or containment-death qualification.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { observeGuestVerifierProcess } from './guest-verifier-process.js';

test('real Linux process identity ignores comm and closes every observation FD while preserving full-image and cgroup checks',
  { skip: process.platform !== 'linux' ? 'actual Linux proc/cgroup is unavailable; not qualified on this host' : false }, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-guest-process-')), image = path.join(root, 'owned-node');
    const original = await readFile(process.execPath), digest = createHash('sha256').update(original).digest('hex');
    await copyFile(process.execPath, image); await chmod(image, 0o555);
    const beforeChild = (await readdir('/proc/self/fd')).length;
    const child = spawn(image, ['-e', "process.title='owned-observer';process.stdout.write('ready\\n');setInterval(()=>{},50)"], { stdio: ['ignore', 'pipe', 'pipe'] });
    const joined = new Promise<void>(resolve => child.once('close', () => resolve())); let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('owned child did not become ready')), 5000);
        child.once('error', reject); child.once('exit', () => reject(new Error('owned child exited before observation')));
        let output = '';
        child.stdout!.on('data', bytes => { output += bytes.toString(); if (output === 'ready\n') resolve(); else reject(new Error('unexpected owned output')); });
      }); clearTimeout(timer); assert(child.pid);
      const group = /(?:^|\n)0::([^\n]+)\n?$/u.exec(await readFile('/proc/self/cgroup', 'utf8'))?.[1]; assert(group);
      const cgroupPath = path.join('/sys/fs/cgroup', group), before = (await readdir('/proc/self/fd')).length;
      const input = { pid: child.pid, uid: process.geteuid!(), cgroupPath, executablePath: image, executableDigest: digest };
      assert.deepEqual(await observeGuestVerifierProcess({ ...input, deadline: performance.now() + 15000 }), { kind: 'matched', comm: 'other' });
      assert.deepEqual(await observeGuestVerifierProcess({ ...input, executableDigest: 'b'.repeat(64), deadline: performance.now() + 15000 }), { kind: 'not_node', comm: 'other' });
      await assert.rejects(observeGuestVerifierProcess({ ...input, uid: input.uid + 1, deadline: performance.now() + 15000 }));
      const falseGroup = path.join(root, 'not-a-cgroup'); await mkdir(falseGroup); await writeFile(path.join(falseGroup, 'cgroup.procs'), String(child.pid) + '\n');
      await assert.rejects(observeGuestVerifierProcess({ ...input, cgroupPath: falseGroup, deadline: performance.now() + 15000 }));
      assert.deepEqual(await observeGuestVerifierProcess({ ...input, deadline: performance.now() - 1 }), { kind: 'deadline' });
      assert.equal((await readdir('/proc/self/fd')).length, before);
      child.kill('SIGTERM'); await joined;
      assert.notEqual((await observeGuestVerifierProcess({ ...input, deadline: performance.now() + 15000 })).kind, 'matched',
        'an actually joined owned process cannot remain a positive observation');
      assert.equal((await readdir('/proc/self/fd')).length, beforeChild, 'owned child pipes and observation FDs really joined');
    } finally {
      clearTimeout(timer); child.kill('SIGTERM'); await joined; await rm(root, { recursive: true, force: true });
    }
  });
