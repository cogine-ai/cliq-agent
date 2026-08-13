import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const verifier = path.resolve(
  'native/macos/CliqKernelProbe/guest/verify-detached-daemon.sh'
);

test('macOS guest daemon proof binds one exact PID, PPID 1, and executable digest', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-daemon-proof-'));
  const procRoot = path.join(fixture, 'proc');
  const daemonPid = '4242';
  const daemonRoot = path.join(procRoot, daemonPid);
  const daemonExecutable = path.join(daemonRoot, 'exe');
  const sha256sum = path.join(fixture, 'sha256sum');
  const daemonBytes = Buffer.from('expected detached daemon bytes\n', 'utf8');
  const expectedDigest = crypto.createHash('sha256').update(daemonBytes).digest('hex');

  try {
    await mkdir(daemonRoot, { recursive: true });
    await mkdir(path.join(procRoot, '9999'));
    await writeFile(path.join(daemonRoot, 'status'), 'Name:\tcliq-daemon\nPPid:\t1\n');
    await writeFile(daemonExecutable, daemonBytes);
    await writeFile(
      sha256sum,
      `#!/usr/bin/env node
const crypto = require('node:crypto');
const fs = require('node:fs');
const filename = process.argv[2];
const digest = crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
process.stdout.write(digest + '  ' + filename + '\\n');
`,
      { mode: 0o755 }
    );
    await chmod(sha256sum, 0o755);

    const environment = {
      ...process.env,
      CLIQ_PROC_ROOT: procRoot,
      CLIQ_SHA256SUM: sha256sum
    };
    await execFileAsync('/bin/sh', [verifier, daemonPid, expectedDigest], {
      env: environment
    });

    await assert.rejects(
      execFileAsync('/bin/sh', [verifier, '9999', expectedDigest], {
        env: environment
      })
    );

    await writeFile(path.join(daemonRoot, 'status'), 'Name:\tcliq-daemon\nPPid:\t99\n');
    await assert.rejects(
      execFileAsync('/bin/sh', [verifier, daemonPid, expectedDigest], {
        env: environment
      })
    );

    await writeFile(path.join(daemonRoot, 'status'), 'Name:\tcliq-daemon\nPPid:\t1\n');
    await writeFile(daemonExecutable, 'different helper bytes\n');
    await assert.rejects(
      execFileAsync('/bin/sh', [verifier, daemonPid, expectedDigest], {
        env: environment
      })
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
