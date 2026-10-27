import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('fixed dependency command data keeps all original fields and the private wire version', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-protocol-'));
  try {
    const binary = path.join(root, 'protocol');
    const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../../native/linux/dependency-npm-protocol.test.c', import.meta.url)), '-o', binary],
    { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
    assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
    const run = spawnSync(binary, [], { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536 });
    assert.equal(run.error, undefined); assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
    const result = JSON.parse(run.stdout); assert.deepEqual(result, { checks: 48, qualified: false });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('owned Linux sealed chunks stage full >1MiB packages and actually close every consumed descriptor',
  { skip: process.platform !== 'linux' ? 'actual Linux memfd/seal component is required' : false }, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-stage-build-'));
    try {
      const binary = path.join(root, 'stage');
      const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        fileURLToPath(new URL('../../../native/linux/dependency-npm-stage.test.c', import.meta.url)), '-o', binary],
      { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
      assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
      const run = spawnSync(binary, [], { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536 });
      assert.equal(run.error, undefined); assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
      const result = JSON.parse(run.stdout);
      assert.equal(result.format, 'cliq-dependency-stage-component-v1'); assert.equal(result.qualified, false);
      assert(Number.isSafeInteger(result.checks) && result.checks > 500);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

test('actual Linux private RW-directory capability cannot escape the blocked worker read-only view',
  { skip: process.platform !== 'linux' ? 'actual Linux user/mount/PID namespaces are required' : false }, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-view-build-'));
    try {
      const binary = path.join(root, 'boundary');
      const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        fileURLToPath(new URL('../../../native/linux/dependency-npm-boundary.test.c', import.meta.url)), '-o', binary],
      { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
      assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
      const run = spawnSync(binary, [], { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536 });
      assert.equal(run.error, undefined); assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
      assert.deepEqual(JSON.parse(run.stdout), { component: 'dependency-private-ro-view-rw-capability', bothCapsDroppedBeforeBlocked: true,
        childDescriptorPruned: true, parentProcDenied: true, pathParentRenameHardlinkReadOnly: true,
        writerAndOriginalDirectoryJoinedBeforeRelease: true, allProcessesAndPipesJoined: true, installedQualification: false });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
