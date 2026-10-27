// Fixed free-CI composition only. No replacement native authority or installed
// qualification. Both full source views and all captured original output remain.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, realpath, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { readQualificationSource, type FrozenQualificationSource } from './qualification-source.js';
import { readQualificationDependencyTree } from './qualification-dependencies.js';
import { prepareSupervisorSeaCarrier, SUPERVISOR_SEA_NODE_VERSION, SUPERVISOR_SEA_CARRIER_CHECKSUMS } from './supervisor-sea-builder.js';
import { readNativeCallbackEvidence } from './native-callback-evidence.js';

const original = { commit: 'ba804a59dcadee80cb41c822e2d0e32198462f20', tree: 'e35a127d9e90848e4c569aa03b398d56a59a025d',
  native: '73cd16a6f23e9054c7a0b50ec6c1dcdeb47a1561f180f661686e1a63f74140a9' };
const candidateNative = 'e5413784fef74decb7e9cc0befac523e003523a69879fc6bb8f8f15498a3d364';
const overlays = Object.freeze({
  'scripts/kernel/testing/model-broker-preparation-lifecycle-child.mjs': '0454d5fd45921b3de29599f383253b28252848a3b765a16ff4de8a12940988c1',
  'scripts/kernel/testing/credential-platform-timeout-child.mjs': '8968ec6ba70492f845b8e0ff3e2e6a110338ca73d363c81072405920e0600b16',
  'scripts/kernel/testing/credential-platform-timeout-fixture.c': '4ba83ef0e0e7b4bb98709703aa704e4c9e026e8013cb4815c7ac2282d33031cc',
});
const suite = ['scripts/kernel/testing/credential-platform-queue.test.ts',
  'scripts/kernel/testing/credential-platform-timeout.test.ts', 'scripts/kernel/testing/model-broker-preparation-lifecycle.test.ts'];
const metadata = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
async function heldBytes(filename: string, maximum: number): Promise<Buffer> {
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    assert(before.isFile() && before.nlink === 1n && before.size >= 0n && before.size <= BigInt(maximum));
    const bytes = await file.readFile(); assert.equal(BigInt(bytes.length), before.size);
    for (const after of [await file.stat({ bigint: true }), await lstat(filename, { bigint: true })])
      assert(metadata.every(key => before[key] === after[key]));
    return bytes;
  } finally { await file.close(); }
}
async function pin(filename: string, maximum = 132 * 1024 * 1024) {
  const bytes = await heldBytes(filename, maximum); return { file: path.basename(filename), bytes: bytes.length, sha256: sha(bytes) };
}
export async function qualifyNativeCallbackLifecycle(destination: string) {
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert(process.getuid!() > 0);
  assert(path.isAbsolute(destination) && await realpath(path.dirname(destination)) === path.dirname(destination));
  await mkdir(destination, { mode: 0o700 }); // No adoption, reset or cleanup of another run.
  const repository = path.resolve(fileURLToPath(new URL('../../..', import.meta.url))); assert.equal(await realpath(repository), repository);
  const report: Record<string, any> = { diagnosticOnly: true, format: 'cliq-native-callback-lifecycle-v1', qualified: false,
    original, installedI1Qualified: false, ready5Qualified: false, stop2Qualified: false, successor30Qualified: false, views: [] };
  let stage = 'source_inventory';
  const git = (...args: string[]) => {
    const value = spawnSync('git', args, { cwd: repository, timeout: 60000, maxBuffer: 132 * 1024 * 1024 });
    assert.equal(value.error, undefined); assert.equal(value.signal, null); assert.equal(value.status, 0); return value.stdout;
  };
  const prepareView = async (name: 'baseline' | 'candidate', revision: string, expectedTree: string) => {
    assert.equal(git('rev-parse', revision + '^{tree}').toString().trim(), expectedTree);
    const members = git('ls-tree', '-rz', '--full-tree', revision).toString('utf8').split('\0').filter(Boolean).map(line => {
      const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(line); assert(match);
      const relative = match[3]!; assert(!relative.includes('\\') && !relative.startsWith('/') && relative.normalize('NFC') === relative &&
        relative.split('/').every(part => part && part !== '.' && part !== '..'));
      return { path: relative, mode: match[1]!, blob: match[2]! };
    });
    assert(members.length > 0 && members.length <= 4096); if (name === 'baseline') assert.equal(members.length, 1475);
    const root = path.join(destination, name), archiveFile = path.join(destination, name + '.source.tar');
    const archive = git('archive', '--format=tar', revision);
    await writeFile(archiveFile, archive, { flag: 'wx', mode: 0o400 }); await mkdir(root, { mode: 0o700 });
    const extracted = spawnSync('tar', ['--no-same-owner', '-xf', archiveFile, '-C', root], { timeout: 60000, maxBuffer: 65536 });
    assert.equal(extracted.error, undefined); assert.equal(extracted.signal, null); assert.equal(extracted.status, 0);
    const inventory: Array<{ path: string; mode: string; size: number; sha256: string }> = []; let total = 0;
    for (const member of members) {
      const filename = path.join(root, member.path), bytes = await heldBytes(filename, 16 * 1024 * 1024); total += bytes.length;
      assert(total <= 128 * 1024 * 1024);
      assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'), member.blob);
      if (name === 'candidate') assert((await heldBytes(path.join(repository, member.path), bytes.length)).equals(bytes), 'candidate checkout differs from HEAD');
      inventory.push({ path: member.path, mode: member.mode, size: bytes.length, sha256: sha(bytes) });
    }
    assert.equal(inventory.find(row => row.path === 'native/linux/credential-platform.c')!.sha256, name === 'baseline' ? original.native : candidateNative);
    for (const [relative, expected] of Object.entries(overlays)) {
      const bytes = await heldBytes(path.join(repository, relative), 65536); assert.equal(sha(bytes), expected);
      if (name === 'baseline') await writeFile(path.join(root, relative), bytes); // Explicit fixture overlay, never a Git-tree claim.
      const row = inventory.find(row => row.path === relative)!; row.size = bytes.length; row.sha256 = expected;
    }
    const lock = inventory.find(row => row.path === 'package-lock.json')!;
    assert.equal(lock.sha256, sha(await heldBytes(path.join(repository, 'package-lock.json'), 16 * 1024 * 1024)));
    await symlink(path.join(repository, 'node_modules'), path.join(root, 'node_modules'));
    for (const member of inventory) await chmod(path.join(root, member.path), member.mode === '100755' ? 0o555 : 0o444);
    const directories = new Set([root]);
    for (const member of inventory) for (let directory = path.dirname(path.join(root, member.path)); directory !== root; directory = path.dirname(directory)) directories.add(directory);
    for (const directory of directories) await chmod(directory, 0o555);
    const manifestPath = path.join(destination, name + '.inventory.json'), manifest = canonicalJsonBytes({ inventory });
    await writeFile(manifestPath, manifest, { flag: 'wx', mode: 0o400 });
    const source: FrozenQualificationSource = Object.freeze({ root, manifestPath, manifestSha256: sha(manifest) });
    const before = await readQualificationSource(source);
    return { source, before, record: { name, originalGitCommit: revision, originalGitTree: expectedTree,
      fixtureOverlay: name === 'baseline' ? overlays : {}, sourceMembersMatchUnmodifiedGitTree: name !== 'baseline',
      nativeSha256: name === 'baseline' ? original.native : candidateNative, archive: await pin(archiveFile),
      manifest: await pin(manifestPath), provenance: before } };
  };
  try {
    const current = git('rev-parse', 'HEAD').toString().trim(), currentTree = git('rev-parse', 'HEAD^{tree}').toString().trim();
    assert.match(current, /^[0-9a-f]{40}$/u); assert.match(currentTree, /^[0-9a-f]{40}$/u);
    const baseline = await prepareView('baseline', original.commit, original.tree), candidate = await prepareView('candidate', current, currentTree);
    const unchanged = [...suite, 'scripts/kernel/build-linux-credential-platform.mjs', 'scripts/kernel/build-linux-model-broker.mjs',
      'scripts/kernel/testing/supervisor-sea-builder.ts', 'scripts/kernel/testing/credential-secret-service-fixture.h'];
    report.originalRecipeAndTestFiles = [];
    for (const relative of unchanged) {
      const bytes = await heldBytes(path.join(baseline.source.root, relative), 16 * 1024 * 1024);
      assert((await heldBytes(path.join(candidate.source.root, relative), 16 * 1024 * 1024)).equals(bytes));
      report.originalRecipeAndTestFiles.push({ path: relative, bytes: bytes.length, sha256: sha(bytes) });
    }
    stage = 'dependencies'; const dependencies = path.join(repository, 'node_modules');
    const dependencyCut = await readQualificationDependencyTree(dependencies); report.sharedDependencyCut = dependencyCut;
    report.sharedDependencyRoot = dependencies; report.views = [baseline.record, candidate.record];
    stage = 'carrier'; const carrierRoot = path.join(destination, 'carrier'); await mkdir(carrierRoot, { mode: 0o700 });
    await prepareSupervisorSeaCarrier(carrierRoot, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const carrierArchive = path.join(carrierRoot, `node-v${SUPERVISOR_SEA_NODE_VERSION}-linux-x64.tar.xz`);
    const carrierPin = await pin(carrierArchive); assert.equal(carrierPin.sha256, SUPERVISOR_SEA_CARRIER_CHECKSUMS['linux-x64']); report.carrier = carrierPin;
    for (const view of [baseline, candidate]) {
      stage = view.record.name;
      const temporary = path.join(destination, view.record.name + '-tmp'); await mkdir(temporary, { mode: 0o700 });
      assert.equal(await readQualificationDependencyTree(dependencies), dependencyCut);
      assert.deepEqual(await readQualificationSource(view.source), view.before);
      assert.deepEqual(await pin(carrierArchive), carrierPin);
      const argv = ['--test', '--test-reporter=tap', '--test-concurrency=1', '--import', 'tsx', ...suite];
      const run = spawnSync(process.execPath, argv, { cwd: view.source.root,
        env: { PATH: process.env.PATH, TMPDIR: temporary, CLIQ_QUALIFICATION_CARRIER_ARCHIVE: carrierArchive },
        timeout: 4 * 180000, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024 });
      const joined = run.error === undefined && run.signal === null && typeof run.status === 'number';
      const stdoutFile = path.join(destination, view.record.name + '.tap'), stderrFile = path.join(destination, view.record.name + '.stderr');
      await writeFile(stdoutFile, run.stdout ?? Buffer.alloc(0), { flag: 'wx', mode: 0o400 });
      await writeFile(stderrFile, run.stderr ?? Buffer.alloc(0), { flag: 'wx', mode: 0o400 });
      const record: Record<string, any> = view.record;
      const collectorCode = (run.error as NodeJS.ErrnoException | undefined)?.code;
      record.run = { argv: [process.execPath, ...argv], code: run.status, signal: run.signal, processAndStdioJoined: joined,
        collectorError: run.error ? collectorCode === 'ENOBUFS' ? 'output_bound' : collectorCode === 'ETIMEDOUT' ? 'collector_timeout' : 'collector_refused' : null,
        stdout: await pin(stdoutFile), stderr: await pin(stderrFile) };
      try { record.evidence = readNativeCallbackEvidence({ mode: view.record.name, stdout: run.stdout, stderr: run.stderr,
        code: run.status, signal: run.signal, joined }); }
      catch { record.evidenceRefused = true; } // Preserve all original failed output; never relabel unknown failure as RED.
      record.sourceAfter = await readQualificationSource(view.source); assert.deepEqual(record.sourceAfter, view.before);
      assert.equal(await readQualificationDependencyTree(dependencies), dependencyCut); assert.deepEqual(await pin(carrierArchive), carrierPin);
    }
    report.qualified = report.views.every((view: Record<string, any>) => view.evidence && !view.evidenceRefused);
  } catch { report.failureStage = stage; }
  await writeFile(path.join(destination, 'native-callback-lifecycle.json'), canonicalJsonBytes(report), { flag: 'wx', mode: 0o644 });
  if (!report.qualified) throw new Error('native callback qualification refused; inspect retained source, input and output evidence');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 3); await qualifyNativeCallbackLifecycle(process.argv[2]!);
}
