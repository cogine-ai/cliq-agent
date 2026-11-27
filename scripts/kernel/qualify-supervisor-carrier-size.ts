// Experimental publisher input only. Never selected by the production builder.
// GNU strip and actual Node/SEA execution must all succeed; even then guest,
// installation, complete R checks and the original READY budget stay unverified.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { copyFile, lstat, mkdir, open, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { compareSupervisorCarrierLayout } from './testing/supervisor-carrier-layout.js';
import { buildSupervisorSeaImage, prepareSupervisorSeaCarrier, SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

const [output, cachedArchive, ...extra] = process.argv.slice(2);
assert.equal(process.platform, 'linux', 'this experiment requires the standard Linux runner');
assert.equal(process.arch, 'x64');
assert(output && path.isAbsolute(output) && !extra.length && (!cachedArchive || path.isAbsolute(cachedArchive)),
  'usage: qualify-supervisor-carrier-size.ts NEW_ABSOLUTE_OUTPUT [FIXED_OFFICIAL_CACHED_ARCHIVE]');
assert(!process.env.NODE_OPTIONS && !process.env.LD_PRELOAD && !process.env.LD_LIBRARY_PATH,
  'the experiment does not accept runtime injection');
await mkdir(output, { mode: 0o700 }); // Never reuse an earlier image or report.
const report: { diagnosticOnly: true; qualified: false; stage: 'carrier' | 'tool' | 'strip_debug' | 'strip_static' | 'complete'; carrier?: Record<string, unknown>;
  stripTool?: Record<string, unknown>; cases: Record<string, unknown>[]; failure?: 'experiment_failed';
  guestExecutionVerified: false; installedRuntimeQualified: false; completeSixteenReadsQualified: false; readyFiveSecondsQualified: false } = {
  diagnosticOnly: true, qualified: false, stage: 'carrier', cases: [], guestExecutionVerified: false,
  installedRuntimeQualified: false, completeSixteenReadsQualified: false, readyFiveSecondsQualified: false,
};
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
async function heldBytes(filename: string, maxBytes = 268_435_456) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    assert(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(maxBytes), 'experiment input must be a bounded single-link regular file');
    const bytes = await handle.readFile(), after = await handle.stat({ bigint: true }), named = await lstat(filename, { bigint: true });
    for (const key of ['dev', 'ino', 'size', 'mode', 'mtimeNs', 'ctimeNs'] as const) {
      assert.equal(after[key], before[key], 'experiment held file changed'); assert.equal(named[key], before[key], 'experiment named file changed');
    }
    assert.equal(bytes.length, Number(before.size));
    return { bytes, identity: before, sha256: digest(bytes), byteCount: bytes.length };
  } finally { await handle.close(); }
}
function run(executable: string, args: string[], expected?: string) {
  const child = spawnSync(executable, args, { cwd: output, encoding: 'utf8', timeout: 60_000, maxBuffer: 65_536,
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' } });
  assert.equal(child.error, undefined, 'experiment process failed to join normally');
  assert.equal(child.signal, null); assert.equal(child.status, 0, 'experiment process failed');
  if (expected !== undefined) assert.equal(child.stdout, expected, 'experiment output did not match its fixed execution probe');
  assert.equal(child.stderr, '', 'experiment command returned unexpected diagnostics');
  return child.stdout;
}
async function unchanged(filename: string, original: Awaited<ReturnType<typeof heldBytes>>) {
  const current = await heldBytes(filename);
  assert.equal(current.sha256, original.sha256, 'original input bytes changed');
  for (const key of ['dev', 'ino', 'size', 'mode', 'mtimeNs', 'ctimeNs'] as const)
    assert.equal(current.identity[key], original.identity[key], 'original input identity changed');
}
const originalInputs: Array<{ filename: string; original: Awaited<ReturnType<typeof heldBytes>> }> = [];
let stripInput: { filename: string; original: Awaited<ReturnType<typeof heldBytes>> } | undefined;
try {
  const cached = cachedArchive ? await heldBytes(cachedArchive) : undefined;
  if (cached && cachedArchive) originalInputs.push({ filename: cachedArchive, original: cached });
  const { carrier } = await prepareSupervisorSeaCarrier(output, cachedArchive);
  const archive = path.join(output, `node-v${SUPERVISOR_SEA_NODE_VERSION}-linux-x64.tar.xz`);
  const originalArchive = await heldBytes(archive), original = await heldBytes(carrier);
  originalInputs.push({ filename: archive, original: originalArchive }, { filename: carrier, original });
  report.carrier = { nodeVersion: SUPERVISOR_SEA_NODE_VERSION, byteCount: original.byteCount, sha256: original.sha256,
    officialArchiveSha256: originalArchive.sha256, originalInputsUnchanged: false };
  report.stage = 'tool';
  const strip = await realpath('/usr/bin/strip'), tool = await heldBytes(strip, 16_777_216);
  assert.equal(tool.identity.uid, 0n); assert.equal(tool.identity.mode & 0o022n, 0n, 'strip must be a protected system tool');
  stripInput = { filename: strip, original: tool };
  const version = run(strip, ['--version']);
  const firstLine = version.split('\n')[0]!;
  assert(/^GNU strip \([\x20-\x7e]{1,96}\) [0-9][\x20-\x7e]{0,48}$/u.test(firstLine), 'only the runner existing GNU strip is accepted; no fallback or installation');
  report.stripTool = { sha256: tool.sha256, byteCount: tool.byteCount, version: firstLine, processAndPipesJoined: true };
  run(carrier, ['--version'], `v${SUPERVISOR_SEA_NODE_VERSION}\n`);
  const probe = path.join(output, 'carrier-probe.ts'), asset = path.join(output, 'carrier-probe-asset.txt');
  await writeFile(asset, 'cliq-carrier-asset-v1\n', { flag: 'wx', mode: 0o400 });
  await writeFile(probe, `import assert from 'node:assert/strict';
import {isSea,getAsset} from 'node:sea';
import {createHash} from 'node:crypto';
assert.equal(process.version,'v24.21.0'); assert.equal(isSea(),true);
assert.equal(getAsset('carrier-probe','utf8'),'cliq-carrier-asset-v1\\n');
assert.equal(createHash('sha256').update('abc').digest('hex'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
process.stdout.write('cliq-carrier-sea-probe-v1\\n');\n`, { flag: 'wx', mode: 0o400 });
  for (const [mode, option] of [['debug', '--strip-debug'], ['static', '--strip-all']] as const) {
    report.stage = mode === 'debug' ? 'strip_debug' : 'strip_static';
    const candidate = path.join(output, `node-${mode}`), row: Record<string, unknown> = { mode, option,
      stripProcessAndPipesJoined: false, structureVerified: false, nodeVersionExecutionVerified: false,
      seaExecutionVerified: false, guestExecutionVerified: false };
    report.cases.push(row);
    await copyFile(carrier, candidate, constants.COPYFILE_EXCL);
    // GNU strip otherwise merges SHT_NOTE records in strip-all mode. The
    // structural gate requires every retained note byte to remain unchanged.
    run(strip, [option, '--no-merge-notes', '--', candidate]);
    row.stripProcessAndPipesJoined = true; await unchanged(strip, tool);
    const selected = await heldBytes(candidate);
    row.candidate = { byteCount: selected.byteCount, sha256: selected.sha256 };
    let structureStage: string | undefined;
    try {
      row.layout = compareSupervisorCarrierLayout(original.bytes, selected.bytes, mode,
        mode === 'static' ? value => { structureStage = value; } : undefined);
      row.structureVerified = true;
    } catch (error) {
      if (mode === 'static' && structureStage !== undefined) row.structureFailureStage = structureStage;
      throw error;
    }
    run(candidate, ['--version'], `v${SUPERVISOR_SEA_NODE_VERSION}\n`); row.nodeVersionExecutionVerified = true;
    const executable = path.join(output, `sea-${mode}`);
    await buildSupervisorSeaImage({ fixture: output, carrier: candidate, entryPoint: probe, executable,
      variant: `carrier-experiment-${mode}`, assets: { 'carrier-probe': asset } });
    const sea = await heldBytes(executable);
    run(executable, [], 'cliq-carrier-sea-probe-v1\n'); row.seaExecutionVerified = true;
    row.sea = { byteCount: sea.byteCount, sha256: sea.sha256, processAndPipesJoined: true };
    await unchanged(carrier, original); await unchanged(archive, originalArchive);
    if (cached && cachedArchive) await unchanged(cachedArchive, cached);
    await unchanged(candidate, selected);
  }
  await unchanged(strip, tool); report.stage = 'complete';
} catch {
  report.failure = 'experiment_failed'; process.exitCode = 1;
} finally {
  let inputsUnchanged = originalInputs.length >= 2;
  for (const input of originalInputs) {
    try { await unchanged(input.filename, input.original); }
    catch { inputsUnchanged = false; report.failure = 'experiment_failed'; process.exitCode = 1; }
  }
  if (report.carrier) report.carrier.originalInputsUnchanged = inputsUnchanged;
  if (stripInput) {
    try { await unchanged(stripInput.filename, stripInput.original); }
    catch { report.failure = 'experiment_failed'; process.exitCode = 1; }
  }
  await writeFile(path.join(output, 'carrier-size-experiment.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
