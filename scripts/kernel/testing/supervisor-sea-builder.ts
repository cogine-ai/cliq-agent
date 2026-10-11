// Qualification-only carrier/image construction. Never a production loader.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';
import { inject } from 'postject';

export const SUPERVISOR_SEA_NODE_VERSION = '24.21.0';
export const SUPERVISOR_SEA_CARRIER_CHECKSUMS: Readonly<Record<string, string>> = {
  'linux-x64': 'fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6',
  'darwin-arm64': '6239d4cf92d864487ec8cd3615038f7b67e7f58b77b21cd2f09ea9fbd68065fe',
};

function run(fixture: string, executable: string, args: string[]) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 60_000, cwd: fixture,
    maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.error, undefined, `${executable}: ${result.error}`);
  assert.equal(result.status, 0, `${executable}: ${result.stderr}`);
  return result;
}

export async function prepareSupervisorSeaCarrier(fixture: string) {
  const platform = `${process.platform}-${process.arch}`;
  const checksum = SUPERVISOR_SEA_CARRIER_CHECKSUMS[platform];
  assert(checksum, `no qualified SEA carrier for ${platform}`);
  const archiveName = `node-v${SUPERVISOR_SEA_NODE_VERSION}-${platform}.tar.xz`;
  const response = await fetch(`https://nodejs.org/download/release/v${SUPERVISOR_SEA_NODE_VERSION}/${archiveName}`,
    { signal: AbortSignal.timeout(60_000) });
  assert(response.ok, `carrier download failed: ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  assert.equal(createHash('sha256').update(archive).digest('hex'), checksum, 'official carrier checksum mismatch');
  const archivePath = path.join(fixture, archiveName);
  await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 });
  run(fixture, 'tar', ['-xJf', archivePath, '-C', fixture]);
  const nodeRoot = path.join(fixture, `node-v${SUPERVISOR_SEA_NODE_VERSION}-${platform}`);
  const carrier = path.join(nodeRoot, 'bin/node');
  assert.equal(run(fixture, carrier, ['--version']).stdout.trim(), `v${SUPERVISOR_SEA_NODE_VERSION}`);
  return { nodeRoot, carrier };
}

export async function buildSupervisorSeaImage(input: {
  fixture: string; carrier: string; entryPoint: string; executable: string;
  variant: string; assets: Record<string, string>; defines?: Record<string, string>;
}): Promise<string> {
  const main = path.join(input.fixture, `${input.variant}.cjs`);
  const result = await build({ entryPoints: [input.entryPoint], outfile: main,
    bundle: true, platform: 'node', format: 'cjs', target: 'node24.21', metafile: true,
    // These entries run only as SEA. The ordinary ESM helper branch cannot run.
    define: { 'import.meta.url': 'undefined', ...input.defines } });
  for (const emitted of Object.values(result.metafile!.outputs)) {
    assert(emitted.imports.every(item => item.external && item.path.startsWith('node:')),
      'SEA application closure must have no runtime filesystem dependency');
  }
  const blob = path.join(input.fixture, `${input.variant}.blob`);
  const configuration = path.join(input.fixture, `${input.variant}-sea.json`);
  await writeFile(configuration, JSON.stringify({ main, output: blob, useSnapshot: false, useCodeCache: false,
    execArgvExtension: 'none', disableExperimentalSEAWarning: true, assets: input.assets }),
  { flag: 'wx', mode: 0o600 });
  run(input.fixture, input.carrier, ['--experimental-sea-config', configuration]);
  await copyFile(input.carrier, input.executable);
  if (process.platform === 'darwin') run(input.fixture, 'codesign', ['--remove-signature', input.executable]);
  await inject(input.executable, 'NODE_SEA_BLOB', await readFile(blob),
    { sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', machoSegmentName: 'NODE_SEA' });
  if (process.platform === 'darwin') run(input.fixture, 'codesign', ['--sign', '-', input.executable]);
  await chmod(input.executable, 0o500);
  return input.executable;
}
