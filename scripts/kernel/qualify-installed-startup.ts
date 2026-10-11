// Actual Linux bootstrap/selected SEA refusals before StateOwner, without a keeper.
// Positive genesis/control/signal coverage runs in the actual keeper campaign.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { canonicalSha256 } from '../../src/kernel/canonical.js';
import { sha256Bytes } from '../../src/kernel/identity.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { createInstalledRuntime } from '../../src/state/installed-runtime.js';
import { STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../src/state/native-owner.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { SUPERVISOR_SEA_CARRIER_CHECKSUMS, SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

assert.equal(process.platform, 'linux', 'installed startup qualification requires a real Linux runner');
assert.equal(process.arch, 'x64', 'no installed startup carrier qualified for this architecture');
assert(process.argv.length <= 3, 'expected at most one new absolute output directory');
if (process.argv[2]) {
  assert(path.isAbsolute(process.argv[2]), 'output directory must be absolute');
  await mkdir(process.argv[2], { mode: 0o700 }); // Never adopt an existing fixture.
}
const fixture = await realpath(process.argv[2] ?? await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-startup-')));
await chmod(fixture, 0o700);
const stateRoot = path.join(fixture, 'state');
const report: Record<string, unknown> = {
  diagnosticOnly: true, qualified: false,
  scope: 'actual signed SEA closed-role and missing-keeper refusals before database/StateOwner/control; positive genesis/control/signal run in keeper campaign, not complete I1',
  nodeVersion: SUPERVISOR_SEA_NODE_VERSION,
  carrierArchiveDigest: SUPERVISOR_SEA_CARRIER_CHECKSUMS['linux-x64']!,
};

async function authorityAbsent(): Promise<void> {
  for (const relative of [KERNEL_DATABASE_FILENAME, `${KERNEL_DATABASE_FILENAME}-wal`, `${KERNEL_DATABASE_FILENAME}-shm`,
    'runtime/state-owner.lock', 'runtime/control-v1.sock'])
    await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
}

try {
  const { packageRoot, releaseKeys, bundle, contents } = await buildInstalledSupervisorPackage(fixture);
  const installed = await createInstalledRuntime({ releaseKeys }).installInitial({ packageRoot, stateRoot });
  assert.equal(installed.bundleDigest, canonicalSha256(bundle));
  const bootstrap = path.join(stateRoot, 'runtime/bootstrap');
  assert.deepEqual(await readFile(bootstrap), contents[0]!.bytes);
  await assert.rejects(lstat(path.join(stateRoot, 'runtime', STATE_OWNER_NATIVE_RELATIVE_PATH)), { code: 'ENOENT' });
  assert.deepEqual(await readFile(path.join(stateRoot, 'runtime/bundles', installed.bundleDigest,
    STATE_OWNER_NATIVE_RELATIVE_PATH)), contents[1]!.bytes);
  const cwd = path.join(fixture, 'unrelated-cwd'); await mkdir(cwd, { mode: 0o700 });
  report.bundleDigest = installed.bundleDigest; report.manifestDigest = bundle.manifestDigest;
  report.supervisorImageDigest = sha256Bytes(contents[0]!.bytes); report.nativeHelperDigest = sha256Bytes(contents[1]!.bytes);
  const rootInfo = await lstat(stateRoot, { bigint: true });
  const rootLocator = `${rootInfo.dev}:${rootInfo.ino}:${rootInfo.uid}`;
  for (const [args, message] of [
    [[], 'expected a fixed installed Supervisor role'],
    [['--installed-supervisor', stateRoot, installed.bundleDigest, rootLocator], 'installed Supervisor differs from the fixed selected image'],
  ] as const) {
    const refused = spawnSync(bootstrap, [...args], { cwd, env: { PATH: process.env.PATH },
      encoding: 'utf8', timeout: 30_000, maxBuffer: 128 * 1024 });
    assert.equal(refused.error, undefined); assert.equal(refused.status, 1); assert.equal(refused.signal, null);
    const diagnostics = refused.stderr.trim().split('\n').filter(Boolean).map(line => parseJsonStrict(line)) as { message?: string }[];
    assert(diagnostics.some(value => value.message === message), 'refusal must come from the actual closed role');
    await authorityAbsent();
  }
  // The real selected image must retain its refusal stderr across terminal exec.
  const keeperRefused = spawnSync(bootstrap, ['--bootstrap-keeper'], { cwd, env: { PATH: process.env.PATH },
    stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 30_000, maxBuffer: 128 * 1024 });
  report.keeperOutsideServiceRefusal = { status: keeperRefused.status, signal: keeperRefused.signal, stderr: keeperRefused.stderr };
  assert.equal(keeperRefused.error, undefined); assert.equal(keeperRefused.status, 1); assert.equal(keeperRefused.signal, null);
  const keeperDiagnostics = keeperRefused.stderr.trim().split('\n').filter(Boolean).map(line => parseJsonStrict(line)) as
    { diagnosticOnly?: boolean; scope?: string; message?: string }[];
  assert(keeperDiagnostics.some(value => value.diagnosticOnly === true && value.scope === 'installed-read-startup' &&
    value.message === 'installed keeper requires its own empty delegated service root'),
  'keeper refusal diagnostic must survive terminal selected-image exec');
  await authorityAbsent();
  await assert.rejects(lstat(path.join(stateRoot, 'runtime/keeper.ready')), { code: 'ENOENT' });
  const refused = spawnSync(bootstrap, ['--bootstrap-supervisor'], { cwd, env: { PATH: process.env.PATH },
    stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 30_000, maxBuffer: 128 * 1024 });
  report.startupRefusal = { status: refused.status, signal: refused.signal, stderr: refused.stderr, joined: true };
  assert.equal(refused.error, undefined); assert.equal(refused.status, 1); assert.equal(refused.signal, null);
  const diagnostics = refused.stderr.trim().split('\n').filter(Boolean).map(line => parseJsonStrict(line)) as
    { diagnosticOnly?: boolean; scope?: string; code?: string; message?: string }[];
  assert(diagnostics.some(value => value.diagnosticOnly === true && value.scope === 'installed-read-startup' &&
    value.code === 'ARTIFACT_MISMATCH' && value.message === 'installed keeper locator is unavailable'),
  'missing keeper must refuse through the actual selected image before StateOwner, not unrelated startup failure');
  await authorityAbsent();
  report.authorityAbsent = true; report.qualified = true;
  report.result = { qualified: true, closedRoleRefusals: 2, missingKeeperBeforeAuthority: true, joined: true };
  console.log('Actual installed SEA missing-keeper/closed-role pre-authority refusal qualification passed; not complete I1');
} catch (error) {
  report.error = String((error as Error).stack ?? error).slice(0, 16_384);
  throw error;
} finally {
  await writeFile(path.join(fixture, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(`Installed startup refusal fixture/report retained: ${fixture}`);
}
