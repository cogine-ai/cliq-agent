// Self-image component qualification, not an installed Supervisor/I1 claim.
// Downloads a checksum-pinned official Node carrier into a new private fixture.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rename, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { inject } from 'postject';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { KERNEL_STATE_SCHEMA_VERSION } from '../../src/config.js';
import { policyProfile, type RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../src/state/native-owner.js';

const version = '24.21.0';
const platform = `${process.platform}-${process.arch}`;
const checksums: Record<string, string> = {
  'linux-x64': 'fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6',
  'darwin-arm64': '6239d4cf92d864487ec8cd3615038f7b67e7f58b77b21cd2f09ea9fbd68065fe',
};
assert(checksums[platform], `no qualified SEA carrier for ${platform}`);
assert(process.argv.length <= 3, 'expected at most one new absolute output directory');
const output = process.argv[2] ? path.resolve(process.argv[2]) : await mkdtemp(path.join(os.tmpdir(), 'cliq-supervisor-image-'));
if (process.argv[2]) {
  assert(path.isAbsolute(process.argv[2]), 'output directory must be absolute');
  await mkdir(output, { mode: 0o700 }); // Never adopt/overwrite an existing fixture.
}
const fixture = await realpath(output);
const repository = fileURLToPath(new URL('../..', import.meta.url));
const report: { diagnosticOnly: true; scope: string; nodeVersion: string; carrierArchiveDigest: string;
  images?: Record<string, { digest: string; byteCount: number }>;
  cases: Array<{ name: string; result: unknown }>; error?: string } = {
  diagnosticOnly: true,
  scope: 'complete Supervisor application image binding only; not installation/control/admission/execution/restart',
  nodeVersion: version, carrierArchiveDigest: checksums[platform]!, cases: [],
};
function run(executable: string, args: string[]) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 60_000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.error, undefined, `${executable}: ${result.error}`);
  assert.equal(result.status, 0, `${executable}: ${result.stderr}`);
  return result;
}
async function bytesIdentity(filename: string) {
  const bytes = await readFile(filename);
  return { digest: createHash('sha256').update(bytes).digest('hex'), byteCount: bytes.length };
}
try {
  const archiveName = `node-v${version}-${platform}.tar.xz`;
  const response = await fetch(`https://nodejs.org/download/release/v${version}/${archiveName}`, { signal: AbortSignal.timeout(60_000) });
  assert(response.ok, `carrier download failed: ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  assert.equal(createHash('sha256').update(archive).digest('hex'), checksums[platform], 'official carrier checksum mismatch');
  const archivePath = path.join(fixture, archiveName);
  await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 });
  run('tar', ['-xJf', archivePath, '-C', fixture]);
  const nodeRoot = path.join(fixture, `node-v${version}-${platform}`);
  const carrier = path.join(nodeRoot, 'bin/node');
  assert.equal(run(carrier, ['--version']).stdout.trim(), `v${version}`);
  const keys = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'explicit-sea-component-test-only',
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const rootAsset = path.join(fixture, 'explicit-test-root.json');
  await writeFile(rootAsset, JSON.stringify(releaseKeys), { flag: 'wx', mode: 0o400 });
  const installation = path.join(fixture, 'image');
  await mkdir(path.join(installation, path.dirname(STATE_OWNER_NATIVE_RELATIVE_PATH)), { recursive: true, mode: 0o700 });
  const helper = path.join(installation, STATE_OWNER_NATIVE_RELATIVE_PATH);
  run('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'darwin' ? ['-bundle', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC']),
    '-I', path.join(nodeRoot, 'include/node'), path.join(repository, 'native/state-owner/state-owner.c'), '-o', helper]);
  await chmod(helper, 0o500);
  async function image(variant: string) {
    const main = path.join(fixture, `${variant}.cjs`);
    const result = await build({ entryPoints: [path.join(repository, 'src/state/testing/supervisor-sea-child.ts')], outfile: main,
      bundle: true, platform: 'node', format: 'cjs', target: 'node24.21', metafile: true,
      // This entry is SEA-only; its ordinary ESM native-helper branch cannot run.
      define: { 'import.meta.url': 'undefined', __QUALIFICATION_IMAGE_VARIANT__: JSON.stringify(variant) } });
    for (const emitted of Object.values(result.metafile!.outputs)) {
      assert(emitted.imports.every((item) => item.external && item.path.startsWith('node:')),
        'SEA application closure must have no runtime filesystem dependency');
    }
    const blob = path.join(fixture, `${variant}.blob`);
    const configuration = path.join(fixture, `${variant}-sea.json`);
    await writeFile(configuration, JSON.stringify({ main, output: blob, useSnapshot: false, useCodeCache: false,
      execArgvExtension: 'none', disableExperimentalSEAWarning: true, assets: { 'explicit-test-root.json': rootAsset } }),
    { flag: 'wx', mode: 0o600 });
    run(carrier, ['--experimental-sea-config', configuration]);
    const executable = path.join(installation, variant);
    await copyFile(carrier, executable);
    if (process.platform === 'darwin') run('codesign', ['--remove-signature', executable]);
    await inject(executable, 'NODE_SEA_BLOB', await readFile(blob),
      { sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', machoSegmentName: 'NODE_SEA' });
    if (process.platform === 'darwin') run('codesign', ['--sign', '-', executable]);
    await chmod(executable, 0o500);
    return executable;
  }
  const supervisor = await image('approved');
  const changedApplication = await image('changed');
  report.images = { approved: await bytesIdentity(supervisor), changed: await bytesIdentity(changedApplication),
    nativeHelper: await bytesIdentity(helper) };
  assert.notEqual(report.images.approved!.digest, report.images.changed!.digest, 'changed app must change the complete image identity');
  async function manifestFor(executable: string) {
    // Other fixture roles are deliberately unused. This is not a complete
    // RuntimeBundle installation/structured-closure or provider qualification.
    // Build this component fixture without the checkout's dist/native helper;
    // only the checksum-pinned carrier's independently compiled helper is used.
    const unused = (role: string, entryId: string, executable: boolean) => {
      const bytes = canonicalJsonBytes({ diagnosticOnly: true, unusedRole: role });
      return { entryId, role, version: '1', relativePath: `unused/${entryId}`, executable,
        digest: createHash('sha256').update(bytes).digest('hex'), byteCount: bytes.length };
    };
    const profile = policyProfile();
    const profileRef = canonicalSha256(profile);
    const bundle: RuntimeBundleManifest = {
      schemaVersion: 1, bundleVersion: 'self-image-component-test-only',
      controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
      stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
      entries: [
        { entryId: 'component-supervisor', role: 'supervisor', executable: true, version: '1',
          relativePath: path.basename(executable), ...await bytesIdentity(executable) },
        { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', executable: true, version: '1',
          relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH, ...await bytesIdentity(helper) },
        unused('worker', 'unused-worker', true), unused('trust_store', 'default_https_trust_store', false),
        unused('sandbox_root_profile', 'unused-root-profile', false),
        { entryId: 'component-policy', role: 'policy_engine', executable: false, version: '1',
          relativePath: 'unused/policy', digest: profileRef, byteCount: canonicalJsonBytes(profile).byteLength },
      ],
      structuredArtifacts: [{ artifactId: 'component-policy', rootEntryId: 'component-policy', kind: 'policy_engine_profile',
        artifactRef: profileRef, semanticDigest: profile.profileDigest, memberRefs: [] }],
      guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '',
    };
    const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
    bundle.manifestDigest = canonicalSha256(core);
    bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
    const filename = path.join(fixture, `${path.basename(executable)}-runtime-bundle.json`);
    await writeFile(filename, canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
    return filename;
  }
  const manifest = await manifestFor(supervisor);
  const changedManifest = await manifestFor(changedApplication);
  async function exercise(name: string, executable: string, expected: boolean, extraEnv: Record<string, string> = {},
    selectedManifest = manifest, expectedCode = 'ARTIFACT_MISMATCH') {
    const state = path.join(fixture, name);
    await mkdir(state, { mode: 0o700 });
    const child = spawnSync(executable, [state, selectedManifest], { encoding: 'utf8', timeout: 30_000, cwd: fixture,
      env: { PATH: process.env.PATH, ...extraEnv }, maxBuffer: 128 * 1024 });
    assert.equal(child.error, undefined, `${name}: ${child.error}`);
    assert.equal(child.status, 0, `${name}: ${child.stderr}`);
    const result = JSON.parse(child.stdout.trim()) as { diagnosticOnly: boolean; accepted: boolean; code?: string; variant: string };
    report.cases.push({ name, result });
    assert.equal(result.diagnosticOnly, true);
    assert.equal(result.variant, path.basename(executable)); // Changed app actually ran.
    assert.equal(result.accepted, expected, `${name}: unexpected authority result`);
    if (!expected) {
      assert.equal(result.code, expectedCode, `${name}: must refuse for the intended image/helper boundary`);
      assert.deepEqual(await readdir(state), [], `${name}: refusal must precede StateRoot mutation`);
    }
  }
  await exercise('signed-image', supervisor, true);
  await exercise('changed-image-own-signature', changedApplication, true, {}, changedManifest);
  await exercise('changed-embedded-application', changedApplication, false);
  const preloadMarker = path.join(fixture, 'preload-executed');
  const preload = path.join(fixture, 'preload.cjs');
  await writeFile(preload, `require('node:fs').writeFileSync(${JSON.stringify(preloadMarker)}, 'unsafe preload executed');\n`,
    { flag: 'wx', mode: 0o400 });
  run(carrier, ['--require', preload, '-e', '']);
  assert.equal(await readFile(preloadMarker, 'utf8'), 'unsafe preload executed', 'preload control must actually run');
  await unlink(preloadMarker);
  await exercise('closed-node-options', supervisor, true, { NODE_OPTIONS: `--require=${preload}` });
  assert(!(await readdir(fixture)).includes(path.basename(preloadMarker)), 'NODE_OPTIONS must not execute outside-image code');
  await chmod(helper, 0o700);
  try { await exercise('writable-helper', supervisor, false); } finally { await chmod(helper, 0o500); }
  const decoy = path.join(fixture, STATE_OWNER_NATIVE_RELATIVE_PATH);
  await mkdir(path.dirname(decoy), { recursive: true, mode: 0o700 });
  await copyFile(helper, decoy);
  await chmod(decoy, 0o500);
  await rename(helper, `${helper}.held-by-campaign`);
  try {
    // The fixed installed helper is missing, despite valid bytes in cwd.
    // Node's exact open ENOENT is a refusal, never an alternate search path.
    await exercise('missing-helper-no-cwd-fallback', supervisor, false, {}, manifest, 'ENOENT');
  } finally { await rename(`${helper}.held-by-campaign`, helper); }
  await rename(helper, `${helper}.held-by-campaign`);
  try {
    await writeFile(helper, Buffer.concat([await readFile(`${helper}.held-by-campaign`), Buffer.from('changed test-only helper bytes')]),
      { flag: 'wx', mode: 0o500 });
    await exercise('changed-helper-bytes', supervisor, false);
  } finally { await unlink(helper); await rename(`${helper}.held-by-campaign`, helper); }
  console.log(`Supervisor self-image component qualification: ${report.cases.length} cases passed; not a completed I1`);
} catch (error) {
  report.error = String((error as Error).stack ?? error).slice(0, 16_384);
  throw error;
} finally {
  await writeFile(path.join(fixture, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(`Component qualification fixture/report retained: ${fixture}`);
}
