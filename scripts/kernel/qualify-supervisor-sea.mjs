import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';
import { inject } from 'postject';
import { canonicalJsonBytes, canonicalSha256 } from '../../dist/kernel/canonical.js';
import { policyProfile } from '../../dist/policy/runtime-authority.js';

const repository = fileURLToPath(new URL('../..', import.meta.url));
const fixture = fileURLToPath(new URL('./fixtures/supervisor-sea-probe.ts', import.meta.url));
const platform = `${process.platform}-${process.arch}`;
const helperRelativePath = `native/${platform}/state-owner.node`;
const helperSource = path.join(repository, 'dist', helperRelativePath);
const readerRelativePath = `native/${platform}/package-reader.node`;
const readerSource = path.join(repository, 'dist', readerRelativePath);
const listenerRelativePath = `native/${platform}/control-listener`;
const listenerSource = path.join(repository, 'dist', listenerRelativePath);

if (!['darwin', 'linux'].includes(process.platform)) {
  throw new Error('Supervisor SEA qualification requires macOS or Linux');
}
const [major, minor] = process.versions.node.split('.').map(Number);
if (major !== 24 || minor < 16) {
  throw new Error('Supervisor SEA qualification requires the pinned Node 24.16+ build line');
}

// Darwin's AF_UNIX sun_path is 104 bytes, including the trailing NUL.
const root = await mkdtemp(path.join(await realpath('/tmp'), 'cliq-supervisor-sea-'));
try {
  const packageRoot = path.join(root, 'package');
  const stateRoot = path.join(root, 'state');
  await mkdir(packageRoot, { mode: 0o700 });
  await mkdir(stateRoot, { mode: 0o700 });
  const bundled = path.join(root, 'supervisor.cjs');
  const blob = path.join(root, 'supervisor.blob');
  const executable = path.join(packageRoot, 'supervisor');
  const config = path.join(root, 'sea-config.json');
  const key = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'sea-qualification-fixture',
    publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const keyAsset = path.join(root, 'release-keys.json');
  await writeFile(keyAsset, JSON.stringify(releaseKeys), { mode: 0o400 });
  const built = await build({
    entryPoints: [fixture], bundle: true, platform: 'node', format: 'cjs', target: 'node24',
    outfile: bundled, write: true, logLevel: 'silent'
  });
  const unexpectedWarnings = built.warnings.filter((warning) => warning.id !== 'empty-import-meta');
  assert.deepEqual(unexpectedWarnings, [], 'SEA bundle has an unexpected build warning');
  await writeFile(config, JSON.stringify({
    main: bundled, output: blob, useSnapshot: false, useCodeCache: false,
    execArgvExtension: 'none', assets: { 'release-keys.json': keyAsset }
  }));
  const prepared = spawnSync(process.execPath, ['--experimental-sea-config', config], {
    encoding: 'utf8', timeout: 30_000
  });
  if (prepared.error) throw prepared.error;
  assert.equal(prepared.status, 0, prepared.stderr);
  await copyFile(process.execPath, executable);
  if (process.platform === 'darwin') {
    const removal = spawnSync('codesign', ['--remove-signature', executable], {
      encoding: 'utf8', timeout: 30_000
    });
    if (removal.error) throw removal.error;
    if (removal.status !== 0) {
      // An unsigned setup-node image needs no removal; never inject over a signature we failed to remove.
      const stillSigned = spawnSync('codesign', ['--verify', executable], {
        encoding: 'utf8', timeout: 30_000
      });
      if (stillSigned.error) throw stillSigned.error;
      assert.notEqual(stillSigned.status, 0, 'could not remove the Node image signature');
    }
  }
  await inject(executable, 'NODE_SEA_BLOB', await readFile(blob), {
    sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
    machoSegmentName: 'NODE_SEA'
  });
  if (process.platform === 'darwin') {
    execFileSync('codesign', ['--sign', '-', executable], { timeout: 30_000, stdio: 'pipe' });
    execFileSync('codesign', ['--verify', executable], { timeout: 30_000, stdio: 'pipe' });
  }
  await chmod(executable, 0o500);
  const helperTarget = path.join(packageRoot, helperRelativePath);
  await mkdir(path.dirname(helperTarget), { recursive: true, mode: 0o700 });
  await copyFile(helperSource, helperTarget);
  await chmod(helperTarget, 0o500);
  const profile = policyProfile();
  const entries = [];
  const add = async (entryId, role, relativePath, source, executableEntry) => {
    const target = path.join(packageRoot, relativePath);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    if (source !== target) {
      if (typeof source === 'string') await copyFile(source, target);
      else await writeFile(target, source);
      await chmod(target, executableEntry ? 0o500 : 0o400);
    }
    const bytes = await readFile(target);
    entries.push({ entryId, role, version: '1', relativePath,
      digest: createHash('sha256').update(bytes).digest('hex'),
      byteCount: (await stat(target)).size, executable: executableEntry });
  };
  await add('supervisor', 'supervisor', 'supervisor', executable, true);
  await add('worker', 'worker', 'payload/worker', Buffer.from('fixture worker'), true);
  await add('state_owner_native', 'platform_helper', helperRelativePath, helperTarget, true);
  await add('runtime_bundle_package_reader', 'platform_helper', readerRelativePath, readerSource, true);
  await add('control_listener_native', 'platform_helper', listenerRelativePath, listenerSource, true);
  await add('policy', 'policy_engine', 'payload/policy', canonicalJsonBytes(profile), false);
  await add('default_https_trust_store', 'trust_store', 'payload/trust', Buffer.from('fixture trust'), false);
  await add('sandbox-root', 'sandbox_root_profile', 'payload/root', Buffer.from('fixture root'), false);
  const manifest = {
    schemaVersion: 1, bundleVersion: 'supervisor-sea-qualification-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 }, workerProtocolRange: { min: 1, max: 1 },
    entries, structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy',
      rootEntryId: 'policy', artifactRef: entries.find((entry) => entry.entryId === 'policy').digest,
      semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0].keyId
  };
  const manifestDigest = canonicalSha256(manifest);
  const signed = { ...manifest, manifestDigest,
    signature: sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`),
      key.privateKey).toString('base64') };
  const manifestPath = path.join(packageRoot, 'runtime-bundle.json');
  await writeFile(manifestPath, canonicalJsonBytes(signed), { mode: 0o400 });
  const launch = (mode, binary = executable) => {
    const result = spawnSync(binary, [mode, stateRoot], {
      encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, NODE_OPTIONS: '--trace-warnings' }
    });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout.trim());
  };
  const imported = launch('import');
  const reopened = launch('reopen');
  // Construct an immutable installed-tree fixture after the signed StateOwner
  // has imported its package. Publication/selection here is test setup only.
  const bundleRef = canonicalSha256(signed);
  const bundleDir = path.join(stateRoot, 'runtime', 'bundles', bundleRef);
  await mkdir(bundleDir, { recursive: true, mode: 0o700 });
  const directories = new Set([bundleDir]);
  for (const entry of entries) {
    const target = path.join(bundleDir, entry.relativePath);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    for (let dir = path.dirname(target); dir.startsWith(`${bundleDir}/`); dir = path.dirname(dir)) {
      directories.add(dir);
    }
    await copyFile(path.join(packageRoot, entry.relativePath), target);
    await chmod(target, entry.executable ? 0o500 : 0o400);
  }
  await copyFile(manifestPath, path.join(bundleDir, 'runtime-bundle.json'));
  await chmod(path.join(bundleDir, 'runtime-bundle.json'), 0o400);
  for (const directory of [...directories].sort((a, b) => b.length - a.length)) {
    await chmod(directory, 0o500);
  }
  await writeFile(path.join(stateRoot, 'runtime', 'active.json'), canonicalJsonBytes({
    schemaVersion: 1, format: 'cliq-runtime-active-selection-v1',
    bundleDigest: bundleRef, manifestDigest
  }), { mode: 0o400 });
  const installed = launch('installed', path.join(bundleDir, 'supervisor'));
  const digest = createHash('sha256').update(await readFile(executable)).digest('hex');
  for (const observed of [imported, reopened, installed]) {
    assert.equal(observed.sea, true);
    assert.equal(observed.executableImageDigest, digest);
    assert.equal(observed.helperPath,
      observed.mode === 'installed' ? path.join(bundleDir, helperRelativePath) : helperTarget);
    assert.match(observed.processStartToken, /^(?:darwin-proc-start-time|linux-proc-start-ticks):/u);
    assert.deepEqual(observed.execArgv, [], 'NODE_OPTIONS must not extend signed Supervisor arguments');
    assert.equal(observed.bundleRef, canonicalSha256(signed));
    assert.equal(observed.helloBundleRef, observed.bundleRef);
    assert.equal(observed.policyDigest, entries.find((entry) => entry.entryId === 'policy').digest);
  }
  assert.equal(imported.mode, 'import');
  assert.equal(reopened.mode, 'reopen');
  assert.equal(reopened.ownerEpoch, imported.ownerEpoch + 1);
  assert.equal(installed.mode, 'installed');
  assert.equal(installed.ownerEpoch, reopened.ownerEpoch + 1);
  const untrusted = generateKeyPairSync('ed25519');
  const wrongSignature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`),
    untrusted.privateKey).toString('base64');
  await chmod(manifestPath, 0o600);
  await writeFile(manifestPath, canonicalJsonBytes({ ...signed, signature: wrongSignature }));
  await chmod(manifestPath, 0o400);
  const rejectedState = path.join(root, 'rejected-state');
  await mkdir(rejectedState, { mode: 0o700 });
  const rejected = spawnSync(executable, ['import', rejectedState], {
    encoding: 'utf8', timeout: 30_000,
    env: { ...process.env, NODE_OPTIONS: '--trace-warnings' }
  });
  if (rejected.error) throw rejected.error;
  assert.notEqual(rejected.status, 0, 'a manifest signed by another key must be rejected');
  assert.match(rejected.stderr, /RuntimeBundle release signature is invalid/u);
  assert.deepEqual(await readdir(rejectedState), [], 'a rejected signature must leave StateRoot empty');
  process.stdout.write(`Supervisor SEA fixture: ${platform}, image ${digest}, signed package imported, selected read-only installed tree reopened, authenticated UDS hello, wrong signer rejected, NODE_OPTIONS ignored\n`);
} finally {
  // Test-only cleanup of the read-only installed directory.
  const bundles = path.join(root, 'state', 'runtime', 'bundles');
  try {
    for (const name of await readdir(bundles)) {
      const installed = path.join(bundles, name);
      for (const dir of ['native', `native/${platform}`, 'payload']) {
        const target = path.join(installed, dir);
        if (await stat(target).then(() => true, () => false)) await chmod(target, 0o700);
      }
      await chmod(installed, 0o700);
    }
  } catch { /* The fixture may fail before installed-tree setup. */ }
  await rm(root, { recursive: true, force: true });
}
