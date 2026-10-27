import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import type { EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { readNpmLockData } from '../../../src/state/dependency-plan.js';
import { readNpmDataImage } from '../../../src/sandbox/npm-data-image.js';
import { buildInstalledNpmDataAsset } from './installed-npm-package.js';
import { installedDependencyFiles, installedDependencyPackage } from './installed-dependency-journey.js';

test('installed locked fixture is a complete original v3 root with a real >1MiB package, bin and lifecycle inputs', () => {
  const archive = installedDependencyPackage(), files = installedDependencyFiles('https://registry.invalid', archive, true);
  const digest = 'a'.repeat(64), tls: EndpointRegistrationV1['tls'] = { serverNameAscii: 'registry.invalid', minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: digest, trustStoreRuntimeBundleManifestDigest: digest, trustStoreEntryId: 'default_https_trust_store',
    trustStoreRef: digest, trustStoreDigest: digest, spkiSha256Pins: [digest] };
  const target = { scheme: 'https' as const, hostAscii: 'registry.invalid', port: 443, basePath: '/', redirectPolicy: 'reject_all' as const };
  const tlsPolicyDigest = canonicalSha256(tls);
  const endpoint: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'registry',
    registrationKind: 'user', ownerPrincipalId: 'principal', purposes: ['dependency_registry'], target, tls, tlsPolicyDigest,
    endpointIdentityDigest: canonicalSha256({ target, tlsPolicyDigest }), createdAt: '2026-10-27T00:00:00.000Z', registrationDigest: '' };
  endpoint.registrationDigest = digestOmitting(endpoint, 'registrationDigest');
  const data = readNpmLockData({ packageJsonBytes: Buffer.from(files.find(file => file.path === 'package.json')!.text),
    packageLockBytes: Buffer.from(files.find(file => file.path === 'package-lock.json')!.text), registryEndpoints: [endpoint],
    bindingGyp: { kind: 'absent' }, maxPackages: 50_000, maxSingleFileBytes: 268_435_456 });
  assert.equal(data.packages.length, 1); assert(archive.length > 1_048_576);
  assert.equal(data.packages[0]!.integrityDigest, createHash('sha512').update(archive).digest('base64'));
  assert.deepEqual(installedDependencyPackage(), archive);
});

const official = process.env.CLIQ_QUALIFICATION_NPM_ARCHIVE;
test('the complete pinned official npm really installs the fixture offline and preserves default deny, explicit lifecycle and bin symlink',
  { skip: !official }, async () => {
    const imageBytes = buildInstalledNpmDataAsset(await readFile(official!)).bytes, image = readNpmDataImage(imageBytes);
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-npm-fixture-'));
    try {
      const npm = path.join(home, 'npm'), cache = path.join(home, 'cache'), work = path.join(home, 'work');
      await mkdir(npm); await mkdir(cache); await mkdir(work);
      for (const file of image.files) {
        const name = path.join(npm, file.path); await mkdir(path.dirname(name), { recursive: true });
        await writeFile(name, imageBytes.subarray(file.payloadOffset, file.payloadOffset + file.byteCount), { flag: 'wx', mode: 0o400 });
      }
      const archive = installedDependencyPackage(), files = installedDependencyFiles('https://registry.invalid', archive, false);
      for (const file of files) await writeFile(path.join(work, file.path), file.text, { flag: 'wx' });
      const original = await Promise.all(['package.json', 'package-lock.json'].map(name => readFile(path.join(work, name))));
      const cacache = createRequire(path.join(npm, 'package.json'))('cacache');
      await cacache.put(path.join(cache, '_cacache'), 'cliq:owned', archive,
        { algorithms: ['sha512'], integrity: 'sha512-' + createHash('sha512').update(archive).digest('base64') });
      const user = path.join(home, 'user'), global = path.join(home, 'global'); await writeFile(user, ''); await writeFile(global, '');
      const environment = { PATH: path.dirname(process.execPath) + ':/usr/bin:/bin', HOME: home, TMPDIR: home, LANG: 'C', LC_ALL: 'C' };
      const run = (ignore: boolean) => {
        const result = spawnSync(process.execPath, ['--no-addons', path.join(npm, 'bin/npm-cli.js'), 'ci', '--offline=true',
          `--ignore-scripts=${ignore}`, '--audit=false', '--fund=false', '--update-notifier=false', '--fetch-retries=0',
          `--cache=${cache}`, `--userconfig=${user}`, `--globalconfig=${global}`, '--script-shell=/bin/bash', '--node-options=',
          '--include=dev', '--include=peer', '--include=optional', '--no-save'], { cwd: work,
          env: environment, timeout: 30000, maxBuffer: 1_048_576 });
        assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0);
      };
      const verify = () => {
        const result = spawnSync(process.execPath, ['--test', '--test-concurrency=1', 'check.test.mjs'], { cwd: work, env: environment, timeout: 10000, maxBuffer: 65536 });
        assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0);
        assert.match(result.stdout.toString(), /(?:#|\u2139) tests 1\n/u); assert.match(result.stdout.toString(), /(?:#|\u2139) pass 1\n/u);
      };
      run(true); verify(); assert.equal(await readlink(path.join(work, 'node_modules/.bin/cliq-owned-dependency')), '../cliq-owned-dependency/cli.cjs');
      await writeFile(path.join(work, 'check.test.mjs'), installedDependencyFiles('https://registry.invalid', archive, true).find(file => file.path === 'check.test.mjs')!.text);
      run(false); verify();
      for (const [index, name] of ['package.json', 'package-lock.json'].entries()) assert((await readFile(path.join(work, name))).equals(original[index]!));
      // This is a real local npm program test, not namespace, CG, READY,
      // NOEXEC, grant, installed service or physical retirement qualification.
    } finally { await rm(home, { recursive: true, force: true }); }
  });
