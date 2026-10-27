// Independent upgrade qualifier composition. Never an official release signer.
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { createInstalledQualificationPublisher } from '../../../src/state/testing/qualification-publisher.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';
import type { InstalledModelPackageFixture } from './installed-model-package.js';
import { prepareLegacyUpgradeSource, LEGACY_UPGRADE_SOURCE } from './legacy-upgrade-source.js';
import { readQualificationSource } from './qualification-source.js';
import { installedClientBuildOptions } from './installed-client-build.js';

export async function buildUpgradeQualificationPackages(input: {
  fixture: string; originalSourceRoot: string; oldBuildFixture: string; model: InstalledModelPackageFixture;
}) {
  const source = await prepareLegacyUpgradeSource(input.originalSourceRoot, path.join(input.fixture, 'legacy-product-source'));
  const publisher = createInstalledQualificationPublisher();
  // Match the existing installed qualifier: the disposable UID must traverse
  // this protected root-owned parent to its transferred700 signed package and
  // read the444 installer. Carrier derivations remain separate private700.
  await mkdir(input.oldBuildFixture, { mode: 0o755 });
  const old = await buildInstalledSupervisorPackage(input.oldBuildFixture, 'complete', input.model, { source, publisher, headlessSchemaVersion: 3 });
  assert.equal(old.bundle.stateSchemaRange.max, 7); assert(old.modelAuthority);
  assert.equal(old.bundle.entries.some(entry => entry.entryId === 'kernel_schema'), false);
  const targetBuildFixture = path.join(input.fixture, 'upgrade-package-build');
  await mkdir(targetBuildFixture, { mode: 0o755 });
  const target = await buildInstalledSupervisorPackage(targetBuildFixture, 'complete', input.model,
    { publisher, headlessSchemaVersion: 3, upgradeSourceBundle: old.bundle });
  assert.equal(target.bundle.stateSchemaRange.max, 8); assert(target.modelAuthority);
  assert.deepEqual(old.releaseKeys, target.releaseKeys);
  assert.notEqual(old.bundle.manifestDigest, target.bundle.manifestDigest);
  assert(target.bundle.entries.some(entry => entry.entryId === 'kernel_schema' && entry.version === '8'));
  assert(target.bundle.entries.some(entry => entry.entryId === 'schema_conversion' && entry.version === '7-to-8'));
  const current = fileURLToPath(new URL('../../..', import.meta.url));
  const bundleNodeOnly = async (sourceRoot: string, entryPoint: string, outfile: string) => {
    const result = await build({ entryPoints: [entryPoint], outfile, bundle: true, platform: 'node', format: 'esm',
      target: 'node22.13', metafile: true, write: false, ...installedClientBuildOptions(sourceRoot) });
    assert.equal(result.outputFiles!.length, 1);
    assert(Object.values(result.metafile!.outputs).flatMap(output => output.imports).every(item => item.external && item.path.startsWith('node:')));
    assert(result.outputFiles![0]!.contents.length <= 16 * 1024 * 1024);
    await writeFile(outfile, result.outputFiles![0]!.contents, { flag: 'wx', mode: 0o444 }); return outfile;
  };
  const oldInstaller = await bundleNodeOnly(source.root, path.join(source.root, 'scripts/kernel/testing/installed-runtime-installer.ts'),
    path.join(input.oldBuildFixture, 'installed-runtime-installer.mjs'));
  const clients = await Promise.all([source.root, current].map((root, index) => bundleNodeOnly(root,
    path.join(root, 'scripts/kernel/testing/installed-control-client-driver.ts'), path.join(input.fixture, `upgrade-client-${index}.mjs`))));
  // The retained normal seal reader is compiled with its actual original
  // product's schema recipe. It remains data-only and creates no Store owner.
  const observers: string[] = [];
  for (const [index, root] of [source.root, current].entries()) {
    const outfile = path.join(input.fixture, `upgrade-retirement-${index}.mjs`);
    const module = path.join(root, 'scripts/kernel/testing/installed-worker-lease.ts');
    const result = await build({ stdin: { contents: `import assert from 'node:assert/strict';
import{inspectInstalledWorkerLaunchIds,inspectInstalledWorkerRetirementHistory}from${JSON.stringify(module)};
const[root,uid,runId]=process.argv.slice(2);assert(root&&uid&&runId&&process.argv.length===5);
const selected=inspectInstalledWorkerLaunchIds(root,Number(uid),runId);assert(selected.launchIds.length>0);
console.log(JSON.stringify(selected.launchIds.map(launchId=>inspectInstalledWorkerRetirementHistory(root,Number(uid),{runId,launchId}))));`,
      resolveDir: root, sourcefile: 'upgrade-retirement-observer.ts', loader: 'ts' }, outfile,
      bundle: true, platform: 'node', format: 'esm', target: 'node22.13', metafile: true, write: false });
    assert(Object.values(result.metafile!.outputs).flatMap(output => output.imports).every(item => item.external && item.path.startsWith('node:')));
    assert.equal(result.outputFiles!.length, 1); await writeFile(outfile, result.outputFiles![0]!.contents, { flag: 'wx', mode: 0o444 }); observers.push(outfile);
  }
  const { signature: _signature, manifestDigest: _manifestDigest, ...unsignedCore } = target.bundle;
  await writeFile(path.join(targetBuildFixture, 'unsigned-candidate.json'), canonicalJsonBytes({ schemaVersion: 1,
    purpose: 'qualification_publisher_only', publisherPublicKeyFingerprintAlgorithm: 'spki_sha256',
    publisherPublicKeySha256: sha256Bytes(createPublicKey(target.releaseKeys[0]!.publicKeyPem).export({ type: 'spki', format: 'der' })),
    signedManifestDigest: target.bundle.manifestDigest, unsignedCore }), { flag: 'wx', mode: 0o444 });
  assert.deepEqual(await readQualificationSource(source), old.sourceProvenance);
  return { old, target, oldInstaller, clients, observers, sourceIdentity: LEGACY_UPGRADE_SOURCE, source };
}
