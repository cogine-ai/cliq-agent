import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError } from './errors.js';
import { createInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { applyKernelSchema } from './schema.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { openStateStore, type StateStore } from './store.js';
import { writeInstalledControlPackage } from './testing/installed-control-fixture.js';

type BoundaryResources = {
  selected?: HeldInstalledRuntime; store?: StateStore;
  preparationDriver?: SqliteDriver; preparationLock?: HeldStateOwnerLock;
  retirementFailed?: boolean;
};
// A teardown failure retains the real holders and their fixture until process
// exit. Never delete the root or retry a possibly consumed descriptor close.
const unretiredBoundaryFixtures = new Set<BoundaryResources>();

function closePreparation(resources: BoundaryResources): void {
  try {
    resources.preparationDriver?.close(); resources.preparationDriver = undefined;
    resources.preparationLock?.close(); resources.preparationLock = undefined;
  } catch (error) { resources.retirementFailed = true; throw error; }
}

async function assertNoOwner(stateRoot: string): Promise<void> {
  const filename = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
  const exists = await lstat(filename).then(() => true, (error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return false;
    throw error;
  });
  if (!exists) return; // Physical absence, not a fabricated owner or death proof.
  const inspector = openSqliteDriver(filename);
  try {
    const count = inspector.prepare('SELECT count(*) AS count FROM state_owners').get<{ count: unknown }>();
    assert.equal(count?.count, 0n, 'refused initial startup must never commit epoch one');
  } finally { inspector.close(); }
}

// This exercises the real Linux installer and StateStore seam. The signed
// current Node is not executed as SEA; no worker, admission or model is claimed.
if (process.platform === 'linux') test('installed genesis refuses seed, root, handle and unowned-business substitutions without epoch one', async t => {
  const campaign = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-boundaries-')));
  await chmod(campaign, 0o700);
  const live = new Set<BoundaryResources>();
  try {
    // Share immutable signed source bytes, never a mutated installation or DB.
    const packageRoot = path.join(campaign, 'package');
    const signed = await writeInstalledControlPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const cases = [
      ['extra_cas', 'an additional honestly published CAS object is not an installation seed'],
      ['missing_seed', 'a physically missing held policy seed is refused'],
      ['changed_seed', 'changed policy seed bytes are refused despite restoring immutable mode'],
      ['replaced_seed', 'identical seed bytes in a different inode cannot replace the held installation'],
      ['extra_bundle', 'an unselected version cannot become initial installed inventory'],
      ['without_handle', 'signed data without its held installation cannot bypass fresh-empty CAS refusal'],
      ['wrong_root', 'a genuine handle cannot authorize a different real installed StateRoot'],
      ['closed_handle', 'a genuinely branded but closed installation is refused'],
      ['proxy_handle', 'a proxy of a genuine handle is refused without any property observation'],
      ['business_residue', 'unowned MCP business-index residue blocks the first owner transaction'],
    ] as const;
    for (const [kind, name] of cases) {
      await t.test(name, async () => {
        const stateRoot = path.join(campaign, kind);
        const resources: BoundaryResources = {};
        live.add(resources);
        let otherRoot: string | undefined;
        try {
          await runtime.installInitial({ packageRoot, stateRoot });
          resources.selected = await runtime.openSelected(stateRoot);
          const authority = { bundle: resources.selected.bundle, releaseKeys: signed.releaseKeys };
          const policyRef = signed.bundle.entries.find(entry => entry.role === 'policy_engine')!.digest;
          const policyPath = path.join(stateRoot, KERNEL_CAS_DIRECTORY, policyRef);
          const cas = new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
          let requestedRoot = stateRoot;
          let requestedHandle: HeldInstalledRuntime | undefined = resources.selected;
          let proxyObservations = 0;
          if (kind === 'extra_cas') {
            const bytes = Buffer.from('independently published, unowned extra CAS payload\n');
            const extraRef = await cas.publish(bytes);
            assert(!signed.seedObjects.some(object => object.artifactRef === extraRef));
            assert.deepEqual(await cas.read(extraRef), bytes);
          } else if (kind === 'missing_seed') {
            await rm(policyPath);
            await assert.rejects(lstat(policyPath), { code: 'ENOENT' });
          } else if (kind === 'changed_seed') {
            const original = signed.seedObjects.find(object => object.artifactRef === policyRef)!.bytes;
            const changed = Buffer.from(original); changed[0] ^= 1;
            const before = await lstat(policyPath, { bigint: true });
            await chmod(policyPath, 0o600);
            await writeFile(policyPath, changed, { flag: 'r+' });
            await chmod(policyPath, 0o400);
            const after = await lstat(policyPath, { bigint: true });
            assert.equal(after.ino, before.ino);
            assert.equal(after.size, before.size);
            assert.equal(after.mode & 0o7777n, 0o400n);
          } else if (kind === 'replaced_seed') {
            const original = signed.seedObjects.find(object => object.artifactRef === policyRef)!.bytes;
            const before = await lstat(policyPath, { bigint: true });
            const temporary = path.join(stateRoot, KERNEL_CAS_DIRECTORY, 'replacement-seed');
            await writeFile(temporary, original, { flag: 'wx', mode: 0o400 });
            await rename(temporary, policyPath);
            const after = await lstat(policyPath, { bigint: true });
            assert.notEqual(after.ino, before.ino, 'the original inode is still held, not reusable');
            assert.deepEqual(await cas.read(policyRef), original, 'byte verification alone would accept this replacement');
          } else if (kind === 'extra_bundle') {
            await mkdir(path.join(stateRoot, 'runtime', 'bundles', 'unselected-version'), { mode: 0o700 });
          } else if (kind === 'without_handle') {
            requestedHandle = undefined;
          } else if (kind === 'wrong_root') {
            otherRoot = path.join(campaign, 'different-installed-root');
            await runtime.installInitial({ packageRoot, stateRoot: otherRoot });
            requestedRoot = otherRoot;
          } else if (kind === 'closed_handle') {
            await resources.selected.close(); resources.selected = undefined;
          } else if (kind === 'proxy_handle') {
            requestedHandle = new Proxy(resources.selected, {
              get() { proxyObservations++; throw new Error('an unbranded proxy property must not execute'); },
            });
          } else {
            // Create and retire the actual signed native lock before creating a
            // DB, otherwise startup would fail merely on a missing lock inode.
            const native = await loadNativeStateOwner(signed.bundle);
            resources.preparationLock = native.acquireLock(stateRoot, true);
            resources.preparationDriver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
            applyKernelSchema(resources.preparationDriver);
            // Deliberately unowned contamination: not a usable registration,
            // grant, observation or StateOwner authority. It must not be adopted.
            resources.preparationDriver.prepare(`INSERT INTO mcp_registrations
              (owner_principal_id, registration_id, current_revision, current_revision_ref)
              VALUES (?, ?, ?, ?)`).run('unowned-fixture-principal', 'unowned-index-residue', 1n, policyRef);
            closePreparation(resources);
          }

          let rejection: unknown;
          try { resources.store = await openStateStore(requestedRoot, authority, requestedHandle); }
          catch (error) { rejection = error; }
          await assertNoOwner(stateRoot);
          if (otherRoot) await assertNoOwner(otherRoot);
          if (kind === 'missing_seed') {
            // This is the real descriptor-relative lstat errno, not a mock.
            assert(rejection instanceof Error);
            assert.equal((rejection as NodeJS.ErrnoException).code, 'ENOENT');
          } else {
            assert(rejection instanceof KernelStorageError);
            assert.equal(rejection.code,
              kind === 'without_handle' || kind === 'business_residue' ? 'RECOVERY_REQUIRED' : 'ARTIFACT_MISMATCH');
            if (kind === 'business_residue') assert.match(rejection.message, /mcp_registrations/u);
            if (kind === 'without_handle') assert.match(rejection.message, /fresh_empty.*non-empty CAS/u);
          }
          assert.equal(proxyObservations, 0);
        } finally {
          if (!resources.retirementFailed) {
            try {
              await resources.store?.close();
              closePreparation(resources);
              await resources.selected?.close();
              live.delete(resources);
            } catch (error) { resources.retirementFailed = true; throw error; }
          }
        }
      });
      if (live.size) break; // Failed retirement is a failed qualification, not another fresh attempt.
    }
  } finally {
    if (live.size) for (const resources of live) unretiredBoundaryFixtures.add(resources);
    else await rm(campaign, { recursive: true, force: true });
  }
});
