import path from 'node:path';
import { getAsset, isSea } from 'node:sea';
import { assertArtifactRef, normalizeAbsolutePath } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { ReleaseTrustKey } from '../policy/runtime-authority.js';
import { openInstalledControl, type InstalledControlService } from './installed-control.js';
import { acquireInstalledAnchor, createInstalledRuntime, initializeInstalledKeeper, withHeldInstalledRuntime,
  type HeldInstalledAnchor, type HeldInstalledKeeper, type HeldInstalledRuntime } from './installed-runtime.js';
import { joinResourceOperations } from './errors.js';
import { openStateStore, type StateStore } from './store.js';

// Hidden Linux SEA entry. Default CLI startup is unchanged. Release roots are
// embedded at image construction, never selected by argv/environment/control.
// Admission and execution are not enabled by this read-only composition.
let selected: HeldInstalledRuntime | undefined;
let store: StateStore | undefined;
let service: InstalledControlService | undefined;
let keeper: HeldInstalledKeeper | undefined;
let anchor: HeldInstalledAnchor | undefined;
let containmentHealth: ReturnType<typeof setInterval> | undefined;
let closing: Promise<void> | undefined;

function close(): Promise<void> {
  return closing ??= (async () => {
    clearInterval(containmentHealth);
    if (keeper) {
      // Independent native ownership: even uncertain anchor retirement must
      // join the selection's descriptors. The Supervisor's Store is different:
      // its failed close must retain StateOwner, preserving the existing order.
      await joinResourceOperations([Promise.resolve().then(() => keeper!.close()), selected?.close()] as const);
      return;
    }
    await service?.close();
    await store?.close();
    // Store retirement must join before releasing containment. Afterwards both
    // independent descriptor owners retire even if one close is uncertain.
    await joinResourceOperations([Promise.resolve().then(() => anchor?.close()), selected?.close()] as const);
  })();
}

async function fail(error: unknown): Promise<void> {
  try { await close(); } catch (retirementError) { report(retirementError); process.exitCode = 1; return; }
  report(error); process.exitCode = 1;
}

function report(error: unknown): void {
  const failure = error as { code?: string; path?: string; message?: string };
  console.error(JSON.stringify({ diagnosticOnly: true, scope: 'installed-read-startup',
    code: failure?.code, path: failure?.path, message: failure?.message ?? String(error) }));
}

async function start(): Promise<void> {
  if (!isSea() || process.platform !== 'linux') throw new Error('expected the installed Linux SEA');
  const executable = normalizeAbsolutePath(process.execPath);
  // These fixed release roots are part of the signed application image.
  // No argv, environment, client or detached manifest can replace it.
  const releaseKeys = parseJsonStrict(new TextDecoder('utf-8', { fatal: true })
    .decode(getAsset('release-trust-roots.json'))) as ReleaseTrustKey[];
  const runtime = createInstalledRuntime({ releaseKeys });
  const mode = process.argv[2];
  if (mode === '--bootstrap-supervisor' || mode === '--bootstrap-keeper') {
    const runtimeRoot = path.dirname(executable);
    if (process.argv.length !== 3 || path.basename(executable) !== 'bootstrap' || path.basename(runtimeRoot) !== 'runtime')
      throw new Error('expected only a fixed role at StateRoot/runtime/bootstrap');
    selected = await runtime.openSelected(path.dirname(runtimeRoot));
    // Bootstrap has no StateOwner, Store, control/worker handles or graceful
    // SIGTERM handler. Exec is terminal, never a running-owner restart API.
    return runtime.executeSelected(selected, mode === '--bootstrap-keeper' ? 'keeper' : 'supervisor');
  }
  if ((mode !== '--installed-supervisor' && mode !== '--installed-keeper') || process.argv.length !== 6)
    throw new Error('expected a fixed installed Supervisor role');
  const stateRoot = normalizeAbsolutePath(process.argv[3]!);
  const bundleDigest = process.argv[4]!, rootLocator = process.argv[5]!;
  if (stateRoot !== process.argv[3] || !/^(0|[1-9][0-9]*):[1-9][0-9]*:(0|[1-9][0-9]*)$/u.test(rootLocator))
    throw new Error('expected canonical installed StateRoot locators');
  assertArtifactRef(bundleDigest);
  process.once('SIGTERM', () => {
    void starting.then(close, close).catch(error => { report(error); process.exitCode = 1; });
  });
  selected = await runtime.openSelected(stateRoot);
  const supervisor = selected.bundle.entries.find(entry => entry.role === 'supervisor')!;
  if (selected.bundleDigest !== bundleDigest || executable !== path.join(stateRoot, 'runtime/bundles', bundleDigest, supervisor.relativePath))
    throw new Error('installed Supervisor differs from the fixed selected image');
  await withHeldInstalledRuntime(selected, async installed => {
    if (`${installed.stateRoot.deviceId}:${installed.stateRoot.fileId}:${installed.stateRoot.ownerUid}` !== rootLocator)
      throw new Error('installed StateRoot differs from the pre-exec root');
  });
  if (mode === '--installed-keeper') {
    keeper = await initializeInstalledKeeper(selected);
    // An FD alone does not keep Node alive. This referenced timer observes
    // native metadata, not full image/CAS hashing or another authority ledger.
    containmentHealth = setInterval(() => {
      try { keeper!.assertHeld(); } catch (error) { void fail(error); }
    }, 1_000);
    return;
  }
  // A stale/missing locator or keeper refuses before the first StateOwner
  // transaction. Never reopen a named cgroup root as an acquisition fallback.
  anchor = await acquireInstalledAnchor(selected);
  anchor.assertHeld();
  // Only this selected mode acquires authority. Genesis borrows these newly
  // held, verified descriptors, never the retired bootstrap's historical FDs.
  store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys }, selected);
  anchor.assertHeld();
  service = openInstalledControl(store, { serverBuild: 'cliq-installed-v1' }, report);
  containmentHealth = setInterval(() => {
    try { anchor!.assertHeld(); } catch (error) { void fail(error); }
  }, 1_000);
}

const starting = start();
void starting.catch(fail);
