import path from 'node:path';
import { getAsset, isSea } from 'node:sea';
import { assertArtifactRef, normalizeAbsolutePath } from '../../kernel/identity.js';
import { parseJsonStrict } from '../../kernel/json.js';
import type { ReleaseTrustKey } from '../../policy/runtime-authority.js';
import { openInstalledControl, type InstalledControlService } from '../installed-control.js';
import { createInstalledRuntime, withHeldInstalledRuntime, type HeldInstalledRuntime } from '../installed-runtime.js';
import { openStateStore, type StateStore } from '../store.js';

// Test composition of actual bootstrap/selected exec/Store/control only. It
// does not claim systemd, keeper, worker or complete I1.
// The detached signed manifest is read only by the real installed producer.
let selected: HeldInstalledRuntime | undefined;
let store: StateStore | undefined;
let service: InstalledControlService | undefined;
let closing: Promise<void> | undefined;

function close(): Promise<void> {
  return closing ??= (async () => {
    await service?.close();
    await store?.close();
    await selected?.close();
  })();
}

function report(error: unknown): void {
  const failure = error as { code?: string; path?: string; message?: string };
  console.error(JSON.stringify({ diagnosticOnly: true, scope: 'installed-read-startup',
    code: failure?.code, path: failure?.path, message: failure?.message ?? String(error) }));
}

async function start(): Promise<void> {
  if (!isSea() || process.platform !== 'linux') throw new Error('expected the installed Linux SEA');
  const executable = normalizeAbsolutePath(process.execPath);
  // This ephemeral public test root is part of the signed application image.
  // No argv, environment, client or detached manifest can replace it.
  const releaseKeys = parseJsonStrict(new TextDecoder('utf-8', { fatal: true })
    .decode(getAsset('explicit-test-root.json'))) as ReleaseTrustKey[];
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
  if (mode !== '--installed-supervisor' || process.argv.length !== 6)
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
  // Only this selected mode acquires authority. Genesis borrows these newly
  // held, verified descriptors, never the retired bootstrap's historical FDs.
  store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys }, selected);
  service = openInstalledControl(store, { serverBuild: 'installed-sea-read-qualification' }, report);
}

const starting = start();
void starting.catch(async error => {
  try { await close(); } catch (retirementError) { report(retirementError); process.exitCode = 1; return; }
  report(error); process.exitCode = 1;
});
