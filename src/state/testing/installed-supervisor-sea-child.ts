import path from 'node:path';
import { getAsset, isSea } from 'node:sea';
import { normalizeAbsolutePath } from '../../kernel/identity.js';
import { parseJsonStrict } from '../../kernel/json.js';
import type { ReleaseTrustKey } from '../../policy/runtime-authority.js';
import { openInstalledControl, type InstalledControlService } from '../installed-control.js';
import { createInstalledRuntime, type HeldInstalledRuntime } from '../installed-runtime.js';
import { openStateStore, type StateStore } from '../store.js';

// Test composition of actual installed selection/Store/control only. It neither
// execs a selected image nor claims systemd, keeper, worker or complete I1.
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
  if (!isSea() || process.platform !== 'linux' || process.argv.length !== 2)
    throw new Error('expected only the installed Linux SEA bootstrap, without arguments');
  const executable = normalizeAbsolutePath(process.execPath);
  const runtimeRoot = path.dirname(executable);
  if (path.basename(executable) !== 'bootstrap' || path.basename(runtimeRoot) !== 'runtime')
    throw new Error('expected the fixed StateRoot/runtime/bootstrap entry');
  const stateRoot = path.dirname(runtimeRoot);
  // This ephemeral public test root is part of the signed application image.
  // No argv, environment, client or detached manifest can replace it.
  const releaseKeys = parseJsonStrict(new TextDecoder('utf-8', { fatal: true })
    .decode(getAsset('explicit-test-root.json'))) as ReleaseTrustKey[];
  selected = await createInstalledRuntime({ releaseKeys }).openSelected(stateRoot);
  store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys }, selected);
  service = openInstalledControl(store, { serverBuild: 'installed-sea-read-qualification' }, report);
}

const starting = start();
void starting.catch(async error => {
  try { await close(); } catch (retirementError) { report(retirementError); process.exitCode = 1; return; }
  report(error); process.exitCode = 1;
});
process.once('SIGTERM', () => {
  void starting.then(close, close).catch(error => { report(error); process.exitCode = 1; });
});
