// Inert measurements only: these tests establish no installed/native authority.
import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import { spawnSync } from 'node:child_process';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { INSTALLED_WORK_CHANNEL, observeInstalledWork, noteInstalledWorkRead,
  type InstalledWorkSnapshot } from './installed-work-diagnostics.js';

test('real overlapping reads stay with their original work spans and rejected work only settles, never succeeds', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-work-observation-'));
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), observed: InstalledWorkSnapshot[] = [];
  const subscriber = (value: unknown) => observed.push(value as InstalledWorkSnapshot);
  diagnostic.subscribe(subscriber);
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  try {
    const filename = path.join(fixture, 'bytes'); await writeFile(filename, 'abcdefghi');
    const file = await open(filename, 'r');
    const read = async (position: number, count: number) => {
      const result = await file.read(Buffer.alloc(count), 0, count, position);
      noteInstalledWorkRead(result.bytesRead);
    };
    try {
      const packageWork = observeInstalledWork('package', async () => {
        await read(0, 4); await blocked; await read(8, 5); return 'original-result';
      });
      const failure = new Error('original-operation-refusal');
      await assert.rejects(observeInstalledWork('revalidate', async () => {
        await read(4, 3); throw failure;
      }), error => error === failure);
      assert.equal(observed.at(-1)!.package.started, 1);
      assert.equal(observed.at(-1)!.package.completed, 0);
      assert.equal(observed.at(-1)!.revalidate.completed, 1);
      release(); assert.equal(await packageWork, 'original-result');
      // A read returned before cancellation still happened; its actual short
      // byte count belongs to the settling operation, not an intended length.
      const aborted = new Error('original-cancellation');
      const cancellation = new AbortController();
      await assert.rejects(observeInstalledWork('revalidate', async () => {
        const result = await file.read(Buffer.alloc(8), 0, 8, 7);
        cancellation.abort(aborted); noteInstalledWorkRead(result.bytesRead); cancellation.signal.throwIfAborted();
      }), error => error === aborted);
      await observeInstalledWork('package', async () => {
        await observeInstalledWork('revalidate', async () => { await read(0, 2); });
        await read(0, 1);
      });
      // The production observer belongs inside the existing invoke callback:
      // merely queuing that callback must not begin a native-call span. This
      // tests diagnostic task semantics, not the native/D-Bus implementation.
      let invoke!: () => void;
      const ready = new Promise<void>(resolve => { invoke = resolve; });
      const precedingNative = observed.at(-1)!.createCompare.started;
      const pendingNative = ready.then(() => observeInstalledWork('create_compare', async () => 'native-result'));
      assert.equal(observed.at(-1)!.createCompare.started, precedingNative);
      invoke(); assert.equal(await pendingNative, 'native-result');
      await assert.rejects(observeInstalledWork('create_compare', async () => { throw failure; }), error => error === failure);
      const final = observed.at(-1)!;
      assert.deepEqual({ ...final.package, spanElapsedMs: 0 }, { started: 2, completed: 2, bytesRead: 6, spanElapsedMs: 0 });
      assert.deepEqual({ ...final.revalidate, spanElapsedMs: 0 }, { started: 3, completed: 3, bytesRead: 7, spanElapsedMs: 0 });
      assert.deepEqual({ ...final.createCompare, spanElapsedMs: 0 }, { started: 2, completed: 2, bytesRead: 0, spanElapsedMs: 0 });
      for (const snapshot of observed) for (const counters of Object.values(snapshot)) {
        assert(Object.values(counters).every(value => Number.isSafeInteger(value) && value >= 0));
        assert(counters.completed <= counters.started);
      }
      assert(Object.isFrozen(final) && Object.isFrozen(final.package));
      assert(!JSON.stringify(observed).includes(filename));
    } finally { release(); await file.close(); }
  } finally { diagnostic.unsubscribe(subscriber); await rm(fixture, { recursive: true, force: true }); }
});

test('an ordinary process without the trusted subscriber preserves its result and writes no work diagnostics', () => {
  const moduleUrl = new URL('./installed-work-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '-e', `
    import { channel } from 'node:diagnostics_channel';
    const { INSTALLED_WORK_CHANNEL, observeInstalledWork, noteInstalledWorkRead } = await import(${JSON.stringify(moduleUrl)});
    if (channel(INSTALLED_WORK_CHANNEL).hasSubscribers) throw new Error('unexpected subscriber');
    const result = await observeInstalledWork('package', async () => { noteInstalledWorkRead(9); return 23; });
    if (result !== 23) throw new Error('original result changed');
  `], { encoding: 'utf8', timeout: 5000, cwd: fileURLToPath(new URL('../..', import.meta.url)) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
