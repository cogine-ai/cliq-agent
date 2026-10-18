import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY } from '../../config.js';
import { canonicalSha256 } from '../../kernel/canonical.js';
import type { ToolContractManifestV1 } from '../../kernel/types.js';
import { ResourceRetirementError } from '../errors.js';
import { createAgentFixture } from './agent-fixtures.js';

// A disposable process owns the genuine Store and OS lock throughout this
// failure. Offline Run metadata does not qualify any native worker backend.
process.chdir(process.argv[2]!);
let started = false;
process.on('message', async command => {
  if (started || command !== 'exercise') return;
  started = true;
  const originalOpen = fs.open;
  let missingPath: string | undefined, savedPath: string | undefined;
  let release: (() => void) | undefined, reading: Promise<unknown> | undefined;
  try {
    const fixture = await createAgentFixture('agent-opening-join', undefined, { tools: ['edit', 'read'] });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const manifest = await fixture.store.artifacts.readCanonical<ToolContractManifestV1>(fixture.authority.assembly.tools.manifestRef);
    missingPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, manifest.entries[0]!.inputSchemaRef);
    savedPath = `${missingPath}.fault-fixture`;
    const delayedPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, manifest.entries[1]!.inputSchemaRef);
    const failure = Object.assign(new Error('uncertainty after the actual CAS handle close'), { code: 'EIO' });
    let entered!: () => void, settled = false, actualCloses = 0;
    const closing = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<void>(resolve => { release = resolve; });
    await fs.rename(missingPath, savedPath);
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      if (args[0] === delayedPath) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => {
          await actualClose(); actualCloses++; entered();
          await held;
          throw failure;
        };
      }
      return handle;
    }) as typeof fs.open;
    reading = fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    void reading.then(() => { settled = true; }, () => { settled = true; });
    await closing; await nextTurn();
    assert.equal(settled, false, 'the missing artifact cannot finish opening while another actual CAS close remains unjoined');
    release!();
    let openingError: unknown;
    await assert.rejects(reading, error => {
      openingError = error;
      return error instanceof ResourceRetirementError && error.cause === failure;
    });
    assert.equal(actualCloses, 1);
    fs.open = originalOpen;
    await fs.rename(savedPath, missingPath); savedPath = undefined;
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    // The physical file has been restored, but that cannot erase the original
    // uncertainty or make the opening producer's close a positive retirement.
    await assert.rejects(fixture.store.close(), error => error === openingError && error instanceof ResourceRetirementError && error.cause === failure);
    await assert.rejects(fixture.store.close(), error => error === openingError);
    const response = { state: 'retained', stateRoot: fixture.stateRoot, workspace: fixture.workspace, runId: fixture.runId,
      beforeDigest: canonicalSha256(before), epoch: fixture.store.ownerEpoch,
      authority: { bundle: fixture.runtimeAuthority.bundle, releaseKeys: fixture.runtimeAuthority.releaseKeys } };
    assert(globalThis.gc, 'the lifecycle fixture requires --expose-gc');
    for (let round = 0; round < 8; round++) { globalThis.gc(); await nextTurn(); }
    process.send!(response);
    // Deliberately do not dispose this failed owner. The parent checks its real
    // lock, kills and joins this process, then safely takes over the same root.
  } catch (error) {
    process.send!({ state: 'failed', message: error instanceof Error ? error.message : 'unknown lifecycle fixture failure' });
  } finally {
    release?.(); await reading?.catch(() => {}); fs.open = originalOpen;
    if (savedPath && missingPath) await fs.rename(savedPath, missingPath);
  }
});
process.send!({ state: 'ready' });
