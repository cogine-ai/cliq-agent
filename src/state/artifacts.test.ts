import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ArtifactCatalog } from './artifacts.js';
import { RECOVERY_ARTIFACT_READ_CONCURRENCY } from './bounded-artifact-reads.js';
import type { ContentAddressedStore } from './cas.js';

test('one ArtifactCatalog bounds CAS reads across independent callers and releases failed slots', async () => {
  let releaseReads!: () => void;
  const blocked = new Promise<void>((resolve) => { releaseReads = resolve; });
  let active = 0;
  let peak = 0;
  const started: string[] = [];
  const failedRef = '0'.repeat(64);
  const cas = {
    async read(ref: string): Promise<Buffer> {
      started.push(ref);
      active += 1;
      peak = Math.max(peak, active);
      await blocked;
      active -= 1;
      if (ref === failedRef) throw new Error('corrupt');
      return Buffer.from(ref);
    }
  } as ContentAddressedStore;
  const catalog = new ArtifactCatalog(cas);
  const refs = Array.from({ length: 40 }, (_, index) => index.toString(16).padStart(64, '0'));
  const reads = refs.map((ref) => catalog.readBytes(ref));
  assert.equal(started.length, RECOVERY_ARTIFACT_READ_CONCURRENCY);
  releaseReads();
  const results = await Promise.allSettled(reads);
  assert.equal(peak, RECOVERY_ARTIFACT_READ_CONCURRENCY);
  assert.equal(started.length, refs.length);
  assert.equal(active, 0);
  assert.equal(results[0]?.status, 'rejected');
  for (const result of results.slice(1)) assert.equal(result.status, 'fulfilled');
});
