import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { KernelStorageError } from './errors.js';
import { hashHeldProcessImage } from './process-image.js';

function withTempFile(body: (file: string, fd: number) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(path.join(tmpdir(), 'cliq-process-image-'));
  const file = path.join(dir, 'image');
  writeFileSync(file, Buffer.from('process image fixture\n'));
  const fd = openSync(file, 'r');
  return body(file, fd).finally(() => {
    closeSync(fd);
    rmSync(dir, { recursive: true, force: true });
  });
}

test('hashHeldProcessImage digests the held executable bytes', async () => {
  await withTempFile(async (_file, fd) => {
    const bytes = Buffer.from('process image fixture\n');
    let held = true;
    const digest = await hashHeldProcessImage(fd, bytes.length, () => {
      if (!held) throw new Error('released');
    });
    held = false;
    assert.equal(digest, createHash('sha256').update(bytes).digest('hex'));
  });
});

test('hashHeldProcessImage refuses mismatched or unbounded byte counts', async () => {
  await withTempFile(async (_file, fd) => {
    const bytes = Buffer.from('process image fixture\n');
    const assertHeld = () => {};
    await assert.rejects(hashHeldProcessImage(fd, bytes.length + 1, assertHeld), error => {
      assert(error instanceof KernelStorageError);
      assert.equal(error.code, 'ARTIFACT_MISMATCH');
      return true;
    });
    await assert.rejects(hashHeldProcessImage(fd, 0, assertHeld), KernelStorageError);
    await assert.rejects(hashHeldProcessImage(fd, 256 * 1024 * 1024 + 1, assertHeld), KernelStorageError);
  });
});
