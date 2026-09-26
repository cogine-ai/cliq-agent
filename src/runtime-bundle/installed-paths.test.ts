import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { runtimeNativePath } from './installed-paths.js';

test('source runs resolve native helpers in dist while a SEA resolves beside its image', () => {
  const relativePath = `native/${process.platform}-${process.arch}/state-owner.node`;
  const sourceUrl = new URL('../state/native-owner.ts', import.meta.url).href;
  assert.equal(runtimeNativePath(relativePath, sourceUrl, false),
    fileURLToPath(new URL(`../../dist/${relativePath}`, sourceUrl)));
  assert.equal(runtimeNativePath(relativePath, sourceUrl, true),
    path.join(path.dirname(process.execPath), relativePath));
});
