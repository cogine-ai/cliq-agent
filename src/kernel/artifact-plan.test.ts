import assert from 'node:assert/strict';
import { test } from 'node:test';

import { sha256Bytes } from './identity.js';
import { planArtifactBytes } from './artifact-plan.js';

test('planned artifacts snapshot input bytes and never expose mutable authority bytes', () => {
  const source = Uint8Array.of(1, 2, 3);
  const artifact = planArtifactBytes(source, 'application/octet-stream', 'fixture-v1');
  source[0] = 9;
  const firstRead = artifact.bytes;
  firstRead[1] = 9;

  assert.deepEqual(artifact.bytes, Uint8Array.of(1, 2, 3));
  assert.equal(artifact.ref, sha256Bytes(Uint8Array.of(1, 2, 3)));
});
