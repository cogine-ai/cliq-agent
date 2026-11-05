import assert from 'node:assert/strict';
import test from 'node:test';
import { LOCAL_INFERENCE_RETENTION_PURPOSES, readLocalInferenceEdges, UnsupportedLocalInferenceReachability } from './local-inference-reachability.js';

test('local inference GC refuses missing original model/registration context and never guesses edges from ref-shaped data', () => {
  const input = { schemaVersion: 1, format: 'caller-metadata', arbitraryRef: 'a'.repeat(64) };
  assert.equal(LOCAL_INFERENCE_RETENTION_PURPOSES.length, 11);
  for (const purpose of LOCAL_INFERENCE_RETENTION_PURPOSES)
    assert.throws(() => readLocalInferenceEdges(purpose, input), UnsupportedLocalInferenceReachability);
});
