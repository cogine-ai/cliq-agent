import assert from 'node:assert/strict';
import { test } from 'node:test';
import { KERNEL_SQLITE_APPLICATION_ID, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { kernelSchemaBirthRecipe, KERNEL_SCHEMA_SQL } from './schema.js';

test('retained v6 birth keeps the exact original DDL and empty-database identities after v7', () => {
  // Pins independently observed from the actual v6 Store's genuine genesis,
  // not regenerated from today's schema or a fabricated StateOwner graph.
  const original = kernelSchemaBirthRecipe(6);
  assert.deepEqual(original, { userVersion: 6,
    schemaDigest: '5aa222e5e2f31bfed84b3a9a59ba95fb741b7f8dd6c79d7dbfd01bba125521f3',
    emptyDatabaseContentDigest: 'df3588c82149115e1345641a7c3b2267409cbbd065da2bae8d086b62852fadb0' });
  assert(Object.isFrozen(original));
  assert.equal(kernelSchemaBirthRecipe(7).schemaDigest,
    'ac049a7d3459598dd40e105b9ab3988e84159088630a11c6c6a78e9a1ab99d7b');
  assert.notEqual(original.schemaDigest, kernelSchemaBirthRecipe(7).schemaDigest);
  assert.notEqual(original.emptyDatabaseContentDigest, kernelSchemaBirthRecipe(7).emptyDatabaseContentDigest);
});

test('current birth still requires the complete current DDL and exact table-count identity', () => {
  const current = kernelSchemaBirthRecipe(KERNEL_STATE_SCHEMA_VERSION);
  assert.equal(current.schemaDigest, sha256Bytes(Buffer.from(KERNEL_SCHEMA_SQL, 'utf8')));
  assert.equal(current.emptyDatabaseContentDigest, canonicalSha256({ applicationId: KERNEL_SQLITE_APPLICATION_ID,
    userVersion: KERNEL_STATE_SCHEMA_VERSION, tables: 21 }));
});

test('a version value cannot select an unknown, coerced or future retained birth recipe', () => {
  for (const version of [undefined, null, '6', '7', 0, 1, 5, 8, -1, 6.5, NaN, Infinity, {}, []])
    assert.throws(() => kernelSchemaBirthRecipe(version), { code: 'RECOVERY_REQUIRED' });
});
