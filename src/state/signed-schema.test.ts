import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_SQLITE_APPLICATION_ID } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { applySignedKernelSchema7To8, assertKernelSchemaVersion, kernelSchemaDefinition,
  kernelSchemaManifest, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { decodeSignedKernelSchema, signedKernelSchemaProfile } from './signed-schema.js';

test('signed full schema binds every fixed statement, catalog object and original six-field manifest', () => {
  const profile = signedKernelSchemaProfile();
  assert.deepEqual(profile.schemaManifest, kernelSchemaManifest(8));
  assert(!kernelSchemaDefinition(7).catalog.some(row => row.name === 'authorization_grants_list_order_v1'));
  assert.equal(profile.catalog.find(row => row.name === 'authorization_grants_list_order_v1')?.sql,
    "CREATE INDEX authorization_grants_list_order_v1 ON authorization_grants(owner_principal_id,json_extract(row_json,'$.createdAt') COLLATE BINARY,grant_id COLLATE BINARY)");
  assert.equal(profile.catalogDigest, canonicalSha256(profile.catalog));
  assert.equal(profile.profileDigest, digestOmitting(profile, 'profileDigest'));
  assert.deepEqual(decodeSignedKernelSchema(profile), profile);
  assert(canonicalJsonBytes(profile).length < 1_048_576);
  for (const mutate of [
    (p: typeof profile) => { p.ddl += '\nSELECT 1;'; },
    (p: typeof profile) => { p.catalog.pop(); },
    (p: typeof profile) => { p.schemaManifest.userVersion = 7 as 8; },
    (p: typeof profile) => { Object.assign(p, { authority: true }); },
  ]) {
    const changed = structuredClone(profile); mutate(changed);
    changed.profileDigest = digestOmitting(changed, 'profileDigest');
    assert.throws(() => decodeSignedKernelSchema(changed), { code: 'ARTIFACT_MISMATCH' });
  }
  let accessed = false;
  const getter = { ...profile }; Object.defineProperty(getter, 'ddl', { enumerable: true, get() { accessed = true; return profile.ddl; } });
  assert.throws(() => decodeSignedKernelSchema(getter));
  assert.throws(() => decodeSignedKernelSchema(new Proxy(profile, { ownKeys() { accessed = true; return []; } })));
  assert.equal(accessed, false);
});

test('fixed source7 DDL rolls back completely on failure and commits exact8 only in its caller transaction', async () => {
  // Real SQLite schema data only. This test creates no StateOwner or upgrade permission.
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-signed-schema-'));
  const driver = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
  try {
    driver.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
    driver.exec(kernelSchemaDefinition(7).ddl); driver.exec('PRAGMA user_version=7');
    const before = driver.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all();
    assert.throws(() => driver.transaction(connection => {
      applySignedKernelSchema7To8(connection); throw new Error('owned commit failure');
    }), /owned commit failure/);
    assert.equal(readSchemaUserVersion(driver), 7);
    assert.deepEqual(driver.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all(), before);
    driver.transaction(connection => applySignedKernelSchema7To8(connection));
    assertKernelSchemaVersion(driver, 8);
    assert.throws(() => driver.transaction(connection => applySignedKernelSchema7To8(connection)), { code: 'RECOVERY_REQUIRED' });
    driver.exec('CREATE TABLE foreign_schema (id INTEGER) STRICT');
    assert.throws(() => assertKernelSchemaVersion(driver, 8), { code: 'RECOVERY_REQUIRED' });
  } finally { driver.close(); await rm(root, { recursive: true, force: true }); }
});
