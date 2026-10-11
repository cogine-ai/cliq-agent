import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSqliteVfsMechanismHelper } from './sqlite-vfs-mechanism-build.js';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('fixed Node engine selects a private VFS across loader lifetimes and refuses lost diagnostic evidence', { timeout: 180000 }, async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-vfs-mechanism-test-'));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const built = await buildSqliteVfsMechanismHelper(fixture, carrier.nodeRoot);
    for (const mode of ['permanent', 'scoped', 'dual', 'marker_failure']) {
      const target = path.join(fixture, `never-created-${mode}.sqlite`);
      const child = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
      const assert = require('node:assert/strict');
      const {DatabaseSync} = require('node:sqlite');
      const mode = ${JSON.stringify(mode)};
      const uri = ${JSON.stringify(`file:${target}?vfs=cliq-sqlite-vfs-mechanism-v1`)};
      assert.throws(() => new DatabaseSync(uri, {allowExtension:false}), /no such vfs/);
      let native;
      if (mode === 'dual') {
        const module = {exports:{}};
        process.dlopen(module, ${JSON.stringify(built.helper)});
        native = module.exports;
        assert.equal(native.observe().initialized, false);
        assert.equal(native.observe().sourceId, null);
      }
      const bootstrap = new DatabaseSync(':memory:', {allowExtension:true});
      const entry = mode === 'scoped' ? 'sqlite3_cliqvfsscopemechanism_init' : 'sqlite3_cliqvfsmechanism_init';
      bootstrap.loadExtension(${JSON.stringify(built.helper)}, entry);
      bootstrap.enableLoadExtension(false);
      assert.throws(() => bootstrap.loadExtension(${JSON.stringify(built.helper)}, entry), /extension loading is not allowed/);
      if (native) {
        assert.equal(native.observe().initialized, true);
        assert.equal(native.observe().privateRegistered, true);
        assert.equal(native.observe().defaultUnchanged, true);
        assert.equal(native.observe().totalOpens, 0);
      }
      bootstrap.close();
      // A failed evidence pipe is not a successful diagnostic callback.
      if (mode === 'marker_failure') require('node:fs').closeSync(2);
      // Only the dual case loads N-API; doing so in either SQLite-only case would mask unload bugs.
      if (mode === 'scoped') assert.throws(() => new DatabaseSync(uri, {allowExtension:false}), /no such vfs/);
      else assert.throws(() => new DatabaseSync(uri, {allowExtension:false}), error => {
        if (mode === 'marker_failure') require('node:fs').writeSync(1,
          JSON.stringify({code:error.code, errcode:error.errcode}) + '\\n');
        return error.code === 'ERR_SQLITE_ERROR' && (mode === 'marker_failure' ? error.errcode === 778
          : error.errcode === 14 && /unable to open database/.test(error.message));
      });
      const ordinary = new DatabaseSync(':memory:', {allowExtension:false});
      assert.equal(ordinary.prepare('SELECT 17 AS value').get().value, 17);
      assert.throws(() => ordinary.enableLoadExtension(true), /disabled at database creation/);
      assert.throws(() => ordinary.exec("SELECT load_extension('forbidden')"), /not authorized/);
      if (native) {
        assert.equal(native.observe().totalOpens, 1);
        assert.equal(native.observe().defaultUnchanged, true);
        assert.equal(native.observe().sourceId, ordinary.prepare('SELECT sqlite_source_id() AS id').get().id);
      }
      ordinary.close();
    `], { cwd: fixture, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
      assert.equal(child.error, undefined); assert.equal(child.signal, null);
      assert.equal(child.status, 0, child.stderr + child.stdout);
      if (mode === 'marker_failure') assert.deepEqual(JSON.parse(child.stdout), {code:'ERR_SQLITE_ERROR', errcode:778});
      else assert.equal(child.stdout, '');
      assert.equal(child.stderr.split('\n').filter(line => line === 'CLIQ_SQLITE_VFS_MECHANISM_OPEN').length,
        mode === 'scoped' || mode === 'marker_failure' ? 0 : 1);
    }
    assert(!(await readdir(fixture)).some(name => name.startsWith('never-created-')));
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

test('a cached carrier is rejected by the fixed checksum before extraction or native compilation', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-vfs-bad-carrier-'));
  try {
    // An existing source file is a safe read-only invalid archive, not executable code.
    await assert.rejects(prepareSupervisorSeaCarrier(fixture, fileURLToPath(new URL('./sqlite-vfs-mechanism-probe.c', import.meta.url))),
      /official carrier checksum mismatch/);
    assert.deepEqual(await readdir(fixture), []);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
