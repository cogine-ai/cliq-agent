import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

// Same signed production entry as local auth. This first tracer is metadata
// only: portable/macOS success cannot qualify the actual Linux invocation.
test('signed installed credential read is independent and rejects unsupported authority formats without genesis',
  { timeout: 180000, skip: process.platform !== 'linux' ? 'requires the actual signed Linux auth entry' : false }, async context => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-journey-')));
    try {
      const signed = await buildInstalledSupervisorPackage(fixture);
      const stateRoot = path.join(fixture, 'state');
      await createInstalledRuntime({ releaseKeys: signed.releaseKeys }).installInitial({ packageRoot: signed.packageRoot, stateRoot });
      const casSnapshot = async () => {
        const directory = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
        return Promise.all((await readdir(directory)).sort().map(async ref =>
          [ref, sha256Bytes(await readFile(path.join(directory, ref)))]));
      };
      const casBefore = await casSnapshot();
      // Command metadata goes in argv; raw credential bytes must never do so.
      // Read/replay must decide their result before requesting secret input.
      const command = canonicalJsonBytes({ schemaVersion: 1, kind: 'read', credentialGrantId: 'missing-credential' }).toString('base64url');
      const read = () => spawnSync(path.join(stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential', command], {
        encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536,
        env: { PATH: process.env.PATH }, cwd: fixture, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const response = read();
      assert.equal(response.error, undefined); assert.equal(response.signal, null);
      assert.equal(response.status, 0, response.stderr);
      assert.deepEqual(JSON.parse(response.stdout), { schemaVersion: 1, record: null });
      assert.deepEqual(await casSnapshot(), casBefore);
      const noRunState = async () => {
        for (const relative of [KERNEL_DATABASE_FILENAME, 'runtime/state-owner.lock', 'runtime/keeper.ready', 'runtime/control-v1.sock'])
          await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
      };
      await noRunState();
      const authority = path.join(stateRoot, 'credentials/authority.sqlite');
      const schema = () => {
        const database = new DatabaseSync(authority, { readOnly: true, allowExtension: false });
        try {
          const names = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name")
            .all().map(row => row.name);
          // Only this fixture's known tables can be read; SQL identifiers do
          // not come from arbitrary schema text or manufacture authority.
          assert(names.every(name => ['endpoint_operations', 'endpoint_records', 'retained_objects', 'sqlitex'].includes(String(name))));
          return { version: database.prepare('PRAGMA user_version').get()?.user_version, names,
            rows: names.map(name => [name, database.prepare(`SELECT count(*) AS count FROM "${name}"`).get()?.count]) };
        } finally { database.close(); }
      };
      const supported = ['endpoint_operations', 'endpoint_records', 'retained_objects'];
      assert.deepEqual(schema(), { version: 1, names: supported, rows: supported.map(name => [name, 0]) },
        'the initial real auth read must establish an empty actual v1 schema');
      const databaseBytes = async () => Promise.all(['', '-wal', '-journal'].map(async suffix => {
        try { return await readFile(`${authority}${suffix}`); }
        catch (error) {
          // Native acquisition may recreate an empty fixed sidecar. This is
          // not a schema/record write or a claim about its file identity.
          if (suffix && (error as NodeJS.ErrnoException).code === 'ENOENT') return Buffer.alloc(0);
          throw error;
        }
      }));
      const unsupported = async (version: number, names: string[]) => {
        const before = schema();
        assert.deepEqual(before, { version, names, rows: names.map(name => [name, 0]) });
        const beforeBytes = await databaseBytes();
        const refused = read();
        assert.equal(refused.error, undefined); assert.equal(refused.signal, null);
        assert.deepEqual(await casSnapshot(), casBefore); await noRunState();
        assert.deepEqual(schema(), before, 'unsupported auth read must not accept or genesis the format');
        assert.deepEqual(await databaseBytes(), beforeBytes, 'unsupported auth read must preserve actual database bytes');
        assert.equal(refused.status, 1, 'unsupported authority format must refuse through the signed entry');
        assert.equal(refused.stdout, '', 'unsupported format must not publish a credential record');
        const lines = refused.stderr.trim().split('\n').filter(line => line.startsWith('{'));
        assert.equal(lines.length, 1);
        assert.deepEqual(JSON.parse(lines[0]!), { diagnosticOnly: true, scope: 'installed-read-startup',
          code: 'RECOVERY_REQUIRED', message: 'endpoint authority schema is not supported' });
      };
      await context.test('v1 with a legal extra sqlitex table is an unsupported format', async () => {
        // The signed auth has exited. Deliberately damage only its exact
        // disposable DB: no raw SQL seeds a valid record or proof.
        const database = new DatabaseSync(authority, { allowExtension: false });
        try { database.exec('CREATE TABLE sqlitex(value TEXT) STRICT'); } finally { database.close(); }
        await unsupported(1, [...supported, 'sqlitex']);
      });
      await context.test('version zero with an existing sqlitex table must not be treated as empty genesis', async () => {
        assert.deepEqual(schema(), { version: 1, names: [...supported, 'sqlitex'],
          rows: [...supported, 'sqlitex'].map(name => [name, 0]) });
        const database = new DatabaseSync(authority, { allowExtension: false });
        try {
          // These are proven-empty fixture tables. Removing them/version is
          // solely a deliberately unsupported-format negative, not v1 setup.
          database.exec('BEGIN; DROP TABLE endpoint_operations; DROP TABLE endpoint_records; DROP TABLE retained_objects; PRAGMA user_version=0; COMMIT');
        } finally { database.close(); }
        await unsupported(0, ['sqlitex']);
      });
    } finally { await rm(fixture, { recursive: true, force: true }); }
  });
