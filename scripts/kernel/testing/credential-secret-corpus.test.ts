import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { CredentialSecretCorpusError, scanCopiedCredentialDatabase, scanCredentialSecretCorpus } from './credential-secret-corpus.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';

// Actual disposable SQLite/filesystem fixtures test the byte diagnostic only.
// They are not credential rows, retained process proof or installed evidence.
const limits = { maxBytes: 32 * 1024 * 1024, maxStreams: 4096 };
const secret = () => Buffer.from('diagnostic-only-secret-avoid-logging');
async function copyFixture(work: (filename: string) => Promise<void>) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-corpus-'));
  try { await chmod(directory, 0o700); await work(path.join(directory, 'authority.sqlite')); }
  finally { await rm(directory, { recursive: true, force: true }); }
}
async function createDatabase(filename: string, configure: (database: DatabaseSync) => void) {
  const database = new DatabaseSync(filename);
  try { configure(database); } finally { database.close(); }
  await chmod(filename, 0o600);
}

test('copied read-only diagnostics scan TEXT/BLOB cells and leave original bytes unchanged', async () => {
  await copyFixture(async filename => {
    await createDatabase(filename, database => {
      database.exec('CREATE TABLE retained_objects(bytes BLOB, text_value TEXT) STRICT');
      database.prepare('INSERT INTO retained_objects VALUES (?,?)').run(Buffer.from('ordinary bytes'), 'ordinary metadata');
    });
    const before = await readFile(filename), scanner = createCredentialSecretScanner([secret()], limits);
    try {
      const result = scanCopiedCredentialDatabase(filename, scanner);
      assert.equal(result.logicalRowsScanned, 1); assert.equal(result.logicalValuesScanned, 4);
      assert(result.logicalBytesScanned > 0); assert.equal(scanner.stats().matched, false);
      assert.deepEqual(await readFile(filename), before);
      assert.deepEqual(Object.keys(result).sort(), ['logicalBytesScanned', 'logicalRowsScanned', 'logicalValuesScanned']);
    } finally { scanner.close(); }
  });
});

test('copied diagnostics retain the real SQLite statement through GC and scan every final row', () => {
  // Real default-engine copies and real scanner; GC acts only in this child
  // diagnostic. No production phase, clock, native proof or authority is used.
  const result = spawnSync(process.execPath, ['--no-warnings', '--expose-gc', '--import', 'tsx', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
    import os from 'node:os'; import path from 'node:path'; import { DatabaseSync } from 'node:sqlite';
    import { scanCopiedCredentialDatabase } from ${JSON.stringify(new URL('./credential-secret-corpus.ts', import.meta.url).href)};
    import { createCredentialSecretScanner } from ${JSON.stringify(new URL('./credential-secret-scan.ts', import.meta.url).href)};
    const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-corpus-'));
    const filename = path.join(directory, 'authority.sqlite'), input = Buffer.from('diagnostic-only-secret-avoid-logging');
    const write = (found) => {
      const database = new DatabaseSync(filename);
      try {
        database.exec('CREATE TABLE retained_objects(value TEXT) STRICT');
        const insert = database.prepare('INSERT INTO retained_objects VALUES (?)');
        for (let index = 0; index < 100; index++) insert.run(found && index === 99 ? input.toString('utf8') : 'ordinary diagnostic bytes');
      } finally { database.close(); }
    };
    const scan = () => {
      const scanner = createCredentialSecretScanner([input], { maxBytes: 32 * 1024 * 1024, maxStreams: 4096 });
      let chunks = 0;
      const checked = { ...scanner, openStream() {
        const stream = scanner.openStream(); return { close: () => stream.close(), scan(bytes) {
          stream.scan(bytes); if (++chunks === 3) { global.gc(); global.gc(); }
        } };
      } };
      try { return scanCopiedCredentialDatabase(filename, checked); } finally { scanner.close(); }
    };
    try {
      await writeFile(filename, '', { flag: 'wx', mode: 0o600 }); write(false);
      const before = await readFile(filename), result = scan();
      assert.equal(result.logicalRowsScanned, 100); assert.equal(result.logicalValuesScanned, 102);
      assert.deepEqual(await readFile(filename), before);
      await rm(filename); await writeFile(filename, '', { flag: 'wx', mode: 0o600 }); write(true);
      const withSecret = await readFile(filename);
      assert.throws(() => scan(), { code: 'SECRET_DETECTED' }); assert.deepEqual(await readFile(filename), withSecret);
      console.log('owned copied SQLite GC scan qualified');
    } finally { input.fill(0); await rm(directory, { recursive: true, force: true }); }
  `], { encoding: 'utf8', timeout: 10000, maxBuffer: 16 * 1024 });
  assert.equal(result.status, 0, 'owned copied SQLite GC scan failed');
  assert.equal(result.stdout, 'owned copied SQLite GC scan qualified\n');
});

test('copied diagnostics scan full-width SQLite integers without losing TEXT/BLOB coverage', async () => {
  await copyFixture(async filename => {
    await createDatabase(filename, database => {
      database.exec('CREATE TABLE retained_objects(native_identity INTEGER, text_value TEXT, bytes BLOB) STRICT');
      database.prepare('INSERT INTO retained_objects VALUES (?,?,?)').run(9223372036854775807n, 'ordinary metadata', Buffer.from('ordinary bytes'));
    });
    const before = await readFile(filename), scanner = createCredentialSecretScanner([secret()], limits);
    try {
      const result = scanCopiedCredentialDatabase(filename, scanner);
      assert.equal(result.logicalRowsScanned, 1); assert.equal(result.logicalValuesScanned, 4);
      assert.deepEqual(await readFile(filename), before); assert.equal(scanner.stats().matched, false);
    } finally { scanner.close(); }
    const input = secret(), detecting = createCredentialSecretScanner([input], limits);
    const writer = new DatabaseSync(filename);
    try { writer.prepare('INSERT INTO retained_objects VALUES (?,?,?)').run(-9223372036854775808n, input.toString('utf8'), Buffer.from('ordinary bytes')); }
    finally { writer.close(); }
    const withSecret = await readFile(filename);
    try {
      assert.throws(() => scanCopiedCredentialDatabase(filename, detecting), { code: 'SECRET_DETECTED' });
      assert.equal(detecting.stats().matched, true); assert.deepEqual(await readFile(filename), withSecret);
    } finally { detecting.close(); input.fill(0); }
  });
});

test('copied diagnostics scan a real outstanding WAL without touching the original writer', async () => {
  await copyFixture(async filename => {
    const original = path.join(path.dirname(filename), 'original.sqlite'), writer = new DatabaseSync(original);
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      writer.exec('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE retained_objects(text_value TEXT, bytes BLOB) STRICT');
      writer.prepare('INSERT INTO retained_objects VALUES (?,?)').run('ordinary metadata', Buffer.from('ordinary bytes'));
      const main = await readFile(original), wal = await readFile(`${original}-wal`); assert(wal.length > 32);
      await writeFile(filename, main, { flag: 'wx', mode: 0o600 });
      await writeFile(`${filename}-wal`, wal, { flag: 'wx', mode: 0o600 });
      const result = scanCopiedCredentialDatabase(filename, scanner);
      assert.equal(result.logicalRowsScanned, 1); assert.equal(result.logicalValuesScanned, 4);
      assert.deepEqual(await readFile(original), main); assert.deepEqual(await readFile(`${original}-wal`), wal);
      assert.equal(writer.prepare('SELECT count(*) AS total FROM retained_objects').get()!.total, 1);
      assert.equal(scanner.stats().matched, false);
    } finally { scanner.close(); writer.close(); }
  });
});

for (const kind of ['TEXT', 'BLOB'] as const) test(`copied logical ${kind} secret detection has a closed data-free error`, async () => {
  await copyFixture(async filename => {
    const input = secret();
    await createDatabase(filename, database => {
      database.exec(`CREATE TABLE values_to_scan(payload ${kind}) STRICT`);
      database.prepare('INSERT INTO values_to_scan VALUES (?)').run(kind === 'TEXT' ? input.toString('utf8') : input);
    });
    const scanner = createCredentialSecretScanner([input], limits);
    try {
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), error => {
        assert(error instanceof Error); assert.equal(error.message, 'credential secret scan detected forbidden bytes');
        assert.equal(Object.hasOwn(error, 'cause'), false); assert(!JSON.stringify(error).includes(filename));
        assert(!JSON.stringify(error).includes(input.toString('utf8'))); return true;
      });
      assert.equal(scanner.stats().matched, true); assert.equal(scanner.stats().closed, true);
    } finally { scanner.close(); input.fill(0); }
  });
});

test('logical BLOB scan detects bytes split across real SQLite pages that raw scanning cannot match', async () => {
  await copyFixture(async filename => {
    const input = randomBytes(8192);
    await createDatabase(filename, database => {
      database.exec('PRAGMA page_size=4096; CREATE TABLE retained_objects(bytes BLOB) STRICT');
      database.prepare('INSERT INTO retained_objects VALUES (?)').run(input);
    });
    const raw = await readFile(filename); assert.equal(raw.includes(input), false);
    const scanner = createCredentialSecretScanner([input], limits);
    try {
      const stream = scanner.openStream(); try { stream.scan(raw); } finally { stream.close(); }
      assert.equal(scanner.stats().matched, false);
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), { code: 'SECRET_DETECTED' });
    } finally { scanner.close(); input.fill(0); raw.fill(0); }
  });
});

test('legal sqlitex user tables are scanned rather than mistaken for SQLite internal tables', async () => {
  await copyFixture(async filename => {
    const input = randomBytes(8192);
    await createDatabase(filename, database => {
      database.exec('PRAGMA page_size=4096; CREATE TABLE ordinary(bytes BLOB) STRICT; CREATE TABLE sqlitex(bytes BLOB) STRICT');
      database.prepare('INSERT INTO ordinary VALUES (?)').run(Buffer.from('ordinary diagnostic bytes'));
      database.prepare('INSERT INTO sqlitex VALUES (?)').run(input);
    });
    const raw = await readFile(filename); assert.equal(raw.includes(input), false);
    const scanner = createCredentialSecretScanner([input], limits);
    try {
      const stream = scanner.openStream(); try { stream.scan(raw); } finally { stream.close(); }
      assert.equal(scanner.stats().matched, false);
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), { code: 'SECRET_DETECTED' });
    } finally { scanner.close(); input.fill(0); raw.fill(0); }
  });
});

test('malformed copied SQLite and an oversized table corpus fail with fixed errors', async () => {
  await copyFixture(async filename => {
    await writeFile(filename, 'arbitrary error text must not escape', { flag: 'wx', mode: 0o600 });
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), error => {
        assert(error instanceof CredentialSecretCorpusError);
        assert.equal(error.message, 'credential secret corpus did not qualify'); assert.equal(Object.hasOwn(error, 'cause'), false);
        assert.deepEqual(error.databaseFailure, { database: 'authority', stage: 'schema', errorClass: 'sqlite_not_database' });
        assert.equal(Object.isFrozen(error.databaseFailure), true);
        assert(!JSON.stringify(error).includes(filename)); assert(!JSON.stringify(error).includes('arbitrary error text'));
        return true;
      });
      await rm(filename);
      await createDatabase(filename, database => { for (let index = 0; index < 65; index++) database.exec(`CREATE TABLE table_${index}(value TEXT)`); });
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), { message: 'credential secret corpus did not qualify' });
    } finally { scanner.close(); }
  });
});

test('copied diagnostics reject non-copy paths and symlink leaves before opening SQLite', async () => {
  await copyFixture(async filename => {
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      for (const value of [undefined, null, 1, Symbol('untrusted filename'), { filename }])
        assert.throws(() => scanCopiedCredentialDatabase(value as never, scanner), error => {
          assert(error instanceof CredentialSecretCorpusError);
          assert.equal(error.message, 'credential secret corpus did not qualify'); assert.equal(Object.hasOwn(error, 'cause'), false);
          assert.equal(error.databaseFailure, undefined); assert(!JSON.stringify(error).includes(filename)); return true;
        });
      assert.throws(() => scanCopiedCredentialDatabase(path.join(path.dirname(filename), 'other.sqlite'), scanner),
        { message: 'credential secret corpus did not qualify' });
      await symlink('/nonexistent/diagnostic-target', filename);
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), { message: 'credential secret corpus did not qualify' });
      assert.equal(scanner.stats().streamsOpened, 0);
    } finally { scanner.close(); }
  });
});

const linux = { skip: process.platform !== 'linux' || process.geteuid?.() === 0 ? 'full corpus fixtures require an ordinary Linux UID' : false };
const stateLayouts = ['home/probe/credential-state', 'home/.cliq/kernel-v1'] as const;
async function actualFixture(layout: typeof stateLayouts[number], work: (stateRoot: string, cas: string) => Promise<void>) {
  const fixture = await mkdtemp('/var/tmp/cliq-systemd-probe.');
  try {
    const stateRoot = path.join(fixture, layout), cas = path.join(stateRoot, 'cas');
    await mkdir(path.join(stateRoot, 'credentials'), { recursive: true, mode: 0o700 });
    for (const directory of [path.join(fixture, 'home'), path.dirname(stateRoot), stateRoot]) await chmod(directory, 0o700);
    await mkdir(cas, { mode: 0o700 });
    for (const filename of [path.join(stateRoot, 'kernel.sqlite3'), path.join(stateRoot, 'credentials/authority.sqlite')]) {
      await createDatabase(filename, database => {
        database.exec('CREATE TABLE retained_objects(bytes BLOB) STRICT');
        database.prepare('INSERT INTO retained_objects VALUES (?)').run(Buffer.from('actual diagnostic fixture bytes'));
      });
    }
    await work(stateRoot, cas);
  } finally { await rm(fixture, { recursive: true, force: true }); }
}

for (const layout of stateLayouts) test(`actual Linux ${layout} fixed-file corpus covers both databases and a flat pinned CAS object`, linux, async () => {
  await actualFixture(layout, async (stateRoot, cas) => {
    await writeFile(path.join(cas, 'a'.repeat(64)), Buffer.from('ordinary immutable object'), { flag: 'wx', mode: 0o400 });
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      const result = await scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner });
      assert.equal(result.diagnosticOnly, true); assert.equal(result.qualified, true); assert.equal(result.sqliteDatabasesScanned, 2);
      assert.equal(result.filesScanned, 3); assert.equal(result.logicalRowsScanned, 2);
      assert.equal(result.evidenceDirectoriesScanned, 0); assert.equal(scanner.stats().matched, false);
      assert(!JSON.stringify(result).includes(stateRoot));
    } finally { scanner.close(); }
  });
});

for (const layout of stateLayouts) test(`actual Linux ${layout} CAS scan detects secret bytes across read chunk boundaries`, linux, async () => {
  await actualFixture(layout, async (stateRoot, cas) => {
    const input = secret(), payload = Buffer.concat([Buffer.alloc(65530, 3), input, Buffer.alloc(17, 4)]);
    await writeFile(path.join(cas, 'b'.repeat(64)), payload, { flag: 'wx', mode: 0o400 });
    const scanner = createCredentialSecretScanner([input], limits);
    try {
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }), { code: 'SECRET_DETECTED' });
      assert.equal(scanner.stats().closed, true);
    } finally { scanner.close(); input.fill(0); payload.fill(0); }
  });
});

for (const layout of stateLayouts) for (const temporary of [false, true]) test(`actual Linux ${layout} CAS ${temporary ? 'temporary' : 'published'} leaf names cannot contain encoded secret bytes`, linux, async () => {
  await actualFixture(layout, async (stateRoot, cas) => {
    const input = randomBytes(32), encoded = input.toString('hex');
    const leaf = temporary ? `.tmp-${encoded}-${'a'.repeat(32)}` : encoded;
    await writeFile(path.join(cas, leaf), Buffer.from('ordinary diagnostic content'), { flag: 'wx', mode: temporary ? 0o600 : 0o400 });
    const scanner = createCredentialSecretScanner([input], limits);
    try {
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }), error => {
        assert(error instanceof Error); assert.equal((error as Error & { code?: string }).code, 'SECRET_DETECTED');
        assert.equal(error.message, 'credential secret scan detected forbidden bytes');
        assert.equal(Object.hasOwn(error, 'cause'), false); assert.equal(JSON.stringify(error).includes(encoded), false);
        return true;
      });
      assert.equal(scanner.stats().matched, true); assert.equal(scanner.stats().closed, true);
    } finally { scanner.close(); input.fill(0); }
  });
});

for (const layout of stateLayouts) test(`actual Linux ${layout} corpus refuses CAS aliases, extra directory breadth and weak file modes`, linux, async () => {
  await actualFixture(layout, async (stateRoot, cas) => {
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      const leaf = path.join(cas, 'c'.repeat(64)); await symlink(path.join(stateRoot, 'kernel.sqlite3'), leaf);
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }),
        { message: 'credential secret corpus did not qualify' });
      await rm(leaf); await mkdir(path.join(cas, 'unrelated'), { mode: 0o700 });
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }),
        { message: 'credential secret corpus did not qualify' });
      await rm(path.join(cas, 'unrelated'), { recursive: true }); await chmod(path.join(stateRoot, 'kernel.sqlite3'), 0o644);
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }),
        { message: 'credential secret corpus did not qualify' });
    } finally { scanner.close(); }
  });
});

for (const layout of stateLayouts) test(`actual Linux ${layout} corpus refuses roots outside either exact fixture layout`, linux, async () => {
  await actualFixture(layout, async stateRoot => {
    const fixture = path.resolve(stateRoot, '../../..');
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      for (const invalidRoot of [path.dirname(stateRoot), `${stateRoot}/extra`,
        path.join(fixture, 'home/probe/other'), path.join(fixture, 'home/.cliq/other'),
        `${stateRoot}/../${path.basename(stateRoot)}`, `${stateRoot}/`]) {
        await assert.rejects(scanCredentialSecretCorpus({ stateRoot: invalidRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }),
          { message: 'credential secret corpus did not qualify' });
      }
      assert.equal(scanner.stats().streamsOpened, 0);
    } finally { scanner.close(); }
  });
});
