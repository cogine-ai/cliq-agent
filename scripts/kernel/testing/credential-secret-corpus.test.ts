import assert from 'node:assert/strict';
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
async function actualFixture(work: (stateRoot: string, cas: string) => Promise<void>) {
  const fixture = await mkdtemp('/var/tmp/cliq-systemd-probe.');
  try {
    const stateRoot = path.join(fixture, 'home/probe/credential-state'), cas = path.join(stateRoot, 'cas');
    await mkdir(path.join(stateRoot, 'credentials'), { recursive: true, mode: 0o700 });
    for (const directory of [path.join(fixture, 'home'), path.join(fixture, 'home/probe'), stateRoot]) await chmod(directory, 0o700);
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

test('actual Linux fixed-file corpus covers both databases and a flat pinned CAS object', linux, async () => {
  await actualFixture(async (stateRoot, cas) => {
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

test('actual Linux CAS scan detects secret bytes across read chunk boundaries', linux, async () => {
  await actualFixture(async (stateRoot, cas) => {
    const input = secret(), payload = Buffer.concat([Buffer.alloc(65530, 3), input, Buffer.alloc(17, 4)]);
    await writeFile(path.join(cas, 'b'.repeat(64)), payload, { flag: 'wx', mode: 0o400 });
    const scanner = createCredentialSecretScanner([input], limits);
    try {
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }), { code: 'SECRET_DETECTED' });
      assert.equal(scanner.stats().closed, true);
    } finally { scanner.close(); input.fill(0); payload.fill(0); }
  });
});

for (const temporary of [false, true]) test(`actual Linux CAS ${temporary ? 'temporary' : 'published'} leaf names cannot contain encoded secret bytes`, linux, async () => {
  await actualFixture(async (stateRoot, cas) => {
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

test('actual Linux corpus refuses CAS aliases, extra directory breadth and weak file modes', linux, async () => {
  await actualFixture(async (stateRoot, cas) => {
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
