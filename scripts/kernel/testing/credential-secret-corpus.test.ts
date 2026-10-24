import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { promises as fs } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { KERNEL_AUTHORITY_TABLES } from '../../../src/state/schema.js';
import * as corpus from './credential-secret-corpus.js';
import { CredentialSecretCorpusError, scanCopiedCredentialDatabase, scanCredentialSecretCorpus } from './credential-secret-corpus.js';
import { CredentialSecretScanError, createCredentialSecretScanner, type CredentialSecretScanStats } from './credential-secret-scan.js';

// Actual disposable SQLite/filesystem fixtures test the byte diagnostic only.
// They are not credential rows, retained process proof or installed evidence.
const limits = { maxBytes: 32 * 1024 * 1024, maxStreams: 4096 };
const secret = () => Buffer.from('diagnostic-only-secret-avoid-logging');

test('whole corpus refusal exposes only the fixed stage and bounded progress, never an input path or cause', async () => {
  const scanner = createCredentialSecretScanner([secret()], limits);
  try {
    await assert.rejects(scanCredentialSecretCorpus({ stateRoot: '/private-untrusted-corpus-path', uid: 1001, evidenceDirs: [], scanner }), error => {
      assert(error instanceof CredentialSecretCorpusError);
      assert.deepEqual(error.corpusFailure, { stage: 'input', errorClass: 'guard_refused', filesScanned: 0,
        fileBytesScanned: 0, sqliteDatabasesScanned: 0, logicalRowsScanned: 0, logicalValuesScanned: 0,
        logicalBytesScanned: 0, evidenceDirectoriesScanned: 0, inventoryEntriesObserved: 0 });
      assert.equal(Object.isFrozen(error.corpusFailure), true);
      assert.equal(Object.hasOwn(error, 'cause'), false); assert(!JSON.stringify(error).includes('private-untrusted'));
      assert.equal(scanner.stats().bytesScanned, 0); return true;
    });
  } finally { scanner.close(); }
});
async function copyFixture(work: (filename: string) => Promise<void>, leaf: 'authority.sqlite' | 'kernel.sqlite3' = 'authority.sqlite') {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-corpus-'));
  try { await chmod(directory, 0o700); await work(path.join(directory, leaf)); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

function failureProgress(error: unknown): unknown {
  const read = (corpus as unknown as { readCredentialSecretCorpusScanProgress?: (error: unknown) => unknown }).readCredentialSecretCorpusScanProgress;
  assert.equal(typeof read, 'function', 'the actual error owns a fixed diagnostic accessor');
  return read!(error);
}

for (const [maxStreams, before] of [[8, 3], [4096, 675]] as const)
  test(`real copied SQLite keeps its original ${maxStreams}-stream refusal and partial observed counters`, async () => {
    await copyFixture(async filename => {
      const value = 'ordinary diagnostic bytes';
      await createDatabase(filename, database => {
        database.exec('CREATE TABLE items(value TEXT) STRICT; BEGIN');
        const insert = database.prepare('INSERT INTO items VALUES (?)');
        for (let index = 0; index < 4095; index++) insert.run(value);
        database.exec('COMMIT');
      });
      const bytes = await readFile(filename);
      let observed: unknown;
      const scanner = createCredentialSecretScanner([secret()], { maxBytes: 512 * 1024 * 1024, maxStreams }, error => { observed = error; });
      try {
        for (let index = 0; index < before; index++) scanner.openStream().close();
        let original: unknown;
        assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), error => {
          original = error; assert.equal(error, observed); assert.equal((error as { code?: unknown }).code, 'LIMIT_EXCEEDED'); return true;
        });
        const rows = maxStreams - before - 1;
        const progress = failureProgress(original);
        assert.deepEqual(progress, { diagnosticOnly: true, source: { kind: 'database_logical', database: 'authority',
          tableBucket: 'items', part: 'cell', logicalRowsObserved: rows, logicalValuesAttempted: rows + 2,
          logicalBytesObserved: Buffer.byteLength('items') + Buffer.byteLength('CREATE TABLE items(value TEXT) STRICT') + rows * Buffer.byteLength(value) } });
        assert.equal(Object.isFrozen(progress), true); assert.equal(Object.isFrozen((progress as { source: object }).source), true);
        assert.equal(scanner.stats().streamsOpened, maxStreams); assert.equal(scanner.stats().streamsClosed, maxStreams);
        assert.equal(scanner.stats().closed, true); assert.equal(scanner.stats().limitExceeded, true);
        assert.deepEqual(await readFile(filename), bytes); assert(!JSON.stringify(progress).includes(filename));
        assert.equal(Object.hasOwn(original as object, 'cause'), false); assert.equal(Object.hasOwn(original as object, 'corpusProgress'), false);
      } finally { scanner.close(); }
    });
  });

const kernelTableBuckets = [['artifacts', 'artifacts'], ['control_requests', 'control'], ['run_events', 'events'],
  ['items', 'items'], ['checkpoints', 'checkpoints'], ['run_journal', 'journal'],
  ['canonical_time_fence', 'canonical_time_fence'], ['state_owners', 'state_owners'], ['sessions', 'sessions'],
  ['runs', 'runs'], ['worker_launches', 'worker_launches'], ['workspace_generations', 'workspace_generations'],
  ['local_inference_activation_cycles', 'local_inference_activation_cycles'], ['local_inference_launches', 'local_inference_launches'],
  ['list_read_cuts', 'list_read_cuts'], ['list_read_cut_entries', 'list_read_cut_entries'], ['child_allocations', 'child_allocations'],
  ['authorization_grants', 'authorization_grants'], ['source_inspection_attempts', 'source_inspection_attempts'],
  ['mcp_registrations', 'mcp_registrations'], ['admin_operations', 'admin_operations']] as const;

test('fixed diagnostic table buckets exhaust the independent canonical kernel inventory without changing six original aliases', () => {
  assert.equal(kernelTableBuckets.length, 21);
  assert.deepEqual(kernelTableBuckets.map(([table]) => table).sort(), [...KERNEL_AUTHORITY_TABLES].sort());
  assert.deepEqual(kernelTableBuckets.slice(0, 6), [['artifacts', 'artifacts'], ['control_requests', 'control'], ['run_events', 'events'],
    ['items', 'items'], ['checkpoints', 'checkpoints'], ['run_journal', 'journal']]);
  assert(kernelTableBuckets.every(([, bucket]) => /^[a-z_]+$/u.test(bucket) && bucket.length < 96));
});

for (const [table, bucket] of [...kernelTableBuckets, ['private_unknown_table', 'other'], ['source_inspection_attempts_private', 'other']] as const)
  test(`copied SQLite failure projects only the fixed ${bucket} bucket`, async () => {
    await copyFixture(async filename => {
      await createDatabase(filename, database => {
        database.exec(`CREATE TABLE ${table}(value TEXT) STRICT; INSERT INTO ${table} VALUES ('ordinary bytes')`);
      });
      let observed: unknown;
      const scanner = createCredentialSecretScanner([secret()], { maxBytes: 1024 * 1024, maxStreams: 2 }, error => { observed = error; });
      try {
        let original: unknown;
        assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), error => { original = error;
          assert.equal(error, observed); return (error as { code?: unknown }).code === 'LIMIT_EXCEEDED'; });
        const progress = failureProgress(original) as { source: { database: string; tableBucket: string; part: string } };
        assert.equal(progress.source.database, 'kernel'); assert.equal(progress.source.tableBucket, bucket); assert.equal(progress.source.part, 'cell');
        assert.equal(scanner.stats().streamsOpened, 2); assert.equal(scanner.stats().streamsClosed, 2);
        assert(!JSON.stringify(progress).includes(filename)); if (bucket === 'other') assert(!JSON.stringify(progress).includes(table));
      } finally { scanner.close(); }
    }, 'kernel.sqlite3');
  });

test('corpus failure accessor ignores foreign objects, functions, accessors and proxies without evaluating them', () => {
  let invoked = 0;
  const poisoned = Object.defineProperty({}, 'source', { get() { invoked++; throw new Error('private error body'); } });
  const traps: ProxyHandler<object> = {};
  for (const name of ['get', 'getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'] as const)
    traps[name] = (() => { invoked++; throw new Error('private error body'); }) as never;
  for (const input of [undefined, null, 1, 'private error body', Symbol('foreign'), () => { invoked++; }, poisoned,
    new Proxy({}, traps), new Proxy(() => { invoked++; }, traps), new Error('private error body'), new CredentialSecretScanError('LIMIT_EXCEEDED'),
    { diagnosticOnly: true, source: { kind: 'cas', part: 'file_bytes' } }]) assert.equal(failureProgress(input), undefined);
  assert.equal(invoked, 0);
});

test('corpus progress is obtained after the real await catch and stays outside the unchanged four-field scan fallback', async () => {
  const source = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert.match(source, /secretCorpusScanProgress = readCredentialSecretCorpusScanProgress\(error\)/u);
  assert.match(source, /copyCredentialSecretScanFailureDiagnostic\(\{ diagnosticOnly: true,\s*firstFailureStage, beforeCorpus, corpusScanFailureCode \}\)/u);
  assert.match(source, /\.\.\.\(secretCorpusScanProgress \? \{ secretCorpusScanProgress \} : \{\}\)/u);
  const observer = source.slice(source.indexOf('  const scanner = createCredentialSecretScanner('), source.indexOf('  const scanBytes ='));
  assert.doesNotMatch(observer, /readCredentialSecretCorpusScanProgress/u, 'the error map does not exist before the scanner throws through corpus');
});
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

test('a real copied SQLite stream-limit refusal retains its first corpus failure and original bytes', async () => {
  await copyFixture(async filename => {
    await createDatabase(filename, database => {
      database.exec('CREATE TABLE ordinary(value TEXT) STRICT; BEGIN');
      const insert = database.prepare('INSERT INTO ordinary VALUES (?)');
      for (let index = 0; index < 4095; index++) insert.run('ordinary diagnostic bytes');
      database.exec('COMMIT');
    });
    const before = await readFile(filename);
    let stage: 'runtime' | 'corpus' | 'report' = 'runtime';
    let firstFailureStage: 'runtime' | 'corpus' | 'report' | null = null, observed: unknown;
    const observations: CredentialSecretScanStats[] = [];
    const scanner = createCredentialSecretScanner([secret()], { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 }, error => {
      observed = error; firstFailureStage ??= stage;
      observations.push(scanner.stats());
    });
    try {
      const originalCounts = scanner.stats();
      const beforeCorpus = Object.freeze({ streamsOpened: originalCounts.streamsOpened, bytesScanned: originalCounts.bytesScanned });
      stage = 'corpus';
      // The schema name/SQL plus 4095 actual independent values exceed the
      // unchanged total 4096-stream budget, not the row, byte or file guards.
      assert.throws(() => scanCopiedCredentialDatabase(filename, scanner), error => {
        assert.equal(error, observed, 'the caller receives the exact observed original scanner error');
        assert.equal((error as { code?: unknown }).code, 'LIMIT_EXCEEDED', 'the original stream guard still refuses');
        return true;
      });
      assert.equal(observations.length, 1, 'the real copied database refusal is observed once');
      assert.equal(observations[0]!.closed, true, 'the real scanner retires before corpus failure observation');
      assert.equal(observations[0]!.streamsOpened, observations[0]!.streamsClosed,
        'all original stream owners have closed at observation');
      stage = 'report';
      assert.throws(() => scanner.openStream(), { code: 'CLOSED' });
      assert.equal(firstFailureStage, 'corpus', 'later report masking cannot replace the first corpus failure');
      assert.deepEqual(beforeCorpus, { streamsOpened: 0, bytesScanned: 0 });
      const stats = scanner.stats();
      assert.equal(stats.streamsOpened, 4096, 'all original independent streams remain counted');
      assert.equal(stats.streamsClosed, 4096, 'all original independent streams close');
      assert.equal(stats.limitExceeded, true, 'the diagnostic cannot qualify exhaustion');
      assert.deepEqual(await readFile(filename), before, 'diagnosis never rewrites the actual copied SQLite input');
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

for (const part of ['entry_name', 'file_bytes'] as const)
  test(`actual Linux CAS ${part} refusal keeps the original 4096 streams and joins real file descriptors`, linux, async t => {
    await actualFixture('home/.cliq/kernel-v1', async (stateRoot, cas) => {
      const filename = path.join(cas, 'c'.repeat(64)), payload = Buffer.from('ordinary immutable diagnostic bytes');
      await writeFile(filename, payload, { flag: 'wx', mode: 0o400 });
      let observed: unknown;
      const scanner = createCredentialSecretScanner([secret()], { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 }, error => { observed = error; });
      // Each existing fixture database has one raw-file stream and its three
      // original schema/value streams. No stream is omitted or joined to another.
      for (let index = 0; index < (part === 'entry_name' ? 4088 : 4087); index++) scanner.openStream().close();
      const active = new Set<object>(), actualOpen = fs.open; let opened = 0;
      t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
        const handle = await actualOpen(...args), close = handle.close.bind(handle); active.add(handle); opened++;
        t.mock.method(handle, 'close', async () => { await close(); assert.equal(active.delete(handle), true); });
        return handle;
      });
      syncBuiltinESMExports();
      try {
        let original: unknown;
        await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }), error => {
          original = error; assert.equal(error, observed); assert.equal((error as { code?: unknown }).code, 'LIMIT_EXCEEDED'); return true;
        });
        assert(opened > 0, 'the original corpus uses the observed real descriptor opens');
        assert.equal(active.size, 0, 'the original corpus finally closes every genuine opened descriptor before observation');
        const progress = failureProgress(original) as { source: object; corpusCounters: Record<string, number> };
        assert.deepEqual(progress.source, { kind: 'cas', part });
        assert.equal(progress.corpusCounters.filesScanned, 2); assert.equal(progress.corpusCounters.sqliteDatabasesScanned, 2);
        assert.equal(progress.corpusCounters.logicalRowsScanned, 2); assert.equal(progress.corpusCounters.logicalValuesScanned, 6);
        assert.equal(progress.corpusCounters.inventoryEntriesObserved, 1); assert.equal(progress.corpusCounters.evidenceDirectoriesScanned, 0);
        assert(progress.corpusCounters.fileBytesScanned! > 0); assert.equal(Object.isFrozen(progress.corpusCounters), true);
        assert.equal(scanner.stats().streamsOpened, 4096); assert.equal(scanner.stats().streamsClosed, 4096);
        assert(!JSON.stringify(progress).includes(filename)); assert.deepEqual(await readFile(filename), payload);
      } finally { scanner.close(); t.mock.restoreAll(); syncBuiltinESMExports(); }
    });
  });

test('actual Linux over-breadth corpus reports the unchanged 1024-entry guard before reading or omitting any CAS object', linux, async () => {
  await actualFixture('home/.cliq/kernel-v1', async (stateRoot, cas) => {
    for (let index = 0; index < 1025; index++)
      await writeFile(path.join(cas, index.toString(16).padStart(64, '0')), '', { flag: 'wx', mode: 0o400 });
    const scanner = createCredentialSecretScanner([secret()], limits);
    try {
      await assert.rejects(scanCredentialSecretCorpus({ stateRoot, uid: process.geteuid!(), evidenceDirs: [], scanner }), error => {
        assert(error instanceof CredentialSecretCorpusError);
        assert.equal(error.corpusFailure?.stage, 'cas_inventory'); assert.equal(error.corpusFailure.errorClass, 'entry_limit_exceeded');
        assert.equal(error.corpusFailure.inventoryEntriesObserved, 1025); assert.equal(error.corpusFailure.filesScanned, 2);
        assert.equal(error.corpusFailure.sqliteDatabasesScanned, 2); assert.equal(error.corpusFailure.logicalRowsScanned, 2);
        assert.equal(error.corpusFailure.evidenceDirectoriesScanned, 0); assert(!JSON.stringify(error).includes(stateRoot));
        assert.equal(Object.hasOwn(error, 'cause'), false); return true;
      });
      assert.equal(scanner.stats().matched, false); assert.equal(scanner.stats().limitExceeded, false);
    } finally { scanner.close(); }
  });
});

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
