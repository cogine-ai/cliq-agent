import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, type TestContext } from 'node:test';
import ts from 'typescript';
import { sha256Bytes } from '../kernel/identity.js';
import type { NativeSourceGitOutputReader } from '../sandbox/linux-worker.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { publishInstalledSourceGitResult } from './source-git-result.js';

type Stream = (reader: NativeSourceGitOutputReader, closed: Set<NativeSourceGitOutputReader>, ceiling: number,
  signal?: AbortSignal) => AsyncGenerator<Buffer>;
async function actualReaderAdapter(): Promise<Stream> {
  const filename = fileURLToPath(new URL('./source-git-result.ts', import.meta.url)), text = await readFile(filename, 'utf8');
  const source = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const names = ['mismatch', 'closeReader', 'sourceGitStream'];
  const declarations = source.statements.filter(statement => ts.isFunctionDeclaration(statement) &&
    statement.name && names.includes(statement.name.text));
  assert.equal(declarations.length, 3);
  const code = ts.transpileModule(declarations.map(node => node.getText(source)).join('\n'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText;
  // Actual private adapter body, exercised only with owned real file readers.
  // No wrapper brand is bypassed and no native/Run proof is manufactured.
  return new Function('createHash', 'KernelStorageError', 'ResourceRetirementError', `${code}; return sourceGitStream;`)(
    createHash, KernelStorageError, ResourceRetirementError) as Stream;
}
async function fileReader(t: TestContext, closeFailure?: ResourceRetirementError) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-output-reader-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'files'), { mode: 0o700 });
  const bytes = Buffer.alloc(65_536 * 2 + 11, 0x47), file = path.join(directory, 'files', 'own-output');
  await writeFile(file, bytes, { mode: 0o600 });
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW); let calls = 0, closes = 0;
  const reader: NativeSourceGitOutputReader = Object.freeze({ identity: Object.freeze({ sha256: sha256Bytes(bytes), byteCount: bytes.length }),
    assertHeld() { fstatSync(fd); }, readChunk() {
      calls++; const buffer = Buffer.alloc(65_536), count = readSync(fd, buffer, 0, buffer.length, null);
      return count ? buffer.subarray(0, count) : undefined;
    }, close() { closes++; closeSync(fd); if (closeFailure) throw closeFailure; } });
  return { bytes, reader, counts: () => ({ calls, closes }), assertJoined: () => assert.throws(() => fstatSync(fd), { code: 'EBADF' }) };
}

test('genuine source result is required before any caller getter, identity or output stream is observed', async () => {
  let calls = 0;
  const value = new Proxy({}, { get() { calls++; throw new Error('private value must remain unobserved'); },
    ownKeys() { calls++; throw new Error('private keys must remain unobserved'); } });
  await assert.rejects(publishInstalledSourceGitResult(value as never, value as never, value as never, value as never), TypeError);
  assert.equal(calls, 0);
});

test('actual private output reader adapter exhausts every byte and EOF then really closes its owned FD', async t => {
  const stream = await actualReaderAdapter(), f = await fileReader(t), closed = new Set<NativeSourceGitOutputReader>(), chunks: Buffer[] = [];
  for await (const bytes of stream(f.reader, closed, f.bytes.length)) chunks.push(bytes);
  assert.deepEqual(Buffer.concat(chunks), f.bytes); assert.deepEqual(f.counts(), { calls: 4, closes: 1 });
  assert(closed.has(f.reader)); f.assertJoined();
});

test('an early return or original cancellation still executes the actual reader finally and preserves its original reason', async t => {
  const stream = await actualReaderAdapter();
  const early = await fileReader(t), iterator = stream(early.reader, new Set(), early.bytes.length);
  try { assert.equal((await iterator.next()).done, false); }
  finally { await iterator.return(undefined); }
  assert.deepEqual(early.counts(), { calls: 1, closes: 1 }); early.assertJoined();
  const aborted = await fileReader(t), abort = new AbortController(), reason = new Error('own source read cancellation');
  const pending = stream(aborted.reader, new Set(), aborted.bytes.length, abort.signal);
  try {
    assert.equal((await pending.next()).done, false); abort.abort(reason);
    await assert.rejects(pending.next(), error => error === reason);
  } finally { await pending.return(undefined); }
  aborted.assertJoined(); assert.equal(aborted.counts().closes, 1);
});

test('bounded identity/hash rejection still closes, and a real late-close retirement failure dominates cancellation', async t => {
  const stream = await actualReaderAdapter(), bounded = await fileReader(t);
  await assert.rejects(async () => { for await (const _ of stream(bounded.reader, new Set(), bounded.bytes.length - 1)) {} },
    { code: 'ARTIFACT_MISMATCH' });
  bounded.assertJoined(); assert.equal(bounded.counts().calls, 0);
  const mismatch = await fileReader(t), wrong = Object.freeze({ ...mismatch.reader,
    identity: { ...mismatch.reader.identity, sha256: '0'.repeat(64) } });
  await assert.rejects(async () => { for await (const _ of stream(wrong, new Set(), mismatch.bytes.length)) {} }, { code: 'ARTIFACT_MISMATCH' });
  mismatch.assertJoined(); assert.equal(mismatch.counts().calls, 4);
  const closeFailure = new ResourceRetirementError('actual private reader late close failed', new Error('own close cause'));
  const f = await fileReader(t, closeFailure), abort = new AbortController(), reason = new Error('own source read cancellation');
  const pending = stream(f.reader, new Set(), f.bytes.length, abort.signal);
  try {
    await pending.next(); abort.abort(reason);
    await assert.rejects(pending.next(), error => error === closeFailure);
  } finally { await pending.return(undefined); }
  f.assertJoined(); assert.equal(f.counts().closes, 1);
});
