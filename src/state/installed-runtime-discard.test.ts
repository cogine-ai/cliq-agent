import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants, fstatSync, lstatSync, type BigIntStats } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, writeFile, type FileHandle } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { isMainThread, Worker } from 'node:worker_threads';
import ts from 'typescript';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';

type File = { handle: FileHandle; info: BigIntStats; digest?: string };
type Reader = { root(path: string): Promise<unknown>; file(root: unknown, path: string, mode: number,
  size: number, digest: string): Promise<File>; verifyDiscard(files: File[], signal?: AbortSignal): Promise<void>; close(): Promise<void> };

/** Original private FS/Worker implementation, extracted only for real resource
 * regression. This creates no selected installation, StateOwner or Run. */
async function discardFixture() {
  const source = await readFile(new URL('./installed-runtime.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('original-discard.ts', source, ts.ScriptTarget.Latest, true);
  const required = new Set(['CHUNK_BYTES', 'retirementFailure', 'mismatch', 'healthy', 'supportedPlatform', 'rememberRetirement',
    'effectiveUid', 'childPath', 'sameDirectory', 'sameFile', 'checkDirectory', 'checkFile', 'Scope', 'assertFile',
    'discardBusy', 'discardWaits', 'grantDiscard', 'discardPermit', 'INSTALLED_HASH_WORKER_SOURCE', 'hashWorkerFailure',
    'throwHashFailure', 'hashJobId', 'DiscardPool', 'discardPool', 'retireDiscardPoolLocked', 'retireDiscardPool',
    'verifyDiscardFiles', 'verifyBytes', 'verifyBytesPipeline']);
  const declarations: string[] = [];
  for (const node of parsed.statements) {
    const names = ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) ? [node.name?.text] : ts.isVariableStatement(node)
      ? node.declarationList.declarations.flatMap(value => ts.isIdentifier(value.name) ? [value.name.text] : []) : [];
    if (names.some(name => name !== undefined && required.has(name))) {
      declarations.push(node.getText(parsed)); for (const name of names) if (name) required.delete(name);
    }
  }
  assert.equal(required.size, 0, 'exercise the complete original resource implementation');
  const workers: Worker[] = [], exited = new Set<Worker>(); let actualBytes = 0;
  class ObservedWorker extends Worker {
    constructor(...args: ConstructorParameters<typeof Worker>) {
      super(...args); workers.push(this); this.once('exit', () => exited.add(this));
    }
  }
  const code = ts.transpileModule(declarations.join('\n'),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const factory = new Function('createHash', 'constants', 'fstatSync', 'lstatSync', 'lstat', 'mkdir', 'open', 'readdir',
    'isMainThread', 'Worker', 'normalizeAbsolutePath', 'joinResourceOperations', 'KernelStorageError', 'ResourceRetirementError',
    'noteInstalledWorkRead', `${code}\nreturn { Scope, verifyBytes };`) as (...args: unknown[]) => {
      Scope: new () => Reader; verifyBytes(file: File, signal?: AbortSignal): Promise<void> };
  const implementation = factory(createHash, constants, fstatSync, lstatSync, lstat, mkdir, open, readdir, isMainThread,
    ObservedWorker, normalizeAbsolutePath, joinResourceOperations, KernelStorageError, ResourceRetirementError,
    (count: number) => { actualBytes += count; });
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-idle-discard-'))), scope = new implementation.Scope();
  const root = await scope.root(directory), files: File[] = [];
  try {
    for (let i = 0; i < 5; i++) {
      const bytes = Buffer.alloc(i < 4 ? 8_388_625 : 17, i + 1), name = String(i);
      await writeFile(path.join(directory, name), bytes, { mode: 0o400, flag: 'wx' });
      files.push(await scope.file(root, name, 0o400, bytes.length, createHash('sha256').update(bytes).digest('hex')));
    }
  } catch (error) { await scope.close(); await rm(directory, { recursive: true, force: true }); throw error; }
  return { ...implementation, scope, files, fds: files.map(file => file.handle.fd), workers, exited, bytes: () => actualBytes,
    async close() { try { await scope.close(); } finally { await rm(directory, { recursive: true, force: true }); } } };
}

if (process.platform === 'linux') test('idle discard pool owns standalone and single-file batches within its original scratch, with full repeated reads', async () => {
  const f = await discardFixture();
  try {
    await f.verifyBytes(f.files[4]!);
    assert.equal(f.workers.length, 0, 'a small read alone never starts Workers');
    const before = f.bytes(), batchBytes = f.files.reduce((sum, file) => sum + Number(file.info.size), 0);
    for (let round = 0; round < 16; round++) {
      await f.scope.verifyDiscard(f.files);
      await f.verifyBytes(f.files[4]!);
      await f.scope.verifyDiscard([f.files[4]!]);
      assert.equal(f.workers.length, 4, 'only the original four scratch lanes survive successful jobs');
      assert.equal(f.exited.size, 0);
      assert.equal(f.bytes() - before, (round + 1) * (batchBytes + 34), 'every byte is read again on every call');
    }
    await f.scope.close(); assert.equal(f.exited.size, 4);
    for (const fd of f.fds) assert.throws(() => fstatSync(fd), { code: 'EBADF' });
  } finally { await f.close(); }
});

for (const kind of ['standalone', 'single_batch'] as const) {
  for (const fault of ['digest', 'short', 'long', 'cancel', 'idle_exit'] as const) {
    if (process.platform === 'linux') test(`${kind} on an idle pool joins real reads and every Worker after ${fault}`, async () => {
      const f = await discardFixture();
      const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
      const abort = new AbortController(), reason = new Error('the original small read was cancelled');
      let armed = false, intercepted = false;
      try {
        await f.scope.verifyDiscard(f.files);
        const small = f.files[4]!;
        if (fault === 'digest') small.digest = '0'.repeat(64);
        if (fault === 'idle_exit') await f.workers[0]!.terminate();
        Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
          const packet = args[0] as { fd?: number; byteCount?: number } | undefined;
          if (armed && packet?.fd === small.handle.fd && !intercepted) {
            intercepted = true;
            // Negative wire mutation only: the real child must independently
            // detect EOF/short reads. No successful observation is fabricated.
            if (fault === 'short') packet.byteCount!++;
            if (fault === 'long') packet.byteCount!--;
            if (fault === 'cancel') queueMicrotask(() => abort.abort(reason));
          }
          return Reflect.apply(descriptor.value, this, args);
        } });
        armed = true;
        const pending = kind === 'standalone' ? f.verifyBytes(small, abort.signal) : f.scope.verifyDiscard([small], abort.signal);
        if (fault === 'cancel') await assert.rejects(pending, error => error === reason);
        else await assert.rejects(pending, { code: 'ARTIFACT_MISMATCH' });
        if (fault !== 'idle_exit') assert.equal(intercepted, true);
        assert.equal(f.workers.length, 4, 'failed or cancelled work never silently starts replacement threads');
        assert.equal(f.exited.size, 4, 'rejection follows actual exit of every original Worker');
        assert(f.files.every(file => fstatSync(file.handle.fd).isFile()), 'owner FDs stay valid through every join');
        await f.scope.close();
        for (const fd of f.fds) assert.throws(() => fstatSync(fd), { code: 'EBADF' });
      } finally {
        armed = false; Object.defineProperty(Worker.prototype, 'postMessage', descriptor); await f.close();
      }
    });
  }
  if (process.platform === 'linux') test(`${kind} accepted before Scope.close joins actual reads and threads before original FD retirement`, async () => {
    const f = await discardFixture();
    try {
      await f.scope.verifyDiscard(f.files);
      const small = f.files[4]!, pending = kind === 'standalone' ? f.verifyBytes(small) : f.scope.verifyDiscard([small]);
      const closing = f.scope.close(); await joinResourceOperations([pending, closing]);
      assert.equal(f.workers.length, 4); assert.equal(f.exited.size, 4);
      for (const fd of f.fds) assert.throws(() => fstatSync(fd), { code: 'EBADF' });
    } finally { await f.close(); }
  });
}

for (const kind of ['standalone', 'single_batch'] as const) {
  if (process.platform === 'linux') test(`${kind} preserves a real joined retirement failure over the original hash refusal`, async () => {
    const f = await discardFixture(), descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
    const failure = new ResourceRetirementError('the actual close was reported uncertain', new Error('negative close report'));
    let injected = false;
    try {
      await f.scope.verifyDiscard(f.files);
      Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
        const packet = args[0] as { kind?: string } | undefined;
        const result = Reflect.apply(descriptor.value, this, args);
        // The real close message is already sent; every Worker still actually
        // exits. Only its negative report is injected, never a cleanup receipt.
        if (!injected && packet?.kind === 'close') { injected = true; throw failure; }
        return result;
      } });
      const small = f.files[4]!; small.digest = '0'.repeat(64);
      const pending = kind === 'standalone' ? f.verifyBytes(small) : f.scope.verifyDiscard([small]);
      await assert.rejects(pending, error => error === failure);
      assert.equal(injected, true); assert.equal(f.workers.length, 4); assert.equal(f.exited.size, 4);
    } finally { Object.defineProperty(Worker.prototype, 'postMessage', descriptor); await f.close(); }
  });
}
