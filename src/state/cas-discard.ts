import type { Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { Worker } from 'node:worker_threads';

// Discard-only readers share four slots across all catalogs. Retaining streams
// never lend their buffers here. A slot lasts through the caller's FD closes.
let active = 0;
type Waiter = { signal?: AbortSignal; ready(): void; abort(): void };
const waiting: Waiter[] = [];
function dispatch(): void {
  while (active < 4 && waiting.length) {
    const next = waiting.shift()!;
    next.signal?.removeEventListener('abort', next.abort);
    if (next.signal?.aborted) { next.abort(); continue; }
    active++; next.ready();
  }
}
export async function withCasDiscardSlot<T>(signal: AbortSignal | undefined, operation: () => Promise<T>): Promise<T> {
  await new Promise<void>((resolve, reject) => {
    signal?.throwIfAborted();
    const waiter: Waiter = { signal, ready: resolve, abort() {
      const index = waiting.indexOf(waiter); if (index >= 0) waiting.splice(index, 1);
      reject(signal!.reason);
    } };
    waiting.push(waiter); signal?.addEventListener('abort', waiter.abort, { once: true }); dispatch();
  });
  try { signal?.throwIfAborted(); return await operation(); }
  finally { active--; dispatch(); }
}

// Fixed trusted code, no retained pool or FD. The same 64 KiB read, hash and
// root-path check run together off the event loop; each operation rereads all
// bytes. This is data verification, not a worker launch or execution authority.
const CAS_DISCARD_SOURCE = String.raw`
const {parentPort,workerData:d}=require('node:worker_threads');
const {fstatSync,lstatSync,readSync}=require('node:fs');
const {createHash}=require('node:crypto');
const stop=new Int32Array(d.control,0,1), bytes=new BigInt64Array(d.control,8,1);
const cancel=()=>{if(Atomics.load(stop,0))throw 'cancelled';};
const file=info=>{
  if(!info.isFile()||info.uid!==d.uid||(info.mode&0o7777)!==0o400||info.nlink!==1||info.size!==d.byteLength)throw 'file';
};
const root=()=>{
  const info=lstatSync(d.rootPath);
  if(!info.isDirectory()||info.isSymbolicLink()||info.uid!==d.uid||(info.mode&0o7777)!==0o700)throw 'root';
  if(info.dev!==d.rootDev||info.ino!==d.rootIno)throw 'root';
};
try {
  cancel(); const before=fstatSync(d.fd); file(before);
  const fields=['dev','ino','size','uid','gid','mode','nlink','mtimeMs','ctimeMs'];
  if(!fields.every(key=>before[key]===d.before[key]))throw 'file';
  const scratch=Buffer.allocUnsafe(65536), hash=createHash('sha256'); let offset=0;
  while(offset<d.byteLength){
    cancel(); const count=readSync(d.fd,scratch,0,Math.min(scratch.length,d.byteLength-offset),offset);
    Atomics.add(bytes,0,BigInt(count)); cancel(); if(!count)throw 'short';
    hash.update(scratch.subarray(0,count)); offset+=count;
    root(); cancel();
  }
  cancel(); const after=fstatSync(d.fd); cancel(); file(after);
  if(!fields.every(key=>before[key]===after[key]))throw 'file';
  if(hash.digest('hex')!==d.ref)throw 'digest';
  root(); cancel(); parentPort.postMessage('ok');
} catch(error){
  parentPort.postMessage(['cancelled','file','root','short','digest'].includes(error)?error:'read');
} finally {parentPort.close();}
`;

/** Borrow actual open descriptors only until the returned promise settles.
 * Both a reply and the real Worker exit are required. Cancellation sets a flag;
 * it never declares an outstanding OS read or thread joined by timeout. */
export async function discardCasChunks(input: {
  file: { handle: FileHandle; info: Stats }; rootPath: string; rootInfo: Stats;
  ref: string; byteLength: number;
}, signal: AbortSignal | undefined, noteRead: (bytes: number) => void): Promise<void> {
  signal?.throwIfAborted();
  const control = new SharedArrayBuffer(16), stop = new Int32Array(control, 0, 1), bytes = new BigInt64Array(control, 8, 1);
  const abort = () => { Atomics.store(stop, 0, 1); };
  const before = Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeMs', 'ctimeMs']
    .map(key => [key, input.file.info[key as keyof Stats]]));
  signal?.addEventListener('abort', abort, { once: true });
  try {
    signal?.throwIfAborted();
    const worker = new Worker(CAS_DISCARD_SOURCE, { eval: true, execArgv: [], env: {}, argv: [],
      resourceLimits: { maxOldGenerationSizeMb: 16, maxYoungGenerationSizeMb: 4, codeRangeSizeMb: 2, stackSizeMb: 1 },
      workerData: { control, before, fd: input.file.handle.fd, uid: input.file.info.uid,
        rootPath: input.rootPath, rootDev: input.rootInfo.dev, rootIno: input.rootInfo.ino,
        ref: input.ref, byteLength: input.byteLength } });
    let reply: unknown, received = false, failed = false;
    await new Promise<void>(resolve => {
      worker.on('message', value => { if (received) failed = true; received = true; reply = value; });
      worker.on('error', () => { failed = true; });
      worker.once('exit', code => { if (code !== 0) failed = true; resolve(); });
    });
    noteRead(Number(Atomics.load(bytes, 0)));
    if (failed || !received || !['ok', 'cancelled', 'file', 'root', 'short', 'digest', 'read'].includes(reply as string))
      throw new Error('CAS discard reader failed before its verified exit');
    if (reply !== 'ok' && reply !== 'cancelled') throw new Error(`CAS discard verification failed: ${reply}`);
    signal?.throwIfAborted();
    if (reply !== 'ok') throw new Error('CAS discard reader cancelled without its original signal');
  } finally { signal?.removeEventListener('abort', abort); }
}
