// Data-reading implementation for the fixed guest program. A caller-owned
// directory handle is I/O capability, never a Run, permission or native proof.
import { constants, type BigIntStats, type OpenDirOptions } from 'node:fs';
import { lstat, open, opendir, type FileHandle } from 'node:fs/promises';
import { READ_MAX_BYTES, LIST_MAX_ENTRIES, FIND_MAX_DEPTH, FIND_MAX_RESULTS,
  GREP_MAX_FILE_BYTES, GREP_MAX_MATCHES } from '../config.js';
import { builtinReadOutputBytes, clipBuiltinText, type BuiltinReadOutput, type BuiltinReadReason, type BuiltinToolInput } from './builtin-tool-data.js';

export class BuiltinToolReadError extends Error {
  constructor(readonly code: 'PATH_FORBIDDEN' | 'PATH_UNAVAILABLE' | 'ENTRY_CHANGED' | 'UNSUPPORTED_ENTRY' |
    'FILE_TOO_LARGE' | 'INVALID_TEXT' | 'RESOURCE_RETIREMENT_FAILED') { super(code); this.name = 'BuiltinToolReadError'; }
}
const fields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
const same = (a: BigIntStats, b: BigIntStats) => fields.every(key => a[key] === b[key]);
const alias = (fd: number) => `/proc/self/fd/${fd}`;
const ordered = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const maximumEntries = 100_000;
function denied(): never { throw new BuiltinToolReadError('PATH_FORBIDDEN'); }
function parts(value: string): string[] {
  if (value === '.') return [];
  if (!value || value.startsWith('/') || value.includes('\\') || value.includes('\0') || value.normalize('NFC') !== value) denied();
  const result = value.split('/');
  if (result.some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255)) denied();
  return result;
}
async function current(handle: FileHandle, before: BigIntStats, named?: string): Promise<void> {
  if (!same(before, await handle.stat({ bigint: true })) || named && !same(before, await lstat(named, { bigint: true })))
    throw new BuiltinToolReadError('ENTRY_CHANGED');
}
async function joined(handles: FileHandle[], primary: { error: unknown } | undefined): Promise<void> {
  const outcomes = await Promise.allSettled(handles.reverse().map(handle => handle.close()));
  const failures = outcomes.filter((value): value is PromiseRejectedResult => value.status === 'rejected');
  if (failures.length) throw new BuiltinToolReadError('RESOURCE_RETIREMENT_FAILED');
  if (primary) throw primary.error;
}
async function atChild<T>(parent: FileHandle, parentBefore: BigIntStats, name: string,
  action: (handle: FileHandle, before: BigIntStats) => Promise<T>): Promise<T> {
  const named = `${alias(parent.fd)}/${name}`, before = await lstat(named, { bigint: true });
  if (before.dev !== parentBefore.dev || before.isSymbolicLink() || !before.isDirectory() && !before.isFile()) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
  const child = await open(named, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK |
    (before.isDirectory() ? constants.O_DIRECTORY : 0));
  let failure: { error: unknown } | undefined, result: T | undefined;
  try {
    if (!same(before, await child.stat({ bigint: true }))) throw new BuiltinToolReadError('ENTRY_CHANGED');
    await current(parent, parentBefore); result = await action(child, before);
    await current(child, before, named); await current(parent, parentBefore);
  } catch (error) { failure = { error }; }
  finally { await joined([child], failure); }
  return result!;
}
async function atRoot<T>(root: FileHandle, relative: string, action: (handle: FileHandle, before: BigIntStats) => Promise<T>): Promise<T> {
  const entries = parts(relative), rootBefore = await root.stat({ bigint: true });
  if (!rootBefore.isDirectory()) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
  // Prune the preceding held ancestor after each real identity check. Keeping
  // every path prefix in every recursive call would exceed the original FD
  // budget at legal depth. Only the original root and immediate parent remain.
  let parent = root, parentBefore = rootBefore, owned: FileHandle | undefined;
  let failure: { error: unknown } | undefined, result: T | undefined;
  try {
    for (const component of entries.slice(0, -1)) {
      const named = `${alias(parent.fd)}/${component}`, before = await lstat(named, { bigint: true });
      if (before.dev !== parentBefore.dev || !before.isDirectory() || before.isSymbolicLink()) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
      const next = await open(named, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try { await current(parent, parentBefore); await current(next, before, named); }
      catch (error) { await joined([next], { error }); throw error; }
      const previous = owned; owned = next; parent = next; parentBefore = before;
      if (previous) await joined([previous], undefined);
    }
    result = entries.length ? await atChild(parent, parentBefore, entries.at(-1)!, action) : await action(root, rootBefore);
    await current(root, rootBefore);
  } catch (error) { failure = { error }; }
  finally { await joined(owned ? [owned] : [], failure); }
  return result!;
}
function regular(before: BigIntStats, maximum: number): void {
  if (!before.isFile() || before.nlink !== 1n) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
  if (before.size < 0n || before.size > BigInt(maximum)) throw new BuiltinToolReadError('FILE_TOO_LARGE');
}
async function readLines(handle: FileHandle, before: BigIntStats, value: BuiltinToolInput['input'], maximum: number) {
  regular(before, maximum);
  const start = value.start_line as number | undefined ?? 1;
  const end = value.end_line as number | undefined ?? Math.min(Number.MAX_SAFE_INTEGER, start + 199);
  let line = 1, lineStarted = false, first = 0, last = 0, used = 0, offset = 0, eof = false, truncated = false, stop = false;
  const output: string[] = [], decoder = new TextDecoder('utf-8', { fatal: true }), buffer = Buffer.alloc(65_536);
  const append = (text: string) => {
    const clipped = clipBuiltinText(text, READ_MAX_BYTES - used); output.push(clipped.text); used += Buffer.byteLength(clipped.text);
    if (clipped.truncated) { truncated = true; stop = true; }
  };
  const segment = (text: string, newline: boolean) => {
    if (line >= start && line <= end) {
      if (!lineStarted) { append(`${first ? '\n' : ''}${line}| `); lineStarted = true; first ||= line; last = line; }
      if (!stop) append(text);
    }
    if (newline) { if (line >= end) stop = true; line++; lineStarted = false; }
  };
  try {
    while (!stop) {
      const remaining = Number(before.size) - offset;
      if (remaining === 0) {
        if ((await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead) throw new BuiltinToolReadError('ENTRY_CHANGED');
        eof = true; const tail = decoder.decode(); segment(tail, false); break;
      }
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, remaining), offset); offset += bytesRead;
      if (!bytesRead) throw new BuiltinToolReadError('ENTRY_CHANGED');
      const text = decoder.decode(buffer.subarray(0, bytesRead), { stream: true }); let at = 0, next: number;
      while (!stop && (next = text.indexOf('\n', at)) !== -1) { segment(text.slice(at, next), true); at = next + 1; }
      if (!stop) segment(text.slice(at), false);
    }
  } catch (error) { if (error instanceof TypeError) throw new BuiltinToolReadError('INVALID_TEXT'); throw error; }
  return { startLine: first, endLine: last, fileByteCount: Number(before.size), bytesRead: offset,
    text: output.join(''), truncated, reachedEof: eof };
}
type Scan = { count: number; stopped: boolean; reasons: Set<BuiltinReadReason> };
async function names(handle: FileHandle, before: BigIntStats, scan: Scan): Promise<string[]> {
  if (!before.isDirectory()) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
  // Node supports buffer directory names; its current OpenDirOptions typings
  // omit this runtime value. Check each genuine Dirent before decoding it.
  const directory = await opendir(alias(handle.fd), { encoding: 'buffer' as OpenDirOptions['encoding'], bufferSize: 32 });
  const result: string[] = []; let failure: { error: unknown } | undefined;
  try {
    for (;;) {
      const entry = await directory.read(); if (!entry) break;
      if (++scan.count > maximumEntries) { scan.reasons.add('entry_limit'); scan.stopped = true; break; }
      const raw: unknown = entry.name; if (!Buffer.isBuffer(raw)) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
      let name: string;
      try { name = new TextDecoder('utf-8', { fatal: true }).decode(raw); }
      catch { scan.reasons.add('invalid_utf8'); continue; }
      if (name.toLowerCase() === '.git') continue;
      if (!name || name.includes('/') || name.includes('\\') || name.includes('\0') || name.normalize('NFC') !== name || raw.length > 255) {
        scan.reasons.add('unreadable'); continue;
      }
      result.push(name);
    }
    await current(handle, before);
  } catch (error) { failure = { error }; }
  finally {
    try { await directory.close(); } catch { throw new BuiltinToolReadError('RESOURCE_RETIREMENT_FAILED'); }
  }
  if (failure) throw failure.error;
  return result.sort(ordered);
}
async function smallText(handle: FileHandle, before: BigIntStats, maximum: number): Promise<string> {
  regular(before, maximum); const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (!bytesRead) throw new BuiltinToolReadError('ENTRY_CHANGED'); offset += bytesRead;
  }
  if ((await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead) throw new BuiltinToolReadError('ENTRY_CHANGED');
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new BuiltinToolReadError('INVALID_TEXT'); }
}
export async function readBuiltinTool(root: FileHandle, capsule: BuiltinToolInput): Promise<Buffer> {
  if (capsule.tool === 'bash') throw new TypeError('bash is not a readonly builtin');
  const path = capsule.input.path as string; parts(path);
  const scan: Scan = { count: 0, stopped: false, reasons: new Set() }; let content: unknown;
  if (capsule.tool === 'read') {
    content = await atRoot(root, path, (handle, before) => readLines(handle, before, capsule.input, capsule.limits.maxSingleFileBytes));
    if ((content as { truncated: boolean }).truncated) scan.reasons.add('output_limit');
  } else if (capsule.tool === 'ls') {
    content = await atRoot(root, path, async (handle, before) => {
      const result: Array<{ name: string; kind: string }> = [];
      for (const name of await names(handle, before, scan)) {
        const actual = await lstat(`${alias(handle.fd)}/${name}`, { bigint: true });
        if (actual.dev !== before.dev) { scan.reasons.add('special_file'); continue; }
        if (result.length === LIST_MAX_ENTRIES) { scan.reasons.add('match_limit'); break; }
        result.push({ name, kind: actual.isDirectory() ? 'directory' : actual.isFile() ? 'file' : actual.isSymbolicLink() ? 'symlink' : 'other' });
      }
      return result;
    });
  } else {
    const result: Array<string | { path: string; line: number; text: string }> = [];
    const cap = capsule.tool === 'find' ? FIND_MAX_RESULTS : GREP_MAX_MATCHES;
    const record = (value: typeof result[number]) => { if (result.length === cap) { scan.reasons.add('match_limit'); scan.stopped = true; } else result.push(value); };
    const file = async (handle: FileHandle, before: BigIntStats, relative: string) => {
      let text: string;
      try { text = await smallText(handle, before, Math.min(capsule.limits.maxSingleFileBytes, GREP_MAX_FILE_BYTES)); }
      catch (error) {
        if (error instanceof BuiltinToolReadError && error.code === 'FILE_TOO_LARGE') scan.reasons.add('file_limit');
        else if (error instanceof BuiltinToolReadError && error.code === 'INVALID_TEXT') scan.reasons.add('invalid_utf8');
        else if (error instanceof BuiltinToolReadError && ['ENTRY_CHANGED', 'RESOURCE_RETIREMENT_FAILED'].includes(error.code)) throw error;
        else scan.reasons.add('unreadable'); return;
      }
      for (const [index, line] of text.split('\n').entries()) {
        if (line.includes(capsule.input.pattern as string)) record({ path: relative, line: index + 1, text: line });
        if (scan.stopped) break;
      }
    };
    const visit = async (handle: FileHandle, before: BigIntStats, relative: string, depth: number): Promise<void> => {
      if (scan.stopped) return;
      if (before.isFile() && capsule.tool === 'grep') { await file(handle, before, relative); return; }
      if (!before.isDirectory()) throw new BuiltinToolReadError('UNSUPPORTED_ENTRY');
      for (const name of await names(handle, before, scan)) {
        if (scan.stopped) break;
        const child = relative === '.' ? name : `${relative}/${name}`;
        const stat = await lstat(`${alias(handle.fd)}/${name}`, { bigint: true });
        if (stat.dev !== before.dev) { scan.reasons.add('special_file'); continue; }
        if (capsule.tool === 'find' && name.includes(capsule.input.name as string)) record(child);
        if (scan.stopped) break;
        if (stat.isSymbolicLink()) { scan.reasons.add('symlink'); continue; }
        if (stat.isDirectory()) { if (depth >= FIND_MAX_DEPTH) scan.reasons.add('depth_limit'); else await atChild(handle, before, name, (next, nextBefore) => visit(next, nextBefore, child, depth + 1)); }
        else if (stat.isFile()) {
          if (stat.nlink !== 1n) scan.reasons.add('hardlink'); else if (capsule.tool === 'grep') await atChild(handle, before, name, (next, nextBefore) => file(next, nextBefore, child));
        } else scan.reasons.add('special_file');
      }
    };
    await atRoot(root, path, (handle, before) => visit(handle, before, path, 0)); content = result;
  }
  const output: BuiltinReadOutput = { schemaVersion: 1, tool: capsule.tool, scope: 'private_generation_non_git', path,
    complete: scan.reasons.size === 0, reasons: [...scan.reasons].sort(), scannedEntries: Math.min(scan.count, maximumEntries + 1), content };
  return builtinReadOutputBytes(output, capsule.limits.maxInvocationOutputBytes);
}
