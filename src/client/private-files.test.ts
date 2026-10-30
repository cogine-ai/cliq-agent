import assert from 'node:assert/strict';
import { fstatSync } from 'node:fs';
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ResourceRetirementError } from '../state/errors.js';
import { openPrivateClientDirectory } from './private-files.js';

const linux = process.platform === 'linux';
async function fixture() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-private-client-'));
  const root = path.join(home, '.cliq', 'client-v1');
  const directory = await openPrivateClientDirectory(root, { create: true });
  return { home, root, directory, async close() { try { await directory.close(); } finally { await rm(home, { recursive: true, force: true }); } } };
}

test('private client files explicitly refuse a platform without descriptor-relative child operations', { skip: linux }, async () => {
  await assert.rejects(openPrivateClientDirectory('/tmp/unused-cliq-client'), /requires Linux descriptor-relative/u);
});

test('actual private files publish once, replace preferences atomically, and close child descriptors without closing the root', { skip: !linux }, async () => {
  const f = await fixture();
  try {
    assert.equal(await f.directory.read('preferences.json', 65536), undefined);
    await f.directory.replace('preferences.json', Buffer.from('first'));
    await f.directory.replace('preferences.json', Buffer.from('second'));
    assert.equal((await f.directory.read('preferences.json', 65536))?.toString(), 'second');
    const [one, two] = await Promise.all([f.directory.publish('original.json', Buffer.from('original')),
      f.directory.publish('original.json', Buffer.from('replacement'))]);
    assert.deepEqual([one, two], ['created', 'existing']);
    assert.equal((await f.directory.read('original.json', 65536))?.toString(), 'original');
    const info = await lstat(path.join(f.root, 'original.json'));
    assert.equal(info.mode & 0o7777, 0o600); assert.equal(info.nlink, 1);
    const group = await f.directory.createDirectory('group'); assert.equal(group.created, true);
    await group.directory.publish('data.json', Buffer.from('owned child'));
    await group.directory.close();
    await assert.rejects(group.directory.read('data.json', 100), /closed/u);
    const reloaded = await f.directory.directory('group');
    assert.equal((await reloaded.read('data.json', 100))?.toString(), 'owned child'); await reloaded.close();
    assert.equal((await f.directory.read('preferences.json', 65536))?.toString(), 'second');
    assert.deepEqual(await readdir(f.root), ['group', 'original.json', 'preferences.json']);
  } finally { await f.close(); }
});

test('actual files reject symlinks, shared inodes, loose modes and oversized input without following or replacing them', { skip: !linux }, async () => {
  const f = await fixture(), outside = path.join(f.home, 'outside');
  try {
    await writeFile(outside, 'outside', { mode: 0o600 });
    await symlink(outside, path.join(f.root, 'link.json'));
    await assert.rejects(f.directory.read('link.json', 100));
    await assert.rejects(f.directory.replace('link.json', Buffer.from('changed')));
    assert.equal(await readFile(outside, 'utf8'), 'outside');
    await f.directory.publish('owned.json', Buffer.from('same inode'));
    await link(path.join(f.root, 'owned.json'), path.join(f.root, 'alias.json'));
    await assert.rejects(f.directory.read('owned.json', 100));
    await assert.rejects(f.directory.replace('alias.json', Buffer.from('changed')));
    await f.directory.publish('mode.json', Buffer.from('private'));
    await chmod(path.join(f.root, 'mode.json'), 0o640); await assert.rejects(f.directory.read('mode.json', 100));
    assert.throws(() => f.directory.read('../outside', 100));
    assert.throws(() => f.directory.read('mode.json', 1024 * 1024 + 1));
    assert.throws(() => f.directory.publish('large.json', Buffer.alloc(1024 * 1024 + 1)));
    assert(!((await f.directory.names()).some(value => value.startsWith('.write-'))));
  } finally { await f.close(); }
});

test('a moved or replaced actual private directory stops reads and writes before using its replacement', { skip: !linux }, async () => {
  const f = await fixture(), old = f.root + '-old';
  try {
    await f.directory.publish('original.json', Buffer.from('original'));
    await rename(f.root, old); await mkdir(f.root, { mode: 0o700 });
    await assert.rejects(f.directory.read('original.json', 100), /identity changed/u);
    await assert.rejects(f.directory.replace('new.json', Buffer.from('no write')), /identity changed/u);
    assert.deepEqual(await readdir(f.root), []);
    assert.equal(await readFile(path.join(old, 'original.json'), 'utf8'), 'original');
  } finally { await f.close(); }
});

test('actual descriptor EOF/identity checks reject a file changed during its original read', { skip: !linux }, async () => {
  const f = await fixture(); let prototype: any, original: any;
  try {
    await f.directory.publish('data.json', Buffer.from('original'));
    const filename = path.join(f.root, 'data.json'), info = await lstat(filename, { bigint: true });
    const sample = await open(filename); prototype = Object.getPrototypeOf(sample); original = prototype.read; await sample.close();
    let changed = false;
    prototype.read = async function(...args: any[]) {
      const selected = fstatSync(this.fd, { bigint: true }).ino === info.ino;
      const result = await original.apply(this, args);
      if (selected && !changed) { changed = true; await writeFile(filename, 'longer changed content'); }
      return result;
    };
    await assert.rejects(f.directory.read('data.json', 100), /exceeds its declared size|changed while reading/u);
    assert.equal(changed, true);
  } finally { if (prototype) prototype.read = original; await f.close(); }
});

test('closing joins the actual accepted file read and rejects later work', { skip: !linux }, async () => {
  const f = await fixture(); let prototype: any, original: any, reading: Promise<unknown> | undefined;
  let enter!: () => void, release!: () => void;
  const entered = new Promise<void>(resolve => { enter = resolve; }), released = new Promise<void>(resolve => { release = resolve; });
  try {
    await f.directory.publish('data.json', Buffer.from('original'));
    const info = await lstat(path.join(f.root, 'data.json'), { bigint: true }), sample = await open(path.join(f.root, 'data.json'));
    prototype = Object.getPrototypeOf(sample); original = prototype.read; await sample.close();
    let held = false;
    prototype.read = async function(...args: any[]) {
      if (!held && fstatSync(this.fd, { bigint: true }).ino === info.ino) { held = true; enter(); await released; }
      return original.apply(this, args);
    };
    reading = f.directory.read('data.json', 100); await entered;
    let closed = false; const closing = f.directory.close().then(() => { closed = true; });
    await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(closed, false);
    await assert.rejects(f.directory.read('data.json', 100), /closed/u);
    release(); assert.equal((await reading as Buffer).toString(), 'original'); await closing; assert.equal(closed, true);
  } finally { release(); await reading?.catch(() => {}); if (prototype) prototype.read = original; await f.close(); }
});

test('original descriptor close failure outranks an ordinary read failure and is never retried', { skip: !linux }, async () => {
  const f = await fixture(); let prototype: any, originalRead: any, closes = 0;
  try {
    await f.directory.publish('data.json', Buffer.from('original'));
    const filename = path.join(f.root, 'data.json'), info = await lstat(filename, { bigint: true }), sample = await open(filename);
    prototype = Object.getPrototypeOf(sample); originalRead = prototype.read; await sample.close();
    prototype.read = async function(...args: any[]) {
      if (fstatSync(this.fd, { bigint: true }).ino === info.ino) {
        const close = this.close;
        this.close = async () => { await close.call(this); closes++; throw new Error('injected original actual close result failure'); };
        throw new Error('injected original read failure');
      }
      return originalRead.apply(this, args);
    };
    let failure: unknown;
    await assert.rejects(f.directory.read('data.json', 100), error => { failure = error; return error instanceof ResourceRetirementError; });
    await assert.rejects(f.directory.close(), error => error === failure); assert.equal(closes, 1);
  } finally {
    if (prototype) prototype.read = originalRead;
    await f.directory.close().catch(() => {}); await rm(f.home, { recursive: true, force: true });
  }
});

test('an actual descriptor write failure preserves the old preference and joins temporary cleanup', { skip: !linux }, async () => {
  const f = await fixture(); let prototype: any, original: any;
  try {
    await f.directory.replace('preferences.json', Buffer.from('original'));
    const sample = await open(path.join(f.root, 'preferences.json')); prototype = Object.getPrototypeOf(sample); original = prototype.writeFile; await sample.close();
    const failure = Object.assign(new Error('injected descriptor storage failure'), { code: 'ENOSPC' });
    prototype.writeFile = async function() { throw failure; };
    await assert.rejects(f.directory.replace('preferences.json', Buffer.from('not committed')), error => error === failure);
    prototype.writeFile = original;
    assert.equal((await f.directory.read('preferences.json', 100))?.toString(), 'original');
    assert.deepEqual(await readdir(f.root), ['preferences.json']);
  } finally { if (prototype) prototype.writeFile = original; await f.close(); }
});
