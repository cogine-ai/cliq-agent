import assert from 'node:assert/strict';
import test from 'node:test';
import { parsePatch } from 'diff';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceDiffOperationV1, WorkspaceDiffV1 } from '../kernel/result.js';
import type { WorkspaceEntry } from '../kernel/types.js';
import { renderWorkspaceReview } from './review.js';

// Original bytes and a disposable view only. No Run, native handle, permission
// or publication receipt is created by these presentation fixtures.
function fixture() {
  const objects = new Map<string, Buffer>(), reads: string[] = [];
  const file = (path: string, bytes: string | Buffer, mode = 0o644): Extract<WorkspaceEntry, { kind: 'file' }> => {
    const data = Buffer.from(bytes), blobRef = sha256Bytes(data); objects.set(blobRef, data);
    return { path, kind: 'file', mode, size: data.length, blobRef };
  };
  const read = async (ref: string, options: { maxBytes: number; signal?: AbortSignal }) => {
    options.signal?.throwIfAborted(); reads.push(ref);
    const bytes = objects.get(ref); assert(bytes, 'only original file refs are read'); assert(bytes.length <= options.maxBytes); return bytes;
  };
  const diff = (operations: WorkspaceDiffOperationV1[]): WorkspaceDiffV1 => {
    const core = { schemaVersion: 1 as const, format: 'cliq-workspace-diff-v1' as const,
      baseSourceRef: 'a'.repeat(64), resultSourceRef: 'b'.repeat(64), operations };
    return { ...core, diffDigest: canonicalSha256(core) };
  };
  return { file, read, reads, diff };
}

test('code review shows exact unified changes, CRLF, BOM and a missing final newline from original blobs', async () => {
  const f = fixture(), before = f.file('src/note.ts', '\ufeffsame\r\nold'), after = f.file('src/note.ts', '\ufeffsame\r\nnew');
  const text = await renderWorkspaceReview(f.diff([{ path: before.path, kind: 'modify', before, after }]), f.read);
  assert.match(text, /1 changed path\n/u);
  assert.match(text, /--- a\/src\/note.ts\n\+\+\+ b\/src\/note.ts\n/u);
  assert.match(text, / \ufeffsame\r\n-old\n\\ No newline at end of file\n\+new\n\\ No newline at end of file/u);
  assert.deepEqual(f.reads, [before.blobRef, after.blobRef]);
  assert.doesNotMatch(text, /REVIEW INCOMPLETE/u);
});

test('review covers additions, deletions, symlink/type changes and mode-only changes without opening host paths', async () => {
  const f = fixture(), old = f.file('deleted', 'old\n'), added = f.file('new', 'new\n'), mode = f.file('script', 'same\n');
  const symlink: WorkspaceEntry = { path: 'link', kind: 'symlink', mode: 0o777, target: 'new', targetDigest: sha256Bytes(Buffer.from('new')) };
  const replaced = f.file('link', 'old-link-file\n');
  const text = await renderWorkspaceReview(f.diff([
    { path: 'deleted', kind: 'delete', before: old }, { path: 'link', kind: 'modify', before: replaced, after: symlink },
    { path: 'new', kind: 'add', after: added }, { path: 'script', kind: 'modify', before: mode, after: { ...mode, mode: 0o755 } }
  ]), f.read);
  assert.match(text, /DELETE "deleted"[\s\S]*-old/u); assert.match(text, /ADD "new"[\s\S]*\+new/u);
  assert.match(text, /symlink → "new"/u); assert.match(text, /-old-link-file/u);
  assert.match(text, /MODIFY "script"[\s\S]*mode 644[\s\S]*mode 755/u);
  assert.equal(f.reads.includes(mode.blobRef), false, 'mode-only changes do not need another content read');
});

test('unusual filenames roundtrip through mature patch-header quoting without injecting header lines', async () => {
  for (const path of ['name\twith-tab', 'name\n+++ injected', 'name"quoted', 'name\\backslash']) {
    const f = fixture(), before = f.file(path, 'old\n'), after = f.file(path, 'new\n');
    const text = await renderWorkspaceReview(f.diff([{ path, kind: 'modify', before, after }]), f.read);
    const patch = parsePatch(text);
    assert.equal(patch.length, 1); assert.equal(patch[0]!.oldFileName, `a/${path}`); assert.equal(patch[0]!.newFileName, `b/${path}`);
    assert.equal(text.split('\n').filter(line => line.startsWith('+++ ')).length, 1);
    assert.equal(text.split('\n').filter(line => line.startsWith('--- ')).length, 1);
  }
});

test('binary, invalid UTF-8 and oversized content are explicitly omitted with original blob refs', async () => {
  const f = fixture(), entries = [f.file('binary', Buffer.from([0, 1])), f.file('invalid', Buffer.from([255])),
    f.file('large', Buffer.alloc(131_073, 97))];
  const text = await renderWorkspaceReview(f.diff(entries.map(after => ({ path: after.path, kind: 'add' as const, after }))), f.read);
  assert.match(text, /REVIEW INCOMPLETE: 3 paths/u);
  for (const entry of entries) assert(text.includes(entry.blobRef));
  assert.equal(f.reads.includes(entries[2]!.blobRef), false, 'large data is not read merely to produce a bounded preview');
});

test('a failed or substituted original blob is a failed review, never a binary omission', async () => {
  const f = fixture(), entry = f.file('note', 'original');
  const diff = f.diff([{ path: entry.path, kind: 'add', after: entry }]), failure = new Error('original read failed');
  await assert.rejects(renderWorkspaceReview(diff, async () => { throw failure; }), error => error === failure);
  await assert.rejects(renderWorkspaceReview(diff, async () => Buffer.from('wrong')), /original entry size/u);
});

test('cancelled review joins its original blob read and never starts the next read', async () => {
  const f = fixture(), before = f.file('note', 'before'), after = f.file('note', 'after'), abort = new AbortController();
  let readJoined = false;
  await assert.rejects(renderWorkspaceReview(f.diff([{ path: 'note', kind: 'modify', before, after }]), async (ref, options) => {
    const bytes = await f.read(ref, options); abort.abort(); readJoined = true; return bytes;
  }, abort.signal), { name: 'AbortError' });
  assert.equal(readJoined, true); assert.deepEqual(f.reads, [before.blobRef]);
});

test('expensive text changes remain explicitly incomplete rather than blocking review without a bound', async () => {
  const f = fixture(), before = f.file('large-change', 'old\n'.repeat(2200)), after = f.file('large-change', 'new\n'.repeat(2200));
  const text = await renderWorkspaceReview(f.diff([{ path: before.path, kind: 'modify', before, after }]), f.read);
  assert.match(text, /Content diff omitted/u); assert.match(text, /REVIEW INCOMPLETE/u);
  assert(text.includes(before.blobRef) && text.includes(after.blobRef));
});
