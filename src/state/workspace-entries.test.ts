import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceEntryManifest } from '../kernel/types.js';
import { decodeWorkspaceEntries } from './decoders.js';

function entriesManifest(): WorkspaceEntryManifest {
  const entries: WorkspaceEntryManifest = {
    schemaVersion: 1,
    format: 'cliq-workspace-entries-v1',
    entries: [
      { path: 'a', kind: 'file', mode: 0o644, size: 2, blobRef: 'a'.repeat(64) },
      { path: 'b', kind: 'symlink', mode: 0o777, target: 'a', targetDigest: sha256Bytes(Buffer.from('a')) }
    ],
    entryCount: 2,
    byteCount: 3,
    treeDigest: ''
  };
  entries.treeDigest = canonicalSha256({
    schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: entries.entries
  });
  return entries;
}

test('workspace entry digest covers the RFC tree projection while counts are checked independently', () => {
  const valid = entriesManifest();
  assert.deepEqual(decodeWorkspaceEntries(valid), valid);
  assert.notEqual(valid.treeDigest, digestOmitting(valid, 'treeDigest'));

  assert.throws(() => decodeWorkspaceEntries({ ...valid, entryCount: 3 }), /entry count/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid, byteCount: 4 }), /byte count/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [{ ...valid.entries[0], size: 3 }, valid.entries[1]], byteCount: 4
  }), /digest does not rehash/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [{ ...valid.entries[0], size: Number.MAX_SAFE_INTEGER }, valid.entries[1]],
    byteCount: Number.MAX_SAFE_INTEGER
  }), /safe-integer range/);
});

test('workspace entries reject traversal, Git metadata, noncanonical modes and escaped links', () => {
  const valid = entriesManifest();
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [{ ...valid.entries[0], path: '../a' }, valid.entries[1]]
  }), /invalid path/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [{ ...valid.entries[0], path: '.git/config' }, valid.entries[1]]
  }), /invalid path/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [{ ...valid.entries[0], mode: 0o600 }, valid.entries[1]]
  }), /noncanonical mode/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [valid.entries[0], { ...valid.entries[1], target: '../outside' }]
  }), /leaves the admitted root/);
  assert.throws(() => decodeWorkspaceEntries({ ...valid,
    entries: [valid.entries[0], { ...valid.entries[1], targetDigest: '0'.repeat(64) }]
  }), /target digest does not rehash/);
});

test('workspace entry trees require each preceding parent to be a directory', () => {
  const nested: WorkspaceEntryManifest = {
    schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [
      { path: 'folder', kind: 'directory', mode: 0o755 },
      { path: 'folder/empty', kind: 'directory', mode: 0o755 },
      { path: 'folder/empty/file', kind: 'file', mode: 0o644, size: 2, blobRef: 'a'.repeat(64) }
    ],
    entryCount: 3, byteCount: 2, treeDigest: ''
  };
  nested.treeDigest = canonicalSha256({ schemaVersion: 1, format: nested.format, entries: nested.entries });
  assert.deepEqual(decodeWorkspaceEntries(nested), nested);

  const missing = { ...nested, entries: nested.entries.slice(1), entryCount: 2, treeDigest: '' };
  missing.treeDigest = canonicalSha256({ schemaVersion: 1, format: missing.format, entries: missing.entries });
  assert.throws(() => decodeWorkspaceEntries(missing), /no preceding directory parent/);

  const fileParent = { ...nested, entries: [
    { path: 'folder', kind: 'file', mode: 0o644, size: 0, blobRef: 'a'.repeat(64) } as const,
    ...nested.entries.slice(1)
  ], treeDigest: '' };
  fileParent.treeDigest = canonicalSha256({ schemaVersion: 1, format: fileParent.format, entries: fileParent.entries });
  assert.throws(() => decodeWorkspaceEntries(fileParent), /no preceding directory parent/);
});
