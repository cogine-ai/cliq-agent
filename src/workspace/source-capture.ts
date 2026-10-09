import { setImmediate } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../state/artifacts.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { assertHeldWorkspaceRoot, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from '../state/native-owner.js';

export type SourceCaptureSelection = Readonly<{
  /** Exact policy-resolved leaves/empty directories, never a recursive glob or
   * a permission grant. The caller must establish Trust and read permission. */
  selectedPaths: readonly string[];
  /** Bounds all visited ordinary metadata, including excluded siblings. */
  maxEntries: number;
  maxBytes: number;
  /** Trusted per-file ceiling; checked before opening any selected payload. */
  maxSingleFileBytes?: number;
  signal?: AbortSignal;
}>;

function invalid(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function checkedPath(value: string): string {
  if (typeof value !== 'string' || value !== value.normalize('NFC') || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part => !part || part === '.' || part === '..' ||
        Buffer.byteLength(part) > 255 || part.toLowerCase() === '.git')) invalid('source selection must contain canonical root-relative paths outside .git');
  return value;
}
function checkedLinks(entries: WorkspaceEntry[]): void {
  const paths = new Map(entries.map(entry => [entry.path, entry]));
  for (const entry of entries) {
    if (entry.kind !== 'symlink') continue;
    if (!entry.target || entry.target !== entry.target.normalize('NFC') || entry.target.startsWith('/') ||
        entry.target.includes('\\') || entry.target.includes('\0') || Buffer.byteLength(entry.target) > 4096)
      invalid('selected source symlink must have a bounded relative NFC target');
    const resolved = entry.path.split('/').slice(0, -1);
    const active = new Set([entry.path]);
    const frames = [{ link: entry.path, parts: entry.target.split('/'), index: 0 }];
    let dangling = false;
    while (frames.length) {
      const frame = frames[frames.length - 1];
      if (frame.index === frame.parts.length) { active.delete(frame.link); frames.pop(); continue; }
      const part = frame.parts[frame.index++];
      if (!part || part === '.') continue;
      if (part === '..') {
        if (!resolved.length) invalid('selected source symlink chain escapes the workspace');
        resolved.pop(); continue;
      }
      if (part.toLowerCase() === '.git') invalid('selected source symlink may not reference Git metadata');
      const candidate = dangling ? undefined : paths.get([...resolved, part].join('/'));
      if (candidate?.kind === 'symlink') {
        if (active.has(candidate.path)) invalid('selected source symlink graph contains a cycle');
        active.add(candidate.path); frames.push({ link: candidate.path, parts: candidate.target.split('/'), index: 0 });
        continue;
      }
      if (candidate?.kind === 'file' && frames.some(pending => pending.index < pending.parts.length))
        invalid('selected source symlink traverses a non-directory');
      if (!candidate) dangling = true;
      resolved.push(part);
    }
  }
}
function retire(resources: readonly { close(): void }[], operationError?: unknown): void {
  const failures: unknown[] = [];
  for (const resource of [...resources].reverse()) {
    try { resource.close(); } catch (error) { failures.push(error); }
  }
  if (failures.length) throw new ResourceRetirementError('source capture descriptor retirement did not complete',
    new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
}

/** Capture only an already-resolved selection through native opaque entries.
 * Enumeration is metadata-only; unopened excluded directories are pruned.
 * This publishes physical bytes, not admission/authentication/permission or a
 * claim that a concurrently writable source was atomically snapshotted. */
export async function captureWorkspaceEntries(root: HeldWorkspaceRoot, artifacts: ArtifactCatalog,
  selection: SourceCaptureSelection): Promise<PublishedArtifact> {
  assertHeldWorkspaceRoot(root);
  if (!Array.isArray(selection.selectedPaths) || !Number.isSafeInteger(selection.maxEntries) || selection.maxEntries < 1 ||
      !Number.isSafeInteger(selection.maxBytes) || selection.maxBytes < 0) invalid('source capture requires an explicit bounded selection');
  const { maxEntries, maxBytes, signal } = selection, maxSingleFileBytes = selection.maxSingleFileBytes ?? maxBytes;
  if (!Number.isSafeInteger(maxSingleFileBytes) || maxSingleFileBytes < 0) invalid('source capture file ceiling is invalid');
  const selected = new Set<string>(), needed = new Set<string>(), folded = new Set<string>();
  for (const value of selection.selectedPaths) {
    const path = checkedPath(value);
    if (selected.has(path) || folded.has(path.toLowerCase())) invalid('source selection has duplicate or case-colliding paths');
    selected.add(path); folded.add(path.toLowerCase());
    for (let slash = path.indexOf('/'); slash >= 0; slash = path.indexOf('/', slash + 1)) needed.add(path.slice(0, slash));
  }
  if (new Set([...selected, ...needed]).size > maxEntries) invalid('source selection exceeds the entry limit');
  const cursors: HeldWorkspaceCursor[] = [], heldEntries: HeldWorkspaceEntry[] = [], entries: WorkspaceEntry[] = [];
  const observedPaths = new Set<string>(), observedFolded = new Set<string>();
  let byteCount = 0, inventoryCount = 0, operationError: unknown;
  try {
    signal?.throwIfAborted(); root.assertHeld();
    const top = root.openSnapshot(); cursors.push(top);
    const stack = [{ cursor: top, selectedEmpty: false }];
    while (stack.length) {
      // Even discarded metadata must be cooperative; no excluded-only loop
      // may defer cancellation until publication or its hard inventory limit.
      await setImmediate();
      signal?.throwIfAborted();
      const { cursor, selectedEmpty } = stack[stack.length - 1];
      const entry = cursor.next();
      if (!entry) { cursor.assertComplete(); stack.pop(); continue; }
      if (selectedEmpty) { retire([entry]); invalid('selected empty source directory is not empty'); }
      if (++inventoryCount > maxEntries) {
        retire([entry]); invalid('source metadata inventory exceeds the entry limit');
      }
      if (!selected.has(entry.path) && !needed.has(entry.path)) { retire([entry]); continue; }
      heldEntries.push(entry);
      checkedPath(entry.path);
      if (observedPaths.has(entry.path) || observedFolded.has(entry.path.toLowerCase())) invalid('selected source entries collide');
      observedPaths.add(entry.path); observedFolded.add(entry.path.toLowerCase());
      if (needed.has(entry.path) && entry.kind !== 'directory') invalid('source selection ancestor is not a directory');
      if (entry.kind === 'directory') {
        entries.push({ path: entry.path, kind: 'directory', mode: 0o755 });
        const child = entry.openDirectory(); cursors.push(child);
        stack.push({ cursor: child, selectedEmpty: selected.has(entry.path) && !needed.has(entry.path) });
      } else if (entry.kind === 'file') {
        if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 || entry.byteCount > maxSingleFileBytes || entry.byteCount > maxBytes - byteCount)
          invalid('selected source bytes exceed the capture limit');
        const reader = entry.openFile();
        let readError: unknown;
        try {
          async function* chunks() {
            for (;;) {
              await setImmediate(); signal?.throwIfAborted(); reader.assertHeld();
              const chunk = reader.readChunk();
              if (chunk === null) { reader.assertHeld(); return; }
              yield chunk;
            }
          }
          const blob = await artifacts.publishChunks(chunks(), 'application/octet-stream', 'cliq-workspace-file-v1', entry.byteCount);
          signal?.throwIfAborted(); reader.assertHeld();
          if (blob.byteLength !== entry.byteCount) invalid('selected source file byte count changed');
          byteCount += blob.byteLength;
          entries.push({ path: entry.path, kind: 'file', mode: entry.mode & 0o111 ? 0o755 : 0o644,
            size: blob.byteLength, blobRef: blob.ref });
        } catch (error) { readError = error; throw error; }
        finally { retire([reader], readError); }
      } else if (entry.kind === 'symlink') {
        const target = entry.readSymlink(), size = Buffer.byteLength(target);
        if (size > maxBytes - byteCount) invalid('selected source bytes exceed the capture limit');
        byteCount += size;
        entries.push({ path: entry.path, kind: 'symlink', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) });
      } else invalid('selected source entry has an unsupported filesystem kind');
    }
    for (const path of selected) if (!observedPaths.has(path)) invalid('selected source path does not exist');
    entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    checkedLinks(entries);
    const manifest: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries,
      entryCount: entries.length, byteCount, treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) };
    const assertComplete = () => {
      signal?.throwIfAborted(); root.assertHeld();
      for (const cursor of cursors) cursor.assertComplete();
      for (const entry of heldEntries) entry.assertHeld();
    };
    assertComplete();
    const result = await artifacts.publishCanonical(manifest, 'cliq-workspace-entries-v1');
    assertComplete();
    return result;
  } catch (error) { operationError = error; throw error; }
  finally { retire([...cursors, ...heldEntries], operationError); }
}
