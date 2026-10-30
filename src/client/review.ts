import { createTwoFilesPatch } from 'diff';
import type { WorkspaceDiffV1 } from '../kernel/result.js';
import type { WorkspaceEntry } from '../kernel/types.js';

// These are disposable review limits, not execution, source or publication
// limits. Every omission is visible and retains the original exportable ref.
const REVIEW_BYTES = 1_048_576, REVIEW_CONTENT_BYTES = REVIEW_BYTES - 1024, FILE_BYTES = 131_072;
type ArtifactReader = (ref: string, options: { maxBytes: number; signal?: AbortSignal }) => Promise<Buffer>;
type FileEntry = Extract<WorkspaceEntry, { kind: 'file' }>;
const describe = (entry: WorkspaceEntry | undefined) => !entry ? 'absent' : entry.kind === 'directory' ? 'directory'
  : entry.kind === 'symlink' ? `symlink → ${JSON.stringify(entry.target)}`
    : `file · mode ${entry.mode.toString(8)} · ${entry.size} bytes · ${entry.blobRef}`;

/** Review only: read original immutable blobs through the authenticated client.
 * No host path, Git process, patch application or permission is involved. */
export async function renderWorkspaceReview(diff: WorkspaceDiffV1, read: ArtifactReader, signal?: AbortSignal): Promise<string> {
  const chunks = [`${diff.operations.length} changed path${diff.operations.length === 1 ? '' : 's'}\n`];
  let bytes = Buffer.byteLength(chunks[0]!), inputBytes = 0, omitted = 0;
  const append = (value: string) => { chunks.push(value); bytes += Buffer.byteLength(value); };
  async function text(entry: FileEntry | undefined): Promise<string | undefined> {
    if (!entry) return '';
    if (entry.size > FILE_BYTES || inputBytes + entry.size > REVIEW_BYTES) return undefined;
    inputBytes += entry.size;
    const data = await read(entry.blobRef, { maxBytes: FILE_BYTES, signal }); signal?.throwIfAborted();
    if (data.length !== entry.size) throw new TypeError('review file differs from its original entry size');
    if (data.includes(0)) return undefined;
    try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data); }
    catch { return undefined; }
  }
  for (const [index, operation] of diff.operations.entries()) {
    signal?.throwIfAborted();
    if (bytes >= REVIEW_CONTENT_BYTES) { omitted += diff.operations.length - index; break; }
    const before = 'before' in operation ? operation.before : undefined, after = 'after' in operation ? operation.after : undefined;
    const header = `\n${operation.kind.toUpperCase()} ${JSON.stringify(operation.path)}\nBefore: ${describe(before)}\nAfter: ${describe(after)}\n`;
    if (bytes + Buffer.byteLength(header) > REVIEW_CONTENT_BYTES) { omitted += diff.operations.length - index; break; }
    append(header);
    const oldFile = before?.kind === 'file' ? before : undefined, newFile = after?.kind === 'file' ? after : undefined;
    if (!oldFile && !newFile || oldFile && newFile && oldFile.blobRef === newFile.blobRef) continue;
    const oldText = await text(oldFile), newText = await text(newFile);
    if (oldText === undefined || newText === undefined) {
      omitted++; append('Content omitted from this bounded text review (binary, invalid UTF-8, or review byte limit). Export the original blob refs above.\n'); continue;
    }
    // Await the actual callback even if the view is cancelled. The library's
    // bounded asynchronous computation must finish before this read joins.
    // jsdiff quotes controls, quotes and backslashes in file headers itself.
    const patch = await new Promise<string | undefined>(resolve => createTwoFilesPatch(
      oldFile ? `a/${operation.path}` : '/dev/null', newFile ? `b/${operation.path}` : '/dev/null',
      oldText, newText, undefined, undefined, { context: 3, maxEditLength: 4096, timeout: 250, callback: resolve }));
    signal?.throwIfAborted();
    if (patch === undefined || bytes + Buffer.byteLength(patch) > REVIEW_CONTENT_BYTES) {
      omitted++; append('Content diff omitted from this bounded review. Export the original blob refs above.\n');
    } else append(patch);
  }
  if (omitted) append(`\nREVIEW INCOMPLETE: ${omitted} path${omitted === 1 ? '' : 's'} have content or entries omitted. Export the complete diff artifact and original blobs before deciding to apply.\n`);
  return chunks.join('');
}
