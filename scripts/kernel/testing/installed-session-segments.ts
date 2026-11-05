// Retained-data qualification reader only. Creates no native scope, Session,
// execution authority or proof that the installed producer ran.
import { walkSessionContextSegments } from '../../../src/kernel/session-context-page-reader.js';
import type { SessionContextHead } from '../../../src/kernel/session-context-pages.js';
import type { SessionContextSegment } from '../../../src/kernel/types.js';

export async function installedSessionSegmentsAt(head: SessionContextHead, itemSeq: number,
  readVerifiedBytes: (ref: string, maximum: number) => Promise<Buffer>): Promise<readonly SessionContextSegment[]> {
  if (!Number.isSafeInteger(itemSeq) || itemSeq < 1 || itemSeq > head.throughItemSeq)
    throw new TypeError('installed Session item is outside its original head');
  const selected: SessionContextSegment[] = [];
  // This data walk has no runtime task scope. The supplied original reader
  // still verifies complete CAS bytes, bounds each read and joins its I/O.
  for await (const segment of walkSessionContextSegments({ readBoundedBytes: readVerifiedBytes,
    assertReadActive() {} }, head)) {
    if (segment.fromItemSeq <= itemSeq && segment.throughItemSeq >= itemSeq) selected.push(segment);
  }
  // Do not return at the selected item: later pages and the complete through
  // boundary must also pass the same production graph decoder.
  return selected;
}
