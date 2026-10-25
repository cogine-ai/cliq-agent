import { CONTROL_FRAME_BYTES } from './v1.js';

/** Pull-driven bounded framing shared by stdio adapters. Each consumer decides
 * its JSON contract; no iterator read overtakes its awaited output. */
export async function* readControlLines(input: AsyncIterable<Uint8Array>): AsyncGenerator<Buffer> {
  let used = 0, pending = Buffer.alloc(0);
  try {
    for await (const chunk of input) {
      if (!(chunk instanceof Uint8Array)) throw new TypeError('control input must be bytes');
      const bytes = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      let offset = 0;
      while (offset < bytes.length) {
        const newline = bytes.indexOf(10, offset), end = newline < 0 ? bytes.length : newline, length = end - offset;
        if (used + length > CONTROL_FRAME_BYTES) throw new TypeError('control request exceeds its bound');
        if (length) {
          if (used + length > pending.length) {
            const grown = Buffer.allocUnsafe(Math.min(CONTROL_FRAME_BYTES, Math.max(used + length, 4096, pending.length * 2)));
            pending.copy(grown, 0, 0, used); pending.fill(0, 0, used); pending = grown;
          }
          bytes.copy(pending, used, offset, end); used += length;
        }
        offset = end + (newline < 0 ? 0 : 1);
        if (newline < 0) continue;
        if (!used) throw new TypeError('empty control request');
        const line = Buffer.from(pending.subarray(0, used)); pending.fill(0, 0, used); used = 0;
        yield line;
      }
    }
    if (used) throw new TypeError('truncated control input');
  } finally { pending.fill(0); }
}
