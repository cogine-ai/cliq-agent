/** Fixed bounded handoff output coalescing only. Original CAS performs its
 * unchanged writes/identity checks/fsync/full reread/EOF/actual descriptor join.
 * Early failure returns the real source iterator, discards the uncommitted
 * tail, and never turns a partial body into a complete publication. */
export async function* coalesceSessionHandoffPublication(source: AsyncIterable<Uint8Array>,
  signal?: AbortSignal): AsyncIterableIterator<Buffer> {
  let pending = Buffer.allocUnsafe(65_536), used = 0;
  for await (const bytes of source) {
    signal?.throwIfAborted(); let offset = 0;
    while (offset < bytes.byteLength) {
      signal?.throwIfAborted();
      const size = Math.min(pending.length - used, bytes.byteLength - offset);
      pending.set(bytes.subarray(offset, offset + size), used); used += size; offset += size;
      if (used === pending.length) {
        yield pending; pending = Buffer.allocUnsafe(65_536); used = 0;
      }
    }
  }
  signal?.throwIfAborted();
  if (used) yield pending.subarray(0, used);
}
