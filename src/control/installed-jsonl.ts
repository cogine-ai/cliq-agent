// Current installed control-v1 request/response JSONL, not headless schema 3.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { CONTROL_FRAME_BYTES, INSTALLED_CONTROL_FEATURES, decodeControlFrame,
  decodeInstalledControlRequest, decodeInstalledControlEnvelope, decodeInstalledControlResponse,
  type InstalledControlFeature } from './v1.js';

/** A serial byte adapter over the existing client, not an owner or transport.
 * The caller acquires/closes that genuine client in its original finally.
 * EOF or an I/O failure never cancels a Run, reconnects or retries a request.
 * Each output is awaited before reading/dispatching the next input frame. */
export async function runInstalledControlJsonl(client: InstalledSupervisorClient,
  input: AsyncIterable<Uint8Array>, write: (bytes: Buffer) => Promise<void>): Promise<void> {
  const output = async (response: unknown) => {
    const bytes = canonicalJsonBytes(response);
    if (bytes.length < 1 || bytes.length > CONTROL_FRAME_BYTES) throw new TypeError('installed JSONL response exceeds its bound');
    await write(Buffer.concat([bytes, Buffer.from('\n')]));
  };
  await output(decodeInstalledControlEnvelope({ protocolVersion: 1, ok: true, result: client.hello }, 'control.hello'));
  let pendingBytes = 0, pending = Buffer.alloc(0);
  for await (const chunk of input) {
    if (!(chunk instanceof Uint8Array)) throw new TypeError('installed JSONL input must be bytes');
    const bytes = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    let offset = 0;
    while (offset < bytes.length) {
      const newline = bytes.indexOf(10, offset), end = newline < 0 ? bytes.length : newline;
      const length = end - offset;
      if (pendingBytes + length > CONTROL_FRAME_BYTES) throw new TypeError('installed JSONL request exceeds its bound');
      if (length) {
        if (pendingBytes + length > pending.length) {
          const grown = Buffer.allocUnsafe(Math.min(CONTROL_FRAME_BYTES,
            Math.max(pendingBytes + length, 4096, pending.length * 2)));
          pending.copy(grown, 0, 0, pendingBytes); pending = grown;
        }
        bytes.copy(pending, pendingBytes, offset, end); pendingBytes += length;
      }
      offset = end + (newline < 0 ? 0 : 1);
      if (newline < 0) continue;
      if (!pendingBytes) throw new TypeError('empty installed JSONL request');
      const request = decodeInstalledControlRequest(decodeControlFrame(pending.subarray(0, pendingBytes)));
      pending.fill(0, 0, pendingBytes); pendingBytes = 0;
      if (!INSTALLED_CONTROL_FEATURES.includes(request.method as InstalledControlFeature))
        throw new TypeError('unsupported installed JSONL method');
      const response = await Reflect.apply(client[request.method as InstalledControlFeature], client, [request]);
      await output(decodeInstalledControlResponse(response, request));
    }
  }
  if (pendingBytes) throw new TypeError('truncated installed JSONL input');
}
