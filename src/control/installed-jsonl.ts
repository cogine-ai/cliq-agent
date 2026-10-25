// Current installed control-v1 request/response JSONL, not headless schema 3.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { CONTROL_FRAME_BYTES, INSTALLED_CONTROL_FEATURES, decodeControlFrame,
  decodeInstalledControlRequest, decodeInstalledControlEnvelope, decodeInstalledControlResponse,
  type InstalledControlFeature } from './v1.js';
import { readControlLines } from './lines.js';

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
  for await (const line of readControlLines(input)) {
      const request = decodeInstalledControlRequest(decodeControlFrame(line));
      if (!INSTALLED_CONTROL_FEATURES.includes(request.method as InstalledControlFeature))
        throw new TypeError('unsupported installed JSONL method');
      const response = await Reflect.apply(client[request.method as InstalledControlFeature], client, [request]);
      await output(decodeInstalledControlResponse(response, request));
  }
}
