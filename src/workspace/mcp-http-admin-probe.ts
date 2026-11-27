// Signed, fixed empty-root program. The controller supplies only its private
// authenticated operation channel on fd 3. This program has no target or key.
import { closeSync, readSync, writeSync } from 'node:fs';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeMcpInitializeResult, decodeMcpToolsListResult, MCP_RESPONSE_BYTES } from '../kernel/mcp.js';
import { decodeMcpInboundMessageData } from '../kernel/mcp-wire.js';
const CHANNEL = 3, MAGIC = 0x434d4131;
const phases = ['initialize', 'initialized', 'tools_list'] as const;
function exactRead(size: number): Buffer {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const got = readSync(CHANNEL, bytes, offset, size - offset, null);
    if (!got) {
      throw new TypeError('closed operation channel');
    }
    offset += got;
  }
  return bytes;
}
function receive(kind: number): unknown {
  const header = exactRead(16), size = header.readUInt32LE(12);
  if (header.readUInt32LE(0) !== MAGIC || header.readUInt32LE(4) !== 1 || header.readUInt32LE(8) !== kind || size < 1 || size > MCP_RESPONSE_BYTES) {
    throw new TypeError('invalid operation frame');
  }
  const bytes = exactRead(size), value = parseJsonStrict(new TextDecoder('utf8', {
    fatal: true,
    ignoreBOM: true
  }).decode(bytes));
  if (kind !== 3 && !canonicalJsonBytes(value).equals(bytes)) {
    throw new TypeError('noncanonical operation frame');
  }
  return value;
}
function send(kind: number, value: unknown): void {
  const bytes = canonicalJsonBytes(value);
  if (bytes.length < 1 || bytes.length > MCP_RESPONSE_BYTES) {
    throw new TypeError('operation frame exceeds its bound');
  }
  const header = Buffer.alloc(16);
  header.writeUInt32LE(MAGIC, 0);
  header.writeUInt32LE(1, 4);
  header.writeUInt32LE(kind, 8);
  header.writeUInt32LE(bytes.length, 12);
  for (const buffer of [header, bytes]) {
    let offset = 0;
    while (offset < buffer.length) {
      const wrote = writeSync(CHANNEL, buffer, offset, buffer.length - offset, null);
      if (!wrote) {
        throw new TypeError('closed operation channel');
      }
      offset += wrote;
    }
  }
}
function probe(): void {
  const config = controlWireRecord(receive(1), ['nonce', 'recipe']);
  const nonce = controlWireText(config.nonce);
  if (!/^[0-9a-f]{64}$/u.test(nonce) || !Array.isArray(config.recipe) || config.recipe.length !== 3) {
    throw new TypeError('invalid fixed Admin recipe');
  }
  const recipe = config.recipe.map((value, index) => {
    const frame = controlWireRecord(value, ['phase', 'bodyJson']);
    if (frame.phase !== phases[index] || typeof frame.bodyJson !== 'string' || Buffer.byteLength(frame.bodyJson) > MCP_RESPONSE_BYTES) {
      throw new TypeError('invalid fixed Admin stage');
    }
    const body = controlWireRecord(parseJsonStrict(frame.bodyJson), ['jsonrpc', 'method', ...(index === 1 ? [] : ['id'])], index === 0 ? ['params'] : []);
    if (body.jsonrpc !== '2.0' || body.method !== ['initialize', 'notifications/initialized', 'tools/list'][index] ||
      canonicalJsonBytes(body).toString('utf8') !== frame.bodyJson) {
      throw new TypeError('Admin recipe method differs');
    }
    if (index === 0) {
      const params = controlWireRecord(body.params, ['protocolVersion', 'capabilities', 'clientInfo']);
      controlWireRecord(params.capabilities, []);
      const client = controlWireRecord(params.clientInfo, ['name', 'version']);
      if (params.protocolVersion !== '2025-11-25' || client.name !== '@cogineai/cliq') {
        throw new TypeError('Admin initialize differs');
      }
      controlWireText(client.version);
    }
    return {
      phase: phases[index]!,
      bodyJson: frame.bodyJson,
      id: body.id
    };
  });
  if (recipe[0]!.id === recipe[2]!.id) {
    throw new TypeError('Admin request ids must differ');
  }
  for (const frame of recipe) {
    send(2, {
      phase: frame.phase,
      bodyJson: frame.bodyJson
    });
    if (frame.phase === 'initialized') {
      const delivered = controlWireRecord(receive(3), ['phase', 'ack']);
      if (delivered.phase !== frame.phase || delivered.ack !== true) {
        throw new TypeError('Admin notification was not acknowledged');
      }
      continue;
    }
    // Original JSON bytes occupy the frame directly. JSON-string wrapping
    // would enlarge valid near-limit responses beyond their original B.
    for (;;) {
      const message = decodeMcpInboundMessageData(receive(3));
      if (message.kind === 'ping') {
        continue;
      } // Native alone owns the correlated reply gates.
      if (message.kind === 'notification') {
        if (message.method === 'notifications/tools/list_changed') {
          throw new TypeError('discovery changed during Admin probe');
        }
        continue;
      }
      if (message.kind !== 'result' || message.id !== frame.id) {
        throw new TypeError('Admin response does not complete its exact stage');
      }
      if (frame.phase === 'initialize') {
        decodeMcpInitializeResult(message.result);
      }
      else
        decodeMcpToolsListResult(message.result);
      break;
    }
  }
  send(4, {
    nonce,
    complete: true
  });
}
try {
  probe();
  closeSync(CHANNEL);
}
catch {
  try {
    send(5, {
      refused: true
    });
  }
  catch { /* Closing the genuine peer joins this failure. */
  }
  try {
    closeSync(CHANNEL);
  }
  catch { /* The controller independently retains custody. */
  }
  process.exitCode = 1;
}
