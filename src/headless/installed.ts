// Schema 3 is a thin control consumer; the legacy schema2 runner stays separate
// until the complete Kernel Cut. Stdio loss never requests Run cancellation.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import { readControlLines } from '../control/lines.js';
import type { InstalledControlSession } from '../control/session.js';
import { CONTROL_FRAME_BYTES, decodeControlFrame, decodeHeadlessControlRequest, headlessControlResponse, headlessControlHello,
  type InstalledControlRequestV1, type HeadlessControlRecordV3, type HeadlessControlResponseV3 } from '../control/v1.js';

type Write = (bytes: Buffer) => Promise<void>;
async function output(value: unknown, write: Write) {
  assertBoundedJsonValue(value, 'headless output');
  const bytes = canonicalJsonBytes(value);
  if (bytes.length < 1 || bytes.length > CONTROL_FRAME_BYTES) throw new TypeError('headless output exceeds its bound');
  await write(Buffer.concat([bytes, Buffer.from('\n')]));
}
function hello(session: InstalledControlSession) {
  return headlessControlHello({ protocolVersion: 1, method: 'control.hello', clientBuild: 'cliq-headless-v3',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 3, max: 3 },
    requestedFeatureIds: session.hello.enabledFeatureIds }, session.hello);
}

/** One explicit attach drains committed pages only; it never subscribes or
 * polls for events after catching up. Every page and displayed event shares
 * the canonical source, and every output yields to transport backpressure. */
async function* records(session: InstalledControlSession, request: InstalledControlRequestV1): AsyncGenerator<HeadlessControlRecordV3> {
  if (request.method === 'run.attach') {
    for await (const page of session.attach(request)) {
      yield headlessControlResponse(page.response, page.request);
      yield* page.events;
    }
  } else yield headlessControlResponse(await session.request(request), request);
}

/** The caller opens the actual authenticated session and joins it in finally.
 * Output is pull-driven; no request is queued behind a stalled output. */
export async function runInstalledHeadlessJsonl(session: InstalledControlSession,
  input: AsyncIterable<Uint8Array>, write: Write): Promise<void> {
  await output(hello(session), write);
  for await (const line of readControlLines(input)) {
    const { request } = decodeHeadlessControlRequest(decodeControlFrame(line));
    if (request.method === 'control.hello') throw new TypeError('the authenticated JSONL hello is already complete');
    for await (const record of records(session, request)) await output(record, write);
  }
}

/** JSON-RPC correlation stays outside the unchanged application response.
 * Notifications cannot mutate state: every command requires an explicit id. */
export async function runInstalledHeadlessRpc(session: InstalledControlSession,
  input: AsyncIterable<Uint8Array>, write: Write): Promise<void> {
  let greeted = false, features: readonly string[] = [];
  for await (const line of readControlLines(input)) {
    let value: unknown;
    try { value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(line)); }
    catch { await output({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }, write); continue; }
    const fields = value && typeof value === 'object' && !Array.isArray(value) ? Object.getOwnPropertyDescriptors(value) : undefined;
    const keys = fields ? Reflect.ownKeys(fields) : [];
    const record = value as Record<string, unknown> | null;
    const validId = typeof record?.id === 'string' && Buffer.byteLength(record.id) <= 256 ||
      typeof record?.id === 'number' && Number.isSafeInteger(record.id);
    if (!fields || keys.length !== 4 || ['jsonrpc', 'id', 'method', 'params'].some(key => !fields[key] ||
        !Object.hasOwn(fields[key], 'value')) || record?.jsonrpc !== '2.0' || typeof record.method !== 'string' || !validId) {
      await output({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } }, write); continue;
    }
    let request;
    try {
      request = decodeHeadlessControlRequest(record.params).request;
      if (request.method !== record.method || !greeted && request.method !== 'control.hello') throw new TypeError('hello required');
    } catch {
      await output({ jsonrpc: '2.0', id: record.id, error: { code: -32602, message: 'invalid control parameters' } }, write); continue;
    }
    let response;
    if (request.method === 'control.hello') {
      response = headlessControlHello(request, session.hello);
      greeted = response.response.ok;
      features = response.response.ok && response.response.result.method === 'control.hello'
        ? response.response.result.enabledFeatureIds : [];
    } else if (!features.includes(request.method)) response = headlessControlResponse({
      protocolVersion: 1, ok: false, method: request.method, error: { schemaVersion: 1, code: 'INVALID_REQUEST',
        retryable: false, messageCode: 'control.feature_not_enabled', issues: [{ path: 'method', issueCode: 'feature_not_enabled' }] } }, request);
    else if (request.method === 'run.attach') {
      let last: HeadlessControlResponseV3 | undefined;
      for await (const notification of records(session, request)) {
        if (notification.type === 'response') last = notification;
        await output({ jsonrpc: '2.0', method: 'control.record', params: { id: record.id, record: notification } }, write);
      }
      if (!last) throw new TypeError('attach produced no authoritative page');
      response = last;
    } else response = headlessControlResponse(await session.request(request), request);
    await output({ jsonrpc: '2.0', id: record.id, result: response }, write);
  }
}
