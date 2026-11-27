// Fixed portable handoff data only. A successful read confers no Session,
// source-lineage, compaction, permission or import authority.
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes } from './canonical.js';
import { parseJsonStrict, MAX_JSON_DEPTH } from './json.js';
import { controlWireInteger, controlWireRecord, controlWireText, assertControlWireJson } from './control-wire-data.js';
import { assertArtifactRef } from './identity.js';
import type { SessionHandoffV1, SessionHandoffEntryV1 } from './session-continuity.js';
export type SessionHandoffHeader = Omit<SessionHandoffV1, 'schemaVersion' | 'format' | 'entries' | 'excludedRanges' | 'handoffDigest'>;
export type SessionHandoffExcludedRange = SessionHandoffV1['excludedRanges'][number];
const kinds = new Set(['run_terminal', 'summary', 'legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark']);
export function decodeSessionHandoffHeader(value: unknown): SessionHandoffHeader {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['sessionId', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'contextRevision', 'throughItemSeq',
    'contextProjectionRef', 'contextProjectionDigest']);
  controlWireText(data.sessionId); controlWireInteger(data.contextRevision, 1); controlWireInteger(data.throughItemSeq);
  for (const key of ['workspaceIdentityRef', 'workspaceIdentityDigest', 'contextProjectionRef', 'contextProjectionDigest']) assertArtifactRef(data[key] as string);
  return data as SessionHandoffHeader;
}
export function decodeSessionHandoffEntry(value: unknown, index: number, through: number): SessionHandoffEntryV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['index', 'sourceKind', 'fromItemSeq', 'throughItemSeq', 'sourceRef', 'sourceDigest', 'contentUtf8']);
  if (data.index !== index || !kinds.has(data.sourceKind as string)) throw new TypeError('handoff entry is not its original ordered visible data');
  const from = controlWireInteger(data.fromItemSeq, 1); controlWireInteger(data.throughItemSeq, from, through);
  assertArtifactRef(data.sourceRef as string); assertArtifactRef(data.sourceDigest as string);
  const text = controlWireText(data.contentUtf8, 1_048_576, 0);
  if (text.includes('\r')) throw new TypeError('handoff source prose must already use canonical LF');
  return data as SessionHandoffEntryV1;
}
export function decodeSessionHandoffExcludedRange(value: unknown, after: number, through: number): SessionHandoffExcludedRange {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['fromItemSeq', 'throughItemSeq', 'sourceItemsDigest']);
  const from = controlWireInteger(data.fromItemSeq, after + 1); controlWireInteger(data.throughItemSeq, from, through);
  assertArtifactRef(data.sourceItemsDigest as string); return data as SessionHandoffExcludedRange;
}

/** The original complete artifact consumer supplies stable, fully hashed and
 * joined bytes. This fixed export profile visits one bounded entry at a time;
 * it does not construct the full entries/ranges arrays or enlarge the general
 * JSON parser's aggregate or depth limits. Each fragment still uses that exact
 * strict parser. Completion requires the full original envelope and digest. */
export async function inspectSessionHandoffBytes(bytes: Buffer, expected: Readonly<{
  sessionId: string; expectedContextRevision: number; throughItemSeq?: number;
}>, signal?: AbortSignal): Promise<Readonly<{ header: SessionHandoffHeader; entryCount: number; excludedRangeCount: number; handoffDigest: string }>> {
  return inspectHandoff(bytes, expected, signal);
}
async function inspectHandoff(bytes: Buffer, expected: Readonly<{
  sessionId: string; expectedContextRevision: number; throughItemSeq?: number;
}>, signal?: AbortSignal, consume?: (entry: SessionHandoffEntryV1) => Promise<void>) {
  signal?.throwIfAborted();
  if (!Buffer.isBuffer(bytes) || bytes.length > 64 * 1024 * 1024) throw new TypeError('handoff exceeds its original complete byte ceiling');
  let at = 0, nextYield = 65_536;
  const invalid = (): never => { throw new TypeError('handoff is not its complete canonical portable envelope'); };
  function literal(text: string): void {
    const value = Buffer.from(text);
    if (!bytes.subarray(at, at + value.length).equals(value)) invalid();
    at += value.length;
  }
  async function active(): Promise<void> {
    signal?.throwIfAborted(); await setImmediate(); signal?.throwIfAborted();
  }
  async function fragment(maximum: number): Promise<unknown> {
    const start = at; let depth = 0, quoted = false, escaped = false;
    for (; at < bytes.length; at++) {
      if (at - start >= maximum) invalid();
      if (at >= nextYield) { nextYield = at + 65_536; await active(); }
      const byte = bytes[at]!;
      if (quoted) {
        if (escaped) escaped = false;
        else if (byte === 92) escaped = true;
        else if (byte === 34) quoted = false;
        continue;
      }
      if (byte === 34) quoted = true;
      else if (byte === 123 || byte === 91) { if (++depth > MAX_JSON_DEPTH) invalid(); }
      else if (byte === 125 || byte === 93) { if (depth === 0) break; depth--; }
      else if (byte === 44 && depth === 0) break;
    }
    const raw = bytes.subarray(start, at);
    const value = parseJsonStrict(new TextDecoder('utf8', { fatal: true, ignoreBOM: true }).decode(raw));
    if (!canonicalJsonBytes(value).equals(raw)) invalid();
    return value;
  }
  async function field(key: string): Promise<unknown> { literal(JSON.stringify(key) + ':'); return fragment(4096); }
  literal('{');
  const contextProjectionDigest = await field('contextProjectionDigest'); literal(',');
  const contextProjectionRef = await field('contextProjectionRef'); literal(',');
  const contextRevision = await field('contextRevision'); literal(',"entries":[');
  let entryCount = 0, maximumThrough = 0;
  while (bytes[at] !== 93) {
    if (entryCount) literal(',');
    // Six bytes per allowed UTF-16 code unit covers every JSON escape; the
    // fixed scalar fields add less than 4 KiB. No valid original entry is lost.
    const entry = decodeSessionHandoffEntry(await fragment(6 * 1_048_576 + 4096), entryCount++, Number.MAX_SAFE_INTEGER);
    await consume?.(entry);
    maximumThrough = Math.max(maximumThrough, entry.throughItemSeq); await active();
  }
  literal('],"excludedRanges":[');
  let excludedRangeCount = 0, rangeThrough = 0;
  while (bytes[at] !== 93) {
    if (excludedRangeCount) literal(',');
    const range = decodeSessionHandoffExcludedRange(await fragment(4096), rangeThrough, Number.MAX_SAFE_INTEGER);
    rangeThrough = range.throughItemSeq; excludedRangeCount++; await active();
  }
  literal('],"format":"cliq-session-handoff-v1",');
  const omittedFrom = at, handoffDigest = await field('handoffDigest'); literal(','); const omittedThrough = at;
  if (await field('schemaVersion') !== 1) invalid(); literal(',');
  const sessionId = await field('sessionId'); literal(',');
  const throughItemSeq = await field('throughItemSeq'); literal(',');
  const workspaceIdentityDigest = await field('workspaceIdentityDigest'); literal(',');
  const workspaceIdentityRef = await field('workspaceIdentityRef'); literal('}');
  if (at !== bytes.length) invalid();
  const header = decodeSessionHandoffHeader({ sessionId, workspaceIdentityRef, workspaceIdentityDigest, contextRevision, throughItemSeq,
    contextProjectionRef, contextProjectionDigest });
  assertArtifactRef(handoffDigest as string);
  const hash = createHash('sha256');
  for (const range of [bytes.subarray(0, omittedFrom), bytes.subarray(omittedThrough)]) {
    for (let offset = 0; offset < range.length; offset += 65_536) { hash.update(range.subarray(offset, offset + 65_536)); await active(); }
  }
  if (hash.digest('hex') !== handoffDigest || maximumThrough > header.throughItemSeq || rangeThrough > header.throughItemSeq) invalid();
  if (header.sessionId !== expected.sessionId || header.contextRevision !== expected.expectedContextRevision ||
      expected.throughItemSeq !== undefined && header.throughItemSeq !== expected.throughItemSeq)
    throw new TypeError('handoff differs from its original cut');
  signal?.throwIfAborted(); return Object.freeze({ header: Object.freeze(header), entryCount, excludedRangeCount, handoffDigest: handoffDigest as string });
}

function markdownHeader(data: SessionHandoffHeader): Buffer {
  return Buffer.from('# Cliq Session Handoff\n\n' + `Session: ${canonicalJsonBytes(data.sessionId).toString('utf8')}\nContext revision: ${data.contextRevision}\nThrough item: ${data.throughItemSeq}\n`);
}
function* markdownEntry(value: SessionHandoffEntryV1, signal?: AbortSignal): IterableIterator<Buffer> {
  yield Buffer.from(`\n## Entry ${value.index + 1}: ${value.sourceKind}\n\n`);
  for (const line of value.contentUtf8.split('\n')) {
    const bytes = Buffer.from(`    ${line}\n`);
    for (let offset = 0; offset < bytes.length; offset += 65_536) { signal?.throwIfAborted(); yield bytes.subarray(offset, offset + 65_536); }
  }
}
const markdownFooter = (count: number) => Buffer.from(`\nExcluded control ranges: ${count}\n`);

/** The same renderer serves export and pair verification; an independently
 * valid Markdown artifact cannot substitute for this exact portable JSON. */
export async function* encodeSessionHandoffMarkdown(input: SessionHandoffHeader, entries: AsyncIterable<SessionHandoffEntryV1>,
  ranges: AsyncIterable<SessionHandoffExcludedRange>, signal?: AbortSignal): AsyncIterableIterator<Buffer> {
  const data = decodeSessionHandoffHeader(input); signal?.throwIfAborted(); yield markdownHeader(data);
  let count = 0;
  for await (const value of entries) {
    const checked = decodeSessionHandoffEntry(value, count++, data.throughItemSeq); signal?.throwIfAborted();
    yield* markdownEntry(checked, signal); await setImmediate(); signal?.throwIfAborted();
  }
  let rangeCount = 0, through = 0;
  for await (const value of ranges) {
    const checked = decodeSessionHandoffExcludedRange(value, through, data.throughItemSeq); through = checked.throughItemSeq; rangeCount++;
    await setImmediate(); signal?.throwIfAborted();
  }
  signal?.throwIfAborted(); yield markdownFooter(rangeCount);
}

export async function verifySessionHandoffPair(bytes: Buffer, expected: Readonly<{
  sessionId: string; expectedContextRevision: number; throughItemSeq?: number;
}>, markdown: Readonly<{ ref: string; sizeBytes: number }>, signal?: AbortSignal): Promise<void> {
  const original = await inspectSessionHandoffBytes(bytes, expected, signal);
  assertArtifactRef(markdown.ref); controlWireInteger(markdown.sizeBytes, 0, 64 * 1024 * 1024);
  const hash = createHash('sha256'); let byteLength = 0, nextYield = 65_536;
  const add = async (chunk: Buffer) => {
    signal?.throwIfAborted(); hash.update(chunk); byteLength += chunk.length;
    if (byteLength >= nextYield) { nextYield = byteLength + 65_536; await setImmediate(); signal?.throwIfAborted(); }
  };
  await add(markdownHeader(original.header));
  const complete = await inspectHandoff(bytes, expected, signal, async entry => {
    for (const chunk of markdownEntry(entry, signal)) await add(chunk);
  });
  await add(markdownFooter(complete.excludedRangeCount));
  if (complete.handoffDigest !== original.handoffDigest || hash.digest('hex') !== markdown.ref || byteLength !== markdown.sizeBytes)
    throw new TypeError('handoff Markdown differs from its complete original JSON rendering');
  signal?.throwIfAborted();
}
