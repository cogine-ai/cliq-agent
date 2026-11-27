// Fixed Legacy Session carrier framing. JSON semantics stay owned by the
// existing strict lexer; this module never becomes another general JSON parser.
import { createHash } from 'node:crypto';
import { normalizeCanonicalText } from '../kernel/canonical.js';
import { MAX_JSON_DEPTH, measureBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import { assertArtifactRef, parseCanonicalTime } from '../kernel/identity.js';
import { assertControlWireJson, controlWireRecord, controlWireText, controlWireInteger } from '../kernel/control-wire-data.js';

export const LEGACY_SOURCE_BYTES = 256 * 1024 * 1024;
export const LEGACY_SOURCE_FRAGMENT_BYTES = 1_048_576;
const KEYS = new Set(['version', 'app', 'id', 'name', 'parentSessionId', 'forkedFromCheckpointId', 'activeTxId',
  'activePlanId', 'approvedPlanId', 'model', 'cwd', 'createdAt', 'updatedAt', 'lifecycle', 'activeSkills',
  'records', 'compactions', 'checkpoints']);
const ARRAYS = new Set(['records', 'compactions', 'checkpoints']);
const RETAINED_METADATA = new Set(['version', 'app', 'id', 'name', 'cwd', 'createdAt', 'updatedAt']);
type State = 'open' | 'key_or_end' | 'key_after_comma' | 'colon' | 'value' | 'separator' |
  'item_or_end' | 'item_after_comma' | 'item_separator' | 'done';
export type LegacySessionSourceItem = Readonly<{
  kind: 'legacy_record' | 'legacy_compaction' | 'legacy_bookmark'; ordinal: number; value: unknown;
}>;
export type LegacySessionPreflightControls = Readonly<{ activeTxId?: string;
  lifecycle: Readonly<{ status: 'idle' | 'running'; turn: number }> }>;
function invalid(message: string): never { throw new TypeError(`legacy Session source: ${message}`); }
function whitespace(value: string): boolean { return value === ' ' || value === '\n' || value === '\r' || value === '\t'; }

/** Data-only streaming decoder. Its result cannot prove a native source,
 * completed backup, credential, migration control or StateOwner authority.
 * The owning caller additionally requires the original source EOF/hash/join. */
export class LegacySessionSourceStream {
  private readonly decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  private readonly hash = createHash('sha256');
  private state: State = 'open';
  private readonly keys = new Set<string>();
  private readonly metadata: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  private readonly controlMetadata: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  private key = '';
  private ordinal = 0;
  private bytes = 0;
  private entries = 0;
  private finished = false;
  private verified = false;
  private failed = false;
  private frame: 'key' | 'metadata' | 'item' | undefined;
  private frameParts: string[] = [];
  private frameBytes = 0;
  private depth = 0;
  private quoted = false;
  private escaped = false;
  private readonly expectedByteCount: number;
  private readonly expectedDigest: string;

  constructor(expected: Readonly<{ byteCount: number; contentDigest: string }>) {
    assertControlWireJson(expected); controlWireRecord(expected, ['byteCount', 'contentDigest']);
    assertArtifactRef(expected.contentDigest);
    if (!Number.isSafeInteger(expected.byteCount) || expected.byteCount < 0 || expected.byteCount > LEGACY_SOURCE_BYTES)
      invalid('complete file exceeds the fixed supported byte profile');
    this.expectedByteCount = expected.byteCount; this.expectedDigest = expected.contentDigest;
  }

  feed(bytes: Uint8Array): readonly LegacySessionSourceItem[] {
    if (this.finished || this.failed) invalid('decoder has already closed or failed');
    try {
      if (bytes.byteLength > 65_536) invalid('input exceeds the original bounded source chunk');
      this.bytes += bytes.byteLength;
      if (this.bytes > this.expectedByteCount || this.bytes > LEGACY_SOURCE_BYTES) invalid('file byte budget exceeded');
      this.hash.update(bytes);
      return this.consume(this.decoder.decode(bytes, { stream: true }));
    } catch (error) { this.failed = true; throw error; }
  }

  finish(): Readonly<Record<string, unknown>> {
    if (this.finished || this.failed) invalid('decoder has already closed or failed');
    this.finished = true;
    const tail = this.consume(this.decoder.decode());
    if (tail.length || this.frame || this.state !== 'done' || this.bytes !== this.expectedByteCount ||
        this.hash.digest('hex') !== this.expectedDigest) invalid('complete UTF-8/JSON/file hash was not observed');
    for (const required of ['version', 'app', 'model', 'cwd', 'createdAt', 'updatedAt', 'lifecycle', 'records'])
      if (!this.keys.has(required)) invalid(`missing ${required}`);
    this.verified = true;
    return Object.freeze({ ...this.metadata });
  }

  /** Nonportable preflight data only, available after this decoder's complete
   * EOF/hash. The owning importer must additionally wait for the real native
   * source_complete/close before using it. Neither stale running/idle nor a
   * transaction id supplies process, tool, config or recovery authority.
   * A producer consumes this immediately and retains only bounded tx ids,
   * never one full control fragment per historical Session. */
  preflightControls(): LegacySessionPreflightControls {
    if (!this.verified || this.failed) invalid('preflight controls require the complete verified source');
    const lifecycle = controlWireRecord(this.controlMetadata.lifecycle, ['status', 'turn'], ['lastUserInputAt', 'lastAssistantOutputAt']);
    if (!['idle', 'running'].includes(lifecycle.status as string)) invalid('source lifecycle has an unknown status');
    const turn = controlWireInteger(lifecycle.turn);
    for (const key of ['lastUserInputAt', 'lastAssistantOutputAt'])
      if (Object.hasOwn(lifecycle, key)) parseCanonicalTime(controlWireText(lifecycle[key]));
    const tx = this.controlMetadata.activeTxId;
    if (tx !== undefined && !/^[A-Za-z0-9_-]{1,128}$/u.test(controlWireText(tx))) invalid('source transaction id is not a fixed safe locator');
    return Object.freeze({ ...(typeof tx === 'string' ? { activeTxId: tx } : {}),
      lifecycle: Object.freeze({ status: lifecycle.status as 'idle' | 'running', turn }) });
  }

  private begin(frame: 'key' | 'metadata' | 'item'): void {
    this.frame = frame; this.frameParts = []; this.frameBytes = 0;
    this.depth = 0; this.quoted = false; this.escaped = false;
  }
  private append(text: string): void {
    if (!text.length) return;
    this.frameBytes += Buffer.byteLength(text, 'utf8');
    if (this.frameBytes > (this.frame === 'key' ? 256 : LEGACY_SOURCE_FRAGMENT_BYTES))
      invalid('fixed fragment memory profile exceeded');
    this.frameParts.push(text);
    // Binary-sized coalescing keeps a byte-at-a-time source from allocating
    // one array slot per character, without repeatedly copying the whole frame.
    while (this.frameParts.length > 1) {
      const last = this.frameParts.length - 1;
      if (this.frameParts[last - 1]!.length > this.frameParts[last]!.length) break;
      const right = this.frameParts.pop()!, left = this.frameParts.pop()!;
      this.frameParts.push(left + right);
    }
  }
  private delimiter(character: string): boolean {
    return !this.quoted && this.depth === 0 && (whitespace(character) || character === ',' ||
      character === '}' || character === ']' || this.frame === 'key' && character === ':');
  }
  private scan(character: string): void {
    if (this.quoted) {
      if (this.escaped) this.escaped = false;
      else if (character === '\\') this.escaped = true;
      else if (character === '"') this.quoted = false;
      return;
    }
    if (character === '"') this.quoted = true;
    else if (character === '{' || character === '[') {
      this.depth++;
      const outer = this.frame === 'item' ? 2 : this.frame === 'metadata' ? 1 : 0;
      if (this.depth + outer > MAX_JSON_DEPTH) invalid('whole-file JSON depth exceeded');
    } else if (character === '}' || character === ']') this.depth--;
  }
  private end(events: LegacySessionSourceItem[]): void {
    const frame = this.frame;
    const source = this.frameParts.join('');
    this.frame = undefined; this.frameParts = []; this.frameBytes = 0;
    if (frame === 'key') {
      const key = parseJsonStrict(source);
      if (typeof key !== 'string' || !KEYS.has(key) || this.keys.has(key)) invalid('unknown or duplicate root field');
      this.keys.add(key); this.key = key; this.state = 'colon'; return;
    }
    if (frame !== 'metadata' && frame !== 'item') invalid('missing original fragment');
    // Put fragments back at their actual carrier depth. This retains original
    // duplicate-key, scalar, per-item entry and whole-source depth checks.
    const wrapped = parseJsonStrict(frame === 'item' ? `{"${this.key}":[${source}]}` : `{"${this.key}":${source}}`) as Record<string, unknown>;
    const measured = measureBoundedJsonValue(wrapped, 'legacy source fragment');
    this.entries += measured.containerEntries - (frame === 'item' ? 1 : 0);
    if (this.entries > LEGACY_SOURCE_BYTES) invalid('complete file member budget exceeded');
    if (frame === 'metadata') {
      if (this.key === 'activeTxId' || this.key === 'lifecycle') this.controlMetadata[this.key] = wrapped[this.key];
      if (RETAINED_METADATA.has(this.key)) {
        let value = wrapped[this.key];
        if (this.key === 'version') {
          if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 5)
            invalid('source version is not a recognized Legacy carrier');
        } else if (this.key === 'app') {
          if (value !== 'cliq') invalid('source app differs');
        } else {
          if (this.key === 'name') {
            if (typeof value !== 'string') invalid('Session name is not text');
            value = normalizeCanonicalText(value);
          }
          if (this.key === 'cwd') {
            if (typeof value !== 'string' || Buffer.byteLength(value) > 4096) invalid('workspace locator exceeds its byte profile');
            // Check scalar/NUL/portable-display bounds, but retain original
            // filesystem lookup bytes. NFC may name another Linux object.
            controlWireText(normalizeCanonicalText(value), 4096);
          } else controlWireText(value, this.key === 'name' ? 256 : 128, this.key === 'name' ? 0 : 1);
          if (this.key === 'createdAt' || this.key === 'updatedAt') parseCanonicalTime(value as string);
        }
        this.metadata[this.key] = value;
      }
      this.state = 'separator'; return;
    }
    const values = wrapped[this.key];
    if (!Array.isArray(values) || values.length !== 1) invalid('fragment did not preserve its original array item');
    events.push(Object.freeze({ kind: this.key === 'records' ? 'legacy_record' : this.key === 'compactions'
      ? 'legacy_compaction' : 'legacy_bookmark', ordinal: this.ordinal++, value: values[0] }));
    this.state = 'item_separator';
  }

  private consume(text: string): readonly LegacySessionSourceItem[] {
    const events: LegacySessionSourceItem[] = [];
    let index = 0, capturedFrom = this.frame ? 0 : -1;
    while (index < text.length) {
      const character = text[index]!;
      if (this.frame) {
        if (this.delimiter(character) && (this.frameBytes > 0 || index > capturedFrom)) {
          this.append(text.slice(capturedFrom, index)); this.end(events); capturedFrom = -1;
          continue; // The delimiter belongs to the original carrier.
        }
        this.scan(character); index++; continue;
      }
      if (whitespace(character)) { index++; continue; }
      if (this.state === 'open') {
        if (character !== '{') invalid('carrier must be an object');
        this.state = 'key_or_end'; index++; continue;
      }
      if (this.state === 'key_or_end' || this.state === 'key_after_comma') {
        if (character === '}' && this.state === 'key_or_end') { this.state = 'done'; index++; continue; }
        if (character !== '"') invalid('expected a root field');
        this.begin('key'); capturedFrom = index; continue;
      }
      if (this.state === 'colon') {
        if (character !== ':') invalid('expected colon');
        this.state = 'value'; index++; continue;
      }
      if (this.state === 'value') {
        if (ARRAYS.has(this.key)) {
          if (character !== '[') invalid('historical sequence must be an array');
          this.entries++; this.ordinal = 0; this.state = 'item_or_end'; index++; continue;
        }
        this.begin('metadata'); capturedFrom = index; continue;
      }
      if (this.state === 'item_or_end' || this.state === 'item_after_comma') {
        if (character === ']' && this.state === 'item_or_end') { this.state = 'separator'; index++; continue; }
        if (character === ']') invalid('trailing array comma');
        this.begin('item'); capturedFrom = index; continue;
      }
      if (this.state === 'item_separator') {
        if (character === ',') this.state = 'item_after_comma';
        else if (character === ']') this.state = 'separator';
        else invalid('expected array separator');
        index++; continue;
      }
      if (this.state === 'separator') {
        if (character === ',') this.state = 'key_after_comma';
        else if (character === '}') this.state = 'done';
        else invalid('expected root separator');
        index++; continue;
      }
      invalid('trailing carrier content');
    }
    if (this.frame) this.append(text.slice(capturedFrom));
    return events;
  }
}
