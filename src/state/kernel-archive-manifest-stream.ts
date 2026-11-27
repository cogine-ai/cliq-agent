// Fixed canonical archive framing, not a replacement JSON lexer. Each small
// fragment uses the original strict parser and exact canonical-byte equality.
// Data completion alone supplies no archive birth, held FD, EOF/join or restore
// authority; the current native reader independently owns those requirements.
import { createHash } from 'node:crypto';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef } from '../kernel/control-wire-data.js';
import { decodeKernelArchiveCasEntry, decodeKernelArchiveCasIdentity, KERNEL_ARCHIVE_MAX_BYTES, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES,
  type KernelArchiveCasEntry, type KernelArchiveCasIdentity } from '../kernel/kernel-archive-namespace.js';
import { decodeCompleteKernelArchiveHeader, kernelArchiveSidecarBytes, type CompleteKernelArchiveHeader } from './kernel-archive-manifest.js';

const FIELDS = ['archiveDirectory', 'cas', 'control', 'database', 'entries', 'excludedTail', 'format', 'localInferenceRuntime', 'localModelStore',
  'manifestDigest', 'schemaVersion', 'snapshotBoundary'] as const;
function invalid(): never { throw new TypeError('archive manifest is not its complete fixed canonical byte stream'); }
/** One bounded source chunk and at most one small canonical fragment survive
 * each feed; emitted entry data is not accepted as a complete manifest until
 * finish validates the original byte hash, full entries and omission digest. */
export class CompleteKernelArchiveManifestStream {
  private readonly decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  private readonly bytesHash = createHash('sha256');
  private readonly manifestHash = createHash('sha256');
  private readonly entriesHash = createHash('sha256');
  private readonly metadata: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  private state: 'prefix' | 'value' | 'first_entry' | 'next_entry' | 'entry' | 'entry_separator' | 'done' = 'prefix';
  private field = 0;
  private prefixOffset = 0;
  private fragment = '';
  private depth = 0;
  private quoted = false;
  private escaped = false;
  private count = 0;
  private totalBytes = 0;
  private previous = '';
  private cas: KernelArchiveCasIdentity | undefined;
  private observedBytes = 0;
  private metadataBytes = 0;
  private failed = false;
  private finished = false;
  private readonly expected: Readonly<{ byteCount: number; sha256: string }>;
  constructor(expected: Readonly<{ byteCount: number; sha256: string }>) {
    assertControlWireJson(expected); controlWireRecord(expected, ['byteCount', 'sha256']);
    this.expected = Object.freeze({ byteCount: controlWireInteger(expected.byteCount, 1, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES),
      sha256: controlWireRef(expected.sha256) });
  }
  feed(chunk: Uint8Array): readonly KernelArchiveCasEntry[] {
    if (this.failed || this.finished) return invalid();
    try {
      if (chunk.byteLength < 1 || chunk.byteLength > 65536 || chunk.byteLength > this.expected.byteCount - this.observedBytes) return invalid();
      this.observedBytes += chunk.byteLength; this.bytesHash.update(chunk);
      return this.consume(this.decoder.decode(chunk, { stream: true }));
    } catch { this.failed = true; return invalid(); }
  }
  finish(): CompleteKernelArchiveHeader {
    if (this.failed || this.finished) return invalid();
    this.finished = true;
    try {
      if (this.consume(this.decoder.decode()).length || this.state !== 'done' || this.fragment ||
          this.observedBytes !== this.expected.byteCount || this.bytesHash.digest('hex') !== this.expected.sha256) return invalid();
      const header = decodeCompleteKernelArchiveHeader(this.metadata);
      if (this.manifestHash.digest('hex') !== header.manifestDigest || this.count !== header.cas.entryCount ||
          this.totalBytes !== header.cas.totalBytes || this.entriesHash.digest('hex') !== header.cas.entriesDigest ||
          header.cas.combinedPayloadBytes !== header.database.byteCount + this.totalBytes ||
          header.cas.combinedPayloadBytes > KERNEL_ARCHIVE_MAX_BYTES - this.observedBytes - kernelArchiveSidecarBytes(header)) return invalid();
      return header;
    } catch { this.failed = true; return invalid(); }
  }
  private begin(): void { this.fragment = ''; this.depth = 0; this.quoted = false; this.escaped = false; }
  private end(events: KernelArchiveCasEntry[]): void {
    const bytes = Buffer.from(this.fragment, 'utf8'), value: unknown = parseJsonStrict(this.fragment);
    if (!canonicalJsonBytes(value).equals(bytes)) return invalid();
    if (this.state === 'entry') {
      const entry = decodeKernelArchiveCasEntry(value);
      if (!this.cas || this.count >= this.cas.entryCount || bytes.length > 512 || entry.name <= this.previous ||
          entry.byteCount > this.cas.totalBytes - this.totalBytes || entry.byteCount > KERNEL_ARCHIVE_MAX_BYTES - this.totalBytes) return invalid();
      if (this.count) this.manifestHash.update(','); this.manifestHash.update(bytes);
      this.previous = entry.name; this.count++; this.totalBytes += entry.byteCount;
      this.entriesHash.update(entry.name).update('\0').update(entry.kind).update('\0').update(entry.sha256).update('\0').update(String(entry.byteCount)).update('\n');
      events.push(entry); this.state = 'entry_separator';
    } else {
      const key = FIELDS[this.field]!; this.metadataBytes += bytes.length;
      if (this.metadataBytes > 1048576) return invalid();
      this.metadata[key] = value;
      if (key === 'cas') this.cas = decodeKernelArchiveCasIdentity(value);
      if (key !== 'manifestDigest') this.manifestHash.update(bytes);
      this.field++; this.prefixOffset = 0; this.state = 'prefix';
    }
    this.fragment = '';
  }
  private consume(text: string): readonly KernelArchiveCasEntry[] {
    const events: KernelArchiveCasEntry[] = [];
    for (let offset = 0; offset < text.length;) {
      const character = text[offset]!;
      if (this.state === 'done') return invalid();
      if (this.state === 'prefix') {
        const key = FIELDS[this.field], prefix = key === undefined ? '}' : `${this.field ? ',' : '{'}"${key}":${key === 'entries' ? '[' : ''}`;
        if (character !== prefix[this.prefixOffset]) return invalid();
        this.prefixOffset++; offset++;
        if (this.prefixOffset !== prefix.length) continue;
        if (key !== 'manifestDigest') this.manifestHash.update(prefix);
        this.prefixOffset = 0;
        if (key === undefined) this.state = 'done';
        else if (key === 'entries') this.state = 'first_entry';
        else { this.begin(); this.state = 'value'; }
        continue;
      }
      if (this.state === 'first_entry' || this.state === 'next_entry') {
        if (character === ']') {
          if (this.state !== 'first_entry') return invalid();
          this.manifestHash.update(']'); this.field++; this.state = 'prefix'; offset++; continue;
        }
        this.begin(); this.state = 'entry'; continue;
      }
      if (this.state === 'entry_separator') {
        if (character === ',') this.state = 'next_entry';
        else if (character === ']') { this.manifestHash.update(']'); this.field++; this.state = 'prefix'; }
        else return invalid();
        offset++; continue;
      }
      if (!this.quoted && this.depth === 0 && this.fragment.length && (character === ',' || character === ']' || character === '}')) {
        this.end(events); continue;
      }
      this.fragment += character;
      // A fixed fragment bound also limits byte-at-a-time input; this is not
      // the whole entries array or a parallel metadata vector.
      if (this.fragment.length > (this.state === 'entry' ? 512 : 1048576)) return invalid();
      if (this.quoted) {
        if (this.escaped) this.escaped = false;
        else if (character === '\\') this.escaped = true;
        else if (character === '"') this.quoted = false;
      } else if (character === '"') this.quoted = true;
      else if (character === '{' || character === '[') { if (++this.depth > 31) return invalid(); }
      else if (character === '}' || character === ']') { if (--this.depth < 0) return invalid(); }
      offset++;
    }
    return events;
  }
}
