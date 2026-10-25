import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { FrozenIgnoreRuleV1, FrozenIgnoreRulesV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog } from '../state/artifacts.js';
import { KernelStorageError } from '../state/errors.js';

// Fixed parser/data ceilings, not a file-read permission or an increased
// workspace/resource budget. Original capture limits apply independently.
const SOURCE_BYTES = 1024 * 1024, TOTAL_BYTES = 16 * SOURCE_BYTES, SOURCES = 4096, RULES = 65536;
type Input = Readonly<{ kind: 'git_info_exclude' | 'gitignore'; path: string; bytes: Uint8Array }>;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedLength = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
const typedOffset = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset')!.get!;
const typedBuffer = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!;
function invalid(): never { throw new TypeError('frozen ignore rules have an invalid closed source or rule'); }
function record(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (required.some(key => !Object.hasOwn(fields, key)) || Reflect.ownKeys(fields).some(key => typeof key !== 'string' ||
      !required.includes(key) && !optional.includes(key) || !fields[key]!.enumerable || !Object.hasOwn(fields[key]!, 'value') ||
      fields[key]!.value === undefined)) return invalid();
  return value as Record<string, unknown>;
}
function digest(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 64 || !/^[0-9a-f]+$/u.test(value)) return invalid(); return value;
}
function canonicalPath(value: unknown): string {
  if (typeof value !== 'string' || !value || value !== value.normalize('NFC') || Buffer.from(value).toString('utf8') !== value ||
      Buffer.byteLength(value) > 4096 || value.includes('\\') || value.includes('\0') ||
      value.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255 || part.toLowerCase() === '.git')) return invalid();
  return value;
}
function sourcePath(kind: unknown, value: unknown): { path: string; base: string } {
  if (kind === 'git_info_exclude' && value === '.git/info/exclude') return { path: value, base: '' };
  if (kind !== 'gitignore') return invalid();
  const path = canonicalPath(value), parts = path.split('/');
  if (parts.pop() !== '.gitignore') return invalid(); return { path, base: parts.join('/') };
}
function integer(value: unknown, maximum: number, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) return invalid(); return value;
}
function array(value: unknown, maximum: number): unknown[] {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !Array.isArray(value) || value.length > maximum ||
      Object.getPrototypeOf(value) !== Array.prototype) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== value.length + 1) return invalid();
  for (let i = 0; i < value.length; i++) {
    const field = fields[String(i)];
    if (!field || !field.enumerable || !Object.hasOwn(field, 'value')) return invalid();
  }
  return value;
}
function sourceBytes(value: unknown): Buffer {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !types.isUint8Array(value)) return invalid();
  // Native typed-array accessors, never an own byteLength/buffer getter or
  // caller iterator. This copies inert data, not a physical-file snapshot.
  const length = typedLength.call(value) as number;
  if (length > SOURCE_BYTES) return invalid();
  return Buffer.from(new Uint8Array(typedBuffer.call(value) as ArrayBuffer, typedOffset.call(value) as number, length));
}
function compareSources(left: { kind: string; path: string }, right: { kind: string; path: string }): number {
  if (left.kind !== right.kind) return left.kind === 'git_info_exclude' ? -1 : 1;
  return left.path.split('/').length - right.path.split('/').length || Buffer.compare(Buffer.from(left.path), Buffer.from(right.path));
}
function escaped(value: string, at: number): boolean {
  let count = 0; for (let i = at - 1; i >= 0 && value[i] === '\\'; i--) count++; return count % 2 === 1;
}
function parse(bytes: Uint8Array, sourceIndex: number, baseDirectory: string, firstOrder: number): FrozenIgnoreRuleV1[] {
  if (types.isProxy(bytes) || !(bytes instanceof Uint8Array) || bytes.byteLength > SOURCE_BYTES) return invalid();
  let text: string; try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return invalid(); }
  if (text.includes('\0')) return invalid();
  const result: FrozenIgnoreRuleV1[] = [];
  for (const [line, original] of text.split('\n').entries()) {
    let pattern = original.endsWith('\r') ? original.slice(0, -1) : original;
    while (pattern.endsWith(' ') && !escaped(pattern, pattern.length - 1)) pattern = pattern.slice(0, -1);
    if (!pattern || pattern.startsWith('#')) continue;
    const negated = pattern.startsWith('!'); if (negated) pattern = pattern.slice(1);
    if (!pattern) continue;
    const directoryOnly = pattern.endsWith('/') && !escaped(pattern, pattern.length - 1);
    if (directoryOnly) pattern = pattern.slice(0, -1);
    const anchored = pattern.startsWith('/'); if (anchored) pattern = pattern.slice(1);
    if (!pattern) continue;
    if (firstOrder + result.length >= RULES) return invalid();
    result.push({ order: firstOrder + result.length, sourceIndex, sourceLine: line + 1, baseDirectory, negated, directoryOnly, anchored, pattern });
  }
  return result;
}

/** Pure compilation of already-authorized frozen bytes. This neither opens
 * paths nor proves their descriptors, grant, trusted Git index or native scope. */
export function compileFrozenIgnoreRules(input: readonly Input[], repositoryIdentityDigest: string): FrozenIgnoreRulesV1 {
  digest(repositoryIdentityDigest);
  const sources = array(input, SOURCES).map(value => {
    const item = record(value, ['kind', 'path', 'bytes']) as unknown as Input;
    const path = sourcePath(item.kind, item.path);
    return { kind: item.kind, ...path, bytes: sourceBytes(item.bytes) };
  }).sort(compareSources);
  if (new Set(sources.map(item => item.path)).size !== sources.length || sources.reduce((total, item) => total + item.bytes.byteLength, 0) > TOTAL_BYTES) return invalid();
  const result: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1',
    repositoryIdentityDigest, sources: [], rules: [], rulesDigest: '' };
  for (const [index, source] of sources.entries()) {
    const hash = sha256Bytes(source.bytes);
    result.sources.push({ index, kind: source.kind, canonicalRootRelativePath: source.path, baseDirectory: source.base, contentRef: hash, contentDigest: hash });
    result.rules.push(...parse(source.bytes, index, source.base, result.rules.length));
  }
  result.rulesDigest = digestOmitting(result, 'rulesDigest'); return immutableSnapshot(result);
}

/** Closed metadata validation. The owning retained reader must additionally
 * read every contentRef and compare its exact compilation with this artifact. */
export function validateFrozenIgnoreRules(value: unknown): FrozenIgnoreRulesV1 {
  const data = record(value, ['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest'], ['repositoryIdentityDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-frozen-ignore-rules-v1' || data.matcherVersion !== 'cliq-git-wildmatch-v1' ||
      typeof data.rulesDigest !== 'string') return invalid();
  const sources = array(data.sources, SOURCES), rules = array(data.rules, RULES);
  if (data.repositoryIdentityDigest === undefined) {
    if (sources.length || rules.length) return invalid();
  } else digest(data.repositoryIdentityDigest);
  let previous: { kind: string; path: string } | undefined;
  const bases: string[] = [];
  for (const [index, item] of sources.entries()) {
    const source = record(item, ['index', 'kind', 'canonicalRootRelativePath', 'baseDirectory', 'contentRef', 'contentDigest']);
    const path = sourcePath(source.kind, source.canonicalRootRelativePath), current = { kind: source.kind as string, path: path.path };
    if (source.index !== index || source.baseDirectory !== path.base || digest(source.contentRef) !== digest(source.contentDigest) ||
        previous && compareSources(previous, current) >= 0) return invalid();
    previous = current; bases.push(path.base);
  }
  let previousSource = -1, previousLine = 0;
  for (const [order, item] of rules.entries()) {
    const rule = record(item, ['order', 'sourceIndex', 'sourceLine', 'baseDirectory', 'negated', 'directoryOnly', 'anchored', 'pattern']);
    const index = integer(rule.sourceIndex, bases.length - 1), line = integer(rule.sourceLine, SOURCE_BYTES + 1, 1);
    if (rule.order !== order || index < previousSource || index === previousSource && line <= previousLine || rule.baseDirectory !== bases[index] ||
        typeof rule.negated !== 'boolean' || typeof rule.directoryOnly !== 'boolean' || typeof rule.anchored !== 'boolean' ||
        typeof rule.pattern !== 'string' || !rule.pattern || rule.pattern.includes('\0') || rule.pattern.includes('\n') ||
        Buffer.from(rule.pattern).toString('utf8') !== rule.pattern || Buffer.byteLength(rule.pattern) > SOURCE_BYTES) return invalid();
    previousSource = index; previousLine = line;
  }
  if (digest(data.rulesDigest) !== digestOmitting(data, 'rulesDigest')) return invalid();
  return immutableSnapshot(data as FrozenIgnoreRulesV1);
}

type Token = { kind: 'literal'; value: number } | { kind: 'one' } | { kind: 'star' } | { kind: 'directories' } | { kind: 'all' } |
  { kind: 'class'; negated: boolean; ranges: readonly [number, number][]; classes: readonly string[] };
const CLASSES: Readonly<Record<string, (byte: number) => boolean>> = Object.freeze(Object.assign(Object.create(null), {
  alnum: (c: number) => c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122,
  alpha: (c: number) => c >= 65 && c <= 90 || c >= 97 && c <= 122, blank: (c: number) => c === 9 || c === 32,
  cntrl: (c: number) => c < 32 || c === 127, digit: (c: number) => c >= 48 && c <= 57,
  graph: (c: number) => c >= 33 && c <= 126, lower: (c: number) => c >= 97 && c <= 122,
  print: (c: number) => c >= 32 && c <= 126, punct: (c: number) => c >= 33 && c <= 126 &&
    !(c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122),
  space: (c: number) => c === 32 || c >= 9 && c <= 13, upper: (c: number) => c >= 65 && c <= 90,
  xdigit: (c: number) => c >= 48 && c <= 57 || c >= 65 && c <= 70 || c >= 97 && c <= 102
}));
function tokens(pattern: string): Token[] | undefined {
  const bytes = Buffer.from(pattern), result: Token[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]!;
    if (byte === 92) { if (++i === bytes.length) return undefined; result.push({ kind: 'literal', value: bytes[i]! }); }
    else if (byte === 63) result.push({ kind: 'one' });
    else if (byte === 42) {
      const start = i; while (bytes[i + 1] === 42) i++;
      const separated = i > start && (start === 0 || bytes[start - 1] === 47);
      if (separated && bytes[i + 1] === 47) { result.push({ kind: 'directories' }); i++; }
      else result.push({ kind: separated && i + 1 === bytes.length ? 'all' : 'star' });
    } else if (byte === 91) {
      let at = i + 1, negated = false;
      if (bytes[at] === 33 || bytes[at] === 94) { negated = true; at++; }
      const ranges: [number, number][] = [], classes: string[] = []; let closed = false;
      if (bytes[at] === 93) { ranges.push([93, 93]); at++; }
      while (at < bytes.length) {
        if (bytes[at] === 93) { closed = true; break; }
        if (bytes[at] === 91 && bytes[at + 1] === 58) {
          const end = bytes.indexOf(Buffer.from(':]'), at + 2);
          if (end < 0) return undefined; const name = bytes.subarray(at + 2, end).toString('ascii');
          if (!Object.hasOwn(CLASSES, name)) return undefined; classes.push(name); at = end + 2; continue;
        }
        let first = bytes[at++]!; if (first === 92) { if (at === bytes.length) return undefined; first = bytes[at++]!; }
        if (bytes[at] === 45 && bytes[at + 1] !== 93 && at + 1 < bytes.length) {
          at++; let last = bytes[at++]!; if (last === 92) { if (at === bytes.length) return undefined; last = bytes[at++]!; }
          ranges.push([first, last]);
        } else ranges.push([first, first]);
      }
      if (!closed) return undefined; result.push({ kind: 'class', negated, ranges, classes }); i = at;
    } else result.push({ kind: 'literal', value: byte });
  }
  return result;
}
function matches(input: readonly Token[] | undefined, path: string): boolean {
  if (!input) return false;
  const bytes = Buffer.from(path); let before = new Uint8Array(bytes.length + 1); before[0] = 1;
  for (const token of input) {
    const after = new Uint8Array(bytes.length + 1);
    if (token.kind === 'star' || token.kind === 'all' || token.kind === 'directories') {
      after[0] = before[0]!; let reachable = before[0] === 1;
      for (let j = 1; j <= bytes.length; j++) {
        if (token.kind === 'directories') { after[j] = before[j] || (reachable && bytes[j - 1] === 47 ? 1 : 0); reachable ||= before[j] === 1; }
        else after[j] = before[j] || (after[j - 1] && (token.kind === 'all' || bytes[j - 1] !== 47) ? 1 : 0);
      }
    } else {
      for (let j = 1; j <= bytes.length; j++) {
        if (!before[j - 1]) continue;
        const byte = bytes[j - 1]!;
        if (token.kind === 'literal' ? byte === token.value : token.kind === 'one' ? byte !== 47 :
          byte !== 47 && (token.ranges.some(([a, b]) => byte >= a && byte <= b) || token.classes.some(name => CLASSES[name]!(byte))) !== token.negated) after[j] = 1;
      }
    }
    before = after;
  }
  return before[bytes.length] === 1;
}

/** One immutable-data matcher per owning validation/capture walk. There is no
 * cross-operation cache and the result is classification, never permission. */
export function createFrozenIgnoreMatcher(value: FrozenIgnoreRulesV1): (path: string, directory: boolean) => boolean {
  const rules = validateFrozenIgnoreRules(value).rules.map(rule => ({ ...rule, tokens: tokens(rule.pattern) }));
  return (input, directory) => {
    const path = canonicalPath(input); if (typeof directory !== 'boolean') return invalid();
    const parts = path.split('/');
    for (let end = 1; end <= parts.length; end++) {
      const candidate = parts.slice(0, end).join('/'), isDirectory = end < parts.length || directory;
      let ignored = false;
      for (const rule of rules) {
        if (rule.directoryOnly && !isDirectory) continue;
        if (rule.baseDirectory && !candidate.startsWith(`${rule.baseDirectory}/`)) continue;
        const relative = rule.baseDirectory ? candidate.slice(rule.baseDirectory.length + 1) : candidate;
        if (matches(rule.tokens, rule.anchored || rule.pattern.includes('/') ? relative : relative.slice(relative.lastIndexOf('/') + 1))) ignored = !rule.negated;
      }
      // Git cannot re-include a descendant of an excluded directory. This is
      // essential even when the retained deeper source was independently read.
      if (ignored) return true;
    }
    return false;
  };
}
export function isFrozenPathIgnored(value: FrozenIgnoreRulesV1, path: string, directory: boolean): boolean {
  return createFrozenIgnoreMatcher(value)(path, directory);
}

/** Compare a retained artifact with all-and-only exact source bytes already
 * read by its owning bounded CAS reader; an artifact digest alone is not parse
 * provenance. Non-Git has only its canonical empty form. */
export function assertFrozenIgnoreContents(value: FrozenIgnoreRulesV1, sources: readonly Input[]): void {
  const actual = validateFrozenIgnoreRules(value);
  if (!actual.repositoryIdentityDigest) { if (sources.length) return invalid(); return; }
  if (!canonicalJsonBytes(actual).equals(canonicalJsonBytes(compileFrozenIgnoreRules(sources, actual.repositoryIdentityDigest)))) return invalid();
}

/** Full retained data closure, with the original catalog's cancellation and
 * descriptor joins. No mutable rule file, ambient config, Git process or
 * current grant is consulted, and no source/read/native authority is returned. */
export type FrozenIgnoreReader = Pick<ArtifactCatalog, 'readCanonical' | 'readBoundedBytes' | 'assertReadActive'> & {
  withReadSignal(signal: AbortSignal): FrozenIgnoreReader;
};
export async function readFrozenIgnoreRules(artifacts: FrozenIgnoreReader, ref: string, repositoryIdentityDigest?: string,
  signal?: AbortSignal): Promise<FrozenIgnoreRulesV1> {
  digest(ref); if (repositoryIdentityDigest !== undefined) digest(repositoryIdentityDigest);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  const raw = await reads.readCanonical(ref);
  if (canonicalSha256(raw) !== ref) throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore artifact is not canonical JSON');
  let rules: FrozenIgnoreRulesV1;
  try { rules = validateFrozenIgnoreRules(raw); }
  catch (cause) { throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules have invalid fields or digest', { cause }); }
  if (rules.repositoryIdentityDigest !== repositoryIdentityDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules have invalid fields for their owning source repository identity');
  const sources: Input[] = []; let total = 0;
  for (const source of rules.sources) {
    const bytes = await reads.readBoundedBytes(source.contentRef, Math.min(SOURCE_BYTES, TOTAL_BYTES - total));
    total += bytes.byteLength;
    reads.assertReadActive();
    if (sha256Bytes(bytes) !== source.contentDigest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore source bytes differ from their digest');
    sources.push({ kind: source.kind, path: source.canonicalRootRelativePath, bytes });
  }
  try { assertFrozenIgnoreContents(rules, sources); }
  catch (cause) { throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen ignore rules differ from their complete retained contents', { cause }); }
  reads.assertReadActive(); return rules;
}
