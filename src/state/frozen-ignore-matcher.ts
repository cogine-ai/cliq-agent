import { normalizeCanonicalText } from '../kernel/canonical.js';
import type { FrozenIgnoreRuleV1, FrozenIgnoreRulesV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

type Token =
  | { kind: 'literal'; byte: number }
  | { kind: 'one' }
  | { kind: 'star' }
  | { kind: 'any-depth' }
  | { kind: 'directory-depth' }
  | { kind: 'class'; members: Uint8Array };

const SLASH = 0x2f;
const BACKSLASH = 0x5c;
const STAR = 0x2a;
const QUESTION = 0x3f;
const OPEN_CLASS = 0x5b;
const CLOSE_CLASS = 0x5d;

function asciiClass(name: string, byte: number): boolean | undefined {
  const digit = byte >= 0x30 && byte <= 0x39;
  const upper = byte >= 0x41 && byte <= 0x5a;
  const lower = byte >= 0x61 && byte <= 0x7a;
  const alpha = upper || lower;
  const alnum = alpha || digit;
  switch (name) {
    case 'alnum': return alnum;
    case 'alpha': return alpha;
    case 'blank': return byte === 0x09 || byte === 0x20;
    case 'cntrl': return byte <= 0x1f || byte === 0x7f;
    case 'digit': return digit;
    case 'graph': return byte >= 0x21 && byte <= 0x7e;
    case 'lower': return lower;
    case 'print': return byte >= 0x20 && byte <= 0x7e;
    case 'punct': return byte >= 0x21 && byte <= 0x7e && !alnum;
    case 'space': return byte === 0x20 || (byte >= 0x09 && byte <= 0x0d);
    case 'upper': return upper;
    case 'xdigit': return digit || (byte >= 0x41 && byte <= 0x46) ||
      (byte >= 0x61 && byte <= 0x66);
    default: return undefined;
  }
}

function parseClass(pattern: Buffer, start: number): { token: Token; next: number } | undefined {
  let index = start + 1;
  const negated = pattern[index] === 0x21 || pattern[index] === 0x5e;
  if (negated) index += 1;
  const members = new Uint8Array(256);
  let previous = 0;
  let first = true;
  for (; index < pattern.length; index += 1) {
    let byte = pattern[index]!;
    if (byte === CLOSE_CLASS && !first) {
      if (negated) {
        for (let value = 0; value < 256; value += 1) members[value] = members[value] ? 0 : 1;
      }
      return { token: { kind: 'class', members }, next: index + 1 };
    }
    first = false;
    if (byte === BACKSLASH) {
      index += 1;
      if (index >= pattern.length) return undefined;
      byte = pattern[index]!;
      members[byte] = 1;
      previous = byte;
      continue;
    }
    if (byte === 0x2d && previous !== 0 &&
        index + 1 < pattern.length && pattern[index + 1] !== CLOSE_CLASS) {
      index += 1;
      byte = pattern[index]!;
      if (byte === BACKSLASH) {
        index += 1;
        if (index >= pattern.length) return undefined;
        byte = pattern[index]!;
      }
      for (let value = previous; value <= byte; value += 1) members[value] = 1;
      previous = 0;
      continue;
    }
    if (byte === OPEN_CLASS && pattern[index + 1] === 0x3a) {
      const end = pattern.indexOf(CLOSE_CLASS, index + 2);
      if (end < 0) return undefined;
      if (end >= index + 3 && pattern[end - 1] === 0x3a) {
        const name = pattern.subarray(index + 2, end - 1).toString('ascii');
        if (asciiClass(name, 0) === undefined) return undefined;
        for (let value = 0; value < 256; value += 1) {
          if (asciiClass(name, value)) members[value] = 1;
        }
        index = end;
        previous = 0;
        continue;
      }
      // A bracket without the POSIX ':]' terminator is an ordinary '['.
    }
    members[byte] = 1;
    previous = byte;
  }
  return undefined;
}

/** Compile the fixed, case-sensitive Git 2.45 wildmatch profile to a byte NFA.
 * The NFA avoids regexp backtracking on workspace-controlled patterns. */
function tokenize(patternText: string, pathname: boolean): Token[] | undefined {
  const pattern = Buffer.from(patternText, 'utf8');
  const tokens: Token[] = [];
  for (let index = 0; index < pattern.length;) {
    const byte = pattern[index]!;
    if (byte === BACKSLASH) {
      if (index + 1 >= pattern.length) return undefined;
      tokens.push({ kind: 'literal', byte: pattern[index + 1]! });
      index += 2;
    } else if (byte === STAR) {
      let end = index + 1;
      while (pattern[end] === STAR) end += 1;
      const boundary = index === 0 || pattern[index - 1] === SLASH;
      if (pathname && end - index >= 2 && boundary && pattern[end] === SLASH) {
        tokens.push({ kind: 'directory-depth' });
        index = end + 1;
      } else if (pathname && end - index >= 2 && boundary &&
          (end === pattern.length || (pattern[end] === BACKSLASH && pattern[end + 1] === SLASH))) {
        tokens.push({ kind: 'any-depth' });
        index = end;
      } else {
        tokens.push({ kind: 'star' });
        index = end;
      }
    } else if (byte === QUESTION) {
      tokens.push({ kind: 'one' });
      index += 1;
    } else if (byte === OPEN_CLASS) {
      const parsed = parseClass(pattern, index);
      if (parsed === undefined) return undefined;
      tokens.push(parsed.token);
      index = parsed.next;
    } else {
      tokens.push({ kind: 'literal', byte });
      index += 1;
    }
  }
  return tokens;
}

/** State is tokenIndex * 2 + phase. Only directory-depth uses phase 1: after
 * consuming a byte it must see a slash before it can leave the globstar. */
function matchTokens(tokens: readonly Token[], text: Buffer, pathname: boolean): boolean {
  const close = (states: Set<number>): Set<number> => {
    const pending = [...states];
    for (let offset = 0; offset < pending.length; offset += 1) {
      const state = pending[offset]!;
      const index = Math.floor(state / 2);
      const kind = tokens[index]?.kind;
      if (kind === 'star' || kind === 'any-depth' ||
          (kind === 'directory-depth' && state % 2 === 0)) {
        const successor = (index + 1) * 2;
        if (!states.has(successor)) {
          states.add(successor);
          pending.push(successor);
        }
      }
    }
    return states;
  };
  let active = close(new Set([0]));
  for (const byte of text) {
    const next = new Set<number>();
    for (const state of active) {
      const index = Math.floor(state / 2);
      const successor = (index + 1) * 2;
      const token = tokens[index];
      if (token === undefined) continue;
      switch (token.kind) {
        case 'literal':
          if (token.byte === byte) next.add(successor);
          break;
        case 'one':
          if (!pathname || byte !== SLASH) next.add(successor);
          break;
        case 'class':
          if ((!pathname || byte !== SLASH) && token.members[byte]) {
            next.add(successor);
          }
          break;
        case 'star':
          if (!pathname || byte !== SLASH) next.add(state);
          break;
        case 'any-depth':
          next.add(state);
          break;
        case 'directory-depth':
          next.add(index * 2 + 1);
          if (byte === SLASH) next.add(successor);
          break;
      }
    }
    active = close(next);
    if (active.size === 0) return false;
  }
  return active.has(tokens.length * 2);
}

/** This low-level matcher operates on UTF-8 bytes, as Git wildmatch does. */
export function matchGitWildmatchV1(pattern: string, text: string, pathname: boolean): boolean {
  const tokens = tokenize(pattern, pathname);
  return tokens !== undefined && matchTokens(tokens, Buffer.from(text, 'utf8'), pathname);
}

type CompiledRule = FrozenIgnoreRuleV1 & { tokens: Token[] | undefined };

function assertCanonicalPath(value: string): void {
  let normalized: string;
  try {
    normalized = normalizeCanonicalText(value);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'ignore match path has invalid Unicode');
  }
  const components = value.split('/');
  if (normalized !== value || value.includes('\\') || Buffer.byteLength(value, 'utf8') > 4096 ||
      components.some((component) => component === '' || component === '.' || component === '..' ||
        Buffer.byteLength(component, 'utf8') > 255)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'ignore match path is not canonical root-relative text');
  }
}

/** Compile once for source classification; an ignored parent remains excluded
 * even when a later negation names its child. Hard exclusions and tracked Git
 * entries are checked by separate classifiers before this evaluator. */
export function compileFrozenIgnoreMatcher(manifest: FrozenIgnoreRulesV1):
  (canonicalRootRelativePath: string, isDirectory: boolean) => boolean {
  const rules: CompiledRule[] = manifest.rules.map((rule) => ({
    ...rule,
    tokens: tokenize(rule.pattern, rule.anchored)
  }));
  const directoryCache = new Map<string, boolean>();
  const directIgnored = (candidate: string, isDirectory: boolean): boolean => {
    let ignored = false;
    for (const rule of rules) {
      if (rule.directoryOnly && !isDirectory || rule.tokens === undefined) continue;
      const relative = rule.baseDirectory === '' ? candidate :
        candidate.startsWith(`${rule.baseDirectory}/`)
          ? candidate.slice(rule.baseDirectory.length + 1) : undefined;
      if (relative === undefined) continue;
      const subject = rule.anchored ? relative : relative.slice(relative.lastIndexOf('/') + 1);
      if (matchTokens(rule.tokens, Buffer.from(subject, 'utf8'), rule.anchored)) {
        ignored = !rule.negated;
      }
    }
    return ignored;
  };
  const directoryIgnored = (directory: string): boolean => {
    const cached = directoryCache.get(directory);
    if (cached !== undefined) return cached;
    const split = directory.lastIndexOf('/');
    const ignored = (split >= 0 && directoryIgnored(directory.slice(0, split))) ||
      directIgnored(directory, true);
    directoryCache.set(directory, ignored);
    return ignored;
  };
  return (canonicalRootRelativePath, isDirectory) => {
    assertCanonicalPath(canonicalRootRelativePath);
    if (isDirectory) return directoryIgnored(canonicalRootRelativePath);
    const split = canonicalRootRelativePath.lastIndexOf('/');
    return (split >= 0 && directoryIgnored(canonicalRootRelativePath.slice(0, split))) ||
      directIgnored(canonicalRootRelativePath, false);
  };
}
