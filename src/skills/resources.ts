// Bounded AgentSkills reference discovery. No renderer, YAML evaluation,
// schema compiler, network request, script import or execution occurs here.
import path from 'node:path';
import { canonicalSkillPath, SKILL_RESOURCE_COUNT } from '../kernel/skill.js';
import { parseJsonStrict } from '../kernel/json.js';

function invalid(): never { throw new TypeError('skill references are unsupported, unsafe, cyclic or outside the selected root'); }
function text(raw: Uint8Array): string {
  const value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
  if (!Buffer.from(value).equals(Buffer.from(raw)) || value.includes('\0')) invalid(); return value;
}
function local(ref: string, source: string, json = false): string | undefined {
  if (!ref || ref.includes('\\') || /[\u0000-\u001f\u007f]/u.test(ref)) invalid();
  if (ref.startsWith('#')) return undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(ref) || ref.startsWith('//')) {
    if (json || /^file:/iu.test(ref) || /^[A-Za-z]:/u.test(ref)) invalid();
    try { new URL(ref.startsWith('//') ? 'https:' + ref : ref); } catch { invalid(); }
    return undefined; // External URLs are inert data and are never fetched.
  }
  if (ref.startsWith('/') || ref.startsWith('~') || /[?*$\[\]{}]/u.test(ref.split('#')[0]!)) invalid();
  let decoded: string; try { decoded = decodeURIComponent(ref.split('#')[0]!); } catch { return invalid(); }
  if (!decoded || decoded.includes('\\') || decoded.endsWith('/') || /[\u0000-\u001f\u007f]/u.test(decoded)) invalid();
  const normalized = path.posix.normalize(json ? path.posix.join(path.posix.dirname(source), decoded) : decoded);
  if ((!json && decoded.split('/').includes('..')) || normalized.split('/').some(part => part.toLowerCase() === '.git')) invalid();
  const result = canonicalSkillPath(normalized);
  if (json && result === source && ref.includes('#')) return undefined;
  return result;
}
function destination(value: string): string {
  const input = value.trim();
  if (input.startsWith('<')) {
    const end = input.indexOf('>'); if (end < 0) invalid(); const rest = input.slice(end + 1).trim();
    if (rest && !/^(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\))$/u.test(rest)) invalid(); return input.slice(1, end);
  }
  const match = /^(\S+?)(?:[ \t]+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?$/u.exec(input);
  if (!match || /[<>\\]/u.test(match[1]!)) invalid(); return match[1]!;
}
function label(value: string): string { return value.trim().replace(/\s+/gu, ' ').toLowerCase(); }
function* lines(value: string): IterableIterator<string> {
  let start = 0;
  for (;;) { const end = value.indexOf('\n', start); if (end < 0) { yield value.slice(start); return; }
    yield value.slice(start, end); start = end + 1; }
}
const FILE_SUFFIX = /\.(?:md|txt|rst|json|jsonl|ya?ml|toml|csv|tsv|xml|html|css|js|mjs|cjs|ts|tsx|py|sh|bash|sql|svg|png|jpe?g|gif|webp|pdf|tmpl|template)$/iu;
function markdown(source: string, value: string): string[] {
  let body = value, license: string | undefined;
  if (source === 'SKILL.md') {
    const header = /^---[ \t]*\n([\s\S]*?)\n---[ \t]*(?:\n|$)/u.exec(value); if (!header) invalid(); body = value.slice(header[0].length);
    const line = /^license:[ \t]*(.*)$/mu.exec(header[1]!);
    if (line) license = line[1]!.trim().replace(/^(["'])(.*)\1$/u, '$2');
  }
  const refs: string[] = [], definitions = new Map<string, string>(); let declarations = 0;
  const add = (ref: string) => { if (++declarations > 10000) invalid(); const file = local(ref, source);
    if (file !== undefined && !refs.includes(file)) refs.push(file); if (refs.length > SKILL_RESOURCE_COUNT) invalid(); };
  if (license) body = license + '\n' + body;
  let definitionFence = '';
  for (const line of lines(body)) {
    const boundary = /^ {0,3}(`{3,}|~{3,})/u.exec(line);
    if (boundary) { definitionFence = definitionFence ? boundary[1]![0] === definitionFence ? '' : definitionFence : boundary[1]![0]!; continue; }
    if (definitionFence) continue;
    const match = /^ {0,3}\[([^\]\n]+)\]:[ \t]*(.*)$/u.exec(line); if (!match) continue;
    const key = label(match[1]!); if (!key || definitions.has(key)) invalid(); definitions.set(key, destination(match[2]!));
    if (definitions.size > 10000) invalid();
  }
  let fenced = false, fence = '';
  for (const original of lines(body)) {
    const boundary = /^ {0,3}(`{3,}|~{3,})/u.exec(original);
    if (boundary) { if (!fenced) { fenced = true; fence = boundary[1]![0]!; } else if (boundary[1]![0] === fence) fenced = false; continue; }
    if (/^ {0,3}\[[^\]\n]+\]:/u.test(original)) continue;
    let line = original;
    line = line.replace(/\b(?:src|href)\s*=\s*["']([^"']*)["']/giu, (whole: string, ref: string) => {
      if (local(ref, source) !== undefined) invalid(); return ' '.repeat(whole.length);
    });
    if (!fenced) {
      let start = 0; const spans: Array<readonly [number, number]> = [];
      while ((start = line.indexOf('](', start)) >= 0) {
        let end = start + 2, depth = 1, angle = line[end] === '<';
        for (; end < line.length && depth; end++) {
          const char = line[end]!; if (angle) { if (char === '>') angle = false; continue; }
          if (char === '(') { if (++depth > 32) invalid(); } else if (char === ')') depth--;
        }
        if (depth || angle) invalid(); add(destination(line.slice(start + 2, end - 1)));
        const begin = line.lastIndexOf('[', start); if (begin < 0) invalid();
        if (begin > 0 && line[begin - 1] === '\\' || spans.length >= 10000) invalid();
        spans.push([begin, end]); start = end;
      }
      if (spans.length) { const pieces: string[] = []; let offset = 0;
        for (const [begin, end] of spans) { if (begin < offset) invalid(); pieces.push(line.slice(offset, begin), ' '.repeat(end - begin)); offset = end; }
        pieces.push(line.slice(offset)); line = pieces.join(''); }
      // Scan each bracket once. A greedy bracket regexp over a long literal
      // run of unmatched '[' would repeatedly rescan its remaining suffix.
      const pieces: string[] = []; let offset = 0, cursor = 0;
      for (;;) {
        const opening = line.indexOf('[', cursor); if (opening < 0) break;
        const end = line.indexOf(']', opening + 1); if (end < 0) break;
        const begin = line.lastIndexOf('[', end);
        const name = line.slice(begin + 1, end); let id: string | undefined, finish = end + 1;
        if (line[finish] === '[') {
          const last = line.indexOf(']', finish + 1); if (last < 0) invalid();
          id = line.slice(finish + 1, last); finish = last + 1;
        }
        const ref = definitions.get(label(id === undefined || id === '' ? name : id));
        if (id !== undefined && ref === undefined) invalid();
        if (ref !== undefined) {
          if (begin > 0 && line[begin - 1] === '\\') invalid();
          add(ref); pieces.push(line.slice(offset, begin), ' '.repeat(finish - begin)); offset = finish;
        }
        cursor = finish;
      }
      if (pieces.length) { pieces.push(line.slice(offset)); line = pieces.join(''); }
    }
    const explicit = (content: string, code: boolean, standalone = false) => {
      for (const match of content.matchAll(/[^\s<>\[\]{}"'`()]+/gu)) {
        let token = code ? match[0] : match[0].replace(/^[,;!]+|[,;!.]+$/gu, ''); if (!token) continue;
        const locator = /(?::([0-9]+)(?::([0-9]+))?|#L([0-9]+)(?:-L?([0-9]+))?)$/u.exec(token);
        if (locator && (token.slice(0, locator.index).includes('/') || /\.[\p{L}][\p{L}\p{N}_-]*$/u.test(token.slice(0, locator.index))) &&
            locator.slice(1).some(value => value !== undefined && (!Number.isSafeInteger(Number(value)) || Number(value) < 1))) invalid();
        token = token.replace(/(?::[1-9][0-9]*(?::[1-9][0-9]*)?|#L[1-9][0-9]*(?:-L?[1-9][0-9]*)?)$/u, '');
        if (code && /^[A-Za-z][A-Za-z0-9+.-]*\.[A-Za-z0-9.-]*:/u.test(token)) invalid();
        if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(token) && !/^[A-Za-z]:[\\/]/u.test(token)) { if (/^file:/iu.test(token)) invalid(); else continue; }
        const slash = token.includes('/') || token.includes('\\');
        if (/^(?:\.\.?\/|\/|~\/|[A-Za-z]:[\\/]|\$[^/]*\/)/u.test(token) ||
            slash && (code || FILE_SUFFIX.test(token) || /^(?:scripts|references|assets|templates)\//u.test(token)) ||
            (code || standalone) && /\.[\p{L}][\p{L}\p{N}_-]*$/u.test(token)) add(token);
      }
    };
    if (fenced) explicit(line, true);
    else { line = line.replace(/`([^`\n]+)`/gu, (whole: string, content: string) => { explicit(content, true); return ' '.repeat(whole.length); });
      explicit(line, false, !/\s/u.test(line.trim())); }
  }
  if (fenced) invalid(); return refs;
}

/** Markdown uses skill-root-relative paths. Fixed JSON $ref paths alone are
 * relative to their own file. Unsupported URI rebasing refuses capture. */
export function skillResourceReferences(sourcePath: string, raw: Uint8Array): readonly string[] {
  canonicalSkillPath(sourcePath); let result: string[] = [];
  if (sourcePath === 'SKILL.md' || /\.md$/iu.test(sourcePath)) result = markdown(sourcePath, text(raw));
  else if (/\.json$/iu.test(sourcePath)) {
    if (raw.byteLength > 1048576) invalid(); const pending = [{ value: parseJsonStrict(text(raw)), depth: 0 }]; let count = 0;
    while (pending.length) {
      const item = pending.pop()!; if (++count > 10000 || item.depth > 32) invalid(); if (!item.value || typeof item.value !== 'object') continue;
      const record = item.value as Record<string, unknown>;
      if ((Object.hasOwn(record, '$id') && (typeof record.$id !== 'string' || record.$id && !record.$id.startsWith('#'))) ||
          Object.hasOwn(record, '$dynamicRef') || Object.hasOwn(record, '$recursiveRef')) invalid();
      if (Object.hasOwn(record, '$ref')) { if (typeof record.$ref !== 'string') invalid(); const target = local(record.$ref, sourcePath, true);
        if (target !== undefined && !result.includes(target)) result.push(target); }
      for (const child of Object.values(record)) pending.push({ value: child, depth: item.depth + 1 });
    }
  }
  if (result.length > SKILL_RESOURCE_COUNT) invalid(); return Object.freeze(result);
}

export function validateFrozenSkillResourceGraph(files: ReadonlyMap<string, Uint8Array>, resources: readonly string[]): void {
  const edges = new Map<string, readonly string[]>();
  for (const [name, raw] of files) edges.set(name, skillResourceReferences(name, raw));
  validateFrozenSkillReferenceEdges(edges, resources);
}

/** The installer may stream opaque binary bytes and separately retain these
 * small, derived reference edges. Every input body still has its own complete
 * signed byte/EOF verification; no empty stand-in body is used as evidence. */
export function validateFrozenSkillReferenceEdges(edges: ReadonlyMap<string, readonly string[]>, resources: readonly string[]): void {
  if (resources.length > SKILL_RESOURCE_COUNT || edges.size !== resources.length + 1) invalid();
  const visiting = new Set<string>(), done = new Set<string>();
  const visit = (name: string, depth: number) => {
    if (depth > 32 || visiting.has(name)) invalid(); if (done.has(name)) return;
    const children = edges.get(name); if (!children) invalid(); visiting.add(name);
    for (const child of children) visit(child, depth + 1);
    visiting.delete(name); done.add(name); if (done.size > SKILL_RESOURCE_COUNT + 1) invalid();
  };
  visit('SKILL.md', 0);
  if (done.size !== edges.size || resources.some(name => name === 'SKILL.md' || !done.has(name))) invalid();
}
