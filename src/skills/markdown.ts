// Pure SKILL.md parsing shared by legacy discovery and frozen capture.
// No configuration, filesystem, environment or executable loading.
import type { ParsedSkillMarkdown, SkillDiagnostic, SkillManifest } from './types.js';
import { parseJsonStrict } from '../kernel/json.js';

const KNOWN_FRONTMATTER_FIELDS = new Set([
  'name',
  'description',
  'license',
  'compatibility',
  'metadata',
  'allowed-tools'
]);

export function isValidSkillName(name: string) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
}

export function diagnostic(level: SkillDiagnostic['level'], code: string, message: string, source?: string): SkillDiagnostic {
  return {
    level,
    code,
    message,
    ...(source ? { source } : {})
  };
}

function stripQuotes(value: string) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseInlineArray(value: string) {
  const trimmed = value.trim();
  if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) {
    return null;
  }
  const body = trimmed.slice(1, -1).trim();
  if (!body) {
    return [];
  }
  return body.split(',').map((part) => stripQuotes(part)).filter(Boolean);
}

function parseFrontmatterBlock(lines: string[], start: number) {
  const block: string[] = [];
  let index = start;
  while (index < lines.length) {
    const line = lines[index]!;
    if (line.trim() && !/^\s/.test(line)) {
      break;
    }
    block.push(line);
    index += 1;
  }
  return { block, nextIndex: index };
}

function parseMetadataBlock(block: string[]) {
  const metadata: Record<string, string> = {};
  for (const line of block) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const match = /^([^:]+):\s*(.*)$/.exec(trimmed);
    if (!match) {
      continue;
    }
    metadata[match[1]!.trim()] = stripQuotes(match[2] ?? '');
  }
  return metadata;
}

function parseAllowedToolsBlock(block: string[]) {
  const tools: string[] = [];
  for (const line of block) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const match = /^-\s*(.+)$/.exec(trimmed);
    if (match) {
      tools.push(stripQuotes(match[1]!));
    }
  }
  return tools;
}

export function parseSkillMarkdown(raw: string, source = 'SKILL.md'): ParsedSkillMarkdown {
  const match = raw.match(/^\uFEFF?---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)([\s\S]*)$/);
  const diagnostics: SkillDiagnostic[] = [];
  if (!match) {
    return {
      manifest: { name: '', description: '' },
      prompt: '',
      diagnostics: [diagnostic('error', 'missing-frontmatter', 'Skill file must begin with frontmatter', source)]
    };
  }

  const manifest: SkillManifest = { name: '', description: '' };
  const frontmatter = match[1] ?? '';
  const lines = frontmatter.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index]!;
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    if (/^\s/.test(rawLine)) {
      diagnostics.push(diagnostic('warning', 'ignored-frontmatter-line', `Ignoring nested frontmatter line: ${trimmed}`, source));
      continue;
    }

    const separator = trimmed.indexOf(':');
    if (separator === -1) {
      diagnostics.push(diagnostic('error', 'invalid-frontmatter-line', `Invalid frontmatter line: ${trimmed}`, source));
      continue;
    }

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    if (!KNOWN_FRONTMATTER_FIELDS.has(key)) {
      diagnostics.push(diagnostic('warning', 'unknown-frontmatter-field', `Ignoring unknown skill field: ${key}`, source));
      continue;
    }

    if (key === 'metadata') {
      if (value) {
        diagnostics.push(diagnostic('warning', 'invalid-metadata', 'metadata must be an indented map', source));
        continue;
      }
      const { block, nextIndex } = parseFrontmatterBlock(lines, index + 1);
      manifest.metadata = parseMetadataBlock(block);
      index = nextIndex - 1;
      continue;
    }

    if (key === 'allowed-tools') {
      const inline = parseInlineArray(value);
      if (inline) {
        manifest.allowedTools = inline;
      } else if (value) {
        manifest.allowedTools = [stripQuotes(value)];
      } else {
        const { block, nextIndex } = parseFrontmatterBlock(lines, index + 1);
        manifest.allowedTools = parseAllowedToolsBlock(block);
        index = nextIndex - 1;
      }
      continue;
    }

    const scalar = stripQuotes(value);
    if (key === 'name') {
      manifest.name = scalar;
    } else if (key === 'description') {
      manifest.description = scalar;
    } else if (key === 'license') {
      manifest.license = scalar;
    } else if (key === 'compatibility') {
      manifest.compatibility = scalar;
    }
  }

  if (!manifest.name) {
    diagnostics.push(diagnostic('error', 'missing-name', 'Skill file must declare a name', source));
  } else if (!isValidSkillName(manifest.name)) {
    diagnostics.push(diagnostic('error', 'invalid-name', `Invalid skill name: ${manifest.name}`, source));
  }
  if (!manifest.description) {
    diagnostics.push(diagnostic('error', 'missing-description', 'Skill file must declare a description', source));
  }

  const prompt = (match[2] ?? '').trim();
  if (!prompt) {
    diagnostics.push(diagnostic('warning', 'empty-body', 'Skill prompt body is empty', source));
  }

  return { manifest, prompt, diagnostics };
}

/** Installed capture's bounded standard frontmatter subset. It accepts
 * literal/folded strings and the standard metadata string map; unsupported
 * YAML evaluation features refuse rather than change the selected closure.
 * The legacy discovery parser above retains its original compatibility. */
export function parseFrozenSkillMarkdown(raw: string): ParsedSkillMarkdown {
  const invalid = (): never => { throw new TypeError('frozen skill frontmatter is not supported AgentSkills string metadata'); };
  const match = /^---[ \t]*\n([\s\S]*?)\n---[ \t]*(?:\n|$)([\s\S]*)$/u.exec(raw); if (!match) invalid();
  const lines = match![1]!.split('\n'), values = new Map<string, string>(), metadata: Record<string, string> = Object.create(null);
  const scalar = (input: string): string => {
    const value = input.trim();
    if (value.startsWith('"')) { const decoded = parseJsonStrict(value); if (typeof decoded !== 'string') invalid(); return decoded as string; }
    if (value.startsWith("'")) { if (!/^'(?:[^']|'')*'$/u.test(value)) invalid(); return value.slice(1, -1).replaceAll("''", "'"); }
    if (!value || /^[!&*\[\]{},>|%@`]/u.test(value) || /:\s/u.test(value) || /^(?:true|false|null|~|[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?)$/iu.test(value)) invalid();
    return value.replace(/[ \t]+#.*$/u, '').trimEnd();
  };
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!; if (!line.trim() || /^\s*#/u.test(line)) continue;
    const field = /^([a-z][a-z-]*):[ \t]*(.*)$/u.exec(line);
    if (!field || !KNOWN_FRONTMATTER_FIELDS.has(field[1]!) || values.has(field[1]!)) invalid();
    const key = field![1]!, value = field![2]!; values.set(key, '');
    if (key === 'metadata') {
      if (value) invalid();
      while (index + 1 < lines.length && /^(?:\s|$)/u.test(lines[index + 1]!)) {
        const next = lines[++index]!; if (!next.trim() || /^\s*#/u.test(next)) continue;
        const item = /^ {2}([^:]+):[ \t]*(.*)$/u.exec(next); if (!item) invalid();
        const name = scalar(item![1]!); if (Object.hasOwn(metadata, name)) invalid(); metadata[name] = scalar(item![2]!);
      }
    } else if (/^[>|][+-]?$/u.test(value)) {
      const block: string[] = [];
      while (index + 1 < lines.length && /^(?: {2}|$)/u.test(lines[index + 1]!)) block.push(lines[++index]!.slice(2));
      if (!block.length) invalid(); values.set(key, block.join(value[0] === '>' ? ' ' : '\n').trim());
    } else values.set(key, scalar(value));
  }
  const name = values.get('name') ?? '', description = values.get('description') ?? '';
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(name) || name.length > 64 || !description || Array.from(description).length > 1024 ||
      values.has('compatibility') && (!values.get('compatibility') || Array.from(values.get('compatibility')!).length > 500)) invalid();
  const manifest: SkillManifest = { name, description, ...(values.has('license') ? { license: values.get('license')! } : {}),
    ...(values.has('compatibility') ? { compatibility: values.get('compatibility')! } : {}),
    ...(values.has('metadata') ? { metadata } : {}), ...(values.has('allowed-tools') ? { allowedTools: values.get('allowed-tools')!.split(/\s+/u) } : {}) };
  return { manifest, prompt: match![2]!.trim(), diagnostics: [] };
}
