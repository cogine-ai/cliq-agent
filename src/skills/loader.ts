import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import { resolveWorkspacePath } from '../tools/path.js';
import type { LoadedSkill, LoadedSkillFrontmatter } from './types.js';

type FrontmatterValue = string | string[] | Record<string, string>;

export function mergeSkillNames(defaultSkills: string[], cliSkills: string[]) {
  return [...new Set([...defaultSkills, ...cliSkills])];
}

function isValidSkillName(name: string) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
}

function normalizeLine(line: string) {
  return line.endsWith('\r') ? line.slice(0, -1) : line;
}

function leadingSpaces(line: string) {
  const match = line.match(/^ */);
  return match?.[0].length ?? 0;
}

function isBlankOrComment(line: string) {
  const trimmed = line.trim();
  return trimmed === '' || trimmed.startsWith('#');
}

function parseKeyValue(line: string, lineNumber: number) {
  const separator = line.indexOf(':');
  if (separator <= 0) {
    throw new Error(`frontmatter line ${lineNumber} must use "key: value" syntax`);
  }

  const key = line.slice(0, separator).trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(key)) {
    throw new Error(`frontmatter line ${lineNumber} has invalid field name "${key}"`);
  }

  return {
    key,
    rawValue: line.slice(separator + 1)
  };
}

function parseScalar(rawValue: string, lineNumber: number) {
  const value = rawValue.trim();
  const quote = value[0];
  if (quote !== '"' && quote !== "'") {
    return value;
  }

  if (value.length < 2 || value[value.length - 1] !== quote) {
    throw new Error(`frontmatter line ${lineNumber} has an unterminated quoted value`);
  }

  const inner = value.slice(1, -1);
  return quote === '"' ? inner.replace(/\\"/g, '"').replace(/\\\\/g, '\\') : inner.replace(/''/g, "'");
}

function parseIndentedBlock(
  lines: string[],
  startIndex: number,
  parentKey: string
): { value: string[] | Record<string, string>; nextIndex: number } {
  const list: string[] = [];
  const record: Record<string, string> = {};
  let mode: 'list' | 'record' | null = null;
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];
    if (isBlankOrComment(line)) {
      index += 1;
      continue;
    }

    const indent = leadingSpaces(line);
    if (indent === 0) {
      break;
    }

    if (indent < 2) {
      throw new Error(`frontmatter line ${index + 1} under "${parentKey}" must be indented`);
    }

    const child = line.slice(indent);
    if (child.startsWith('- ')) {
      if (mode === 'record') {
        throw new Error(`frontmatter field "${parentKey}" cannot mix list items and mapped values`);
      }
      mode = 'list';
      list.push(parseScalar(child.slice(2), index + 1));
      index += 1;
      continue;
    }

    if (mode === 'list') {
      throw new Error(`frontmatter field "${parentKey}" cannot mix list items and mapped values`);
    }

    mode = 'record';
    const { key, rawValue } = parseKeyValue(child, index + 1);
    record[key] = parseScalar(rawValue, index + 1);
    index += 1;
  }

  if (mode === 'list') {
    return { value: list, nextIndex: index };
  }

  return { value: record, nextIndex: index };
}

function splitSkillMarkdown(raw: string) {
  const lines = raw.replace(/^\uFEFF/, '').split('\n').map(normalizeLine);
  if (lines[0]?.trim() !== '---') {
    throw new Error('Skill frontmatter must begin with ---');
  }

  const closeIndex = lines.findIndex((line, index) => index > 0 && line.trim() === '---');
  if (closeIndex === -1) {
    throw new Error('Skill frontmatter must close with ---');
  }

  return {
    frontmatterLines: lines.slice(1, closeIndex),
    body: lines.slice(closeIndex + 1).join('\n')
  };
}

function parseFrontmatter(lines: string[]) {
  const fields = new Map<string, FrontmatterValue>();
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    if (isBlankOrComment(line)) {
      index += 1;
      continue;
    }

    if (leadingSpaces(line) !== 0) {
      throw new Error(`frontmatter line ${index + 1} must be a top-level field`);
    }

    const { key, rawValue } = parseKeyValue(line, index + 1);
    if (fields.has(key)) {
      throw new Error(`frontmatter field "${key}" is declared more than once`);
    }

    if (rawValue.trim() === '') {
      const nextLine = lines[index + 1];
      if (nextLine !== undefined && !isBlankOrComment(nextLine) && leadingSpaces(nextLine) > 0) {
        const block = parseIndentedBlock(lines, index + 1, key);
        fields.set(key, block.value);
        index = block.nextIndex;
        continue;
      }
    }

    fields.set(key, parseScalar(rawValue, index + 1));
    index += 1;
  }

  return fields;
}

function readRequiredString(fields: Map<string, FrontmatterValue>, key: 'name' | 'description') {
  const value = fields.get(key);
  if (typeof value !== 'string' || value.trim() === '') {
    if (key === 'name') {
      throw new Error('frontmatter must declare a name in required field "name"');
    }
    throw new Error(`frontmatter must declare required field "${key}"`);
  }

  return value.trim();
}

function readOptionalString(fields: Map<string, FrontmatterValue>, key: 'license' | 'compatibility') {
  if (!fields.has(key)) {
    return undefined;
  }

  const value = fields.get(key);
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`frontmatter field "${key}" must be a non-empty string`);
  }

  return value.trim();
}

function readOptionalMetadata(fields: Map<string, FrontmatterValue>) {
  if (!fields.has('metadata')) {
    return undefined;
  }

  const value = fields.get('metadata');
  if (!value || Array.isArray(value) || typeof value === 'string') {
    throw new Error('frontmatter field "metadata" must be a mapping');
  }

  return value;
}

function readOptionalAllowedTools(fields: Map<string, FrontmatterValue>) {
  if (!fields.has('allowed-tools')) {
    return undefined;
  }

  const value = fields.get('allowed-tools');
  if (typeof value === 'string') {
    if (value.trim() === '') {
      throw new Error('frontmatter field "allowed-tools" must be a non-empty string or list');
    }
    return value.trim();
  }

  if (Array.isArray(value)) {
    if (value.length === 0 || value.some((tool) => tool.trim() === '')) {
      throw new Error('frontmatter field "allowed-tools" must be a non-empty string or list');
    }
    return value.map((tool) => tool.trim());
  }

  throw new Error('frontmatter field "allowed-tools" must be a string or list');
}

function buildOptionalFrontmatter(fields: Map<string, FrontmatterValue>) {
  const frontmatter: LoadedSkillFrontmatter = {};
  const license = readOptionalString(fields, 'license');
  const compatibility = readOptionalString(fields, 'compatibility');
  const metadata = readOptionalMetadata(fields);
  const allowedTools = readOptionalAllowedTools(fields);

  if (license !== undefined) {
    frontmatter.license = license;
  }
  if (compatibility !== undefined) {
    frontmatter.compatibility = compatibility;
  }
  if (metadata !== undefined) {
    frontmatter.metadata = metadata;
  }
  if (allowedTools !== undefined) {
    frontmatter.allowedTools = allowedTools;
  }

  return Object.keys(frontmatter).length > 0 ? frontmatter : undefined;
}

function parseSkillMarkdown(raw: string): LoadedSkill {
  const { frontmatterLines, body } = splitSkillMarkdown(raw);
  const fields = parseFrontmatter(frontmatterLines);
  const name = readRequiredString(fields, 'name');
  const description = readRequiredString(fields, 'description');
  const frontmatter = buildOptionalFrontmatter(fields);

  const prompt = body.trim();
  if (!prompt) {
    throw new Error('Skill prompt body must not be empty');
  }

  return {
    name,
    description,
    prompt,
    ...(frontmatter ? { frontmatter } : {})
  };
}

export async function loadSkills(cwd: string, names: string[]): Promise<LoadedSkill[]> {
  const loaded: LoadedSkill[] = [];

  for (const name of names) {
    if (!isValidSkillName(name)) {
      throw new Error(`Invalid skill name: ${name}`);
    }

    const { targetRealPath } = await resolveWorkspacePath(cwd, path.join(APP_DIR, 'skills', name, 'SKILL.md'));
    const raw = await fs.readFile(targetRealPath, 'utf8');
    let skill: LoadedSkill;
    try {
      skill = parseSkillMarkdown(raw);
    } catch (error) {
      throw new Error(`Skill ${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (skill.name !== name) {
      throw new Error(`Skill ${name}: frontmatter name mismatch; expected "${name}", received "${skill.name}"`);
    }
    loaded.push(skill);
  }

  return loaded;
}
