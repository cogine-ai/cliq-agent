import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import { resolveCliqHome } from '../session/store.js';
import { isPathInsideWorkspace } from '../tools/path.js';
import type {
  ActiveSkill,
  LoadedSkill,
  ParsedSkillMarkdown,
  SkillActivationSource,
  SkillCatalog,
  SkillCatalogEntry,
  SkillDiagnostic,
  SkillManifest,
  SkillScope,
  SkillSourceKind,
  SkillStatus
} from './types.js';

type SkillDiscoveryRoot = {
  scope: SkillScope;
  sourceKind: SkillSourceKind;
  sourceRoot: string;
  ownerRoot?: string;
  rank: number;
};

export type SkillDiscoveryOptions = {
  homeDir?: string;
  cliqHome?: string;
};

export type LoadSkillsOptions = {
  catalog?: SkillCatalog;
  discovery?: SkillDiscoveryOptions;
  projectOnly?: boolean;
};

export type ActivateSkillOptions = LoadSkillsOptions & {
  activatedBy: SkillActivationSource;
};

const KNOWN_FRONTMATTER_FIELDS = new Set([
  'name',
  'description',
  'license',
  'compatibility',
  'metadata',
  'allowed-tools'
]);

export function mergeSkillNames(defaultSkills: string[], cliSkills: string[]) {
  return [...new Set([...defaultSkills, ...cliSkills])];
}

export function isValidSkillName(name: string) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
}

function diagnostic(level: SkillDiagnostic['level'], code: string, message: string, source?: string): SkillDiagnostic {
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

async function exists(target: string) {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function realpathIfExists(target: string) {
  try {
    return await fs.realpath(target);
  } catch {
    return null;
  }
}

async function findGitRoot(cwd: string) {
  let current = path.resolve(cwd);
  while (true) {
    if (await exists(path.join(current, '.git'))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return path.resolve(cwd);
    }
    current = parent;
  }
}

async function projectDiscoveryRoots(cwd: string): Promise<SkillDiscoveryRoot[]> {
  const start = path.resolve(cwd);
  const gitRoot = await findGitRoot(start);
  const roots: SkillDiscoveryRoot[] = [];
  let current = start;
  let depth = 0;
  while (true) {
    const baseRank = 10_000 - depth * 10;
    roots.push({
      scope: 'project',
      sourceKind: 'project-cliq',
      sourceRoot: path.join(current, APP_DIR, 'skills'),
      ownerRoot: current,
      rank: baseRank + 2
    });
    roots.push({
      scope: 'project',
      sourceKind: 'project-agents',
      sourceRoot: path.join(current, '.agents', 'skills'),
      ownerRoot: current,
      rank: baseRank + 1
    });
    if (current === gitRoot) {
      break;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
    depth += 1;
  }
  return roots;
}

function userDiscoveryRoots(options: SkillDiscoveryOptions = {}): SkillDiscoveryRoot[] {
  const homeDir = path.resolve(options.homeDir ?? os.homedir());
  const cliqHome = path.resolve(options.cliqHome ?? resolveCliqHome(process.env, homeDir));
  return [
    {
      scope: 'user',
      sourceKind: 'user-cliq',
      sourceRoot: path.join(cliqHome, 'skills'),
      rank: 2
    },
    {
      scope: 'user',
      sourceKind: 'user-agents',
      sourceRoot: path.join(homeDir, '.agents', 'skills'),
      rank: 1
    }
  ];
}

async function readSkillEntry(root: SkillDiscoveryRoot, dirName: string): Promise<SkillCatalogEntry | null> {
  const skillDir = path.join(root.sourceRoot, dirName);
  const skillFile = path.join(skillDir, 'SKILL.md');
  const skillFileRealPath = await realpathIfExists(skillFile);
  if (!skillFileRealPath) {
    return null;
  }

  const diagnostics: SkillDiagnostic[] = [];
  let raw = '';
  try {
    raw = await fs.readFile(skillFileRealPath, 'utf8');
  } catch (error) {
    diagnostics.push(
      diagnostic(
        'error',
        'read-failed',
        `Failed to read skill file: ${error instanceof Error ? error.message : String(error)}`,
        skillFile
      )
    );
  }

  if (root.ownerRoot) {
    const ownerRealPath = await realpathIfExists(root.ownerRoot);
    const skillDirRealPath = await realpathIfExists(skillDir);
    if (!ownerRealPath || !skillDirRealPath || !isPathInsideWorkspace(ownerRealPath, skillDirRealPath)) {
      diagnostics.push(
        diagnostic(
          'error',
          'project-skill-escape',
          `Project skill ${dirName} must stay inside its trusted project root`,
          skillFile
        )
      );
    }
  }

  const parsed = parseSkillMarkdown(raw, skillFile);
  diagnostics.push(...parsed.diagnostics);
  if (parsed.manifest.name && parsed.manifest.name !== dirName) {
    diagnostics.push(
      diagnostic(
        'error',
        'name-mismatch',
        `Skill ${dirName} must declare matching frontmatter name`,
        skillFile
      )
    );
  }

  const name = dirName;
  const status: SkillStatus = diagnostics.some((item) => item.level === 'error') ? 'invalid' : 'available';
  return {
    id: `${root.sourceKind}:${skillFileRealPath}`,
    name,
    description: parsed.manifest.description || null,
    scope: root.scope,
    sourceKind: root.sourceKind,
    sourceRoot: root.sourceRoot,
    skillDir,
    skillFile: skillFileRealPath,
    status,
    diagnostics,
    rank: root.rank
  };
}

async function readRootEntries(root: SkillDiscoveryRoot): Promise<SkillCatalogEntry[]> {
  let dirents;
  try {
    dirents = await fs.readdir(root.sourceRoot, { withFileTypes: true });
  } catch {
    return [];
  }

  const entries: SkillCatalogEntry[] = [];
  for (const dirent of dirents) {
    if (!dirent.isDirectory() && !dirent.isSymbolicLink()) {
      continue;
    }
    const entry = await readSkillEntry(root, dirent.name);
    if (entry) {
      entries.push(entry);
    }
  }
  return entries;
}

export async function discoverSkillCatalog(cwd: string, options: SkillDiscoveryOptions = {}): Promise<SkillCatalog> {
  const roots = [...(await projectDiscoveryRoots(cwd)), ...userDiscoveryRoots(options)];
  const entries = (await Promise.all(roots.map((root) => readRootEntries(root)))).flat();

  const groups = new Map<string, SkillCatalogEntry[]>();
  for (const entry of entries) {
    groups.set(entry.name, [...(groups.get(entry.name) ?? []), entry]);
  }

  for (const group of groups.values()) {
    const ranked = [...group].sort((left, right) => right.rank - left.rank || left.skillFile.localeCompare(right.skillFile));
    const winner = ranked[0];
    for (const entry of ranked.slice(1)) {
      entry.status = 'shadowed';
      if (winner) {
        entry.shadowedBy = winner.id;
        entry.diagnostics.push(
          diagnostic('info', 'shadowed', `Skill ${entry.name} is shadowed by ${winner.sourceKind} ${winner.skillFile}`, entry.skillFile)
        );
      }
    }
  }

  entries.sort((left, right) => right.rank - left.rank || left.name.localeCompare(right.name));
  return {
    entries,
    diagnostics: entries.flatMap((entry) => entry.diagnostics)
  };
}

function findCatalogEntry(catalog: SkillCatalog, name: string, projectOnly: boolean) {
  const candidates = catalog.entries
    .filter((entry) => entry.name === name && entry.status !== 'shadowed')
    .filter((entry) => !projectOnly || entry.scope === 'project')
    .sort((left, right) => right.rank - left.rank);
  return candidates[0] ?? null;
}

export async function loadSkillFromCatalog(
  catalog: SkillCatalog,
  name: string,
  opts: { projectOnly?: boolean } = {}
): Promise<LoadedSkill> {
  if (!isValidSkillName(name)) {
    throw new Error(`Invalid skill name: ${name}`);
  }

  const anyNamed = catalog.entries.some((entry) => entry.name === name && entry.status !== 'shadowed');
  const entry = findCatalogEntry(catalog, name, opts.projectOnly === true);
  if (!entry) {
    throw new Error(anyNamed ? `Skill ${name} is not project-owned` : `Unknown skill: ${name}`);
  }
  if (entry.status !== 'available') {
    const errors = entry.diagnostics
      .filter((item) => item.level === 'error')
      .map((item) => item.message)
      .join('; ');
    throw new Error(`Skill ${name} is invalid${errors ? `: ${errors}` : ''}`);
  }

  const raw = await fs.readFile(entry.skillFile, 'utf8');
  const parsed = parseSkillMarkdown(raw, entry.skillFile);
  const errors = parsed.diagnostics.filter((item) => item.level === 'error');
  if (errors.length > 0) {
    throw new Error(`Skill ${name} is invalid: ${errors.map((item) => item.message).join('; ')}`);
  }

  return {
    name: entry.name,
    description: parsed.manifest.description || null,
    prompt: parsed.prompt,
    manifest: parsed.manifest,
    scope: entry.scope,
    sourceKind: entry.sourceKind,
    sourceRoot: entry.sourceRoot,
    skillDir: entry.skillDir,
    skillFile: entry.skillFile,
    diagnostics: parsed.diagnostics
  };
}

export async function loadSkills(cwd: string, names: string[], options: LoadSkillsOptions = {}): Promise<LoadedSkill[]> {
  const catalog = options.catalog ?? (await discoverSkillCatalog(cwd, options.discovery));
  const loaded: LoadedSkill[] = [];
  for (const name of names) {
    loaded.push(await loadSkillFromCatalog(catalog, name, { projectOnly: options.projectOnly }));
  }
  return loaded;
}

export async function activateSkill(
  cwd: string,
  session: { activeSkills?: ActiveSkill[] },
  name: string,
  options: ActivateSkillOptions
): Promise<{ status: 'activated' | 'already-active'; skill: ActiveSkill }> {
  const [loaded] = await loadSkills(cwd, [name], options);
  const activeSkills = session.activeSkills ?? [];
  const existing = activeSkills.find((skill) => skill.skillFile === loaded.skillFile);
  if (existing) {
    session.activeSkills = activeSkills;
    return { status: 'already-active', skill: existing };
  }

  const active: ActiveSkill = {
    ...loaded,
    activatedBy: options.activatedBy,
    activatedAt: new Date().toISOString()
  };
  const sameNameIndex = activeSkills.findIndex((skill) => skill.name === loaded.name);
  if (sameNameIndex >= 0) {
    activeSkills[sameNameIndex] = active;
    session.activeSkills = activeSkills;
    return { status: 'activated', skill: active };
  }

  activeSkills.push(active);
  session.activeSkills = activeSkills;
  return { status: 'activated', skill: active };
}

export async function refreshActiveSkill(skill: ActiveSkill): Promise<{ skill: ActiveSkill | null; diagnostics: SkillDiagnostic[] }> {
  let raw: string;
  try {
    raw = await fs.readFile(skill.skillFile, 'utf8');
  } catch (error) {
    const item = diagnostic(
      'error',
      'active-skill-unavailable',
      `Active skill ${skill.name} could not be refreshed: ${error instanceof Error ? error.message : String(error)}`,
      skill.skillFile
    );
    return { skill: null, diagnostics: [item] };
  }

  const parsed = parseSkillMarkdown(raw, skill.skillFile);
  const diagnostics = [...parsed.diagnostics];
  if (parsed.manifest.name && parsed.manifest.name !== skill.name) {
    diagnostics.push(
      diagnostic('error', 'name-mismatch', `Skill ${skill.name} must declare matching frontmatter name`, skill.skillFile)
    );
  }
  if (diagnostics.some((item) => item.level === 'error')) {
    return { skill: null, diagnostics };
  }

  return {
    skill: {
      ...skill,
      description: parsed.manifest.description || null,
      prompt: parsed.prompt,
      manifest: parsed.manifest,
      diagnostics
    },
    diagnostics
  };
}

export function formatSkillCatalog(catalog: SkillCatalog, activeSkills: readonly ActiveSkill[] = []) {
  const active = new Set(activeSkills.map((skill) => skill.name));
  const lines = ['Skills:'];
  for (const entry of catalog.entries) {
    const marker = active.has(entry.name) ? '*' : ' ';
    lines.push(
      `${marker} ${entry.name} [${entry.scope}/${entry.status}] ${entry.description ?? '(no description)'} - ${entry.skillFile}`
    );
  }
  return lines.join('\n');
}
