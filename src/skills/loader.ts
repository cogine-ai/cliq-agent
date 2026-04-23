import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import { resolveWorkspacePath } from '../tools/path.js';
import type { LoadedSkill } from './types.js';

export function mergeSkillNames(defaultSkills: string[], cliSkills: string[]) {
  return [...new Set([...defaultSkills, ...cliSkills])];
}

function isValidSkillName(name: string) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
}

function parseSkillMarkdown(raw: string): LoadedSkill {
  const match = raw.match(/^\uFEFF?---\r?\n([\s\S]*?)\r?\n---\r?\n+([\s\S]*)$/);
  if (!match) {
    throw new Error('Skill file must begin with frontmatter');
  }

  const headers = Object.fromEntries(
    match[1]
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const [key, ...rest] = line.split(':');
        return [key.trim(), rest.join(':').trim()];
      })
  );

  if (!headers.name) {
    throw new Error('Skill file must declare a name');
  }

  const prompt = match[2].trim();
  if (!prompt) {
    throw new Error('Skill prompt body must not be empty');
  }

  return {
    name: headers.name,
    description: headers.description ?? null,
    prompt
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
    const skill = parseSkillMarkdown(raw);
    if (skill.name !== name) {
      throw new Error(`Skill ${name} must declare matching frontmatter name`);
    }
    loaded.push(skill);
  }

  return loaded;
}
