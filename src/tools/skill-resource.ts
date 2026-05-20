import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { SkillResourceAction } from '../protocol/model/actions.js';
import type { ActiveSkill } from '../skills/types.js';
import { isPathInsideWorkspace } from './path.js';
import type { ToolDefinition, ToolResult } from './types.js';

const SKILL_RESOURCE_MAX_BYTES = 64_000;
const SKILL_RESOURCE_LIST_MAX_ENTRIES = 200;

function rejectUnsafeResourcePath(inputPath: string) {
  if (path.isAbsolute(inputPath)) {
    throw new Error('skill resource path must be skill-relative');
  }
  const normalized = path.normalize(inputPath || '.');
  if (normalized === '..' || normalized.startsWith(`..${path.sep}`)) {
    throw new Error('skill resource path must be skill-relative');
  }
  return normalized;
}

async function resolveSkillResource(skill: ActiveSkill, inputPath: string) {
  const relativePath = rejectUnsafeResourcePath(inputPath);
  const skillDirRealPath = await fs.realpath(skill.skillDir);
  const target = path.resolve(skill.skillDir, relativePath);
  const targetRealPath = await fs.realpath(target);
  if (!isPathInsideWorkspace(skillDirRealPath, targetRealPath)) {
    throw new Error('skill resource path resolves outside the activated skill directory');
  }
  return {
    relativePath,
    targetRealPath
  };
}

function findActiveSkill(skills: readonly ActiveSkill[], name: string) {
  return skills.find((skill) => skill.name === name);
}

function isBinary(buffer: Buffer) {
  return buffer.includes(0);
}

async function listResource(skill: ActiveSkill, inputPath: string) {
  const { relativePath, targetRealPath } = await resolveSkillResource(skill, inputPath);
  const stat = await fs.stat(targetRealPath);
  if (!stat.isDirectory()) {
    throw new Error('skill resource list target must be a directory');
  }
  const dirents = await fs.readdir(targetRealPath, { withFileTypes: true });
  const entries = dirents
    .slice(0, SKILL_RESOURCE_LIST_MAX_ENTRIES)
    .map((entry) => `${entry.isDirectory() ? 'dir ' : 'file'} ${entry.name}`)
    .join('\n');
  const truncated = dirents.length > SKILL_RESOURCE_LIST_MAX_ENTRIES ? '\n... (truncated)' : '';
  return {
    relativePath,
    content: `${entries}${truncated}`.trim()
  };
}

async function readResource(skill: ActiveSkill, inputPath: string) {
  const { relativePath, targetRealPath } = await resolveSkillResource(skill, inputPath);
  const stat = await fs.stat(targetRealPath);
  if (!stat.isFile()) {
    throw new Error('skill resource read target must be a file');
  }
  if (stat.size > SKILL_RESOURCE_MAX_BYTES) {
    throw new Error(`skill resource exceeds ${SKILL_RESOURCE_MAX_BYTES} bytes`);
  }
  const buffer = await fs.readFile(targetRealPath);
  if (isBinary(buffer)) {
    throw new Error('skill resource appears to be binary');
  }
  return {
    relativePath,
    content: buffer.toString('utf8')
  };
}

export const skillResourceTool: ToolDefinition<{ skillResource: SkillResourceAction }> = {
  name: 'skillResource',
  access: 'read',
  supports(action): action is { skillResource: SkillResourceAction } {
    return (
      typeof (action as { skillResource?: unknown }).skillResource === 'object' &&
      !!(action as { skillResource?: unknown }).skillResource
    );
  },
  async execute(action, context): Promise<ToolResult> {
    const request = action.skillResource;
    try {
      const activeSkill = findActiveSkill(context.session.activeSkills ?? [], request.skill);
      if (!activeSkill) {
        throw new Error(`Skill ${request.skill} is not active`);
      }
      const resourcePath = request.path ?? '.';
      const resource =
        request.mode === 'list'
          ? await listResource(activeSkill, resourcePath)
          : await readResource(activeSkill, resourcePath);

      return {
        tool: 'skillResource',
        status: 'ok',
        meta: {
          skill: activeSkill.name,
          path: resource.relativePath,
          mode: request.mode ?? 'read'
        },
        content:
          `TOOL_RESULT skillResource OK\n` +
          `skill=${activeSkill.name}\n` +
          `path=${resource.relativePath}\n` +
          resource.content.trim()
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'skillResource',
        status: 'error',
        meta: {
          skill: request.skill,
          path: request.path ?? '.',
          error: message
        },
        content: `TOOL_RESULT skillResource ERROR\nskill=${request.skill}\npath=${request.path ?? '.'}\n${message}`
      };
    }
  }
};
