import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';

export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
};

const EMPTY_WORKSPACE_CONFIG: WorkspaceConfig = {
  instructionFiles: [],
  extensions: [],
  defaultSkills: []
};

function cloneEmptyWorkspaceConfig(): WorkspaceConfig {
  return {
    instructionFiles: [...EMPTY_WORKSPACE_CONFIG.instructionFiles],
    extensions: [...EMPTY_WORKSPACE_CONFIG.extensions],
    defaultSkills: [...EMPTY_WORKSPACE_CONFIG.defaultSkills]
  };
}

function readStringArray(record: Record<string, unknown>, key: keyof WorkspaceConfig) {
  const value = record[key];
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`${key} must be an array of strings`);
  }

  return value;
}

export async function loadWorkspaceConfig(cwd: string): Promise<WorkspaceConfig> {
  const target = path.join(cwd, APP_DIR, 'config.json');

  try {
    const parsed = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('workspace config must be a JSON object');
    }

    const record = parsed as Record<string, unknown>;
    return {
      instructionFiles: readStringArray(record, 'instructionFiles'),
      extensions: readStringArray(record, 'extensions'),
      defaultSkills: readStringArray(record, 'defaultSkills')
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return cloneEmptyWorkspaceConfig();
    }

    throw error;
  }
}
