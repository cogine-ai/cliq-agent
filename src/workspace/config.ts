import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import type { PartialModelConfig } from '../model/config.js';

export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
  model?: PartialModelConfig;
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

function readModelConfig(record: Record<string, unknown>): PartialModelConfig | undefined {
  const value = record.model;
  if (value === undefined) {
    return undefined;
  }

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('model must be an object');
  }

  const model = value as Record<string, unknown>;
  for (const key of ['provider', 'model', 'baseUrl', 'streaming'] as const) {
    if (model[key] !== undefined && typeof model[key] !== 'string') {
      throw new Error(`model.${key} must be a string`);
    }
  }

  if (typeof model.streaming === 'string' && !['auto', 'on', 'off'].includes(model.streaming)) {
    throw new Error('model.streaming must be one of: auto, on, off');
  }

  return {
    ...(typeof model.provider === 'string' ? { provider: model.provider } : {}),
    ...(typeof model.model === 'string' ? { model: model.model } : {}),
    ...(typeof model.baseUrl === 'string' ? { baseUrl: model.baseUrl } : {}),
    ...(typeof model.streaming === 'string' ? { streaming: model.streaming } : {})
  };
}

export async function loadWorkspaceConfig(cwd: string): Promise<WorkspaceConfig> {
  const target = path.join(cwd, APP_DIR, 'config.json');

  try {
    const parsed = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('workspace config must be a JSON object');
    }

    const record = parsed as Record<string, unknown>;
    const model = readModelConfig(record);
    return {
      instructionFiles: readStringArray(record, 'instructionFiles'),
      extensions: readStringArray(record, 'extensions'),
      defaultSkills: readStringArray(record, 'defaultSkills'),
      ...(model ? { model } : {})
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return cloneEmptyWorkspaceConfig();
    }

    throw error;
  }
}
