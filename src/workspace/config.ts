import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import type { PartialModelConfig } from '../model/config.js';
import type { AutoCompactConfig } from '../session/auto-compact-config.js';

export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
  model?: PartialModelConfig;
  autoCompact: AutoCompactConfig;
};

const EMPTY_WORKSPACE_CONFIG: WorkspaceConfig = {
  instructionFiles: [],
  extensions: [],
  defaultSkills: [],
  autoCompact: {}
};

function cloneEmptyWorkspaceConfig(): WorkspaceConfig {
  return {
    instructionFiles: [...EMPTY_WORKSPACE_CONFIG.instructionFiles],
    extensions: [...EMPTY_WORKSPACE_CONFIG.extensions],
    defaultSkills: [...EMPTY_WORKSPACE_CONFIG.defaultSkills],
    autoCompact: {}
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

type NumericAutoCompactConfigKey = Exclude<keyof AutoCompactConfig, 'enabled'>;

function readNumberField(record: Record<string, unknown>, key: NumericAutoCompactConfigKey) {
  const value = record[key];
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'number') {
    throw new Error(`autoCompact.${String(key)} must be a number`);
  }

  return value;
}

function assignNumberField(
  target: AutoCompactConfig,
  source: Record<string, unknown>,
  key: NumericAutoCompactConfigKey
) {
  const value = readNumberField(source, key);
  if (value !== undefined) {
    Object.assign(target, { [key]: value });
  }
}

function readAutoCompactConfig(record: Record<string, unknown>): AutoCompactConfig {
  const value = record.autoCompact;
  if (value === undefined) {
    return {};
  }

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('autoCompact must be an object');
  }

  const autoCompact = value as Record<string, unknown>;
  const enabled = autoCompact.enabled;
  if (enabled !== undefined && enabled !== 'auto' && enabled !== 'on' && enabled !== 'off') {
    throw new Error('autoCompact.enabled must be one of: auto, on, off');
  }

  const config: AutoCompactConfig = {};
  if (enabled !== undefined) {
    config.enabled = enabled;
  }
  for (const key of [
    'contextWindowTokens',
    'thresholdRatio',
    'reserveTokens',
    'keepRecentTokens',
    'minNewTokens',
    'maxThresholdCompactionsPerTurn',
    'maxOverflowRetriesPerModelCall'
  ] as const) {
    assignNumberField(config, autoCompact, key);
  }

  return config;
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
    const autoCompact = readAutoCompactConfig(record);
    return {
      instructionFiles: readStringArray(record, 'instructionFiles'),
      extensions: readStringArray(record, 'extensions'),
      defaultSkills: readStringArray(record, 'defaultSkills'),
      autoCompact,
      ...(model ? { model } : {})
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return cloneEmptyWorkspaceConfig();
    }

    throw error;
  }
}
