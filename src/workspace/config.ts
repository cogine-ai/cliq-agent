import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import type { PartialModelConfig } from '../model/config.js';
import type { AutoCompactConfig } from '../session/auto-compact-config.js';

export type TxMode = 'off' | 'edit';
export type TxAuto = 'per-turn' | 'manual';
export type TxApplyPolicy = 'interactive' | 'auto-on-pass' | 'manual-only';
export type TxBashPolicy = 'passthrough' | 'confirm' | 'deny';
export type TxCopyMode = 'auto' | 'reflink' | 'copy';

export type TxShellValidator = {
  name: string;
  command: string;
  severity: 'blocking' | 'advisory';
  timeoutMs?: number;
};

export type TxStagedViewConfig = {
  copyMode?: TxCopyMode;
  bindPaths?: string[];
};

export type TxValidatorsConfig = {
  shell?: TxShellValidator[];
  disabled?: string[];
  serial?: boolean;
};

export type TxConfig = {
  mode?: TxMode;
  auto?: TxAuto;
  applyPolicy?: TxApplyPolicy;
  bashPolicy?: TxBashPolicy;
  stagedView?: TxStagedViewConfig;
  validators?: TxValidatorsConfig;
  abortRetention?: string;
};

export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
  model?: PartialModelConfig;
  autoCompact: AutoCompactConfig;
  transactions?: TxConfig;
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

export function parseTransactions(input: unknown): TxConfig | undefined {
  if (input === undefined) {
    return undefined;
  }

  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('transactions must be an object');
  }

  const raw = input as Record<string, unknown>;
  const result: TxConfig = {};

  // mode
  if (raw.mode !== undefined) {
    if (raw.mode !== 'off' && raw.mode !== 'edit') {
      throw new Error('transactions.mode must be one of: off, edit');
    }
    result.mode = raw.mode;
  }

  // auto
  if (raw.auto !== undefined) {
    if (raw.auto !== 'per-turn' && raw.auto !== 'manual') {
      throw new Error('transactions.auto must be one of: per-turn, manual');
    }
    result.auto = raw.auto;
  }

  // applyPolicy
  if (raw.applyPolicy !== undefined) {
    if (
      raw.applyPolicy !== 'interactive' &&
      raw.applyPolicy !== 'auto-on-pass' &&
      raw.applyPolicy !== 'manual-only'
    ) {
      throw new Error('transactions.applyPolicy must be one of: interactive, auto-on-pass, manual-only');
    }
    result.applyPolicy = raw.applyPolicy;
  }

  // bashPolicy
  if (raw.bashPolicy !== undefined) {
    if (
      raw.bashPolicy !== 'passthrough' &&
      raw.bashPolicy !== 'confirm' &&
      raw.bashPolicy !== 'deny'
    ) {
      throw new Error('transactions.bashPolicy must be one of: passthrough, confirm, deny');
    }
    result.bashPolicy = raw.bashPolicy;
  }

  // stagedView
  if (raw.stagedView !== undefined) {
    if (!raw.stagedView || typeof raw.stagedView !== 'object' || Array.isArray(raw.stagedView)) {
      throw new Error('transactions.stagedView must be an object');
    }
    const sv = raw.stagedView as Record<string, unknown>;
    const stagedView: TxStagedViewConfig = {};

    if (sv.copyMode !== undefined) {
      if (sv.copyMode !== 'auto' && sv.copyMode !== 'reflink' && sv.copyMode !== 'copy') {
        throw new Error('transactions.stagedView.copyMode must be one of: auto, reflink, copy');
      }
      stagedView.copyMode = sv.copyMode;
    }

    if (sv.bindPaths !== undefined) {
      if (!Array.isArray(sv.bindPaths) || sv.bindPaths.some((p) => typeof p !== 'string')) {
        throw new Error('transactions.stagedView.bindPaths must be an array of strings');
      }
      stagedView.bindPaths = sv.bindPaths as string[];
    }

    result.stagedView = stagedView;
  }

  // validators
  if (raw.validators !== undefined) {
    if (!raw.validators || typeof raw.validators !== 'object' || Array.isArray(raw.validators)) {
      throw new Error('transactions.validators must be an object');
    }
    const val = raw.validators as Record<string, unknown>;
    const validators: TxValidatorsConfig = {};

    if (val.shell !== undefined) {
      if (!Array.isArray(val.shell)) {
        throw new Error('transactions.validators.shell must be an array');
      }
      const shell: TxShellValidator[] = [];
      for (const entry of val.shell) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
          throw new Error('transactions.validators.shell entries must be objects');
        }
        const e = entry as Record<string, unknown>;
        if (typeof e.name !== 'string') {
          throw new Error('transactions.validators.shell entries must have a string name');
        }
        if (typeof e.command !== 'string') {
          throw new Error('transactions.validators.shell entries must have a string command');
        }
        if (e.severity !== 'blocking' && e.severity !== 'advisory') {
          throw new Error('transactions.validators.shell entries must have severity of blocking or advisory');
        }
        const validator: TxShellValidator = { name: e.name, command: e.command, severity: e.severity };
        if (e.timeoutMs !== undefined) {
          if (typeof e.timeoutMs !== 'number' || !Number.isInteger(e.timeoutMs) || e.timeoutMs <= 0) {
            throw new Error('transactions.validators.shell entry timeoutMs must be a positive integer');
          }
          validator.timeoutMs = e.timeoutMs;
        }
        shell.push(validator);
      }
      validators.shell = shell;
    }

    if (val.disabled !== undefined) {
      if (!Array.isArray(val.disabled) || val.disabled.some((d) => typeof d !== 'string')) {
        throw new Error('transactions.validators.disabled must be an array of strings');
      }
      validators.disabled = val.disabled as string[];
    }

    if (val.serial !== undefined) {
      if (typeof val.serial !== 'boolean') {
        throw new Error('transactions.validators.serial must be a boolean');
      }
      validators.serial = val.serial;
    }

    result.validators = validators;
  }

  // abortRetention
  if (raw.abortRetention !== undefined) {
    if (typeof raw.abortRetention !== 'string') {
      throw new Error('transactions.abortRetention must be a string');
    }
    result.abortRetention = raw.abortRetention;
  }

  return result;
}

export function parseWorkspaceConfig(input: unknown): WorkspaceConfig {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('workspace config must be a JSON object');
  }

  const record = input as Record<string, unknown>;
  const model = readModelConfig(record);
  const autoCompact = readAutoCompactConfig(record);
  const transactions = parseTransactions(record.transactions);
  return {
    instructionFiles: readStringArray(record, 'instructionFiles'),
    extensions: readStringArray(record, 'extensions'),
    defaultSkills: readStringArray(record, 'defaultSkills'),
    autoCompact,
    ...(model ? { model } : {}),
    ...(transactions !== undefined ? { transactions } : {})
  };
}

export async function loadWorkspaceConfig(cwd: string): Promise<WorkspaceConfig> {
  const target = path.join(cwd, APP_DIR, 'config.json');

  try {
    const parsed = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
    return parseWorkspaceConfig(parsed);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return cloneEmptyWorkspaceConfig();
    }

    throw error;
  }
}
