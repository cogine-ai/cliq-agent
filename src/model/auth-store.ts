import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { withPathLock } from '../lib/path-lock.js';
import { getModelProvider, isProviderName } from './registry.js';
import type { ProviderName, StreamingMode } from './types.js';

export type ProviderAuthEntry = {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  streaming?: StreamingMode;
};

export type ProviderAuthStore = {
  version: 1;
  activeProvider?: ProviderName;
  providers: Partial<Record<ProviderName, ProviderAuthEntry>>;
};

export type ProviderAuthStoreOptions = {
  cliqHome?: string;
};

export type ProviderAuthUpsertInput = ProviderAuthEntry & {
  provider: ProviderName;
};

export const EMPTY_PROVIDER_AUTH_STORE: ProviderAuthStore = {
  version: 1,
  providers: {}
};

export function authFilePath(cliqHome: string) {
  return path.join(cliqHome, 'auth.json');
}

function resolveAuthCliqHome(options: ProviderAuthStoreOptions = {}) {
  return options.cliqHome ?? process.env.CLIQ_HOME ?? path.join(os.homedir(), '.cliq');
}

function resolveAuthFilePath(options: ProviderAuthStoreOptions = {}) {
  return authFilePath(resolveAuthCliqHome(options));
}

function emptyProviderAuthStore(): ProviderAuthStore {
  return {
    version: 1,
    providers: {}
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function readString(record: Record<string, unknown>, key: string) {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new Error(`auth.${key} must be a string`);
  }
  return value;
}

function readStreaming(record: Record<string, unknown>) {
  const value = readString(record, 'streaming');
  if (value === undefined) return undefined;
  if (value !== 'auto' && value !== 'on' && value !== 'off') {
    throw new Error('auth.streaming must be one of: auto, on, off');
  }
  return value;
}

function normalizeEntry(value: unknown, provider: ProviderName): ProviderAuthEntry {
  if (!isRecord(value)) {
    throw new Error(`auth.providers.${provider} must be an object`);
  }

  return {
    ...(readString(value, 'apiKey') ? { apiKey: readString(value, 'apiKey') } : {}),
    ...(readString(value, 'model') ? { model: readString(value, 'model') } : {}),
    ...(readString(value, 'baseUrl') ? { baseUrl: readString(value, 'baseUrl') } : {}),
    ...(readStreaming(value) ? { streaming: readStreaming(value) } : {})
  };
}

function normalizeProviderAuthStore(value: unknown): ProviderAuthStore {
  if (!isRecord(value)) {
    throw new Error('auth.json must contain an object');
  }
  if (value.version !== 1) {
    throw new Error('auth.json version must be 1');
  }

  const providersRaw = value.providers;
  if (!isRecord(providersRaw)) {
    throw new Error('auth.providers must be an object');
  }

  const providers: Partial<Record<ProviderName, ProviderAuthEntry>> = {};
  for (const [provider, entry] of Object.entries(providersRaw)) {
    if (!isProviderName(provider)) {
      throw new Error(`Unknown model provider in auth.json: ${provider}`);
    }
    providers[provider] = normalizeEntry(entry, provider);
  }

  const activeProvider = value.activeProvider;
  if (activeProvider !== undefined && (typeof activeProvider !== 'string' || !isProviderName(activeProvider))) {
    throw new Error(`Unknown active model provider in auth.json: ${String(activeProvider)}`);
  }

  return {
    version: 1,
    ...(activeProvider ? { activeProvider } : {}),
    providers
  };
}

async function atomicWriteJson0600(target: string, value: unknown) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await fs.chmod(temp, 0o600);
    await fs.rename(temp, target);
    await fs.chmod(target, 0o600);
  } catch (error) {
    await fs.rm(temp, { force: true });
    throw error;
  }
}

async function tightenExistingAuthFileMode(target: string) {
  if (process.platform === 'win32') {
    return;
  }
  const mode = (await fs.stat(target)).mode & 0o777;
  if ((mode & 0o177) !== 0) {
    await fs.chmod(target, 0o600);
  }
}

export async function loadProviderAuthStore(options: ProviderAuthStoreOptions = {}): Promise<ProviderAuthStore> {
  return await loadProviderAuthStoreFromPath(resolveAuthFilePath(options));
}

async function loadProviderAuthStoreFromPath(target: string): Promise<ProviderAuthStore> {
  let raw: string;
  try {
    await tightenExistingAuthFileMode(target);
    raw = await fs.readFile(target, 'utf8');
  } catch (error) {
    if (error && typeof error === 'object' && (error as { code?: unknown }).code === 'ENOENT') {
      return emptyProviderAuthStore();
    }
    throw error;
  }

  return normalizeProviderAuthStore(JSON.parse(raw));
}

export async function saveProviderAuthStore(store: ProviderAuthStore, options: ProviderAuthStoreOptions = {}) {
  const target = resolveAuthFilePath(options);
  await withPathLock(target, async () => {
    await saveProviderAuthStoreToPath(target, store);
  });
}

async function saveProviderAuthStoreToPath(target: string, store: ProviderAuthStore) {
  await atomicWriteJson0600(target, normalizeProviderAuthStore(store));
}

export async function upsertProviderAuth(input: ProviderAuthUpsertInput, options: ProviderAuthStoreOptions = {}) {
  const target = resolveAuthFilePath(options);
  return await withPathLock(target, async () => {
    const store = await loadProviderAuthStoreFromPath(target);
    const current = store.providers[input.provider] ?? {};
    const next: ProviderAuthEntry = {
      ...current,
      ...(input.apiKey ? { apiKey: input.apiKey } : {}),
      ...(input.model ? { model: input.model } : {}),
      ...(input.baseUrl ? { baseUrl: input.baseUrl } : {}),
      ...(input.streaming ? { streaming: input.streaming } : {})
    };

    const updated: ProviderAuthStore = {
      version: 1,
      activeProvider: input.provider,
      providers: {
        ...store.providers,
        [input.provider]: next
      }
    };
    await saveProviderAuthStoreToPath(target, updated);
    return updated;
  });
}

export function getProviderAuthEntry(store: ProviderAuthStore | undefined, provider: ProviderName) {
  return store?.providers[provider];
}

export function formatProviderAuthSummary(store: ProviderAuthStore, provider: ProviderName) {
  const displayName = getModelProvider(provider).displayName;
  const entry = store.providers[provider];
  const details: string[] = [];
  if (entry?.model) details.push(`model ${entry.model}`);
  if (entry?.baseUrl) details.push('base URL configured');
  if (entry?.streaming) details.push(`streaming ${entry.streaming}`);
  return `${displayName} credential saved${details.length > 0 ? ` (${details.join(', ')})` : ''}.`;
}
