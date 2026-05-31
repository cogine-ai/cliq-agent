#!/usr/bin/env tsx

import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  getCatalogSnapshot,
  listProviderCatalog,
  mapOpenClawProviderToCatalogEntry,
  mapPiModelToCatalogEntry,
  type OpenClawProviderRecord,
  type PiModelCatalogRecord
} from '../../src/model/catalog/index.js';
import type { CatalogSnapshot, ModelCatalogEntry, ProviderCatalogEntry } from '../../src/model/catalog/schema.js';

const DEFAULT_PI_MODELS_URL =
  'https://raw.githubusercontent.com/earendil-works/pi/main/packages/ai/src/models.generated.ts';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

type Args = {
  piGenerated: string;
  openclawDir?: string;
  out: string;
  generatedAt: string;
};

function parseArgs(argv: string[]): Args {
  const args: Args = {
    piGenerated: DEFAULT_PI_MODELS_URL,
    out: path.join(repoRoot, 'src/model/catalog/snapshot.ts'),
    generatedAt: new Date().toISOString()
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === '--pi-generated' && next) {
      args.piGenerated = next;
      i += 1;
    } else if (arg === '--openclaw-dir' && next) {
      args.openclawDir = next;
      i += 1;
    } else if (arg === '--out' && next) {
      args.out = next;
      i += 1;
    } else if (arg === '--generated-at' && next) {
      args.generatedAt = next;
      i += 1;
    } else if (arg === '--help') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown or incomplete argument: ${arg}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage: npm run catalog:update -- [options]

Options:
  --pi-generated <path|url>  Pi models.generated.ts input. Defaults to ${DEFAULT_PI_MODELS_URL}
  --openclaw-dir <path>      Optional OpenClaw checkout for provider metadata.
  --out <path>               Output snapshot module. Defaults to src/model/catalog/snapshot.ts
  --generated-at <iso>       Deterministic timestamp for tests/reproducible runs.
`);
}

async function readText(input: string): Promise<string> {
  if (/^https?:\/\//.test(input)) {
    const response = await fetch(input);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${input}: ${response.status} ${response.statusText}`);
    }
    return response.text();
  }
  return readFile(input, 'utf8');
}

function extractString(block: string, key: string): string | undefined {
  const match = block.match(new RegExp(`\\n\\s*${key}: "([^"]*)"`));
  return match?.[1];
}

function extractBoolean(block: string, key: string): boolean | undefined {
  const match = block.match(new RegExp(`\\n\\s*${key}: (true|false)`));
  return match?.[1] === undefined ? undefined : match[1] === 'true';
}

function extractNumber(block: string, key: string): number | undefined {
  const match = block.match(new RegExp(`\\n\\s*${key}: ([0-9.]+)`));
  if (!match?.[1]) {
    return undefined;
  }
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function extractInput(block: string): string[] | undefined {
  const match = block.match(/\n\s*input: \[([^\]]*)\]/);
  if (!match?.[1]) {
    return undefined;
  }
  return Array.from(match[1].matchAll(/"([^"]+)"/g), (item) => item[1]).filter(Boolean);
}

function extractCost(block: string): PiModelCatalogRecord['cost'] | undefined {
  const costBlock = block.match(/\n\s*cost: \{([\s\S]*?)\n\s*\}/)?.[1];
  if (!costBlock) {
    return undefined;
  }
  return {
    input: extractNumber(`\n${costBlock}`, 'input'),
    output: extractNumber(`\n${costBlock}`, 'output'),
    cacheRead: extractNumber(`\n${costBlock}`, 'cacheRead'),
    cacheWrite: extractNumber(`\n${costBlock}`, 'cacheWrite')
  };
}

function parsePiGeneratedCatalog(source: string): PiModelCatalogRecord[] {
  const lines = source.split(/\r?\n/);
  const records: PiModelCatalogRecord[] = [];
  let currentProvider: string | undefined;

  for (let i = 0; i < lines.length; i += 1) {
    const providerMatch = lines[i]?.match(/^\t"([^"]+)": \{$/);
    if (providerMatch?.[1]) {
      currentProvider = providerMatch[1];
      continue;
    }

    const modelStart = lines[i]?.match(/^\t\t"(.+)": \{$/);
    if (!modelStart) {
      continue;
    }

    const blockLines: string[] = [];
    for (i += 1; i < lines.length; i += 1) {
      const line = lines[i] ?? '';
      if (/^\t\t} satisfies Model</.test(line)) {
        break;
      }
      blockLines.push(line);
    }

    const block = `\n${blockLines.join('\n')}`;
    const id = extractString(block, 'id') ?? modelStart[1];
    const api = extractString(block, 'api');
    const provider = extractString(block, 'provider') ?? currentProvider;
    if (!id || !api || !provider) {
      continue;
    }

    records.push({
      id,
      provider,
      api,
      name: extractString(block, 'name'),
      baseUrl: extractString(block, 'baseUrl'),
      reasoning: extractBoolean(block, 'reasoning'),
      input: extractInput(block),
      cost: extractCost(block),
      contextWindow: extractNumber(block, 'contextWindow'),
      maxTokens: extractNumber(block, 'maxTokens')
    });
  }

  return records;
}

async function readOpenClawProviders(openclawDir: string): Promise<OpenClawProviderRecord[]> {
  const extensionsDir = path.join(openclawDir, 'extensions');
  const extensionNames = await readdir(extensionsDir);
  const providers: OpenClawProviderRecord[] = [];

  for (const name of extensionNames) {
    const manifestPath = path.join(extensionsDir, name, 'openclaw.plugin.json');
    let raw: string;
    try {
      raw = await readFile(manifestPath, 'utf8');
    } catch {
      continue;
    }

    const manifest = JSON.parse(raw) as {
      providers?: unknown;
    };
    const manifestProviders = manifest.providers;
    if (Array.isArray(manifestProviders)) {
      for (const provider of manifestProviders) {
        if (provider && typeof provider === 'object') {
          providers.push(provider as OpenClawProviderRecord);
        }
      }
    } else if (manifestProviders && typeof manifestProviders === 'object') {
      for (const [id, provider] of Object.entries(manifestProviders)) {
        providers.push({
          id,
          ...(provider && typeof provider === 'object' ? (provider as Omit<OpenClawProviderRecord, 'id'>) : {})
        });
      }
    }
  }

  return providers;
}

function uniqueModels(entries: ModelCatalogEntry[]): ModelCatalogEntry[] {
  const byKey = new Map<string, ModelCatalogEntry>();
  for (const entry of entries) {
    const key = `${entry.provider}/${entry.model}`;
    if (!byKey.has(key)) {
      byKey.set(key, entry);
    }
  }
  return Array.from(byKey.values()).sort((a, b) => `${a.provider}/${a.model}`.localeCompare(`${b.provider}/${b.model}`));
}

function mergeModels(generated: ModelCatalogEntry[]): ModelCatalogEntry[] {
  const byKey = new Map<string, ModelCatalogEntry>();
  for (const entry of generated) {
    byKey.set(`${entry.provider}/${entry.model}`, entry);
  }
  for (const entry of getCatalogSnapshot().models) {
    byKey.set(`${entry.provider}/${entry.model}`, {
      ...byKey.get(`${entry.provider}/${entry.model}`),
      ...entry
    });
  }
  return uniqueModels(Array.from(byKey.values()));
}

function mergeProviders(generated: ProviderCatalogEntry[]): ProviderCatalogEntry[] {
  const byId = new Map<string, ProviderCatalogEntry>();
  for (const provider of generated) {
    byId.set(provider.id, provider);
  }
  for (const provider of listProviderCatalog()) {
    byId.set(provider.id, {
      ...provider,
      ...byId.get(provider.id),
      source: provider.source
    });
  }
  return Array.from(byId.values()).sort((a, b) => a.id.localeCompare(b.id));
}

function renderSnapshot(snapshot: CatalogSnapshot): string {
  return `import type { CatalogSnapshot } from './schema.js';

export const CATALOG_SNAPSHOT = ${JSON.stringify(snapshot, null, 2)} satisfies CatalogSnapshot;
`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const piSource = await readText(args.piGenerated);
  const piRecords = parsePiGeneratedCatalog(piSource);
  const models = mergeModels(piRecords.flatMap((record) => mapPiModelToCatalogEntry(record) ?? []));

  const openClawProviders = args.openclawDir ? await readOpenClawProviders(args.openclawDir) : [];
  const providers = mergeProviders(openClawProviders.flatMap((record) => mapOpenClawProviderToCatalogEntry(record) ?? []));

  const snapshot: CatalogSnapshot = {
    version: 1,
    generatedAt: args.generatedAt,
    providers,
    models: models.length > 0 ? models : getCatalogSnapshot().models
  };

  await writeFile(args.out, renderSnapshot(snapshot), 'utf8');
  console.log(`Wrote ${args.out}`);
  console.log(`Providers: ${snapshot.providers.length}`);
  console.log(`Models: ${snapshot.models.length}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
