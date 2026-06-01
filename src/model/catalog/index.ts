import type { ModelDescriptor, ModelModality, ProviderName } from '../types.js';
import { CATALOG_SNAPSHOT } from './snapshot.js';
import type { CatalogSnapshot, ModelCatalogEntry, ProviderCatalogEntry, ProviderKind } from './schema.js';

export type {
  CatalogSnapshot,
  CatalogSource,
  CatalogSourceConfidence,
  CatalogSourceKind,
  ConfigSourceLabel,
  ContextWindowSource,
  ContextWindowSourceKind,
  ModelCatalogEntry,
  ModelListSource,
  ModelListSourceKind,
  ProviderAuth,
  ProviderCatalogEntry,
  ProviderKind
} from './schema.js';

export type PiModelCatalogRecord = {
  provider: string;
  id: string;
  name?: string;
  api: string;
  baseUrl?: string;
  reasoning?: boolean;
  input?: string[];
  cost?: {
    input?: number;
    output?: number;
    cacheRead?: number;
    cacheWrite?: number;
  };
  contextWindow?: number;
  maxTokens?: number;
  compat?: Record<string, unknown>;
};

export type OpenClawProviderRecord = {
  id: string;
  name?: string;
  docs?: string;
  categories?: string[];
  authChoices?: Array<{
    method?: string;
    optionKey?: string;
    cliOption?: string;
    choiceHint?: string;
  }>;
};

const PROVIDER_IDS = new Set<ProviderName>(['openrouter', 'anthropic', 'openai', 'openai-compatible', 'ollama']);

const PI_PROVIDER_MAP: Record<string, ProviderName | undefined> = {
  openrouter: 'openrouter',
  anthropic: 'anthropic',
  openai: 'openai'
};

const PROVIDER_ENV_VARS: Partial<Record<ProviderName, string>> = {
  openrouter: 'OPENROUTER_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  'openai-compatible': 'CLIQ_MODEL_API_KEY'
};

const PROVIDER_DEFAULT_MODELS: Partial<Record<ProviderName, string>> = {
  openrouter: 'anthropic/claude-sonnet-4.6',
  anthropic: 'claude-sonnet-4-20250514',
  openai: 'gpt-5.2'
};

function isProviderName(value: string): value is ProviderName {
  return PROVIDER_IDS.has(value as ProviderName);
}

function normalizeInputModalities(input: string[] | undefined): ModelModality[] {
  const normalized = (input ?? ['text']).filter((value): value is ModelModality =>
    value === 'text' || value === 'image' || value === 'audio' || value === 'video'
  );
  return normalized.length > 0 ? normalized : ['text'];
}

function withOptionalNumber<T extends Record<string, unknown>>(record: T, key: string, value: number | undefined): T {
  if (value === undefined) {
    return record;
  }
  return {
    ...record,
    [key]: value
  };
}

function hasCompletePricing(cost: PiModelCatalogRecord['cost']): cost is Required<NonNullable<PiModelCatalogRecord['cost']>> {
  return (
    cost !== undefined &&
    Number.isFinite(cost.input) &&
    Number.isFinite(cost.output) &&
    Number.isFinite(cost.cacheRead) &&
    Number.isFinite(cost.cacheWrite)
  );
}

export function mapPiModelToCatalogEntry(record: PiModelCatalogRecord): ModelCatalogEntry | null {
  const provider = PI_PROVIDER_MAP[record.provider];
  if (!provider) {
    return null;
  }

  const capabilities = withOptionalNumber(
    withOptionalNumber(
      {
        input: normalizeInputModalities(record.input),
        output: ['text'],
        streaming: true,
        reasoning: record.reasoning === true,
        toolCalling: true
      },
      'contextWindow',
      record.contextWindow
    ),
    'maxOutputTokens',
    record.maxTokens
  ) as ModelCatalogEntry['capabilities'];

  const entry: ModelCatalogEntry = {
    provider,
    model: record.id,
    displayName: record.name ?? record.id,
    capabilities,
    routing: {
      api: record.api,
      ...(record.baseUrl ? { baseUrl: record.baseUrl } : {})
    },
    ...(hasCompletePricing(record.cost)
      ? {
          pricing: {
            input: record.cost.input,
            output: record.cost.output,
            cacheRead: record.cost.cacheRead,
            cacheWrite: record.cost.cacheWrite
          }
        }
      : {}),
    ...(record.compat ? { compat: record.compat } : {}),
    source: {
      kind: 'pi',
      confidence: 'medium',
      upstreamProvider: record.provider,
      upstreamModelId: record.id
    }
  };

  return entry;
}

function inferProviderKind(provider: ProviderName, categories: string[] | undefined): ProviderKind {
  if (provider === 'openrouter') return 'aggregator';
  if (provider === 'ollama') return 'local-runtime';
  if (provider === 'openai-compatible') return 'openai-compatible';
  if (categories?.includes('local')) return 'local-runtime';
  return 'hosted-api';
}

export function mapOpenClawProviderToCatalogEntry(record: OpenClawProviderRecord): ProviderCatalogEntry | null {
  if (!isProviderName(record.id)) {
    return null;
  }

  const envVar = PROVIDER_ENV_VARS[record.id];
  const auth =
    record.id === 'ollama'
      ? ({ kind: 'none' } as const)
      : ({
          kind: 'api-key',
          envVar: envVar ?? 'CLIQ_MODEL_API_KEY',
          required: record.id !== 'openai-compatible'
        } as const);

  const setupPrimary =
    record.id === 'openai-compatible'
      ? ['Set a base URL and model id for the OpenAI-compatible endpoint.']
      : auth.kind === 'none'
      ? ['Run the local provider service before selecting a model.']
      : [`Set ${auth.envVar} or configure an ${record.name ?? record.id} credential.`];

  const modelListSource =
    record.id === 'ollama'
      ? {
          kind: 'ollama-tags' as const,
          description: 'Local Ollama /api/tags discovery.'
        }
      : record.id === 'openai-compatible'
        ? {
            kind: 'user-config' as const,
            description: 'User or workspace configuration supplies the model id.'
          }
        : {
            kind: 'snapshot' as const,
            description: 'Static CLIQ catalog generated from upstream metadata.'
          };

  return {
    id: record.id,
    displayName: record.name ?? record.id,
    kind: inferProviderKind(record.id, record.categories),
    auth,
    configSources:
      record.id === 'ollama' ? ['Local service', 'Workspace', 'Global', 'CLI'] : ['ENV', 'Workspace', 'Global', 'CLI'],
    setup: {
      primary: setupPrimary,
      ...(record.docs ? { docsUrl: record.docs } : {})
    },
    modelListSource,
    ...(PROVIDER_DEFAULT_MODELS[record.id] ? { defaultModelId: PROVIDER_DEFAULT_MODELS[record.id] } : {}),
    visibleModelLimit: record.id === 'openai-compatible' ? 0 : 12,
    source: {
      kind: 'openclaw',
      confidence: 'medium',
      upstreamProvider: record.id
    }
  };
}

export function getCatalogSnapshot(): CatalogSnapshot {
  return CATALOG_SNAPSHOT;
}

export function listProviderCatalog(): ProviderCatalogEntry[] {
  return [...CATALOG_SNAPSHOT.providers];
}

export function getProviderCatalogEntry(provider: ProviderName): ProviderCatalogEntry | null {
  return CATALOG_SNAPSHOT.providers.find((entry) => entry.id === provider) ?? null;
}

export function listModelCatalogEntries(provider?: ProviderName): ModelCatalogEntry[] {
  return CATALOG_SNAPSHOT.models.filter((entry) => provider === undefined || entry.provider === provider);
}

export function resolveModelMetadata(provider: ProviderName, model: string): ModelCatalogEntry | null {
  return (
    CATALOG_SNAPSHOT.models.find((entry) => entry.provider === provider && entry.model === model) ??
    null
  );
}

export function toModelDescriptor(entry: ModelCatalogEntry): ModelDescriptor {
  return {
    provider: entry.provider,
    model: entry.model,
    displayName: entry.displayName,
    capabilities: entry.capabilities
  };
}

export function listModelDescriptors(provider: ProviderName): ModelDescriptor[] {
  return listModelCatalogEntries(provider).map(toModelDescriptor);
}
