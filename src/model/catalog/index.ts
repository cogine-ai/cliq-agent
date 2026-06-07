import type { ModelDescriptor, ModelModality, ProviderName } from '../types.js';
import { CATALOG_SNAPSHOT } from './snapshot.js';
import type {
  CatalogSnapshot,
  CliqModelCatalogMetadata,
  CliqModelVisibility,
  ModelCatalogEntry,
  ProviderCatalogEntry,
  ProviderKind
} from './schema.js';

export type {
  CatalogSnapshot,
  CatalogSource,
  CatalogSourceConfidence,
  CatalogSourceKind,
  CliqModelArtifactSource,
  CliqModelCatalogMetadata,
  CliqModelChecksum,
  CliqModelVisibility,
  ConfigSourceLabel,
  ContextWindowSource,
  ContextWindowSourceKind,
  ManagedRuntimeCatalog,
  ManagedRuntimeInstallationChannel,
  ManagedRuntimeOwnershipMode,
  ManagedRuntimePlatform,
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

const PROVIDER_IDS = new Set<ProviderName>([
  'openrouter',
  'anthropic',
  'openai',
  'openai-compatible',
  'ollama',
  'cliq-models'
]);

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
  if (provider === 'ollama' || provider === 'cliq-models') return 'local-runtime';
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
    record.id === 'ollama' || record.id === 'cliq-models'
      ? ({ kind: 'none' } as const)
      : ({
          kind: 'api-key',
          envVar: envVar ?? 'CLIQ_MODEL_API_KEY',
          required: record.id !== 'openai-compatible'
        } as const);

  const setupPrimary =
    record.id === 'openai-compatible'
      ? ['Set a base URL and model id for the OpenAI-compatible endpoint.']
      : record.id === 'cliq-models'
        ? ['Choose a curated Cliq Models allowlist entry before using the managed local runtime.']
      : auth.kind === 'none'
        ? ['Run the local provider service before selecting a model.']
        : [`Set ${auth.envVar} or configure an ${record.name ?? record.id} credential.`];

  const modelListSource =
    record.id === 'ollama'
      ? {
          kind: 'ollama-tags' as const,
          description: 'Local Ollama /api/tags discovery.'
        }
      : record.id === 'cliq-models'
        ? {
            kind: 'curated-local' as const,
            description: 'Cliq-managed curated local model allowlist.'
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
      record.id === 'ollama' || record.id === 'cliq-models'
        ? ['Local service', 'Workspace', 'Global', 'CLI']
        : ['ENV', 'Workspace', 'Global', 'CLI'],
    setup: {
      primary: setupPrimary,
      ...(record.docs ? { docsUrl: record.docs } : {})
    },
    modelListSource,
    ...(PROVIDER_DEFAULT_MODELS[record.id] ? { defaultModelId: PROVIDER_DEFAULT_MODELS[record.id] } : {}),
    visibleModelLimit: record.id === 'openai-compatible' ? 0 : record.id === 'cliq-models' ? 8 : 12,
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

export type ParsedCliqModelCatalogEntry = ModelCatalogEntry & {
  provider: 'cliq-models';
  cliqModel: CliqModelCatalogMetadata;
};

export type CliqModelCatalogParseResult =
  | {
      ok: true;
      entry: ParsedCliqModelCatalogEntry;
    }
  | {
      ok: false;
      issues: string[];
    };

const SELECTABLE_CLIQ_MODEL_VISIBILITIES = new Set<CliqModelVisibility>(['recommended', 'experimental']);

function isPositiveInteger(value: number | undefined) {
  return Number.isInteger(value) && value !== undefined && value > 0;
}

function isNonEmptyString(value: string | undefined) {
  return typeof value === 'string' && value.trim() !== '';
}

function validateChecksum(metadata: CliqModelCatalogMetadata, issues: string[]) {
  const checksum = metadata.artifact.checksum;
  if (checksum.algorithm === 'sha256') {
    if (!/^[a-f0-9]{64}$/i.test(checksum.value)) {
      issues.push('cliqModel.artifact.checksum.value must be a 64 character hex SHA-256 digest');
    }
    return;
  }

  if (checksum.algorithm === 'ollama-blob-digest') {
    if (!/^[a-f0-9]{12,64}$/i.test(checksum.value)) {
      issues.push('cliqModel.artifact.checksum.value must be a 12-64 character Ollama blob digest');
    }
    return;
  }

  issues.push('cliqModel.artifact.checksum.algorithm must be sha256 or ollama-blob-digest');
}

function validateArtifactSource(metadata: CliqModelCatalogMetadata, issues: string[]) {
  const source = metadata.artifact.source;
  if (source.type === 'hugging-face-gguf') {
    if (!isNonEmptyString(source.repository)) issues.push('cliqModel.artifact.source.repository is required');
    if (!isNonEmptyString(source.filename)) issues.push('cliqModel.artifact.source.filename is required');
    if (!isNonEmptyString(source.url)) issues.push('cliqModel.artifact.source.url is required');
    return;
  }

  if (source.type === 'ollama-library') {
    if (!isNonEmptyString(source.model)) issues.push('cliqModel.artifact.source.model is required');
    if (!isNonEmptyString(source.manifestDigest)) issues.push('cliqModel.artifact.source.manifestDigest is required');
    if (!isNonEmptyString(source.url)) issues.push('cliqModel.artifact.source.url is required');
    return;
  }

  issues.push('cliqModel.artifact.source.type must be hugging-face-gguf or ollama-library');
}

export function validateCliqModelCatalogEntry(entry: ModelCatalogEntry): string[] {
  const issues: string[] = [];
  if (entry.provider !== 'cliq-models') {
    issues.push('provider must be cliq-models');
  }

  const metadata = entry.cliqModel;
  if (!metadata) {
    issues.push('cliqModel metadata is required');
    return issues;
  }

  if (metadata.selectable !== true) issues.push('cliqModel.selectable must be true');
  if (!SELECTABLE_CLIQ_MODEL_VISIBILITIES.has(metadata.visibility)) {
    issues.push('cliqModel.visibility must be recommended or experimental for selectable entries');
  }
  if (!isNonEmptyString(metadata.family)) issues.push('cliqModel.family is required');
  if (!isNonEmptyString(metadata.baseModel)) issues.push('cliqModel.baseModel is required');
  if (!isNonEmptyString(metadata.parameterSize)) issues.push('cliqModel.parameterSize is required');
  if (!isNonEmptyString(metadata.quantization)) issues.push('cliqModel.quantization is required');

  validateArtifactSource(metadata, issues);
  if (!isPositiveInteger(metadata.artifact.downloadSizeBytes)) {
    issues.push('cliqModel.artifact.downloadSizeBytes must be a positive integer');
  }
  if (!isPositiveInteger(metadata.artifact.diskSizeBytes)) {
    issues.push('cliqModel.artifact.diskSizeBytes must be a positive integer');
  } else if (
    isPositiveInteger(metadata.artifact.downloadSizeBytes) &&
    metadata.artifact.diskSizeBytes < metadata.artifact.downloadSizeBytes
  ) {
    issues.push('cliqModel.artifact.diskSizeBytes must be greater than or equal to downloadSizeBytes');
  }
  if (!isNonEmptyString(metadata.artifact.license.name)) issues.push('cliqModel.artifact.license.name is required');
  validateChecksum(metadata, issues);

  if (!isPositiveInteger(metadata.requirements.recommendedRamBytes)) {
    issues.push('cliqModel.requirements.recommendedRamBytes must be a positive integer');
  }
  if (!isPositiveInteger(metadata.runtimeOptions.contextWindow)) {
    issues.push('cliqModel.runtimeOptions.contextWindow must be a positive integer');
  }
  if (!isNonEmptyString(metadata.runtimeImport.runtimeId)) issues.push('cliqModel.runtimeImport.runtimeId is required');
  if (!isNonEmptyString(metadata.runtimeImport.targetModelTag)) {
    issues.push('cliqModel.runtimeImport.targetModelTag is required');
  }
  if (metadata.runtimeImport.instructions.length === 0) {
    issues.push('cliqModel.runtimeImport.instructions must not be empty');
  }
  if (!isNonEmptyString(metadata.prompts.disk)) issues.push('cliqModel.prompts.disk is required');
  if (!isNonEmptyString(metadata.prompts.license)) issues.push('cliqModel.prompts.license is required');
  if (!isNonEmptyString(metadata.prompts.checksum)) issues.push('cliqModel.prompts.checksum is required');

  return issues;
}

export function parseCliqModelCatalogEntry(entry: ModelCatalogEntry): CliqModelCatalogParseResult {
  const issues = validateCliqModelCatalogEntry(entry);
  if (issues.length > 0) {
    return { ok: false, issues };
  }
  return { ok: true, entry: entry as ParsedCliqModelCatalogEntry };
}

export function listCliqModelCatalogEntries(): ParsedCliqModelCatalogEntry[] {
  return CATALOG_SNAPSHOT.models.flatMap((entry) => {
    const parsed = parseCliqModelCatalogEntry(entry);
    return parsed.ok ? [parsed.entry] : [];
  });
}

export function isSelectableCliqModel(model: string): boolean {
  const entry = resolveModelMetadata('cliq-models', model);
  if (!entry) {
    return false;
  }
  const parsed = parseCliqModelCatalogEntry(entry);
  return parsed.ok && parsed.entry.cliqModel.selectable && SELECTABLE_CLIQ_MODEL_VISIBILITIES.has(parsed.entry.cliqModel.visibility);
}
