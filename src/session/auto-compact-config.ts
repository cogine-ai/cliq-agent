export type AutoCompactEnabled = 'auto' | 'on' | 'off';
export type AutoCompactContextWindowSource = 'config' | 'model-descriptor' | 'overflow-error';

export type AutoCompactConfig = {
  enabled?: AutoCompactEnabled;
  contextWindowTokens?: number;
  thresholdRatio?: number;
  reserveTokens?: number;
  keepRecentTokens?: number;
  minNewTokens?: number;
  maxThresholdCompactionsPerTurn?: number;
  maxOverflowRetriesPerModelCall?: number;
};

export type ResolvedAutoCompactConfig = {
  enabled: AutoCompactEnabled;
  contextWindowTokens: number | null;
  contextWindowSource: AutoCompactContextWindowSource | null;
  thresholdRatio: number;
  reserveTokens: number;
  keepRecentTokens: number;
  minNewTokens: number;
  maxThresholdCompactionsPerTurn: number;
  maxOverflowRetriesPerModelCall: number;
  usableLimitTokens: number | null;
};

const DEFAULTS = {
  enabled: 'auto' as const,
  thresholdRatio: 0.8,
  reserveTokens: 16_000,
  keepRecentTokens: 20_000,
  minNewTokens: 4_000,
  maxThresholdCompactionsPerTurn: 1,
  maxOverflowRetriesPerModelCall: 1
};

function assertInteger(name: string, value: number, minimum: number) {
  if (!Number.isInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
}

export function resolveAutoCompactConfig({
  config,
  modelContextWindowTokens,
  overflowContextWindowTokens
}: {
  config: AutoCompactConfig;
  modelContextWindowTokens?: number;
  overflowContextWindowTokens?: number;
}): ResolvedAutoCompactConfig {
  const resolved = {
    ...DEFAULTS,
    ...config
  };

  if (resolved.enabled !== 'auto' && resolved.enabled !== 'on' && resolved.enabled !== 'off') {
    throw new Error('autoCompact.enabled must be one of: auto, on, off');
  }
  if (resolved.thresholdRatio <= 0 || resolved.thresholdRatio >= 1) {
    throw new Error('autoCompact.thresholdRatio must be greater than 0 and less than 1');
  }

  assertInteger('autoCompact.reserveTokens', resolved.reserveTokens, 0);
  assertInteger('autoCompact.keepRecentTokens', resolved.keepRecentTokens, 0);
  assertInteger('autoCompact.minNewTokens', resolved.minNewTokens, 0);
  assertInteger('autoCompact.maxThresholdCompactionsPerTurn', resolved.maxThresholdCompactionsPerTurn, 1);
  assertInteger('autoCompact.maxOverflowRetriesPerModelCall', resolved.maxOverflowRetriesPerModelCall, 1);

  const contextWindowTokens = config.contextWindowTokens ?? modelContextWindowTokens ?? overflowContextWindowTokens ?? null;
  const contextWindowSource: AutoCompactContextWindowSource | null =
    config.contextWindowTokens !== undefined
      ? 'config'
      : modelContextWindowTokens !== undefined
        ? 'model-descriptor'
        : overflowContextWindowTokens !== undefined
          ? 'overflow-error'
          : null;

  if (contextWindowTokens !== null) {
    assertInteger('autoCompact.contextWindowTokens', contextWindowTokens, 1);
    if (resolved.reserveTokens >= contextWindowTokens) {
      throw new Error('autoCompact.reserveTokens must be less than contextWindowTokens');
    }
  }
  if (resolved.enabled === 'on' && contextWindowTokens === null) {
    throw new Error('autoCompact.enabled on requires a context window');
  }

  const usableLimitTokens =
    contextWindowTokens === null
      ? null
      : Math.floor(Math.min(contextWindowTokens * resolved.thresholdRatio, contextWindowTokens - resolved.reserveTokens));

  if (usableLimitTokens !== null && usableLimitTokens <= 0) {
    throw new Error('autoCompact usableLimit must be positive');
  }
  if (usableLimitTokens !== null && resolved.keepRecentTokens >= usableLimitTokens) {
    throw new Error('autoCompact.keepRecentTokens must be less than usableLimit');
  }

  return {
    enabled: resolved.enabled,
    contextWindowTokens,
    contextWindowSource,
    thresholdRatio: resolved.thresholdRatio,
    reserveTokens: resolved.reserveTokens,
    keepRecentTokens: resolved.keepRecentTokens,
    minNewTokens: resolved.minNewTokens,
    maxThresholdCompactionsPerTurn: resolved.maxThresholdCompactionsPerTurn,
    maxOverflowRetriesPerModelCall: resolved.maxOverflowRetriesPerModelCall,
    usableLimitTokens
  };
}
