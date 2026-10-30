// User choices only. These records never establish Trust, model eligibility,
// endpoint/credential authority, operation permission or a spending allowance.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord as record, controlWireText as text } from '../kernel/control-wire-data.js';
import { mergeBudgets } from '../kernel/control-submit.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { RunSpec } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { PrivateClientDirectory } from './private-files.js';
import type { ClientPreferencesV1 } from './types.js';
export type { ClientModelSelectionV1, ClientPreferencesV1 } from './types.js';

export const CLIENT_PREFERENCES_FILE = 'preferences.json';
export const CLIENT_PREFERENCES_BYTES = 65_536;
export const CLIENT_MODEL_SELECTION_LIMIT = 32;
export const EMPTY_CLIENT_PREFERENCES: ClientPreferencesV1 = Object.freeze({ schemaVersion: 1, modelSelections: Object.freeze([]) });

export function decodeClientPreferences(value: unknown): ClientPreferencesV1 {
  assertControlWireJson(value);
  const data = record(value, ['schemaVersion', 'modelSelections'], ['defaultModelAlias', 'budgetDefaults']);
  if (data.schemaVersion !== 1 || !Array.isArray(data.modelSelections) || data.modelSelections.length > CLIENT_MODEL_SELECTION_LIMIT)
    throw new TypeError('client preferences are outside their closed format');
  const modelSelections = data.modelSelections.map(value => {
    const selected = record(value, ['alias', 'provider', 'model', 'endpointRegistrationId', 'credentialGrantId']);
    if (selected.provider !== 'openai-compatible') throw new TypeError('client selection requires a supported installed provider');
    return { alias: text(selected.alias), provider: 'openai-compatible' as const, model: text(selected.model, 512),
      endpointRegistrationId: text(selected.endpointRegistrationId), credentialGrantId: text(selected.credentialGrantId) };
  });
  if (new Set(modelSelections.map(selected => selected.alias)).size !== modelSelections.length)
    throw new TypeError('client model aliases must be unique');
  const defaultModelAlias = data.defaultModelAlias === undefined ? undefined : text(data.defaultModelAlias);
  if (defaultModelAlias !== undefined && !modelSelections.some(selected => selected.alias === defaultModelAlias))
    throw new TypeError('default model alias names no selected model');
  let budgetDefaults: RunSpec['budgets'] | undefined;
  if (data.budgetDefaults !== undefined) {
    const budgets = record(data.budgetDefaults, ['wallTimeMs', 'modelTokens', 'costMicros', 'toolCalls', 'repairAttempts', 'childDepth', 'childConcurrency']);
    budgetDefaults = mergeBudgets(budgets as RunSpec['budgets']);
  }
  const result = immutableSnapshot({ schemaVersion: 1 as const, modelSelections,
    ...(defaultModelAlias === undefined ? {} : { defaultModelAlias }), ...(budgetDefaults === undefined ? {} : { budgetDefaults }) });
  if (canonicalJsonBytes(result).length > CLIENT_PREFERENCES_BYTES) throw new TypeError('client preferences exceed their byte bound');
  return result;
}

/** The host supplies its held, actual-account private directory. No locator,
 * home/environment override or credential store enters this data module. */
export async function readClientPreferences(directory: PrivateClientDirectory): Promise<ClientPreferencesV1> {
  const bytes = await directory.read(CLIENT_PREFERENCES_FILE, CLIENT_PREFERENCES_BYTES);
  if (bytes === undefined) return EMPTY_CLIENT_PREFERENCES;
  if (!Buffer.isBuffer(bytes) || bytes.length > CLIENT_PREFERENCES_BYTES) throw new TypeError('client preferences exceed their byte bound');
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  const decoded = decodeClientPreferences(value);
  if (!canonicalJsonBytes(decoded).equals(bytes)) throw new TypeError('client preferences are not canonical');
  return decoded;
}

export async function writeClientPreferences(directory: PrivateClientDirectory, value: unknown): Promise<ClientPreferencesV1> {
  const decoded = decodeClientPreferences(value);
  await directory.replace(CLIENT_PREFERENCES_FILE, canonicalJsonBytes(decoded));
  return decoded;
}
