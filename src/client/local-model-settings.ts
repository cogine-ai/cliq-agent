// The client stores user choices. The fixed installed operation owns model
// import, strong backend selection, registry transactions and all authority.
import { controlWireText } from '../kernel/control-wire-data.js';
import type { HeldInstalledRuntime } from '../state/installed-runtime.js';
import { enrollInstalledLocalModel, listInstalledLocalModels, retireInstalledLocalModel } from '../state/local-model-operations.js';
import type { InstalledClientData } from './installed-data.js';
import { CLIENT_MODEL_SELECTION_LIMIT, readClientPreferences, writeClientPreferences, type ClientModelSelectionV1 } from './preferences.js';

export async function configureInstalledLocalModel(selected: HeldInstalledRuntime, data: InstalledClientData,
  alias: string, manifestPath: string, signal?: AbortSignal) {
  controlWireText(alias, 128); controlWireText(manifestPath, 4096);
  signal?.throwIfAborted();
  const preferences = await readClientPreferences(data.directory);
  if (!preferences.modelSelections.some(value => value.alias === alias) && preferences.modelSelections.length >= CLIENT_MODEL_SELECTION_LIMIT)
    throw new TypeError('model aliases are full; local enrollment was not started');
  const model = await enrollInstalledLocalModel(selected, manifestPath, signal);
  if (model.provider !== 'ollama' || model.state !== 'active') throw new TypeError('local model enrollment did not produce an active original registration');
  signal?.throwIfAborted();
  const choice = await saveLocalChoice(data, alias, model.model);
  return { choice, model };
}

export async function selectInstalledLocalModel(selected: HeldInstalledRuntime, data: InstalledClientData,
  alias: string, name: string, signal?: AbortSignal) {
  controlWireText(alias, 128); controlWireText(name, 512); signal?.throwIfAborted();
  const available = await listInstalledLocalModels(selected, signal);
  const model = available.find(value => value.model === name && value.provider === 'ollama' && value.state === 'active');
  if (!model) throw new TypeError('select an active enrolled local model');
  signal?.throwIfAborted();
  return { choice: await saveLocalChoice(data, alias, name), model };
}

async function saveLocalChoice(data: InstalledClientData, alias: string, model: string): Promise<ClientModelSelectionV1> {
  const choice: ClientModelSelectionV1 = { alias, provider: 'ollama', model };
  await data.directory.withLock(async () => {
    const current = await readClientPreferences(data.directory);
    if (!current.modelSelections.some(value => value.alias === alias) && current.modelSelections.length >= CLIENT_MODEL_SELECTION_LIMIT)
      throw new TypeError('model aliases became full; the enrolled model remains available for explicit selection');
    await writeClientPreferences(data.directory, { ...current,
      modelSelections: [...current.modelSelections.filter(value => value.alias !== alias), choice],
      defaultModelAlias: current.defaultModelAlias ?? alias });
  });
  return choice;
}

export async function retireInstalledLocalModelAlias(selected: HeldInstalledRuntime, data: InstalledClientData,
  alias: string, signal?: AbortSignal) {
  controlWireText(alias, 128); signal?.throwIfAborted();
  const preferences = await readClientPreferences(data.directory);
  const choice = preferences.modelSelections.find(value => value.alias === alias);
  if (!choice || choice.provider !== 'ollama') throw new TypeError('select a configured local model alias to retire');
  const result = await retireInstalledLocalModel(selected, choice.model, signal);
  if (result.provider !== 'ollama' || result.model !== choice.model || result.state !== 'retired')
    throw new TypeError('local model retirement did not retain its exact original selection');
  // Keep the explicit choice: a later Run must report this retired model,
  // rather than silently falling back to another model or paid provider.
  return result;
}

export { listInstalledLocalModels };
