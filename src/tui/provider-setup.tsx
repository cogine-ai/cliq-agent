import { Box, render, Text, useApp, useInput } from 'ink';

import { formatModelSetupMessage, type ModelSetupRequiredError } from '../model/config.js';
import type { ModelPickerSnapshot } from '../model/model-picker.js';
import type { ProviderAuthStore } from '../model/auth-store.js';
import type { ResolvedModelConfig } from '../model/types.js';
import { ModelSetupFlow, type ModelSetupApplyRequest } from './components/model-setup-flow.js';

export type ProviderSetupProps = {
  error: ModelSetupRequiredError;
};

export type ProviderSetupResult =
  | ProviderAuthStore
  | { auth: ProviderAuthStore; modelConfig: ResolvedModelConfig };

export type ProviderSetupInteractiveOptions = {
  snapshot: ModelPickerSnapshot;
  onApply: (request: ModelSetupApplyRequest) => ProviderSetupResult | Promise<ProviderSetupResult>;
};

export function ProviderSetup({ error }: ProviderSetupProps) {
  const { exit } = useApp();
  const lines = formatModelSetupMessage(error).split('\n');

  useInput((input, key) => {
    if (input === 'q' || key.return || key.escape || (key.ctrl && (input === 'c' || input === 'd'))) {
      exit();
    }
  });

  return (
    <Box flexDirection="column">
      {lines.map((line, index) => (
        <Text key={`${index}:${line}`}>{line}</Text>
      ))}
      <Text>Press Enter or q to exit.</Text>
    </Box>
  );
}

export async function mountProviderSetupAndWait(
  error: ModelSetupRequiredError,
  options?: ProviderSetupInteractiveOptions,
  renderImpl: typeof render = render
): Promise<ProviderSetupResult | null> {
  if (!options) {
    const instance = renderImpl(<ProviderSetup error={error} />, { exitOnCtrlC: false });
    await instance.waitUntilExit();
    return null;
  }

  let result: ProviderSetupResult | null = null;
  let resultError: unknown;
  let instance: ReturnType<typeof render> | undefined;
  const close = () => {
    instance?.unmount();
  };
  instance = renderImpl(
    <ModelSetupFlow
      snapshot={options.snapshot}
      onApply={async (request) => {
        try {
          result = await options.onApply(request);
        } catch (error) {
          resultError = error;
        } finally {
          close();
        }
      }}
      onClose={close}
      initialProvider={error.provider}
    />,
    { exitOnCtrlC: false }
  );
  await instance.waitUntilExit();
  if (resultError) {
    throw resultError;
  }
  return result;
}
