import { Box, Text, useInput, type Key } from 'ink';
import { useEffect, useMemo, useRef, useState } from 'react';

import type {
  ModelPickerModelRow,
  ModelPickerSnapshot
} from '../../model/model-picker.js';
import type { ProviderName } from '../../model/types.js';

export type ModelSetupApplyRequest = {
  provider: ProviderName;
  model: string;
  persist: boolean;
  baseUrl?: string;
  apiKey?: string;
};

export type ModelSetupFlowProps = {
  snapshot: ModelPickerSnapshot;
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>;
  onClose: () => void;
  initialProvider?: ProviderName;
};

type Step =
  | { kind: 'providers'; selectedIndex: number }
  | { kind: 'models'; provider: ProviderName; selectedIndex: number; draft?: SetupDraft }
  | { kind: 'custom-model'; provider: ProviderName; value: string; draft?: SetupDraft }
  | { kind: 'secret-confirm'; provider: ProviderName; model: string; draft: SetupDraft }
  | {
      kind: 'setup-input';
      provider: ProviderName;
      field: SetupField;
      value: string;
      draft?: SetupDraft;
      optional?: boolean;
    };

type SetupField = 'apiKey' | 'baseUrl' | 'model';

type SetupDraft = {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
};

const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;

export function ModelSetupFlow({
  snapshot,
  onApply,
  onClose,
  initialProvider
}: ModelSetupFlowProps) {
  const [step, setStep] = useState<Step>({
    kind: 'providers',
    selectedIndex: providerIndex(snapshot, initialProvider ?? snapshot.selectedProvider)
  });
  const isActiveRef = useRef(false);
  const [isActive, setIsActive] = useState(false);

  useEffect(() => {
    isActiveRef.current = false;
    setIsActive(false);
    const handle = setImmediate(() => {
      isActiveRef.current = true;
      setIsActive(true);
    });
    return () => {
      clearImmediate(handle);
      isActiveRef.current = false;
    };
  }, []);

  const selectedProvider = useMemo(() => {
    if (step.kind === 'providers') {
      return snapshot.providers[step.selectedIndex]?.provider ?? snapshot.selectedProvider;
    }
    return step.provider;
  }, [snapshot, step]);

  useInput((input: string, key: Key) => {
    if (!isActiveRef.current) return;
    if (input === 'q' || input === 'Q' || key.escape) {
      onClose();
      return;
    }

    if (step.kind === 'providers') {
      handleProviderInput(input, key, step, snapshot, setStep);
      return;
    }

    if (step.kind === 'models') {
      void handleModelInput(input, key, step, snapshot, onApply, setStep);
      return;
    }

    if (step.kind === 'secret-confirm') {
      void handleSecretConfirmInput(input, key, step, onApply);
      return;
    }

    if (step.kind === 'custom-model') {
      void handleTextInput(input, key, step.value, (value) => {
        setStep({ ...step, value });
      }, async (value) => {
        const model = value.trim();
        if (!model) return;
        await onApply(buildApplyRequest(step.provider, model, false, step.draft));
      });
      return;
    }

    void handleSetupInput(input, key, step, snapshot, onApply, setStep);
  });

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
      <Text color="cyan" bold>
        Model setup
      </Text>
      {step.kind === 'providers' ? (
        <ProviderStep snapshot={snapshot} selectedIndex={step.selectedIndex} />
      ) : step.kind === 'models' ? (
        <ModelStep snapshot={snapshot} provider={step.provider} selectedIndex={step.selectedIndex} />
      ) : step.kind === 'custom-model' ? (
        <TextInputStep title={`Custom model for ${step.provider}`} value={step.value} secret={false} />
      ) : step.kind === 'secret-confirm' ? (
        <SecretConfirmStep provider={step.provider} model={step.model} />
      ) : (
        <TextInputStep
          title={setupTitle(step.provider, step.field, step.optional === true)}
          value={step.value}
          secret={step.field === 'apiKey'}
        />
      )}
      <Box marginTop={1}>
        <Text dimColor>{footerForStep(step)}</Text>
      </Box>
      {!isActive ? <Text dimColor>Waiting for fresh input...</Text> : null}
      <Text dimColor>{`Selected provider: ${selectedProvider}`}</Text>
    </Box>
  );
}

function handleProviderInput(
  input: string,
  key: Key,
  step: Extract<Step, { kind: 'providers' }>,
  snapshot: ModelPickerSnapshot,
  setStep: (step: Step) => void
) {
  if (key.downArrow || input === 'j' || input === 'J') {
    setStep({ kind: 'providers', selectedIndex: Math.min(step.selectedIndex + 1, snapshot.providers.length - 1) });
    return;
  }
  if (key.upArrow || input === 'k' || input === 'K') {
    setStep({ kind: 'providers', selectedIndex: Math.max(step.selectedIndex - 1, 0) });
    return;
  }
  if (key.return || key.rightArrow) {
    const provider = snapshot.providers[step.selectedIndex];
    if (!provider) return;
    if (provider.state !== 'configured' && provider.issues.length > 0) {
      setStep({
        kind: 'setup-input',
        provider: provider.provider,
        field: setupFieldForIssues(provider.issues),
        value: '',
        draft: {}
      });
      return;
    }
    setStep({ kind: 'models', provider: provider.provider, selectedIndex: 0 });
  }
}

async function handleModelInput(
  input: string,
  key: Key,
  step: Extract<Step, { kind: 'models' }>,
  snapshot: ModelPickerSnapshot,
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>,
  setStep: (step: Step) => void
) {
  const rows = modelRows(snapshot, step.provider);
  if (key.leftArrow || key.backspace || key.delete) {
    setStep({ kind: 'providers', selectedIndex: providerIndex(snapshot, step.provider) });
    return;
  }
  if (key.downArrow || input === 'j' || input === 'J') {
    setStep({ ...step, selectedIndex: Math.min(step.selectedIndex + 1, rows.length - 1) });
    return;
  }
  if (key.upArrow || input === 'k' || input === 'K') {
    setStep({ ...step, selectedIndex: Math.max(step.selectedIndex - 1, 0) });
    return;
  }
  if (input === 'c' || input === 'C') {
    setStep({
      kind: 'custom-model',
      provider: step.provider,
      value: '',
      ...(step.draft ? { draft: step.draft } : {})
    });
    return;
  }
  const row = rows[step.selectedIndex];
  if (!row) return;
  if (row.kind === 'custom' && key.return) {
    setStep({
      kind: 'custom-model',
      provider: step.provider,
      value: '',
      ...(step.draft ? { draft: step.draft } : {})
    });
    return;
  }
  if (row.kind === 'model' && key.return) {
    await onApply(buildApplyRequest(row.provider, row.model, false, step.draft));
    return;
  }
  if (row.kind === 'model' && input === ' ') {
    if (step.draft?.apiKey) {
      setStep({
        kind: 'secret-confirm',
        provider: row.provider,
        model: row.model,
        draft: step.draft
      });
      return;
    }
    await onApply(buildApplyRequest(row.provider, row.model, true, step.draft));
  }
}

async function handleSecretConfirmInput(
  input: string,
  key: Key,
  step: Extract<Step, { kind: 'secret-confirm' }>,
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>
) {
  if (input === ' ') {
    await onApply(buildApplyRequest(step.provider, step.model, true, step.draft));
    return;
  }
  if (key.return) {
    await onApply(buildApplyRequest(step.provider, step.model, false, step.draft));
  }
}

async function handleSetupInput(
  input: string,
  key: Key,
  step: Extract<Step, { kind: 'setup-input' }>,
  snapshot: ModelPickerSnapshot,
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>,
  setStep: (step: Step) => void
) {
  if (step.field === 'model' && input === ' ') {
    await submitSetupModel(step, true, onApply, setStep);
    return;
  }
  if (step.field === 'apiKey' && step.optional === true && input === ' ') {
    await submitOptionalApiKey(step, true, onApply);
    return;
  }

  await handleTextInput(
    input,
    key,
    step.value,
    (value) => {
      setStep({ ...step, value });
    },
    async () => {
      if (step.field === 'apiKey') {
        if (step.optional === true) {
          await submitOptionalApiKey(step, false, onApply);
          return;
        }
        const apiKey = step.value.trim();
        if (!apiKey) return;
        setStep({
          kind: 'models',
          provider: step.provider,
          selectedIndex: 0,
          draft: mergeDraft(step.draft, { apiKey })
        });
        return;
      }

      if (step.field === 'baseUrl') {
        const baseUrl = step.value.trim();
        if (!baseUrl) return;
        const draft = mergeDraft(step.draft, { baseUrl });
        if (step.provider === 'openai-compatible' || shouldCollectDirectModel(snapshot, step.provider)) {
          setStep({ kind: 'setup-input', provider: step.provider, field: 'model', value: '', draft });
          return;
        }
        setStep({ kind: 'models', provider: step.provider, selectedIndex: 0, draft });
        return;
      }

      await submitSetupModel(step, false, onApply, setStep);
    }
  );
}

async function submitSetupModel(
  step: Extract<Step, { kind: 'setup-input' }>,
  persist: boolean,
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>,
  setStep: (step: Step) => void
) {
  const model = step.value.trim();
  if (!model) return;
  const draft = mergeDraft(step.draft, { model });
  if (step.provider === 'openai-compatible' && !persist) {
    setStep({
      kind: 'setup-input',
      provider: step.provider,
      field: 'apiKey',
      value: '',
      draft,
      optional: true
    });
    return;
  }
  await onApply(buildApplyRequest(step.provider, model, persist, draft));
}

async function submitOptionalApiKey(
  step: Extract<Step, { kind: 'setup-input' }>,
  persist: boolean,
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>
) {
  const draft = mergeDraft(step.draft, step.value.trim() ? { apiKey: step.value.trim() } : {});
  if (!draft.model) return;
  await onApply(buildApplyRequest(step.provider, draft.model, persist, draft));
}

async function handleTextInput(
  input: string,
  key: Key,
  value: string,
  onChange: (value: string) => void,
  onSubmit?: (value: string) => void | Promise<void>
) {
  if (key.return) {
    await onSubmit?.(value);
    return;
  }
  if (key.backspace) {
    onChange(value.slice(0, -1));
    return;
  }
  if (key.ctrl || key.meta || key.tab || key.escape) return;
  const printable = input.replace(CONTROL_CHARS, '');
  if (!printable) return;
  onChange(value + printable);
}

function ProviderStep({ snapshot, selectedIndex }: { snapshot: ModelPickerSnapshot; selectedIndex: number }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      {snapshot.providers.map((provider, index) => (
        <Text key={provider.provider} color={index === selectedIndex ? 'cyan' : undefined}>
          {`${index === selectedIndex ? '> ' : '  '}${provider.displayName.padEnd(18)} ${provider.stateLabel}${provider.issues.length > 0 ? ` · needs ${provider.issues.join(', ')}` : ''}`}
        </Text>
      ))}
    </Box>
  );
}

function ModelStep({
  snapshot,
  provider,
  selectedIndex
}: {
  snapshot: ModelPickerSnapshot;
  provider: ProviderName;
  selectedIndex: number;
}) {
  const rows = modelRows(snapshot, provider);
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold>{provider}</Text>
      {rows.map((row, index) => (
        <Text
          key={row.kind === 'custom' ? `${provider}:custom` : `${provider}:${row.model}`}
          color={index === selectedIndex ? 'cyan' : undefined}
        >
          {formatModelRow(row, index === selectedIndex)}
        </Text>
      ))}
    </Box>
  );
}

function TextInputStep({ title, value, secret }: { title: string; value: string; secret: boolean }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold>{title}</Text>
      <Text>{secret ? '*'.repeat(value.length) || ' ' : value || ' '}</Text>
    </Box>
  );
}

function SecretConfirmStep({ provider, model }: { provider: ProviderName; model: string }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold>{`Save API key for ${provider}?`}</Text>
      <Text>{`Model: ${model}`}</Text>
    </Box>
  );
}

function modelRows(snapshot: ModelPickerSnapshot, provider: ProviderName) {
  return snapshot.modelsByProvider[provider] ?? [];
}

function shouldCollectDirectModel(snapshot: ModelPickerSnapshot, provider: ProviderName) {
  return modelRows(snapshot, provider).filter((row) => row.kind === 'model').length === 0;
}

function providerIndex(snapshot: ModelPickerSnapshot, provider: ProviderName) {
  const index = snapshot.providers.findIndex((row) => row.provider === provider);
  return index >= 0 ? index : 0;
}

function setupFieldForIssues(issues: string[]): SetupField {
  if (issues.some((issue) => /api[_ -]?key|key/i.test(issue))) return 'apiKey';
  if (issues.some((issue) => /base url/i.test(issue))) return 'baseUrl';
  return 'model';
}

function mergeDraft(current: SetupDraft | undefined, next: SetupDraft): SetupDraft {
  return {
    ...(current ?? {}),
    ...next
  };
}

function buildApplyRequest(
  provider: ProviderName,
  model: string,
  persist: boolean,
  draft: SetupDraft | undefined
): ModelSetupApplyRequest {
  return {
    provider,
    model,
    persist,
    ...(draft?.baseUrl ? { baseUrl: draft.baseUrl } : {}),
    ...(draft?.apiKey ? { apiKey: draft.apiKey } : {})
  };
}

function setupTitle(provider: ProviderName, field: SetupField, optional: boolean) {
  if (optional && field === 'apiKey') return `Enter optional ${provider} API key`;
  if (field === 'apiKey') return `Enter ${provider} API key`;
  if (field === 'baseUrl') return `Enter ${provider} base URL`;
  return `Enter ${provider} model id`;
}

function formatModelRow(row: ModelPickerModelRow, selected: boolean) {
  const prefix = selected ? '> ' : '  ';
  const labels = row.labels.length > 0 ? ` · ${row.labels.join(', ')}` : '';
  return `${prefix}${row.displayName}${row.model ? ` (${row.model})` : ''}${labels}`;
}

function footerForStep(step: Step) {
  if (step.kind === 'providers') {
    return 'Provider step: Enter/Right models · Up/Down select · Esc/q close';
  }
  if (step.kind === 'models') {
    if (step.draft?.apiKey) {
      return 'Model step: Enter use now · Space review API key/default save · c custom model · Left back · Esc/q close';
    }
    return 'Model step: Enter use now · Space save default provider/model · c custom model · Left back · Esc/q close';
  }
  if (step.kind === 'custom-model') {
    return 'Custom model: Enter use now · Esc/q close';
  }
  if (step.kind === 'secret-confirm') {
    return 'Secret storage: Space save API key/default · Enter use now only · Esc/q close';
  }
  if (step.field === 'apiKey' && step.optional === true) {
    return 'Optional API key: Enter use now/skip · Space save default/secret · Esc/q close';
  }
  if (step.field === 'model') {
    return 'Setup model: Enter continue/use now · Space save default provider/model · Esc/q close';
  }
  return 'Setup: Enter continue · Esc/q close';
}
