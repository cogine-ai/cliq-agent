# Provider-First TUI Model Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #53: provider-first TUI setup, model picking, explicit credential/default persistence, and runtime model switching.

**Architecture:** Add a model-picker data layer under `src/model/` that combines provider status, catalog models, Ollama tags, configured model ids, and current runtime state without importing TUI code. Add a reusable Ink modal flow under `src/tui/components/` that `/model`, `/models`, `/providers configure`, and first-run setup can all use. Runtime model changes are applied by rebuilding the TUI runner/client with the selected `ResolvedModelConfig`, updating `session.model`, and dispatching a `UiState.model` update.

**Tech Stack:** TypeScript, Node.js 22, React/Ink, `node:test`, `ink-testing-library`, existing model registry/auth-store/provider-status modules.

---

## Current Findings

- `gh issue view 53` confirms the issue is open and last updated `2026-06-02T18:37:47Z`.
- `main` is clean and aligned with `origin/main`.
- The prerequisites are present on `main`: first-run setup shell, provider management, catalog metadata, and local auth-store.
- `/model` and `/models` do not exist in `src/tui/slash.ts`.
- `src/tui/app.tsx` exposes only `onProviderStatus`; it needs callbacks for building picker data, applying a runtime model, and saving setup/defaults.
- `src/tui/components/provider-management.tsx` is status/detail-only; it needs a configure action that hands off to the shared setup flow.
- `src/tui/provider-setup.tsx` is static first-run guidance; it must eventually reuse the interactive setup flow or first-run users with no model still cannot reach `/model`.
- `src/cli.ts` captures `runner`, `modelClient`, and `modelConfig` at TUI construction time. Applying a model must rebuild or swap the runner/client and update `autoCompact.modelConfig`.
- `ProviderStatus.baseUrl` can currently contain auth-store userinfo/query/fragment. It is rendered directly in `/providers` detail. Add a display-safe base URL path before expanding UI surfaces.
- README still says Cliq does not store provider secrets, which conflicts with the merged auth-store behavior.

## File Map

- Modify `src/model/provider-status.ts`: sanitize display/report base URLs; keep status output safe.
- Test `src/model/provider-status.test.ts`: unsafe auth-store base URL does not leak through report JSON or formatted output.
- Create `src/model/model-picker.ts`: model-picker snapshot builder and helper types.
- Test `src/model/model-picker.test.ts`: provider step selection, row sources/labels, configured/custom/OpenAI-compatible/Ollama cases.
- Modify `src/tui/slash.ts`: add `/model` and `/models` alias parsing/completion/help.
- Modify `src/tui/store.ts`: add a `model-change` action for `UiState.model`.
- Create `src/tui/components/model-setup-flow.tsx`: reusable provider/model/setup modal.
- Test `src/tui/components/model-setup-flow.test.tsx`: provider step, footer hints, masked input, Enter/Space controls, setup-to-model transition.
- Modify `src/tui/components/provider-management.tsx`: add configure action and callback.
- Modify `src/tui/app.tsx` and `src/tui/index.tsx`: wire `/model`, `/models`, `/providers configure`, modal blocking, callback types.
- Modify `src/cli.ts`: mutable TUI model runtime state, runner rebuild helper, auth refresh/save callbacks, first-run interactive setup follow-up.
- Modify `src/tui/provider-setup.tsx`: preserve static guidance until the shared startup setup mount is ready, then delegate to shared flow.
- Modify `README.md` and `docs/provider-management.md`: document `/model`, `/models`, session-only Enter, Space default save, auth-store secret persistence, OpenAI-compatible setup, and out-of-scope items.

## Task 1: Make Provider Status Display-Safe

**Files:**
- Modify: `src/model/provider-status.ts`
- Test: `src/model/provider-status.test.ts`

- [ ] **Step 1: Write the failing base URL leak test**

Append this test to `src/model/provider-status.test.ts`:

```ts
test('provider status sanitizes auth-store base URLs before report output', async () => {
  await withEnv({}, async () => {
    const auth: ProviderAuthStore = {
      version: 1,
      activeProvider: 'openai-compatible',
      providers: {
        'openai-compatible': {
          model: 'local-model',
          baseUrl: 'https://user:pass@example.test/v1?token=secret#fragment'
        }
      }
    };

    const report = await buildProviderStatusReport({
      workspace: {},
      cli: {},
      auth,
      discoverOllamaModels: unavailableOllama
    });

    const compatible = report.providers.find((provider) => provider.provider === 'openai-compatible');
    assert.equal(compatible?.baseUrl, 'https://example.test/v1');

    const serialized = JSON.stringify(report);
    const rendered = formatProviderStatusReport(report);
    assert.doesNotMatch(serialized, /user:pass|token=secret|fragment/);
    assert.doesNotMatch(rendered, /user:pass|token=secret|fragment/);
  });
});
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
node --test --import tsx src/model/provider-status.test.ts
```

Expected: FAIL because `compatible.baseUrl` still includes `user:pass`, query, and fragment.

- [ ] **Step 3: Add a safe display URL helper**

In `src/model/provider-status.ts`, add:

```ts
export function sanitizeBaseUrlForDisplay(baseUrl: string): string {
  try {
    const url = new URL(baseUrl);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString().replace(/\/$/, baseUrl.endsWith('/') ? '/' : '');
  } catch {
    return baseUrl.replace(/\/\/[^/@\s]+@/, '//').replace(/[?#].*$/, '');
  }
}
```

Then replace every `...(baseUrl ? { baseUrl } : {})` in returned `ProviderStatus` objects with:

```ts
...(baseUrl ? { baseUrl: sanitizeBaseUrlForDisplay(baseUrl) } : {})
```

- [ ] **Step 4: Run the provider status tests**

Run:

```bash
node --test --import tsx src/model/provider-status.test.ts
```

Expected: PASS.

## Task 2: Add the Model Picker Data Builder

**Files:**
- Create: `src/model/model-picker.ts`
- Test: `src/model/model-picker.test.ts`

- [ ] **Step 1: Create failing tests for provider-first snapshot data**

Create `src/model/model-picker.test.ts` with tests covering:

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import type { ProviderAuthStore } from './auth-store.js';
import { buildModelPickerSnapshot } from './model-picker.js';
import type { ProviderStatusReport } from './provider-status.js';

const report: ProviderStatusReport = {
  activeProvider: 'openai',
  activeModel: 'gpt-auth',
  providers: [
    {
      provider: 'openai',
      displayName: 'OpenAI',
      current: true,
      state: 'configured',
      sources: ['Managed credential'],
      issues: [],
      setup: [],
      model: 'gpt-auth',
      baseUrl: 'https://api.openai.com/v1'
    },
    {
      provider: 'openai-compatible',
      displayName: 'OpenAI-compatible',
      current: false,
      state: 'not-configured',
      sources: [],
      issues: [{ code: 'missing-base-url', requirement: 'base URL', message: 'Base URL required.' }],
      setup: []
    },
    {
      provider: 'ollama',
      displayName: 'Ollama',
      current: false,
      state: 'configured',
      sources: ['Local service'],
      issues: [],
      setup: [],
      modelCount: 2,
      model: 'qwen3.5:4b',
      baseUrl: 'http://localhost:11434'
    }
  ],
  credentialPersistence: {
    mode: 'local-auth-file',
    supportsManagedCredentials: true,
    message: 'local auth'
  }
};

test('model picker defaults provider selection to current runtime provider', () => {
  const snapshot = buildModelPickerSnapshot({
    report,
    auth: { version: 1, activeProvider: 'openai', providers: { openai: { model: 'gpt-auth' } } },
    currentModel: { provider: 'ollama', model: 'qwen3.5:4b' },
    workspaceModel: {},
    cliModel: {},
    env: {},
    ollamaModels: [{ name: 'qwen3.5:4b' }, { name: 'llama3.2:latest' }]
  });

  assert.equal(snapshot.selectedProvider, 'ollama');
  assert.equal(snapshot.providers.find((provider) => provider.provider === 'ollama')?.stateLabel, 'Configured');
});

test('model picker labels current, startup default, provider default, catalog, local, configured, and custom rows', () => {
  const auth: ProviderAuthStore = {
    version: 1,
    activeProvider: 'openai',
    providers: {
      openai: { model: 'gpt-auth' },
      'openai-compatible': { model: 'custom-compatible', baseUrl: 'http://localhost:4000/v1' }
    }
  };

  const snapshot = buildModelPickerSnapshot({
    report,
    auth,
    currentModel: { provider: 'openai', model: 'gpt-auth' },
    workspaceModel: { provider: 'openai-compatible', model: 'workspace-compatible' },
    cliModel: {},
    env: {},
    ollamaModels: [{ name: 'qwen3.5:4b' }, { name: 'llama3.2:latest' }]
  });

  const openai = snapshot.modelsByProvider.openai ?? [];
  assert.deepEqual(openai.find((row) => row.model === 'gpt-auth')?.labels, [
    'Current',
    'Startup default',
    'Configured'
  ]);
  assert.ok(openai.some((row) => row.labels.includes('Catalog')));

  const compatible = snapshot.modelsByProvider['openai-compatible'] ?? [];
  assert.deepEqual(compatible.find((row) => row.model === 'custom-compatible')?.labels, [
    'Provider default',
    'Configured'
  ]);
  assert.deepEqual(compatible.find((row) => row.model === 'workspace-compatible')?.labels, ['Configured']);
  assert.equal(compatible.at(-1)?.kind, 'custom');

  const ollama = snapshot.modelsByProvider.ollama ?? [];
  assert.deepEqual(ollama.find((row) => row.model === 'qwen3.5:4b')?.labels, ['Local']);
});
```

- [ ] **Step 2: Run the failing tests**

Run:

```bash
node --test --import tsx src/model/model-picker.test.ts
```

Expected: FAIL because `src/model/model-picker.ts` does not exist.

- [ ] **Step 3: Implement `model-picker.ts`**

Create `src/model/model-picker.ts` with these exported types and helpers:

```ts
import type { ProviderAuthStore } from './auth-store.js';
import { getProviderAuthEntry } from './auth-store.js';
import type { PartialModelConfig } from './config.js';
import { listModelCatalogEntries } from './catalog/index.js';
import type { ProviderStatusReport } from './provider-status.js';
import { formatProviderStateLabel } from './provider-status.js';
import type { OllamaModelSummary } from './providers/ollama-discovery.js';
import type { ProviderName } from './types.js';

export type ModelRowLabel =
  | 'Current'
  | 'Startup default'
  | 'Provider default'
  | 'Catalog'
  | 'Local'
  | 'Configured'
  | 'Custom';

export type ModelPickerProviderRow = {
  provider: ProviderName;
  displayName: string;
  state: 'configured' | 'not-configured' | 'unavailable';
  stateLabel: string;
  current: boolean;
  issues: string[];
};

export type ModelPickerModelRow = {
  kind: 'model' | 'custom';
  provider: ProviderName;
  model: string;
  displayName: string;
  labels: ModelRowLabel[];
};

export type ModelPickerSnapshot = {
  selectedProvider: ProviderName;
  providers: ModelPickerProviderRow[];
  modelsByProvider: Partial<Record<ProviderName, ModelPickerModelRow[]>>;
};

export function buildModelPickerSnapshot(opts: {
  report: ProviderStatusReport;
  auth: ProviderAuthStore;
  currentModel: { provider: ProviderName; model: string };
  workspaceModel?: PartialModelConfig;
  cliModel?: PartialModelConfig;
  env?: Record<string, string | undefined>;
  ollamaModels?: OllamaModelSummary[];
}): ModelPickerSnapshot {
  const providers = opts.report.providers.map((provider) => ({
    provider: provider.provider,
    displayName: provider.displayName,
    state: provider.state,
    stateLabel: formatProviderStateLabel(provider.state),
    current: provider.provider === opts.currentModel.provider,
    issues: provider.issues.map((issue) => issue.requirement)
  }));

  const modelsByProvider: Partial<Record<ProviderName, ModelPickerModelRow[]>> = {};
  for (const provider of opts.report.providers) {
    modelsByProvider[provider.provider] = buildModelRowsForProvider({
      provider: provider.provider,
      auth: opts.auth,
      currentModel: opts.currentModel,
      workspaceModel: opts.workspaceModel ?? {},
      cliModel: opts.cliModel ?? {},
      env: opts.env ?? process.env,
      ollamaModels: opts.ollamaModels ?? []
    });
  }

  return {
    selectedProvider: opts.currentModel.provider,
    providers,
    modelsByProvider
  };
}

function buildModelRowsForProvider(opts: {
  provider: ProviderName;
  auth: ProviderAuthStore;
  currentModel: { provider: ProviderName; model: string };
  workspaceModel: PartialModelConfig;
  cliModel: PartialModelConfig;
  env: Record<string, string | undefined>;
  ollamaModels: OllamaModelSummary[];
}): ModelPickerModelRow[] {
  const rows = new Map<string, ModelPickerModelRow>();
  const add = (model: string, displayName: string, source: Exclude<ModelRowLabel, 'Current' | 'Startup default' | 'Provider default' | 'Custom'>) => {
    if (!model) return;
    const existing = rows.get(model);
    if (existing) {
      if (!existing.labels.includes(source)) existing.labels.push(source);
      return;
    }
    rows.set(model, { kind: 'model', provider: opts.provider, model, displayName, labels: [source] });
  };

  for (const entry of listModelCatalogEntries(opts.provider)) {
    add(entry.model, entry.displayName, 'Catalog');
  }
  if (opts.provider === 'ollama') {
    for (const model of opts.ollamaModels) add(model.name, model.name, 'Local');
  }

  for (const model of configuredModelIds(opts)) {
    add(model, model, 'Configured');
  }

  for (const row of rows.values()) {
    const authEntry = getProviderAuthEntry(opts.auth, opts.provider);
    const labels: ModelRowLabel[] = [];
    if (opts.currentModel.provider === opts.provider && opts.currentModel.model === row.model) labels.push('Current');
    if (opts.auth.activeProvider === opts.provider && authEntry?.model === row.model) labels.push('Startup default');
    if (opts.auth.activeProvider !== opts.provider && authEntry?.model === row.model) labels.push('Provider default');
    for (const label of row.labels) if (!labels.includes(label)) labels.push(label);
    row.labels = labels;
  }

  return [
    ...rows.values(),
    {
      kind: 'custom',
      provider: opts.provider,
      model: '',
      displayName: 'Custom model id',
      labels: ['Custom']
    }
  ];
}

function configuredModelIds(opts: {
  provider: ProviderName;
  auth: ProviderAuthStore;
  workspaceModel: PartialModelConfig;
  cliModel: PartialModelConfig;
  env: Record<string, string | undefined>;
}) {
  const ids = new Set<string>();
  const addIfProviderApplies = (config: PartialModelConfig | undefined) => {
    if (!config?.model) return;
    if (config.provider === undefined || config.provider === opts.provider) ids.add(config.model);
  };
  addIfProviderApplies(opts.cliModel);
  addIfProviderApplies(opts.workspaceModel);
  if (opts.env.CLIQ_MODEL && (opts.env.CLIQ_MODEL_PROVIDER === undefined || opts.env.CLIQ_MODEL_PROVIDER === opts.provider)) {
    ids.add(opts.env.CLIQ_MODEL);
  }
  const authEntry = getProviderAuthEntry(opts.auth, opts.provider);
  if (authEntry?.model) ids.add(authEntry.model);
  return [...ids];
}
```

- [ ] **Step 4: Run the model picker tests**

Run:

```bash
node --test --import tsx src/model/model-picker.test.ts
```

Expected: PASS.

## Task 3: Add Slash Parsing and Store Model Updates

**Files:**
- Modify: `src/tui/slash.ts`
- Modify: `src/tui/store.ts`
- Test: `src/tui/slash.test.ts`
- Test: `src/tui/store.test.ts`

- [ ] **Step 1: Add failing slash tests**

Update `src/tui/slash.test.ts`:

```ts
test('parseSlash maps model picker commands', () => {
  assert.deepEqual(parseSlash('/model'), { kind: 'model' });
  assert.deepEqual(parseSlash('/models'), { kind: 'model' });
  const withArg = parseSlash('/model openai');
  assert.equal(withArg.kind, 'invalid');
  if (withArg.kind === 'invalid') assert.match(withArg.reason, /does not accept arguments/);
});
```

Also update the command lists in existing tests to include `/model` and `/models`.

- [ ] **Step 2: Add failing store test**

Append to `src/tui/store.test.ts`:

```ts
test('model-change updates the rendered model identity', () => {
  const s = reduce(baseInit(), {
    type: 'model-change',
    model: { provider: 'openai', model: 'gpt-5.2' }
  });
  assert.deepEqual(s.model, { provider: 'openai', model: 'gpt-5.2' });
});
```

- [ ] **Step 3: Run the failing tests**

Run:

```bash
node --test --import tsx src/tui/slash.test.ts src/tui/store.test.ts
```

Expected: FAIL because the new command/action do not exist.

- [ ] **Step 4: Implement slash and store support**

In `src/tui/slash.ts`, add:

```ts
{ name: '/model', description: 'Open provider-first model setup' },
{ name: '/models', description: 'Same as /model' },
```

Add to `ParsedSlashCommand`:

```ts
| { kind: 'model' }
```

Add parsing:

```ts
case '/model':
case '/models':
  if (rest.length > 0) {
    return { kind: 'invalid', head, reason: `${head} does not accept arguments yet` };
  }
  return { kind: 'model' };
```

In `src/tui/store.ts`, add to `UiAction`:

```ts
| { type: 'model-change'; model: { provider: ProviderName; model: string } }
```

Add reducer case:

```ts
case 'model-change':
  return { ...state, model: action.model };
```

- [ ] **Step 5: Run the tests**

Run:

```bash
node --test --import tsx src/tui/slash.test.ts src/tui/store.test.ts src/tui/components/slash-palette.test.tsx
```

Expected: PASS.

## Task 4: Build the Reusable Model Setup Flow

**Files:**
- Create: `src/tui/components/model-setup-flow.tsx`
- Test: `src/tui/components/model-setup-flow.test.tsx`

- [ ] **Step 1: Write failing UI tests**

Create `src/tui/components/model-setup-flow.test.tsx` with this concrete starting point:

```ts
import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ModelPickerSnapshot } from '../../model/model-picker.js';
import { ModelSetupFlow, type ModelSetupApplyRequest } from './model-setup-flow.js';

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

function makeSnapshot(overrides: Partial<ModelPickerSnapshot> = {}): ModelPickerSnapshot {
  const snapshot: ModelPickerSnapshot = {
    selectedProvider: 'ollama',
    providers: [
      {
        provider: 'ollama',
        displayName: 'Ollama',
        state: 'configured',
        stateLabel: 'Configured',
        current: true,
        issues: []
      },
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'configured',
        stateLabel: 'Configured',
        current: false,
        issues: []
      }
    ],
    modelsByProvider: {
      ollama: [
        {
          kind: 'model',
          provider: 'ollama',
          model: 'qwen3.5:4b',
          displayName: 'qwen3.5:4b',
          labels: ['Current', 'Local']
        }
      ],
      openai: [
        {
          kind: 'model',
          provider: 'openai',
          model: 'gpt-5.2',
          displayName: 'GPT-5.2',
          labels: ['Startup default', 'Catalog']
        }
      ]
    }
  };
  return { ...snapshot, ...overrides };
}

test('model setup flow opens provider step first with current runtime provider selected', () => {
  const { lastFrame } = render(
    <ModelSetupFlow snapshot={makeSnapshot()} onRefresh={makeSnapshot} onApply={() => {}} onClose={() => {}} />
  );
  const frame = lastFrame() ?? '';
  assert.match(frame, /Model setup/);
  assert.match(frame, /> Ollama\s+Configured/);
  assert.match(frame, /Provider step: Enter\/Right models/);
});

test('model setup flow moves to model step with Enter and applies current session with Enter', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={makeSnapshot()}
      onRefresh={makeSnapshot}
      onApply={(request) => applied.push(request)}
      onClose={() => {}}
    />
  );

  stdin.write('\r');
  await flush();
  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, [{ provider: 'ollama', model: 'qwen3.5:4b', persist: false }]);
});

test('model setup flow saves startup default with Space', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={makeSnapshot()}
      onRefresh={makeSnapshot}
      onApply={(request) => applied.push(request)}
      onClose={() => {}}
    />
  );

  stdin.write('\r');
  await flush();
  stdin.write(' ');
  await flush();

  assert.deepEqual(applied, [{ provider: 'ollama', model: 'qwen3.5:4b', persist: true }]);
});

test('model setup flow masks API key input and never renders the secret', async () => {
  const snapshot = makeSnapshot({
    selectedProvider: 'openai',
    providers: [
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['OPENAI_API_KEY']
      }
    ],
    modelsByProvider: { openai: [] }
  });
  const { stdin, lastFrame } = render(
    <ModelSetupFlow snapshot={snapshot} onRefresh={() => snapshot} onApply={() => {}} onClose={() => {}} />
  );

  stdin.write('\r');
  await flush();
  stdin.write('sk-secret');
  await flush();

  const frame = lastFrame() ?? '';
  assert.match(frame, /\*{4,}/);
  assert.doesNotMatch(frame, /sk-secret/);
});
```

Use the existing `flush = () => new Promise<void>((r) => setImmediate(r));` pattern from `src/tui/app.test.tsx`.

- [ ] **Step 2: Run the failing tests**

Run:

```bash
node --test --import tsx src/tui/components/model-setup-flow.test.tsx
```

Expected: FAIL because the component does not exist.

- [ ] **Step 3: Implement the component**

Create `ModelSetupFlow` with this public API:

```ts
export type ModelSetupApplyRequest = {
  provider: ProviderName;
  model: string;
  persist: boolean;
  baseUrl?: string;
  apiKey?: string;
};

export type ModelSetupFlowProps = {
  snapshot: ModelPickerSnapshot;
  onRefresh: () => ModelPickerSnapshot | Promise<ModelPickerSnapshot>;
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>;
  onClose: () => void;
  initialProvider?: ProviderName;
};
```

Implement states:

```ts
type Step =
  | { kind: 'providers'; selectedIndex: number }
  | { kind: 'models'; provider: ProviderName; selectedIndex: number }
  | { kind: 'custom-model'; provider: ProviderName; value: string }
  | { kind: 'setup-input'; provider: ProviderName; field: 'apiKey' | 'baseUrl' | 'model'; value: string; confirmSecret: boolean };
```

Use page-specific footers:

```text
Provider step: Enter/Right models · Up/Down select · Esc/q close
Model step: Enter use now · Space save default provider/model · c custom model · Left back · Esc/q close
```

For secret input, render mask characters (`*`) and never render the raw value. If using `ink-text-input`, pass `mask="*"`. If using local input code, render `'*'.repeat(value.length)`.

- [ ] **Step 4: Run the component tests**

Run:

```bash
node --test --import tsx src/tui/components/model-setup-flow.test.tsx
```

Expected: PASS.

## Task 5: Wire `/model`, `/models`, and `/providers configure` in the App

**Files:**
- Modify: `src/tui/app.tsx`
- Modify: `src/tui/index.tsx`
- Modify: `src/tui/components/provider-management.tsx`
- Test: `src/tui/app.test.tsx`

- [ ] **Step 1: Add failing App tests**

Add these tests to `src/tui/app.test.tsx`:

```ts
function pickerSnapshot(provider: 'openai' | 'ollama' = 'ollama'): ModelPickerSnapshot {
  return {
    selectedProvider: provider,
    providers: [
      {
        provider,
        displayName: provider === 'ollama' ? 'Ollama' : 'OpenAI',
        state: 'configured',
        stateLabel: 'Configured',
        current: true,
        issues: []
      }
    ],
    modelsByProvider: {
      [provider]: [
        {
          kind: 'model',
          provider,
          model: provider === 'ollama' ? 'qwen3.5:4b' : 'gpt-5.2',
          displayName: provider === 'ollama' ? 'qwen3.5:4b' : 'GPT-5.2',
          labels: ['Current']
        }
      ]
    }
  };
}

test('/model opens provider-first model setup', async () => {
  const store = makeStore();
  let calls = 0;
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onModelSetupSnapshot={() => {
        calls += 1;
        return pickerSnapshot();
      }}
      onModelSetupApply={() => {}}
    />
  );

  stdin.write('/model');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  assert.equal(calls, 1);
  assert.match(lastFrame() ?? '', /Model setup/);
  assert.match(lastFrame() ?? '', /> Ollama/);
});

test('/models is an alias for /model', async () => {
  const store = makeStore();
  let calls = 0;
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onModelSetupSnapshot={() => {
        calls += 1;
        return pickerSnapshot();
      }}
      onModelSetupApply={() => {}}
    />
  );

  stdin.write('/models');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  assert.equal(calls, 1);
  assert.match(lastFrame() ?? '', /Model setup/);
});

test('/providers configure reuses model setup for selected provider', async () => {
  const store = makeStore();
  let modelSetupCalls = 0;
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onProviderStatus={() => providerReport}
      onModelSetupSnapshot={() => {
        modelSetupCalls += 1;
        return pickerSnapshot('openai');
      }}
      onModelSetupApply={() => {}}
    />
  );

  stdin.write('/providers');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();
  stdin.write('\r');
  await flush();
  await flush();
  stdin.write('c');
  await flush();
  await flush();

  assert.equal(modelSetupCalls, 1);
  assert.match(lastFrame() ?? '', /Model setup/);
  assert.match(lastFrame() ?? '', /OpenAI/);
});
```

- [ ] **Step 2: Run the failing App tests**

Run:

```bash
node --test --import tsx src/tui/app.test.tsx
```

Expected: FAIL because callbacks and modal state are not wired.

- [ ] **Step 3: Add App callback types**

In `src/tui/app.tsx` and `src/tui/index.tsx`, add:

```ts
onModelSetupSnapshot?: () => ModelPickerSnapshot | Promise<ModelPickerSnapshot>;
onModelSetupApply?: (request: ModelSetupApplyRequest) => void | Promise<void>;
```

- [ ] **Step 4: Add modal state and slash handling**

In `App`, replace the single `providerReport` state with modal state:

```ts
type ActiveProviderModal =
  | { kind: 'providers'; report: ProviderStatusReport }
  | { kind: 'model-setup'; snapshot: ModelPickerSnapshot; initialProvider?: ProviderName };
```

Route slash:

```ts
case 'model':
  if (!onModelSetupSnapshot || !onModelSetupApply) {
    pushSystem('No model setup handler is available in this TUI session.');
    return;
  }
  providerInteractionActiveRef.current = true;
  setProviderStatusPending(true);
  setActiveProviderModal({ kind: 'model-setup', snapshot: await onModelSetupSnapshot() });
  setProviderStatusPending(false);
  return;
```

- [ ] **Step 5: Add ProviderManagement configure callback**

In `ProviderManagementProps`:

```ts
onConfigure?: (provider: ProviderName) => void;
```

In detail footer add:

```text
[c]onfigure [b]ack Esc/q close
```

On `c`, call `onConfigure(detail.provider)`.

- [ ] **Step 6: Run App tests**

Run:

```bash
node --test --import tsx src/tui/app.test.tsx
```

Expected: PASS.

## Task 6: Apply Model Selection by Rebuilding the TUI Runner

**Files:**
- Modify: `src/cli.ts`
- Test: add focused test if feasible under `src/tui/app.test.tsx`; otherwise add a small exported helper test near CLI helper functions.

- [ ] **Step 1: Extract a TUI runner builder**

Inside `runChatTuiSession`, replace the single `const runner = createRunner(...)` with:

```ts
let currentModelConfig = opts.modelConfig;
let currentModelClient = opts.modelClient;
let currentAuth = opts.auth;

function buildTuiRunner(modelClient: ModelClient, modelConfig: ResolvedModelConfig) {
  return createRunner({
    model: modelClient,
    hooks: [...opts.assembly.hooks, ...tuiHooks],
    commandHooks: opts.assembly.commandHooks ?? {},
    policy: livePolicy.engine,
    confirm: async () => false,
    instructions: opts.assembly.instructions,
    autoCompact: {
      config: opts.assembly.workspaceConfig.autoCompact,
      modelConfig
    },
    ...(tuiTransactions ? { transactions: tuiTransactions } : {}),
    async onEvent(event) {
      store.dispatch({ type: 'runtime-event', event });
    }
  });
}

let runner = buildTuiRunner(currentModelClient, currentModelConfig);
```

- [ ] **Step 2: Add apply callback**

Wire `onModelSetupApply`:

```ts
onModelSetupApply: async (request) => {
  if (request.persist) {
    currentAuth = await upsertProviderAuth({
      provider: request.provider,
      model: request.model,
      // Persist baseUrl only when the setup flow collected it explicitly.
      // Space on a catalog/configured model is provider/model confirmation,
      // not permission to copy a possibly secret-bearing URL from env/CLI.
      ...(request.baseUrl ? { baseUrl: request.baseUrl } : {}),
      ...(request.apiKey ? { apiKey: request.apiKey } : {})
    });
  }

  const sessionBaseUrl =
    request.baseUrl ??
    (request.provider === currentModelConfig.provider ? currentModelConfig.baseUrl : undefined);
  const resolved = await resolveModelConfig({
    workspace: opts.assembly.workspaceConfig,
    cli: {
      provider: request.provider,
      model: request.model,
      ...(sessionBaseUrl ? { baseUrl: sessionBaseUrl } : {}),
      streaming: currentModelConfig.streaming
    },
    auth: currentAuth
  });

  currentModelConfig = resolved;
  currentModelClient = createModelClient(resolved);
  runner = buildTuiRunner(currentModelClient, currentModelConfig);
  session.model = { provider: resolved.provider, model: resolved.model, baseUrl: resolved.baseUrl };
  store.dispatch({ type: 'model-change', model: { provider: resolved.provider, model: resolved.model } });
  store.dispatch({ type: 'system-message', text: `model switched to ${resolved.provider}/${resolved.model}` });
}
```

Important: if `request.persist` is false, do not call `upsertProviderAuth`.

- [ ] **Step 3: Update reset behavior**

In `onReset`, use `currentModelConfig`, not `opts.modelConfig`:

```ts
session.model = {
  provider: currentModelConfig.provider,
  model: currentModelConfig.model,
  baseUrl: currentModelConfig.baseUrl
};
```

- [ ] **Step 4: Add regression test for current-session model switch**

Add this App-level regression test after `/model opens provider-first model setup`:

```ts
test('/model Enter applies a current-session model and updates the composer label', async () => {
  const store = makeStore();
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin, lastFrame } = render(
    <App
      store={store}
      onSubmit={() => {}}
      onModelSetupSnapshot={() => pickerSnapshot('openai')}
      onModelSetupApply={(request) => {
        applied.push(request);
        store.dispatch({
          type: 'model-change',
          model: { provider: request.provider, model: request.model }
        });
      }}
    />
  );

  stdin.write('/model');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  assert.deepEqual(applied, [{ provider: 'openai', model: 'gpt-5.2', persist: false }]);
  assert.match(lastFrame() ?? '', /openai\/gpt-5\.2/);
});
```

- [ ] **Step 5: Run targeted tests**

Run:

```bash
node --test --import tsx src/tui/app.test.tsx src/tui/store.test.ts src/model/model-picker.test.ts
```

Expected: PASS.

## Task 7: Provider Setup Inputs and Secret Persistence

**Files:**
- Modify: `src/tui/components/model-setup-flow.tsx`
- Test: `src/tui/components/model-setup-flow.test.tsx`
- Modify: `src/cli.ts`

- [ ] **Step 1: Add failing tests for missing setup fields**

Add these tests to `src/tui/components/model-setup-flow.test.tsx`:

```ts
test('missing required remote API key opens masked input and requires save confirmation', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const snapshot = makeSnapshot({
    selectedProvider: 'openai',
    providers: [
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['OPENAI_API_KEY']
      }
    ],
    modelsByProvider: {
      openai: [
        {
          kind: 'model',
          provider: 'openai',
          model: 'gpt-5.2',
          displayName: 'GPT-5.2',
          labels: ['Catalog']
        }
      ]
    }
  });
  const { stdin, lastFrame } = render(
    <ModelSetupFlow
      snapshot={snapshot}
      onRefresh={() => snapshot}
      onApply={(request) => applied.push(request)}
      onClose={() => {}}
    />
  );

  stdin.write('\r');
  await flush();
  stdin.write('sk-secret');
  await flush();
  stdin.write('\r');
  await flush();
  assert.match(lastFrame() ?? '', /Save API key to local auth file\? y\/N/);
  assert.doesNotMatch(lastFrame() ?? '', /sk-secret/);

  stdin.write('y');
  await flush();
  assert.deepEqual(applied, [{ provider: 'openai', model: 'gpt-5.2', persist: true, apiKey: 'sk-secret' }]);
  assert.doesNotMatch(lastFrame() ?? '', /sk-secret/);
});

test('openai-compatible collects base URL then direct model id', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const snapshot = makeSnapshot({
    selectedProvider: 'openai-compatible',
    providers: [
      {
        provider: 'openai-compatible',
        displayName: 'OpenAI-compatible',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['base URL', 'model']
      }
    ],
    modelsByProvider: { 'openai-compatible': [] }
  });
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={snapshot}
      onRefresh={() => snapshot}
      onApply={(request) => applied.push(request)}
      onClose={() => {}}
    />
  );

  stdin.write('\r');
  await flush();
  stdin.write('http://localhost:4000/v1');
  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('local-model');
  await flush();
  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, [
    {
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      persist: true
    }
  ]);
});

test('declining secret persistence does not apply provider credentials', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const snapshot = makeSnapshot({
    selectedProvider: 'openai',
    providers: [
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['OPENAI_API_KEY']
      }
    ],
    modelsByProvider: { openai: [] }
  });
  const { stdin, lastFrame } = render(
    <ModelSetupFlow
      snapshot={snapshot}
      onRefresh={() => snapshot}
      onApply={(request) => applied.push(request)}
      onClose={() => {}}
    />
  );

  stdin.write('\r');
  await flush();
  stdin.write('sk-secret');
  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('n');
  await flush();

  assert.deepEqual(applied, []);
  assert.doesNotMatch(lastFrame() ?? '', /sk-secret/);
});
```

- [ ] **Step 2: Implement setup state transitions**

For selected provider:

- If issue includes `missing-api-key`, ask API key with masked input and explicit `y/N` save confirmation.
- If issue includes `missing-base-url`, ask base URL.
- If issue includes `missing-model`, ask model id.
- If provider is `openai-compatible`, always make custom model entry easy with `c`.
- After successful setup apply/save, call `onRefresh()` and continue to model step for the same provider.

- [ ] **Step 3: Run setup flow tests**

Run:

```bash
node --test --import tsx src/tui/components/model-setup-flow.test.tsx
```

Expected: PASS and no frame contains literal API key values.

## Task 8: Reuse the Flow for First-Run Setup

**Files:**
- Modify: `src/tui/provider-setup.tsx`
- Modify: `src/cli.ts`
- Test: `src/tui/provider-setup.test.tsx`
- Test: `src/cli.test.ts`

- [ ] **Step 1: Add failing startup setup behavior test**

Export and test this helper shape from `src/cli.ts` so first-run behavior can be tested without brittle full TTY simulation:

```ts
export async function resolveModelConfigWithInteractiveSetup(opts: {
  workspace: WorkspaceConfig;
  cliModel: PartialModelConfig;
  initialAuth: ProviderAuthStore;
  wantsTui: boolean;
  mountSetup: (error: ModelSetupRequiredError) => Promise<ProviderAuthStore | null>;
}): Promise<{ modelConfig: ResolvedModelConfig; auth: ProviderAuthStore } | null>
```

Add this test to `src/cli.test.ts`:

```ts
test('interactive model setup can repair startup model config and continue', async () => {
  const authAfterSetup: ProviderAuthStore = {
    version: 1,
    activeProvider: 'openai',
    providers: {
      openai: { apiKey: 'sk-secret', model: 'gpt-5.2' }
    }
  };
  const result = await resolveModelConfigWithInteractiveSetup({
    workspace: {},
    cliModel: { provider: 'openai' },
    initialAuth: { version: 1, providers: {} },
    wantsTui: true,
    mountSetup: async () => authAfterSetup
  });

  assert.equal(result?.modelConfig.provider, 'openai');
  assert.equal(result?.modelConfig.model, 'gpt-5.2');
  assert.equal(result?.auth.providers.openai?.apiKey, 'sk-secret');
});
```

- [ ] **Step 2: Replace static first-run exit with shared setup mount**

In the `isModelSetupRequiredError(error)` branch for `wantsTui`, do not immediately `return` after rendering static text. Mount the shared setup flow. If it returns a valid config, continue normal chat startup. If the user exits, return.

- [ ] **Step 3: Keep deterministic non-interactive behavior**

Verify the non-TTY path still writes `formatModelSetupMessage(error)` and exits with the same `ReportedCliError`.

- [ ] **Step 4: Run startup tests**

Run:

```bash
node --test --import tsx src/tui/provider-setup.test.tsx src/cli.test.ts
```

Expected: PASS.

## Task 9: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/provider-management.md`

- [ ] **Step 1: Update README provider management section**

Replace the stale line that says Cliq does not store provider secrets with text covering:

```md
- In the TUI, run `/model` or `/models` to open provider-first setup and model selection.
- `Enter` applies the selected provider/model to the current TUI session only.
- `Space` saves the selected provider/model as the startup default in the local auth file and also applies it to the current session.
- API keys entered in the TUI are masked and require explicit confirmation before being saved to `${CLIQ_HOME:-~/.cliq}/auth.json`.
- OpenAI-compatible setup supports base URL, direct model id, and an optional API key.
```

- [ ] **Step 2: Update provider-management boundary doc**

Move #53 handoff text from future tense to implemented behavior. Keep out of scope:

```md
Out of scope: workspace config writer, separate global-default layer, remote provider model-list APIs, multi-model allow-list, and Ollama pull/install.
```

- [ ] **Step 3: Run docs smoke**

Run:

```bash
git diff --check
```

Expected: no whitespace errors.

## Task 10: Final Validation

**Files:** all touched files.

- [ ] **Step 1: Run focused tests**

Run:

```bash
node --test --import tsx \
  src/model/provider-status.test.ts \
  src/model/model-picker.test.ts \
  src/tui/slash.test.ts \
  src/tui/store.test.ts \
  src/tui/components/model-setup-flow.test.tsx \
  src/tui/app.test.tsx \
  src/tui/provider-setup.test.tsx
```

Expected: PASS.

- [ ] **Step 2: Run import isolation**

Run:

```bash
node --test --import tsx src/tui/import-isolation.test.ts
```

Expected: PASS. No runtime/headless/protocol module statically imports Ink/React or `src/tui/`.

- [ ] **Step 3: Run build**

Run:

```bash
npm run build
```

Expected: PASS.

- [ ] **Step 4: Run full tests**

Run:

```bash
npm test
```

Expected: PASS.

## Commit Sequence Recommendation

- Commit 1: Tasks 1-3. Safe provider status output, model-picker data builder, slash/store plumbing.
- Commit 2: Tasks 4-6. Reusable model setup flow, `/model` and `/models`, `/providers configure`, and runtime runner rebuild.
- Commit 3: Tasks 7-9. Secret/base URL/model setup inputs, first-run setup reuse, and docs.
- Commit 4: Task 10 follow-up fixes if final full validation finds anything.

Do not split the GitHub issue or require multiple PRs. Keep commits logical so review can still inspect the risk boundaries independently.

## Self-Review

- Spec coverage: `/model`, `/models`, provider-first step, current runtime selection, provider state vocabulary, Enter/Space behavior, row labels, OpenAI-compatible direct entry, Ollama local rows, `/providers configure`, first-run dead-start, auth-store persistence, and docs are covered.
- Known deferred items are explicitly out of scope: workspace config writer, future global default, remote model-list APIs, multi-model allow-list, Ollama pull/install.
- Security checks are explicit: secret input masked, secret confirmation required, auth-store path reused, unsafe base URL display sanitized, no static TUI imports into headless/runtime/protocol.
