# Provider Management Boundary

This is the provider-management implementation boundary for issue #52. It
creates a shared provider status layer plus user-facing management entry points:

- TUI: `/providers`
- CLI: `cliq providers status`, `cliq providers list`, and
  `cliq providers validate [provider]`
- CLI credential setup: `cliq providers auth set <provider>`

## In scope

- Report providers as `Configured`, `Not configured`, or `Unavailable`.
- Put the active provider first and mark it `Current`.
- Show safe configuration source labels such as `ENV`, `Workspace`,
  `Managed credential`, `CLI`, and `Local service`.
- Treat Ollama as a local service with model availability, not as a credentialed
  remote provider.
- Return structured validation issues for missing API keys, base URLs, model
  ids, local models, or local service availability.
- Save directly entered provider API keys to the local user auth file.
- Let local auth entries provide provider/model/base URL defaults when selected.
- Keep headless and one-shot behavior non-interactive.

## Out of scope

- No `/connect <provider>` slash command.
- No remote credential correctness checks against provider APIs.
- No OAuth, provider-native login, OS keychain, or external password-manager
  integration.

## Model Picker and Setup Flow

`/model` and `/models` are aliases for the same model-selection flow. The flow
always opens a lightweight provider step first, even when one or more providers
are already configured. The currently active runtime provider is selected by
default, regardless of how many providers are configured.

From that provider step, Enter or Right Arrow should continue into the model
picker or provider setup for the selected provider. In the model step, `Enter`
applies the highlighted provider/model to the current TUI session only, while
`Space` saves the provider/model as the startup default in the local auth file
and also applies it to the current session.

`/providers` remains the provider management/status surface, but provider detail
view exposes a configure action that reuses the same setup flow. It does not
become the primary model-selection entry point.

The picker source list is intentionally conservative: static catalog rows,
local Ollama `/api/tags` rows, configured model ids from workspace/env/auth, and
direct custom model-id entry. Remote dynamic model-list APIs and Ollama pull
actions remain separate future work.

## Secret Persistence Decision

Cliq can persist directly entered provider API keys in the local user auth file:

```bash
cliq providers auth set openai --api-key --model gpt-5.2
printf '%s\n' "$OPENAI_COMPATIBLE_API_KEY" | cliq providers auth set openai-compatible --api-key-stdin --base-url http://localhost:4000/v1 --model local-model
```

The auth file lives at `${CLIQ_HOME:-~/.cliq}/auth.json`. Writes create the file
with mode `0600` and command output never prints the saved secret value.
`--api-key` prompts for a masked key and does not accept the key as an argv
value; `--api-key-stdin` reads one key line from stdin for scripts.

Environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`OPENROUTER_API_KEY`, `ZHIPU_API_KEY`, `ZHIPUAI_API_KEY`, `CLIQ_MODEL_API_KEY`,
or `OPENAI_COMPATIBLE_API_KEY` still work and take precedence over the auth
file. Workspace config may hold non-secret defaults such as provider, model,
base URL, and streaming mode.

The TUI can also collect API keys with masked input. Persisting a secret still
requires an explicit save action. For non-secret provider/model defaults, the
`Space` save action is the confirmation; `Enter` is current-session only.

Future OAuth/provider-native login, OS keychain storage, SecretRef-style
external stores, or remote correctness checks need separate design and tests.
