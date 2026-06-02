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
- No model picker or model switching; that belongs to #53.
- No first-run setup screen changes beyond exposing reusable status primitives.
- No remote credential correctness checks against provider APIs.
- No OAuth, provider-native login, OS keychain, or external password-manager
  integration.

## Model Picker Handoff for #53

`/model` and `/models` should be aliases for the same model-selection flow. The
flow should always open a lightweight provider step first, even when one or more
providers are already configured. The currently active runtime provider should
be selected by default, regardless of how many providers are configured.

From that provider step, Enter or Right Arrow should continue into the model
picker for the selected provider. This keeps the model picker provider-first
without turning `/providers` into the model-selection surface.

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
`OPENROUTER_API_KEY`, `CLIQ_MODEL_API_KEY`, or `OPENAI_COMPATIBLE_API_KEY` still
work and take precedence over the auth file. Workspace config may hold
non-secret defaults such as provider, model, base URL, and streaming mode.

Future OAuth/provider-native login, OS keychain storage, SecretRef-style
external stores, or remote correctness checks need separate design and tests.
