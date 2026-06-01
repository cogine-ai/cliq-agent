# Provider Management Boundary

This is the first implementation slice for issue #52. It creates a shared
provider status layer plus user-facing read-only management entry points:

- TUI: `/providers`
- CLI: `cliq providers status`, `cliq providers list`, and
  `cliq providers validate [provider]`

## In scope

- Report providers as `Configured`, `Not configured`, or `Unavailable`.
- Put the active provider first and mark it `Current`.
- Show safe configuration source labels such as `ENV`, `Workspace`, `CLI`, and
  `Local service`.
- Treat Ollama as a local service with model availability, not as a credentialed
  remote provider.
- Return structured validation issues for missing API keys, base URLs, model
  ids, local models, or local service availability.
- Keep headless and one-shot behavior non-interactive.

## Out of scope

- No `/connect <provider>` slash command.
- No model picker or model switching; that belongs to #53.
- No first-run setup screen changes beyond exposing reusable status primitives.
- No remote credential correctness checks against provider APIs.
- No Cliq-managed API key storage.

## Model Picker Handoff for #53

`/model` and `/models` should be aliases for the same model-selection flow. The
flow should always open a lightweight provider step first, even when one or more
providers are already configured. The currently active runtime provider should
be selected by default, regardless of how many providers are configured.

From that provider step, Enter or Right Arrow should continue into the model
picker for the selected provider. This keeps the model picker provider-first
without turning `/providers` into the model-selection surface.

## Secret Persistence Decision

Cliq does not persist provider secrets in this slice. API keys stay in
environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`OPENROUTER_API_KEY`, `CLIQ_MODEL_API_KEY`, or `OPENAI_COMPATIBLE_API_KEY`.
Workspace config may hold non-secret defaults such as provider, model, base URL,
and streaming mode.

Future managed credentials, local auth files, or OS keychain storage need a
separate design and tests before any secret is written by Cliq.
