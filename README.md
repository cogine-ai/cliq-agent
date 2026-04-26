# Cliq

[![npm version](https://img.shields.io/npm/v/@cogineai/cliq.svg)](https://www.npmjs.com/package/@cogineai/cliq)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Every team has their own agent. This is ours.

Cliq is a tiny local coding agent harness built around a minimal, provider-agnostic action protocol.

## What it is

- **Local-first**: runs in the directory where you invoke it
- **Provider-agnostic protocol**: the model responds with plain JSON actions
- **Minimal by design**: small surface area, easy to inspect, easy to extend
- **Persistent sessions**: each workspace keeps its own local session state

## Quick start

Requirements: Node.js 20 or newer.

```bash
npm install -g @cogineai/cliq
```

## Usage

Start in any project directory:

```bash
cd path/to/your-project
cliq
```

Running `cliq` with no arguments starts interactive chat. `cliq chat` is the explicit equivalent.

Run a one-shot task:

```bash
cliq "inspect this repo and summarize the architecture"
```

## Current scope

Cliq is intentionally small right now. It supports:

- Interactive chat and one-shot tasks
- Structured file inspection with read, list, find, and grep
- Shell command execution
- Exact text replacement edits
- Local session persistence per workspace
- Final assistant responses after tool work completes

## Why this shape

- No dependency on provider-native tool calling
- Keeps the runtime protocol inspectable
- Makes local execution and replay straightforward
- Provides a simple base for a local coding agent

## Develop from source

```bash
npm install
npm run build
npm link
```

## Model Providers

Cliq is local-first. If you do not configure a provider or model, Cliq tries local Ollama first:

```bash
ollama pull qwen3:4b
cliq "inspect this repo"
```

On startup, Cliq calls `http://localhost:11434/api/tags`. If local models exist, it chooses the first model whose name contains `qwen`; otherwise it uses the first model returned by Ollama. If Ollama has no models, Cliq prints a configuration error with next steps instead of silently falling back to a remote provider.

Select a provider from the CLI:

```bash
cliq --provider anthropic --model claude-sonnet-4-20250514 "inspect this repo"
cliq --provider openai --model gpt-5.2 "inspect this repo"
cliq --provider ollama --model qwen3:4b "inspect this repo"
```

Use `.cliq/config.json` for workspace defaults:

```json
{
  "model": {
    "provider": "ollama",
    "model": "qwen3:4b",
    "baseUrl": "http://localhost:11434",
    "streaming": "auto"
  }
}
```

Supported providers:

- `openrouter`: requires `OPENROUTER_API_KEY`
- `anthropic`: requires `ANTHROPIC_API_KEY`
- `openai`: requires `OPENAI_API_KEY`
- `openai-compatible`: requires `--base-url` or `CLIQ_MODEL_BASE_URL`; uses `CLIQ_MODEL_API_KEY` when set
- `ollama`: uses local `http://localhost:11434` by default, can auto-discover an installed model, and does not require an API key

OpenAI-compatible streaming modes:

- `auto` (default): first sends `stream: true`; if the endpoint rejects streaming before response-body consumption with a compatibility-style HTTP status (`400`, `404`, `405`, `415`, or `422`), Cliq retries once with `stream: false`
- `on`: sends `stream: true` and does not fall back
- `off`: sends `stream: false`

## Commands

Run a one-shot task in the current directory:

```bash
cliq "inspect this repo and add a tiny README improvement"
```

Start interactive chat:

```bash
cliq
cliq chat
```

Reset persisted conversation for the current directory:

```bash
cliq reset
```

Print raw persisted session:

```bash
cliq history
```

Run with a stricter policy mode:

```bash
cliq --policy read-only "inspect the runner and explain how tool dispatch works"
```

Activate one or more local skills for a run:

```bash
cliq --skill reviewer --skill safe-edit "inspect the runtime and suggest a minimal refactor"
```

## Safety model

Cliq runs tools on your local machine in the current workspace. It is not a sandbox.

The default policy mode is `auto`, which allows registered tools to execute without confirmation. For unfamiliar repositories or exploratory review, prefer:

```bash
cliq --policy read-only "inspect this repo"
```

For day-to-day coding, `confirm-write`, `confirm-bash`, or `confirm-all` provide explicit approval checkpoints.

## Policy modes

- `auto`: execute all registered tools
- `confirm-write`: ask before `edit`
- `read-only`: allow only `read`, `ls`, `find`, and `grep`
- `confirm-bash`: ask before `bash`
- `confirm-all`: ask before every tool

You can set the default with:

```bash
export CLIQ_POLICY_MODE=read-only
```

## Workspace config

Cliq reads optional runtime config from `./.cliq/config.json` in the current workspace.

```json
{
  "instructionFiles": [".cliq/instructions.md"],
  "extensions": ["builtin:policy-instructions", "./.cliq/extensions/log-turns.js"],
  "defaultSkills": ["reviewer"],
  "model": {
    "provider": "ollama",
    "model": "qwen3:4b",
    "baseUrl": "http://localhost:11434",
    "streaming": "auto"
  }
}
```

All fields are optional. If the file is missing, Cliq uses no repo-local prompt, skill, or extension overrides and resolves the model with its local-first Ollama default.

## Local skills

Local skills live at `./.cliq/skills/<name>/SKILL.md` and inject additional system instructions without changing Cliq core code.

```md
---
name: reviewer
description: inspection-first review mode
---

Prefer read-only inspection first. Summarize structure before proposing mutations.
```

You can activate a skill explicitly with `--skill <name>` or make it load by default via `defaultSkills` in workspace config.

## Extensions

Phase 2 extensions add instruction overlays and runtime hooks.

Enable the built-in policy overlay:

```json
{
  "extensions": ["builtin:policy-instructions"]
}
```

Enable a local workspace extension module:

```json
{
  "extensions": ["./.cliq/extensions/log-turns.js"]
}
```

Extensions are intentionally limited to hooks and instruction contributions. They do not register new model-callable top-level actions.

## Session model

Each workspace gets its own local state directory:

```txt
./.cliq/session.json
```

Cliq replays prior records back into the model in order, including normalized tool results. Runtime-composed instructions are rebuilt on each turn from the current workspace config, loaded skills, and extensions; they are not persisted as session records.

## Internal architecture

The Phase 0 runtime split organizes the code into focused modules:

- `src/session` for persistence, lifecycle state, and migration
- `src/protocol` for action parsing and protocol types
- `src/model` for provider registry, config resolution, adapters, and streaming transport
- `src/tools` for executable tool definitions and registry lookup
- `src/runtime` for turn execution and lifecycle hooks
- `src/cli.ts` for CLI and REPL behavior

## Non-goals for the current version

The current version is an early open source starting point. It does **not** yet aim to provide:

- sandboxing
- rich approval UX
- token-by-token final answer rendering
- broad tool surface area
- multi-agent orchestration
- remote execution

## Roadmap themes

Near-term priorities are:

1. safer execution controls
2. richer local tool primitives beyond raw shell
3. stronger validation and recovery paths
4. better session and run ergonomics

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT
