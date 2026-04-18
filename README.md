# Cliq

Every team has their own agent. This is ours.

Cliq is a tiny local coding agent harness built around a minimal, provider-agnostic action protocol.

## What it is

- **Local-first**: runs in the directory where you invoke it
- **Provider-agnostic protocol**: the model responds with plain JSON actions
- **Minimal by design**: small surface area, easy to inspect, easy to extend
- **Persistent sessions**: each workspace keeps its own local session state

## Current scope

Cliq is intentionally small right now. It supports structured inspection, shell execution, exact text replacement, and final responses:

```json
{"bash":"npm test"}
```

```json
{"edit":{"path":"src/index.ts","old_text":"foo","new_text":"bar"}}
```

```json
{"read":{"path":"src/runtime/runner.ts","start_line":1,"end_line":80}}
```

```json
{"ls":{"path":"src"}}
```

```json
{"find":{"path":"src","name":"runner"}}
```

```json
{"grep":{"path":"src","pattern":"runTurn"}}
```

```json
{"message":"Done. Updated the README and ran tests."}
```

## Why this shape

- No dependency on provider-native tool calling
- Keeps the runtime protocol inspectable
- Makes local execution and replay straightforward
- Provides a simple base for a local coding agent

## Install

```bash
npm install
npm run build
npm link
```

Set your API key:

```bash
export OPENROUTER_API_KEY=...
```

## Usage

Run a one-shot task in the current directory:

```bash
cliq "inspect this repo and add a tiny README improvement"
```

Start interactive chat:

```bash
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

## Session model

Each workspace gets its own local state directory:

```txt
./.cliq/session.json
```

Cliq replays prior records back into the model in order, including normalized tool results. This keeps session continuity simple and portable without relying on provider-specific tool call envelopes.

## Internal architecture

The Phase 0 runtime split organizes the code into focused modules:

- `src/session` for persistence, lifecycle state, and migration
- `src/protocol` for action parsing and protocol types
- `src/model` for provider clients
- `src/tools` for executable tool definitions and registry lookup
- `src/runtime` for turn execution and lifecycle hooks
- `src/cli.ts` for CLI and REPL behavior

## Non-goals for the current version

The current version is an early open source starting point. It does **not** yet aim to provide:

- sandboxing
- rich approval UX
- streaming output
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
