# Cliq

[![npm version](https://img.shields.io/npm/v/@cogineai/cliq.svg)](https://www.npmjs.com/package/@cogineai/cliq)

Every team has their own agent. This is ours.

Cliq is a local coding-agent CLI built around a small, provider-agnostic JSON action protocol. It runs in your current workspace, keeps sessions on your machine, and works with local or hosted model providers.

## Install

Requirements: Node.js 22 or newer.

```bash
npm install -g @cogineai/cliq
```

Check the installed version:

```bash
cliq --version
```

Update to the latest published version:

```bash
npm install -g @cogineai/cliq@latest
```

## Quick Start

Start an interactive session in any project directory:

```bash
cd path/to/your-project
cliq
```

Run a one-shot prompt:

```bash
cliq run "inspect this repo and summarize the architecture"
```

Run with structured JSONL events for automation:

```bash
cliq run --jsonl "inspect this repo"
```

`cliq "prompt"` still works as a shorthand, but scripts should prefer `cliq run`.

## Model Setup

Cliq is local-first. If you do not configure a model, Cliq tries local Ollama first.

```bash
ollama pull qwen3.5:4b
cliq "inspect this repo"
```

Supported providers:

- `ollama`: uses local `http://localhost:11434` by default and does not require an API key
- `openrouter`: requires `OPENROUTER_API_KEY`
- `anthropic`: requires `ANTHROPIC_API_KEY`
- `openai`: requires `OPENAI_API_KEY`
- `openai-compatible`: requires `--base-url` or `CLIQ_MODEL_BASE_URL`; uses `CLIQ_MODEL_API_KEY` when set

Select a provider from the CLI:

```bash
cliq --provider anthropic --model claude-sonnet-4-20250514 "inspect this repo"
cliq --provider openai --model gpt-5.2 "inspect this repo"
cliq --provider ollama --model qwen3.5:4b "inspect this repo"
```

Save provider credentials locally:

```bash
cliq providers auth set openai --api-key
cliq providers auth set anthropic --api-key
cliq providers auth set openrouter --api-key
```

Check provider status:

```bash
cliq providers status
cliq providers validate
```

Use `.cliq/config.json` for workspace defaults:

```json
{
  "model": {
    "provider": "ollama",
    "model": "qwen3.5:4b",
    "baseUrl": "http://localhost:11434",
    "streaming": "auto"
  }
}
```

OpenAI-compatible streaming modes:

- `auto`: try streaming first, then retry non-streaming for compatibility-style HTTP failures
- `on`: require streaming
- `off`: use non-streaming responses

## Interactive UI

`cliq` and `cliq chat` start the terminal UI on a TTY. The UI keeps normal shell scrollback and shows a transcript, input bar, and status line.

Useful controls:

| Action | Keys or command |
|---|---|
| Show help | `/help` |
| Change model | `/model` or `/models` |
| Manage providers | `/providers` |
| Rotate policy mode | `Shift+Tab` |
| Cancel active turn | `Ctrl+C` |
| Exit on empty input | `Ctrl+D` |
| Fold or unfold latest tool output | `Ctrl+O` |
| Recall prompt history | Up / Down |

Use the classic readline interface when you want a simpler terminal mode:

```bash
cliq --classic
CLIQ_TUI=0 cliq chat
```

## Common Commands

Start chat:

```bash
cliq
cliq chat
```

Run headlessly:

```bash
cliq run "inspect this repo"
cliq run --jsonl "inspect this repo"
```

Use a stricter planning mode:

```bash
cliq --policy plan run "inspect the runner and explain how tool dispatch works"
```

Activate skills for a run:

```bash
cliq --skill reviewer --skill safe-edit run "inspect the runtime and suggest a minimal refactor"
```

Manage local session history:

```bash
cliq reset
cliq history
cliq checkpoint create "before refactor"
cliq checkpoint list
cliq checkpoint restore CHECKPOINT_ID --scope session
cliq compact create --summary "Stable context summary"
cliq compact list
cliq handoff create
```

Use stdio JSON-RPC for local integrations:

```bash
cliq rpc
```

## Safety And Permissions

Cliq runs tools on your local machine in the current workspace. It is not a sandbox.

Workspace trust controls whether Cliq may load workspace-local configuration such as `.cliq/config.json`, hooks, validators, instructions, skills, and extensions. Trusting a workspace does not approve edits or shell commands.

Tool actions are controlled by policy modes:

| Mode | Behavior |
|---|---|
| `default` | Ask before edits, shell commands, transaction apply, and permission requests |
| `accept-edits` | Allow edits and successful transaction apply; ask before shell commands |
| `plan` | Inspect and produce a plan; block edits, shell commands, transaction apply, and permission requests |
| `yolo` | Auto-approve normal tool calls and permission requests, subject to built-in and explicit deny rules |

Set a mode per run:

```bash
cliq --policy plan "inspect this repo"
cliq --policy accept-edits "fix the failing test"
```

Set a default:

```bash
export CLIQ_POLICY_MODE=plan
```

Layer explicit tool rules when needed:

```bash
cliq \
  --allow "bash: git *" \
  --allow "fs-read: docs/*" \
  --deny  "fs-write: .env" \
  --ask   "fs-write: src/*" \
  "ship a fix"
```

## Transactions Preview

Cliq can stage edits in a transaction overlay before applying them to the real workspace.

Enable transaction edit mode for a run:

```bash
cliq --tx edit --tx-apply auto-on-pass "fix the failing parser test"
```

Useful transaction commands:

```bash
cliq tx open refactor-auth
cliq tx list
cliq tx status <txId>
cliq tx diff <txId>
cliq tx show <txId>
cliq tx validate <txId>
cliq tx approve <txId> --override tsc --reason "known flaky check"
cliq tx apply <txId>
cliq tx abort <txId>
```

Current preview limits:

- `edit-tx` stages text replacements in existing files.
- File creation, deletion, rename, and mode changes are outside the staged diff.
- `bash` runs against the real workspace. Its side effects are recorded for review but are not rolled back if the transaction is aborted.
- Validator override names must match the validator result name exactly.

## Skills And Extensions

Cliq ships a small built-in system skill set:

- `skill-creator`
- `skill-installer`
- `skill-doctor`

Built-in skills are included in the `@cogineai/cliq` package and synced on first use into `${CLIQ_HOME:-~/.cliq}/skills/.system`.

Cliq discovers local skills from:

- Project: `./.cliq/skills/<name>/SKILL.md` and `./.agents/skills/<name>/SKILL.md`
- User: `~/.cliq/skills/<name>/SKILL.md` and `~/.agents/skills/<name>/SKILL.md`
- Built-in: `${CLIQ_HOME:-~/.cliq}/skills/.system/<name>/SKILL.md`

Activate skills with `--skill <name>` or from the TUI. Skill activation injects instructions only; it does not grant bash, edit, network, or MCP permissions.

Workspace extensions can add instruction overlays and runtime hooks:

```json
{
  "extensions": ["builtin:policy-instructions", "./.cliq/extensions/log-turns.js"]
}
```

Extensions do not register new model-callable top-level actions.

## Local Data

By default, Cliq stores session state outside your project:

```txt
~/.cliq/
```

`CLIQ_HOME` changes that location:

```bash
export CLIQ_HOME=/path/to/cliq-home
```

Workspace-local `.cliq/config.json`, instruction files, skills, and extensions remain opt-in project configuration.

## Troubleshooting

If startup asks for provider setup, either configure a remote provider API key or install and pull a local Ollama model.

If a workspace is denied by trust state, reset or review the trust record under:

```txt
${CLIQ_HOME:-~/.cliq}/workspaces/<workspaceId>/trust.json
```

If a command needs more model/tool iterations, raise the turn budget:

```bash
CLIQ_MAX_TURNS=120 cliq run --jsonl "complete the benchmark sweep"
cliq run --max-turns 40 "inspect this repo"
```

## Support

For support requests, include:

- `cliq --version`
- `node --version`
- operating system and shell
- provider and model
- the command you ran
- the full error message or relevant JSONL event
