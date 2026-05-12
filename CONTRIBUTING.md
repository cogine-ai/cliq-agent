# Contributing to Cliq

Thanks for your interest in contributing.

## Local development

```bash
npm install
npm run build
npm link
```

Set your API key before running the CLI:

```bash
export OPENROUTER_API_KEY=...
```

## Common commands

```bash
npm run build
npm run dev -- "your task here"
node dist/index.js chat
```

## TUI development (Phase A)

The Ink TUI lives at `src/tui/` and is wired in via the `--tui` opt-in flag through `cli.ts`. It is loaded with `await import('./tui/index.js')` on the dispatch path so headless / RPC code never pulls in Ink or React.

- Components: `src/tui/components/*.tsx` — each pairs with a `*.test.tsx` driven by `ink-testing-library`.
- Pure store: `src/tui/store.ts` — reducer is exhaustive on `UiAction` and on `RuntimeEvent` via `assertNever`. New variants on either side fail to compile here first.
- Isolation: `src/tui/import-isolation.test.ts` walks `src/headless/`, `src/runtime/`, and `src/protocol/` and fails if any file imports `react`, `ink`, `ink-text-input`, or anything under `src/tui/`. Do not break this — it is the contract that lets headless users avoid the TUI dependency footprint.
- Run TUI tests: `npm test` (the TUI test files are picked up by the existing glob). Build: `npm run build`.

When you add a new `RuntimeEvent` variant in `src/protocol/runtime/events.ts`, you also need to update `src/tui/store.ts` (and `src/headless/events.ts`) — both rely on `assertNever` for compile-time exhaustiveness.

## Contribution scope

At this stage, the most useful contributions are:

- bug fixes
- small usability improvements
- protocol/runtime clarity improvements
- documentation improvements

Please keep changes focused and easy to review.

## Issues

Please use the GitHub issue templates when reporting bugs, asking questions, or proposing features. Redact API keys, local session files, private repository paths, and other sensitive data before sharing logs.

## Pull requests

- prefer small PRs
- include a brief summary of what changed
- mention how you validated the change
