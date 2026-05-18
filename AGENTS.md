# AGENTS.md — Conventions for AI coding agents

This file is the canonical onboarding doc for AI coding agents (Cursor, Codex
CLI, Claude Code, Copilot CLI, Gemini CLI, etc.) operating on this repository.
Human contributors are welcome to read it as well.

Anything below applies to the whole repo unless a deeper-nested `AGENTS.md`
overrides it for a subtree.

## Repository

- Public repo: `cogine-ai/cliq-agent`. Default branch: `main`.
- Project: `@cogineai/cliq` (TypeScript, Node.js ≥ 22).
- Source layout: `src/` (CLI, runtime, session, TUI, transactions, headless,
  workspace, tools); tests live next to the code as `*.test.ts`.

## Build and test

Before pushing or opening a PR, the following must succeed locally:

```bash
npm run build   # tsc -p tsconfig.json
npm test        # node --test
```

Add or update tests for any new behavior. Prefer adding focused tests next to
the changed module rather than expanding unrelated suites.

## Working with PR / code-review feedback

When addressing feedback from CodeRabbit, Codex, human reviewers, or any other
automated reviewer:

- Re-verify each finding against the current code; fix only findings that are
  still valid, and briefly note any that are obsolete or already-handled
  rather than silently skipping them.
- Stay aligned with the PR's stated business goal — do not let the literal
  wording of an individual comment pull the change off-scope.
- Keep changes minimal and self-contained; rerun build + tests before pushing.

## Security model: three independent layers

When working on workspace trust, tool permissions, sandboxing, or any related
security surface, distinguish three independent layers and do not collapse
them:

1. **Workspace Trust** — the gate that decides whether a directory is allowed
   to load repo-side configuration and enter the agent runtime at all
   (`./.cliq/config`, hooks, validators, `createRuntimeAssembly`, etc.).
   Trusting a directory is **not** an automatic permission grant for file
   edits or shell commands.
2. **Tool Permission** — per-action authorization (read / write / bash / MCP /
   network) for tools that the agent runtime invokes once a workspace is
   trusted. Lives in policy modes (`auto`, `confirm-write`, `confirm-all`,
   `read-only`) and per-tool/policy hooks.
3. **Sandbox / Boundary** — OS- or container-level enforcement (process
   sandbox, filesystem jails, network rules) as the last line of defense
   behind layers 1 and 2.

Anything that loads workspace-controlled state (config, hooks, validators,
runtime assembly) **must** run after the Workspace Trust layer has decided.
Avoid load-order regressions where repo-controlled config takes effect before
the trust UI/decision.

## Reference targets for trust / permission UX

When evaluating prior art for the **workspace-first-run trust** experience
specifically, prefer the layered behavior of **CodeBuddy**, **Codex CLI**, and
**Claude Code**. Do not treat Cline, OpenCode, or Pi as the baseline for the
first-run trust gate — their defaults sit at a different point on the
trust/convenience tradeoff than what we want here.

For tool-permission UX (layer 2), the same three references plus existing
internal `policy-mode` semantics are the primary references.

## Git workflow

- Branch off `main`; use a short kebab-case prefix that hints at scope, e.g.
  `cliq/<topic>` or `fix/<topic>`.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `chore:`,
  `docs:`, `test:`, `refactor:` …). Reference issues/PRs (`#NN`) where
  relevant.
- Do not force-push to `main`. Do not amend commits that have already been
  pushed unless the user explicitly asks for it.
- Open PRs against `main`. Keep PRs small and reviewable; split mechanical
  changes from behavior changes when practical.
