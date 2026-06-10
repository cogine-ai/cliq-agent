# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Removed duplicate typed prompt mode/streaming helpers from the runner and
  provider clients after the typed `ModelPromptRequest` protocol rollout. Mode
  selection and streaming inference now share `selectTypedRequestMode` and
  `typedRequestShouldStream` from `prompt-mapping.ts`.
- Removed the unused `coerceHookPermissionScope` helper from the runner.
  PermissionRequest hook `scope` values remain accepted for forward compatibility
  (#62-A) but still have no persistent effect until the #62-B allowlist surface
  ships; headless one-shot behavior is unchanged.

## [0.13.1] - 2026-06-05

This patch release improves OpenAI-compatible model setup and TUI status output
after the v0.13.0 provider-first rollout.

### Added

- **OpenAI-compatible `/models` discovery** during TUI provider setup, merging
  discovered rows into the model picker while preserving direct custom model
  entry (#296).
- Regression coverage for OpenAI-compatible discovery without an API key and
  API-key fallback order across request input, environment, and saved provider
  auth (#297).

### Changed

- OpenAI-compatible setup now offers optional API-key entry after selecting a
  discovered or custom model when no key has already been supplied (#296).
- The TUI bottom status bar now keeps the current working directory separate
  from fixed tx and token segments, improving truncation and scanability (#296).
- Documentation now describes OpenAI-compatible `/models` discovery alongside
  direct custom model entry and optional API keys (#296).

## [0.13.0] - 2026-06-04

This release completes the provider-first model configuration slice and hardens
Plan progress state after the v0.12 Plan Mode rollout.

### Added

- **Provider/model catalog** with checked-in provider and model metadata,
  dynamic local Ollama metadata inspection, and a development-only
  `npm run catalog:update` snapshot generator (#54).
- **Provider management surfaces** in the TUI and CLI, including `/providers`,
  `cliq providers status`, `cliq providers list`, `cliq providers validate`,
  and `cliq providers auth set` for local provider credential setup (#52).
- **Provider-first model setup and picker** through `/model` and `/models`,
  with current-session model selection, explicit startup-default saving, custom
  model entry, and startup setup when no usable provider/model is configured
  (#49).
- Documentation for provider management, model catalog ownership, local auth
  persistence, and updated non-interactive `cliq run` examples.

### Changed

- The TUI now keeps provider/model selection reachable from slash commands and
  provider detail actions, while keeping headless and one-shot commands
  non-interactive.
- The composer/status layout and empty transcript frame received additional
  polish after the v0.12.1 status-bar patch.
- Removed stale transaction launch-gate docs and orphan `CLIQ_TX_*`
  compatibility exports that no longer match current transaction policy
  behavior.

### Fixed

- Plan instruction reads no longer reset execution progress, and fresh plan
  approval progress seeding is scoped to the current approval only.
- Provider setup preserves session-only auth choices, compatible defaults,
  streaming settings, TUI API-key persistence, and slash-completion argument
  spacing.
- Added regression coverage for plan items, progress guards, policy modes,
  permission grammar, provider status, model setup, provider credentials, and
  catalog metadata.

## [0.12.1] - 2026-05-29

This patch release polishes the TUI status layout for the Plan Mode release.

### Changed

- Move composer hints into a compact line directly above the input row, keeping
  prompt-adjacent state near the composer without duplicating Plan progress.
- Keep update notices fixed at the far end of the bottom status bar, leaving
  plan progress in the dedicated Plan progress panel.

## [0.12.0] - 2026-05-29

This release completes the first Plan Mode workflow slice and aligns Cliq's
permission language around clearer policy modes. It adds artifact-backed plan
review, editable plan files and plan items, and a Claude Code-style execution
tracker that the model updates through the new todo action.

### Added

- **Artifact-backed Plan Mode workflow** with plan draft/finalize/review
  storage, TUI review controls, approved-plan context injection, and explicit
  execution-mode handoff after approval (#239).
- **Editable plan files and structured plan items** stored under the Cliq plan
  artifact directory, with reviewed snapshots frozen for stable approval
  semantics (#254).
- **Plan execution tracker** backed by persisted progress state, a new `todo`
  model action, runtime/headless `plan-progress-updated` events, and TUI
  tracker rendering (#259).
- TUI discoverability improvements for mode state, command hints, slash
  command affordances, and permission-policy status (#217).

### Changed

- Policy modes now use the canonical `default`, `accept-edits`, `plan`, and
  `yolo` tokens across CLI/config/env, TUI, slash commands, docs, and internal
  runtime policy state (#222).
- Plan Mode now carries minimal system guidance that the model should analyze
  and produce a plan without modifying files or running side-effecting commands
  until the plan is approved (#222, #239).
- Headless runtime events now use schema version `2` to reflect the added plan
  progress event surface (#259).

### Fixed

- YOLO mode discovery and TUI labeling now match the current permission-mode
  language (#218).
- Plan approval seeds execution progress before committing approved state, so a
  failed progress write no longer leaves a half-approved plan (#259).
- Historical approved plans missing `progress.json` lazily seed progress on
  hydration or todo updates, and the TUI clears stale progress when a new plan
  review supersedes an approved plan (#259).
- Reviewed plan artifacts keep their approved snapshot stable even when editable
  plan files are changed later (#254).

## [0.11.2] - 2026-05-25

This patch release focuses on permission-boundary correctness and cancellation
reliability after the v0.11 tool-permission rollout.

### Added

- Provider-level streaming cancellation coverage for Anthropic-compatible,
  Ollama, OpenAI-compatible, and OpenRouter adapters, ensuring abort signals
  stop incremental output and cancel the underlying stream.
- Regression coverage for env split-string shell wrappers, read-only hard
  denies, TUI turn-state transitions, and approval-scope handling.

### Changed

- Permission approval helpers are now shared outside the TUI, keeping
  approval-scope and interactive-policy behavior consistent across runtime
  surfaces.
- TUI turn state now preserves distinct runtime error stages instead of
  collapsing separate failures into one generic state.

### Fixed

- Bash allow rules no longer auto-approve compound inline shell payloads hidden
  behind `bash -c`, `env -S`, env assignments, or env option wrappers.
- Read-only mode now hard-denies non-read tool execution before workspace,
  persisted, CLI, session, or hook permission decisions can override it.
- Repeated read-only blocked tool requests now stop the turn instead of letting
  a local model loop indefinitely on the same denied action.
- Streaming model reads now propagate `AbortSignal` through provider adapters
  and clean up abort listeners on already-aborted and in-flight cancellation
  paths.
- `cliq -v` / `cliq --version` works without loading workspace trust state.

## [0.11.1] - 2026-05-22

This patch release hardens the first built-in skills rollout and closes a
permission allowlist edge case found during dogfooding.

### Added

- **Built-in skill delivery** — Cliq now ships and syncs the default
  `skill-creator`, `skill-installer`, and `skill-doctor` skills into
  `~/.cliq/skills/.system`, so fresh installs and upgrades have the core
  skill maintenance helpers available without a separate manual install (#163).
- **Regression coverage** for project skill trust escapes, diff-sanity path
  normalization with `..` inside a filename segment, and workspace
  `defaultSkills` rejecting user-only skills (#181).

### Changed

- Upgraded `ws` from 8.20.0 to 8.20.1 (#162).

### Fixed

- Built-in skill sync now repairs partially copied managed skill directories
  instead of treating a lone `SKILL.md` as complete, and handles installer
  GitHub refs that contain slashes when falling back to git auth (#163).
- Built-in skill metadata parsing now accepts top-level `name` fields from
  skill manifests (#163).
- Bash permission allow rules no longer auto-approve commands that append
  executable shell syntax such as `&&`, `;`, pipes, newlines, `$()`,
  backticks, or process substitution after an allowed command head (#183).
- Project skill loading keeps validating both the skill directory and
  `SKILL.md` realpaths inside the trusted project root (#181).

## [0.11.0] - 2026-05-22

This release completes the user-facing tool-permission surface that followed
the v0.10 Workspace Trust gate, and adds the foundation for local Agent Skills:
deterministic discovery, explicit and model-driven activation, TUI/RPC
inspection, active-skill state, and bounded resource reads.

### Added

- **Agent Skills foundation** — Cliq now discovers local `SKILL.md` files from
  project `.cliq/skills` / `.agents/skills` and user `~/.cliq/skills` /
  `~/.agents/skills` roots after Workspace Trust has decided. The catalog
  includes scope, source kind, diagnostics, deterministic collision handling,
  and robust frontmatter parsing for standard Agent Skills files (#120-#128).
- **Skill activation surfaces** — existing `defaultSkills`, repeatable
  `--skill`, and headless `skills` now share the catalog-backed loader. TUI
  users can inspect and activate skills through `/skills` and `/skill <name>`,
  while models can activate discovered skills through the new `skill` action.
  Workspace `defaultSkills` remain restricted to project-owned skills (#120-#128).
- **Active skill state and instruction refresh** — activated skills are tracked
  in session state and reinjected into runtime-composed instructions on later
  turns, including after session replay and compaction-sensitive paths. Missing
  or invalidated active skills surface diagnostics instead of silently
  disappearing (#120-#128).
- **Bounded skill resources** — activated skills can expose bundled files
  through the `skillResource` action. Reads and listings stay relative to the
  activated skill directory and reject traversal, symlink escape, binary files,
  and oversized files (#120-#128).
- **RPC skill catalog visibility** — `cliq rpc` now exposes `skills.list` so
  GUI, gateway, and automation clients can inspect available and active skills
  without scraping terminal output (#120-#128).
- **TUI update notice** — the status bar can surface npm update availability
  without failing the session if the update check errors.
- **Per-workspace `permissions.json` persistence** — `~/.cliq/workspaces/<id>/permissions.json` stores allow/deny rules picked from the TUI "Always allow in this workspace" decision. Atomic writes, fail-closed reads (corrupted/version-mismatched/workspace-id-mismatched records are ignored rather than honored), and the same load-order invariant as `trust.json` (must follow the Workspace Trust gate). User-global allow/deny is deliberately not shipped in v0 (#62).
- **Workspace `permissions` config section** — `.cliq/config.json` now accepts `permissions: { preset?, allow?, deny?, ask? }` so a workspace can pin its default friction level and per-action rules without forcing every invocation to pass CLI flags. Errors carry the offending rule index for fast typo location (#62).
- **Shared `<channel>: <pattern>` permission grammar** — one parser used by workspace config, CLI flags, and the TUI session memory; covers `fs-read`, `fs-write`, `bash`, `mcp`, `network` channels with literal / `*` / `prefix *` matching. Forward-compat for MCP and network channels; today they only carry the model's stated intent (#62).
- **CLI flags `--allow / --deny / --ask` (repeatable) and `--preset` alias for `--policy`** — feed `'cli'`-tagged rules into the layered permission table. `--policy` and `--preset` are mutually exclusive on the same invocation to avoid silent winners; `CLIQ_POLICY_MODE` does not count as a conflict so CLI flags can override an env default (#62).
- **Composed layered `PermissionTable` runtime** — `PolicyEngine` now consults builtin deny → workspace config → persisted `permissions.json` → CLI flags → session memory before falling back to the `PolicyMode` preset. Behavior surface is unchanged for callers that don't set any permission rules; the default empty table degrades to the legacy `PolicyMode`-only decision (#62).
- **TUI 5-option ApprovalModal** — `y` allow / `a` allow this turn / `s` allow this session / `Shift+W` always allow in this workspace / `n` deny. `[W]orkspace` is dim-colored to flag it as the most sticky decision. Session/workspace scopes only render on tool subjects; tx-apply and permission-request modals stay one-shot. Workspace-scope decisions persist via `appendPersistedWorkspacePermission`; persist failures surface as stderr warnings without blocking the current turn (#62).
- **README `## Tool permissions` section** documenting the rule grammar, all five layers, CLI flags, workspace config, modal scopes, and the headless one-shot guarantee.

### Changed

- `POLICY_MODES` / `isPolicyMode` / `POLICY_MODE_LIST` extracted from `src/cli.ts` into a shared `src/policy/modes.ts` so workspace config, CLI flags, slash commands, and the TUI all read from one source of truth (#62).
- `accessChannelPrimaryKey` now exported from `src/policy/decision-table.ts` so other layers (TUI extend-allow, slash command rendering, audit log) can derive a stable rule pattern from a live subject without re-implementing the channel switch (#62).
- Headless / `--json` / `rpc` / non-TTY paths are explicitly documented as one-shot scope only: `PermissionRequest` hooks emitting `scope: 'session'` or `scope: 'workspace'` are coerced down to `'once'` (already enforced via `coerceHookPermissionScope` since #62-A), and `~/.cliq/workspaces/<id>/permissions.json` is never written from these paths. Pinned by a new regression test in `src/headless/run.test.ts` (#62).

### Fixed

- Project skill loading now validates the canonical realpath of both the skill
  directory and `SKILL.md` file before treating a project skill as available,
  closing a symlink escape where `SKILL.md` could point outside the trusted
  project root (#120-#128).
- Shift+Tab handling no longer leaks raw terminal input into the TUI buffer.
- Update-check failures are absorbed by the TUI instead of interrupting the
  interactive session.

## [0.10.0] - 2026-05-16

This release lands the first layer of Cliq's three-layer security model
(**Workspace Trust → Tool Permission → Sandbox**, see `AGENTS.md`): an
interactive trust gate that fronts repo-side configuration loading, plus
the internal machinery (decision table, AccessChannel classification,
forward-compatible hook surface) that the user-visible per-tool
permission UX will plug into in v0.11.

### Added

- **Workspace trust gate** — interactive chat prompts once per canonical workspace before reading `./.cliq/config`; headless/`run --jsonl`/`rpc`/`tx validate|apply` fail closed unless `CLIQ_TRUST_WORKSPACE` or persisted trust permits it (#48, #61).
- **Tool permission decision table (internal)** — `PolicyEngine` now consults a layered `PermissionTable` (builtin deny → workspace deny → allow → ask → preset) before falling back to the legacy `PolicyMode` preset. Every tool `ApprovalSubject` carries an `AccessChannel` (`fs-read`, `fs-write`, `bash`, `mcp`, `network`) derived deterministically in `buildToolApprovalSubject`. No user-visible surface yet — the table is empty by default and call sites are unchanged. CLI flags, workspace config, and persisted per-workspace rules land in the follow-up #62-B (#62, #71).
- **`HookOutput.permissionDecision.scope`** (forward-compatible) — `PermissionRequest` hooks may now emit `scope: 'once' | 'session' | 'workspace'` and `additionalAllowlistEntries: string[]`. The runner only acts on `'once'` today; richer scopes are accepted but coerced to `'once'` until the persistence surface ships in #62-B. Existing hooks are unaffected (#62, #71).
- **`AGENTS.md`** — canonical onboarding doc for AI coding agents and human contributors. Documents the three-layer security model, code-review conventions, and reference targets for trust UX (CodeBuddy, Codex CLI, Claude Code) (#70, #72).
- **`docs/beta/cliq-internal-beta-user-guide.docx`** — ships the current internal beta user guide alongside the source (#70).

### Changed

- **Bash decision flow merged into a single path** — `enforceBashPolicy` accepts a new `policyAlreadyApproved` flag (set by the runner-driven tool execute path) so the tx overlay no longer re-prompts when `PolicyEngine` has already approved. `bashPolicy=passthrough` and `bashPolicy=confirm` collapse to allow; `bashPolicy=deny` still wins. The headless + `bashPolicy=confirm` CI safety net is preserved (#62, #71).

### Fixed

- Trust gate polish from review: clearer `--classic` disclosure, canonical `realpath` required for trust keys, corrupted `trust.json` ignored like "no record", Ink prompt guard against duplicate decisions (#61).
- `cliq tx validate` / `cliq tx apply` with `--json` or `--headless` now surface workspace-trust refusals as a one-line JSON error on stdout instead of dumping plain text to stderr — matches the rest of the tx machine-readable contract (#69).
- Interactive runtime trust gate now writes the failure message to stderr before throwing, eliminating silent non-zero exits in `CLIQ_TRUST_WORKSPACE=deny` / persisted-denied / non-TTY paths (#69).
- Latent always-deny bug for interactive `bashPolicy=confirm` (the bash tool never passed a confirm callback). The merged decision flow above eliminates the double-prompt by trusting the upstream `PolicyEngine` decision (#62, #71).
- `parseBashCommandHead` now correctly skips `nice -n`/`--priority`/`--adjustment` args (incl. attached-value forms) and pins regression coverage for redirection-prefixed lines like `> out.txt ls` (#71).
- Default `PermissionTable` singletons (`EMPTY_PERMISSION_TABLE`, `BUILTIN_DENY`) are now deeply frozen so a stray mutation can't poison shared `PolicyEngine` defaults (#71).

## [0.9.0] - 2026-05-14

This release lands Phase A of the Ink-based interactive terminal UI as the
default interactive surface, plus a workspace command-hook control plane,
payload-aware approvals, and a steady stream of TUI polish.

### Added

- **Phase A Ink TUI as the default interactive surface.** Launching `cliq`
  (or `cliq chat`) on a TTY now enters a three-zone Ink layout — scrolling
  transcript, input bar, and status line — rendered inline so shell scrollback
  keeps working. Includes slash commands (`/exit`, `/quit`, `/reset`,
  `/help`, `/policy <mode>`) with palette popover and Tab completion, an
  approval modal for `--policy confirm-*` and interactive `--tx-apply`
  decisions, and a status bar surfacing provider/model, policy mode, tx state,
  and session token estimate. Opt out with `--classic` or `CLIQ_TUI=0`; opt in
  explicitly with `--tui`. (#42, #43, #44)
- **Cursor and history navigation in the input bar.** ↑ / ↓ recall previously
  submitted prompts and preserve the in-progress draft on the way back down;
  ← / → move the cursor inside the buffer; mid-buffer insertion, Backspace, and
  forward Delete all respect the cursor position; Tab completion and other
  external buffer replacements snap the cursor to the new end. (#55)
- **Shift+Tab policy rotation in the TUI.** Cycles through the configured
  policy modes; the status bar segment is colour-coded per mode. (#44)
- **Workspace command hooks.** A new `hooks` config block runs user-defined
  commands at lifecycle points — `SessionStart`, `UserPromptSubmit`,
  `PreToolUse`, `PostToolUse`, `PermissionRequest`, `TxFinalized`,
  `TxValidated`, `TxApplyReview`, `Stop`. Hook commands receive a versioned
  JSON payload on stdin and can return structured allow/deny decisions or
  inject additional context. (#51)
- **Payload-aware approval decisions.** Approval subjects now carry the action
  payload, so approval callbacks (and command hooks listening on
  `PermissionRequest`) can inspect tool parameters before deciding. (#41)
- **Tab cursor handling, transcript noise filtering, and tool-body rendering
  improvements** in the TUI's first wave of real-terminal usage. (#43)

### Changed

- **`cliq` on a TTY now defaults to the Ink TUI.** Non-TTY one-shot runs
  (`cliq "task"`) and headless modes (`cliq run --jsonl`) are unaffected.
  Set `CLIQ_TUI=0` or pass `--classic` to keep the previous readline REPL.
  (#42)
- **`transactions.bashPolicy=confirm` is now accepted by config validation.**
  In headless mode it promotes to deny with a structured reason; in interactive
  mode it requires a confirm callback (not yet wired into the tx-mode bash
  tool, so invocations conservatively deny — use `passthrough` or `deny` until
  the prompt is connected to the TUI). (#38)
- **Tx review surfaces are tightened** along the validate / approve / apply /
  abort path, including better summaries for validator results and clearer
  artifact references. (#39)

### Fixed

- **Lexical JSON escape errors in model action output are now repaired** before
  parse, so streaming providers that emit non-canonical escapes no longer fail
  a turn outright. (#40; merged through the v0.8.1 repair branch and released
  here, with no separate v0.8.1 tag.)
- **Ctrl+O no longer leaks a literal `o` into the input buffer** in the TUI
  (ink-text-input's Ctrl-letter passthrough is replaced by a tiny custom
  single-line input that skips every modifier combination). (#43)
- **Tab cursor desync** in the input bar after slash completion. (#43)

### Notes

- Documented release-note format for earlier versions lives in
  [GitHub Releases](https://github.com/cogine-ai/cliq-agent/releases); this
  file starts with v0.9.0.

[Unreleased]: https://github.com/cogine-ai/cliq-agent/compare/v0.13.1...HEAD
[0.13.1]: https://github.com/cogine-ai/cliq-agent/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/cogine-ai/cliq-agent/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.11.2...v0.12.0
[0.11.2]: https://github.com/cogine-ai/cliq-agent/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/cogine-ai/cliq-agent/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.8.0...v0.9.0
