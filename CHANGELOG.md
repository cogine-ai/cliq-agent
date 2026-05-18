# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/cogine-ai/cliq-agent/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.8.0...v0.9.0
