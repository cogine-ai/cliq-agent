# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/cogine-ai/cliq-agent/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/cogine-ai/cliq-agent/compare/v0.8.0...v0.9.0
