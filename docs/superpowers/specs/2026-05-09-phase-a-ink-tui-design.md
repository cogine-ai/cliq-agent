# Phase A — Ink TUI (in-process) Design Spec

**Status:** draft 2026-05-09 (design discussion)
**Branch:** `cliq/phase-a-ink-tui` (proposed)
**Parent:** current `main` after `cliq/feishu-workflow` lands
**Reference:** Claude Code (`claude`), Gemini CLI, Codex CLI (legacy TS) — all use Ink in-process; OpenCode uses Bubble Tea + local server (rejected pattern, see A.0).

## Goal

Replace the readline-based interactive chat (`cli.ts:1891-2002`) with a real terminal UI built on Ink, **same Node process as the runtime**. After this phase a user typing `cliq` (or `cliq chat`) on a TTY enters a rich TUI with: rolling transcript, persistent status bar, slash command palette, structured tool-result rendering, and an approval modal that replaces the bare `askYesNo` prompt.

This phase deliberately ships *parity-plus-approval-UX* — not panels, not streaming tokens, not session tree. Those land in Phase A2 / B once the interaction loop and event plumbing are validated.

## Scope

**In scope:**
1. New `src/tui/` module: components, store, input handling, Ink entry point.
2. CLI dispatch change: `cliq` and `cliq chat` enter the TUI on TTY; `--classic` and non-TTY fall back to the current REPL.
3. `UiStore`: in-memory pubsub that mirrors `RuntimeEvent` shape (forcing function for future RPC-driven UI; see A.4).
4. Approval modal replacing `askYesNo` for `confirm-write` / `confirm-bash` / `confirm-all` and `tx apply` interactive prompt.
5. Slash commands wired in Phase A: `/exit`, `/quit`, `/reset`, `/help`, `/policy <mode>`.
6. Cancellation: Ctrl+C cancels the active turn via `AbortSignal`; Ctrl+D exits.
7. Tests: pure logic (reducers/selectors) under `node --test`; component snapshots with `ink-testing-library`.

**Out of scope (Phase A2 or later):**
- Side panels (JSON action timeline, cumulative session diff, tx overlay panel).
- Token-level streaming inside the transcript (current README explicitly lists this as non-goal).
- Rich `@file` mention expansion (Phase A treats `@path` as plain text).
- Mid-session `/model` and `/skill` swap.
- Replay mode, session tree / fork browser.
- Mouse support, alt-screen mode (see A.2).
- Web GUI, separate native binary on top of `cliq rpc` (Phase B candidate).

## Non-goals

- **No RPC indirection between TUI and runtime.** The TUI imports `src/runtime` directly. `cliq rpc` keeps its existing role for *external* clients (automation, future GUIs, subagent orchestrators) and is not touched in this phase. Earlier discussion considered forcing the TUI through RPC; rejected — see A.0.
- **No backward-compatibility invariant for the readline REPL.** Once `--classic` is wired, the legacy code path can shrink. Tests for the old REPL get updated alongside the code.
- **No new top-level model-callable actions.** TUI is purely a render/input layer; the protocol is unchanged.

## Architectural Decisions

### A.0 — TUI is in-process, not behind `cliq rpc`

Claude Code, Gemini CLI, and the legacy Codex CLI all run their Ink TUI in the same process as the agent runtime. The dominant pattern is in-process; the cross-process TUI (OpenCode's Bubble Tea over local HTTP) exists because OpenCode targets multi-client / web GUI scenarios that Cliq does not have today.

Decision: **in-process import of `src/runtime`, `src/session`, `src/model`**. `cliq rpc` keeps its independent purpose (external clients).

Rejected alternatives:
- *TUI as a separate process consuming `cliq rpc`:* premature abstraction; pays serialization + lifecycle complexity for no current product benefit; slows UX iteration ~3-5x.
- *Two-binary split (Node runtime + Go/Rust TUI):* deferred to Phase B, only if Ink hits a perf ceiling we can measure.

### A.1 — TUI module lives at `src/tui/`, not a separate npm package

Same repo, same release cadence, shared TypeScript types with the runtime. A separate `@cogineai/cliq-tui` package was considered to preserve `dependencies: {}` purity for the main package, but:

- It complicates `npm i -g @cogineai/cliq` UX (the TUI has to be a peer install or postinstall).
- It splits the test/CI surface across two artifacts.
- The zero-dep stance was a v0.x purity statement, not a contract; we drop it for Cliq main and document the trade-off (A.14).

Decision: keep one package, add Ink deps to the main `package.json`.

### A.2 — Inline rendering, not alt-screen

Claude Code uses inline (no alt-screen): the TUI prints to the existing terminal scrollback and updates the bottom region in place. Codex CLI (TS legacy) likewise.

Reasons we follow:
- Preserves shell scrollback; users can `Cmd-F` find earlier output and paste it elsewhere.
- Plays well with multiplexers (tmux/zellij) and CI tail logs.
- Aligns with Cliq's "easy to inspect" positioning — the session you just ran is still there above your shell prompt.

Alt-screen is reserved for a later "workbench" mode (`cliq workbench`?) if/when we add side panels or replay scrubbing.

### A.3 — `cliq` enters the TUI by default on TTY

Behavior matrix:

| Invocation | stdin/stdout TTY | Behavior |
|---|---|---|
| `cliq` (no args) | yes | Enter TUI |
| `cliq chat` | yes | Enter TUI |
| `cliq tui` | yes | Enter TUI (explicit alias) |
| `cliq` / `cliq chat` | no | Current readline REPL (unchanged) |
| `cliq --classic [chat]` | yes/no | Force legacy REPL |
| `cliq "<prompt>"` | any | One-shot run, no TUI (unchanged) |
| `cliq run --jsonl ...` | any | Headless (unchanged) |
| `CLIQ_TUI=0` env | yes | Force legacy REPL (escape hatch for early users / CI) |

The TTY check uses the existing `process.stdin.isTTY && process.stdout.isTTY` pattern (mirrors `askYesNo` at `cli.ts:1186`).

Rejected: gating the TUI behind a `CLIQ_TUI=1` opt-in. We're confident enough in inline-Ink to make it default; the opt-out is the safer escape hatch.

### A.4 — `UiStore` is the single integration point with the runtime

Even though TUI and runtime share a process, we route all runtime → UI traffic through one in-memory pubsub:

```ts
// src/tui/store.ts (sketch)
type UiState = {
  transcript: TranscriptEntry[];        // user/assistant/tool/system entries in order
  activeTurn: { startedAt: string; modelChunks: number; modelChars: number } | null;
  pendingApproval: PendingApproval | null;  // drives the modal
  policy: PolicyMode;
  model: { provider: ProviderName; model: string };
  session: { id: string; cwd: string };
  tx: { id: string; state: TxState; diffSummary?: DiffSummary } | null;
  errors: ErrorEntry[];                 // last N errors, surfaced in status bar
};

type UiAction =
  | { type: 'runtime-event'; event: RuntimeEvent }
  | { type: 'tool-start'; tool: string; preview?: string }     // from hooks
  | { type: 'tool-end'; result: ToolResult }                   // from hooks
  | { type: 'user-input'; text: string }
  | { type: 'final'; message: string }
  | { type: 'approval-resolve'; decision: 'allow' | 'deny' | 'allow-turn' }
  | { type: 'session-reset' }
  | { type: 'policy-change'; mode: PolicyMode };
```

Why this matters:
- The store is the *only* place that knows about UI shape. Components are pure projections.
- Reducer is a pure function — testable under `node --test` without Ink.
- If we ever swap to a separate-process TUI consuming `cliq rpc` (Phase B), the reducer migrates verbatim; only the source of `UiAction` changes (RPC notifications instead of in-process subscriptions). This is the "RPC-shape in memory" insurance from the technical-selection discussion — we get optionality at near-zero cost.

Hooks (the existing `RuntimeHook` surface) and `onEvent` both publish into the store; components subscribe via a tiny `useUiStore` hook (no Redux, no Zustand — keep it ~80 LOC).

### A.5 — Streaming is rendered as progress, not token-by-token text

`RuntimeEvent` already includes `model-progress { chunks, chars }` (events.ts:8). README explicitly lists "token-by-token final answer rendering" as a non-goal for the current version. Phase A respects that:

- During a turn, the transcript shows a spinner row "thinking… 1.2k chars" updated from `model-progress`.
- Final assistant text is appended atomically when `final` arrives.
- We do *not* parse partial JSON actions or render partial tool calls.

Phase A2 may revisit token streaming once the model adapter exposes a true text delta stream.

### A.6 — Approval modal replaces `askYesNo`

Today `policy/engine.ts` calls a `confirm(prompt: string) => Promise<boolean>`; in interactive mode `cli.ts:1216` wires it to `askYesNo`. We replace that with a TUI-aware confirm that:

- Pushes a `PendingApproval` into the store.
- Renders a modal over the input area showing: tool name, action summary, target path (if `edit`), short diff preview (for `edit`, max 20 lines), policy mode, "why this is being asked".
- Hotkeys: `y` allow, `n`/Esc deny, `a` allow-for-this-turn (sticky until turn ends), `?` toggle full diff.
- Resolves the deferred Promise on key press and clears `pendingApproval`.

`tx apply` interactive confirm at `cli.ts:1936-1942` reuses the same modal with a tx-specific summary (file count, validator status).

`allow-for-this-turn` is new sugar; semantically equivalent to flipping policy to `auto` for the remaining tool calls in the current turn, then snapping back. Implemented as a turn-scoped policy override, not a global state change.

### A.7 — Slash commands wired in Phase A

| Command | Behavior | Source |
|---|---|---|
| `/exit`, `/quit` | exit TUI, save session | parity with current REPL |
| `/reset` | `ensureFresh(cwd)` (matches `cli.ts:1976`) | parity |
| `/help` | inline help overlay | new |
| `/policy <mode>` | live-swap policy via `createPolicyEngine` swap on the runner | new |

Deferred to Phase A2: `/model`, `/skill`, `/checkpoint`, `/compact`, `/handoff`, `/tx`. Their CLI subcommands already exist; the TUI mappings are mechanical and worth a separate PR.

Slash command palette UI: typing `/` opens a small popover with fuzzy filter. Tab completes. This is one Ink component (~150 LOC) reused as we add more commands.

### A.8 — Layout: three vertical zones, no panels

```
┌──────────────────────────────────────────────────────┐
│ Transcript (scrolling, inline above input)           │
│   user> ...                                          │
│   ▸ tool: read src/foo.ts (ok, 1.2KB)                │
│   ▸ tool: edit src/foo.ts (ok, +3 -1)                │
│   assistant: ...                                     │
│   thinking… 842 chars                                │
├──────────────────────────────────────────────────────┤
│ > _                                                  │ ← input
├──────────────────────────────────────────────────────┤
│ ollama/qwen3:4b · auto · ses_a1b2 · /repo · tx idle  │ ← status bar
└──────────────────────────────────────────────────────┘
```

The transcript renders only the **last N entries** (default 200) to avoid Ink's reconciliation cost on long sessions; older entries remain in the shell scrollback (because we're inline) and the full history is on disk. This is the deliberate tradeoff that makes inline + Ink viable for long sessions.

Side panels (JSON action timeline, cumulative diff, tx overlay) are explicitly deferred. They are the *interesting* differentiation work, but they require alt-screen-style layout management and would balloon Phase A scope.

### A.9 — Cancellation and exit

- Ctrl+C during an active turn: dispatch `AbortSignal.abort()` on the runner's signal; UI shows "cancelling…"; runner emits `error { stage: 'cancel' }`; transcript marks the turn as cancelled.
- Ctrl+C with no active turn: clears the current input buffer (vim-style), does not exit. (Diverges from readline default; the explicit `/exit` is the exit path.)
- Ctrl+D on empty input: exits cleanly via `saveSession`.
- Ctrl+D on non-empty input: ignored (matches Claude Code).

### A.10 — Tool result rendering

Reuse `formatToolResultLine` from `cli.ts:1158` for the one-line summary. Phase A adds:

- Group consecutive `bash` outputs into a fenced code block (folded by default if > 20 lines, expandable with `o` when the tool entry is focused; focus is implicit-last-only in Phase A).
- For `edit`: show `+N -M` summary and the file path; full diff in the approval modal only.
- For `read` / `ls` / `find` / `grep`: show path/pattern + result count; details on demand deferred to Phase A2.

Color/iconography: a single status glyph per row (`▸` running, `✓` ok, `✗` error). No emoji unless the user opts in via env (`CLIQ_TUI_EMOJI=1`).

### A.11 — Status bar contents

Always: `provider/model · policy · sessionId(short) · cwd(basename) · tx state`.
Conditional: token count when the model adapter exposes it; auto-compact countdown when inside threshold band; a red dot when last turn produced an error.

Cost guard / token-budget bar is **not** in Phase A — depends on token governance landing first.

### A.12 — Dependencies

Add to main `package.json` `dependencies`:

```
ink                ^5
react              ^18
ink-text-input     ^6 (or build a tiny one if breakage risk is high)
```

Rejected:
- `ink-spinner`, `ink-syntax-highlight`, `ink-table`, `ink-link` — pull in their own deps; we write 30-line replacements where needed in Phase A. Ecosystem libs can be re-evaluated in Phase A2 once the surface is stable.
- `chalk` — Ink ships its own color path; no need.

The main `dependencies: {}` invariant is dropped. Headless / RPC code paths must continue to *work* without importing Ink (lazy-import `src/tui/` only from the TUI dispatch branch; static analysis check via a unit test that walks `src/headless/**` and `src/runtime/**` import graphs).

### A.13 — Tests

- **Reducer tests** (`src/tui/store.test.ts`): table-driven over `UiAction` → `UiState` transitions. Pure, fast, no Ink.
- **Component snapshot tests** (`src/tui/components/*.test.tsx`): use `ink-testing-library`. Cover transcript row variants, status bar, approval modal, slash palette.
- **Integration smoke** (`src/tui/integration.test.tsx`): drive a fake runner that emits a scripted `RuntimeEvent` sequence; assert the final visible frame.
- **Import-isolation test** (`src/tui/import-isolation.test.ts`): walks `src/headless/**` and `src/runtime/**` modules, fails if any of them transitively imports `src/tui/**` or `react`/`ink`.

We do **not** try to drive the real Ink loop end-to-end against a real TTY in CI — flaky and low value. Real-TTY behavior is verified manually before each release.

### A.14 — Documentation and migration

- `README.md` "Quick start" replaces the screenshot-equivalent (no screenshot in repo) with a description of the TUI; documents `--classic` and `CLIQ_TUI=0` opt-outs.
- `CONTRIBUTING.md` adds a "TUI development" section: `npm run dev:tui` for fast feedback; explains the import-isolation rule.
- One paragraph in `docs/rfcs/2026-04-17-agent-runtime-architecture.md` updates the "TUI / workbench" non-goal note to point at this spec.

## Phased deliverables

Suggested rhythm — adjust as we go:

**Stage 1 — scaffolding (≈ 2-3 days)**
- `src/tui/index.tsx` Ink entry point.
- `UiStore` with reducer + subscribe + 5 actions wired.
- Minimal `<App>`: transcript + input + status bar; renders one user message and one final assistant message via the runner.
- Dispatch change in `cli.ts`: `cliq` / `cliq chat` route to TUI on TTY.
- README/CONTRIBUTING note + `--classic` flag.

**Stage 2 — full transcript + slash commands (≈ 3-4 days)**
- All `RuntimeEvent` variants drive store actions.
- Tool-result rendering with `formatToolResultLine` + bash grouping.
- `/exit`, `/quit`, `/reset`, `/help` parity.
- Slash command palette component.
- Reducer + component tests.

**Stage 3 — approval modal + cancellation + policy (≈ 3-4 days)**
- Replace `askYesNo` with `<ApprovalModal>`.
- Wire `tx apply` interactive prompt to the same modal.
- Ctrl+C abort plumbing.
- `/policy <mode>` live swap.
- Integration smoke test.

**Stage 4 — polish + beta (≈ 2-3 days)**
- Status bar full content (token count, auto-compact countdown).
- Error surfaces, empty-state copy.
- Manual TTY pass on macOS Terminal, iTerm2, Alacritty, tmux, VS Code integrated terminal.
- Manual pass for narrow terminals (< 80 cols) and tall transcripts.

Total: ≈ 2 calendar weeks at one engineer's focus, with the option to ship Stage 1+2 as an `--tui` opt-in beta and flip the default after Stage 3.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Ink + readline contention on stdin | Replace readline entirely in the TUI path; keep readline only behind `--classic`. The two paths must not coexist in one process. |
| Long sessions cause Ink reconciliation jank | Cap visible transcript at N entries (A.8); rely on shell scrollback + on-disk session for full history. Re-evaluate at Phase A2 if users hit the cap. |
| Dependency footprint for users who never use the TUI | Lazy-import `src/tui/**` only from the TUI dispatch branch; the headless / `cliq run --jsonl` / `cliq rpc` paths never load Ink. Enforced by import-isolation test (A.13). |
| Future Bubble Tea / Ratatui migration | `UiStore` reducer is reusable; the migration cost is "render the same state in another framework" — bounded. We pay nothing extra in Phase A for this option. |
| Windows / conPTY edge cases | Ink works on Windows but is less battle-tested than on Unix. Phase A targets macOS + Linux as Tier-1; Windows is best-effort with a known-issues list before flipping default. |
| Accessibility / screenreaders / `NO_COLOR` | Honor `NO_COLOR=1`; avoid color-only signaling (use glyphs). Inline mode is friendlier to screenreaders than alt-screen, which is one more reason for A.2. |

## Open questions

1. **`--classic` lifetime.** Do we plan to remove the readline REPL in v1.0, or keep it indefinitely for power users / CI? Recommendation: keep through v0.9, re-evaluate before v1.0 based on telemetry of `--classic`/`CLIQ_TUI=0` usage.
2. **Approval modal: per-action vs batched.** When the model returns multiple tool calls in one turn, do we ask once-per-action (status quo) or batch into a single modal? Phase A keeps once-per-action (simpler, matches current semantics).
3. **`/policy` live swap and tx mode.** If the user is mid-tx and lowers policy to `auto`, do staged edits get auto-applied? Current behavior: `applyPolicy` is set at runner construction; live `/policy` should not affect it. Documented but worth confirming.
4. **Beta flag vs immediate default.** Ship Stage 1+2 behind `--tui` opt-in for one minor version, then flip? Or flip default in the same release that lands Stage 3? Lean toward beta-first for risk control.

## Appendix — file-level deltas

```
new:
  src/tui/index.tsx                      Ink entry, mounts <App>
  src/tui/app.tsx                        top-level layout
  src/tui/store.ts                       UiStore + reducer
  src/tui/store.test.ts                  reducer tests
  src/tui/import-isolation.test.ts       headless/runtime stay Ink-free
  src/tui/components/transcript.tsx
  src/tui/components/transcript-row.tsx
  src/tui/components/input-bar.tsx
  src/tui/components/status-bar.tsx
  src/tui/components/approval-modal.tsx
  src/tui/components/slash-palette.tsx
  src/tui/components/spinner.tsx         tiny inline replacement for ink-spinner
  src/tui/hooks/use-ui-store.ts
  src/tui/hooks/use-keybindings.ts
  src/tui/integration.test.tsx

modified:
  src/cli.ts                             dispatch TTY → TUI; add --classic
  src/runtime/runner.ts                  no change expected; verify onEvent + confirm hooks suffice
  src/policy/engine.ts                   accept a confirm function that returns the new ApprovalDecision shape (allow / deny / allow-turn) — backward compatible
  package.json                           add ink, react, ink-text-input
  README.md                              quick-start updates, --classic doc
  CONTRIBUTING.md                        TUI dev section
  docs/rfcs/2026-04-17-agent-runtime-architecture.md   pointer to this spec
```
