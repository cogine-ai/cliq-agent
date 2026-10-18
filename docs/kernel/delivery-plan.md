# Kernel delivery plan

## Goal and baseline

Complete all six work packages and the I1–I4 integration/release gates behind
the single Kernel Cut. The goal is usable, verifiable work, not a count of
modules, tests, or merged PRs. The RFC remains authoritative; this plan changes
ordering and records delivery scope, not safety, billing, or success semantics.

Baseline: `cefa89ae797d8763686b87811743c4422922743c` (PR #523), reviewed
2026-10-18. Its tree equals the qualified `990656c` follow-up. The installed
Linux execution/restart and cancellation foundations are real, but a final
model turn still stops at `candidate_required`. No work package or complete I1
is declared finished by the 32 passing checks.

| Owner | Implemented foundation | Remaining delivery obligation |
| --- | --- | --- |
| WP01 | SQLite/CAS, StateOwner, admission/replay, Journal/budgets, recovery | Result/verification/delivery transactions; business descriptor I/O; import/rollback; scale/integrity qualification |
| WP02 | Typed model/tool continuation, retry, compaction, approval/input reducers | Candidate/verification/repair/child continuation; installed full tool/provider integration; real capability and billing evidence |
| WP03 | Signed Linux worker/edit/broker, private generations, containment retirement | Verifier/publication and remaining execution recipes; dependencies/MCP/local service; supported macOS backend; remaining physical fault evidence |
| WP04 | Installed Supervisor, authenticated UDS, queue, cancellation/restart | Full application services, waits/children/reconciliation, service/reboot qualification and bounded read/retention operations |
| WP05 | Normative contracts and reusable legacy algorithms | Candidate → required verifier → immutable result → explicit delivery, plus bounded repair and child result integration |
| WP06 | Signed Linux installation, credential authority, restricted control path | Generated thin clients, ecosystem/Session surfaces, upgrade/migration, all-platform release qualification and one cutover |

## Delivery order

### A. Inspectable results and explicit delivery (I2 implementation)

Build one consumer-connected path on the existing StateStore, worker lifecycle,
Journal, Checkpoint and installed application services:

1. Convert a complete final model turn and its actual quiesced private workspace
   into the immutable final candidate, exact source projection and diff.
2. Execute frozen required/advisory verifiers in the strong read-only boundary,
   with exact command/environment authorization, whole-containment retirement,
   source-integrity checks and Journal-backed receipts.
3. Retry only explicitly permitted infrastructure attempts on the same source.
   Feed only required assertion failures to bounded same-Run repair; a repaired
   candidate invalidates all old gating receipts.
4. Commit the proof-carrying closure and RunResult through the sole successful
   terminal transaction, publishing one Session outcome. Demonstrate verified
   success, honest no-required-check completion, and exhausted assertion failure.
5. Expose result/diff inspection over the existing authenticated protocol and
   deterministic generated client; preserve reconnect/restart and replay.
6. Admit explicit delivery as another Run. Privately merge against current
   workspace drift, reverify changed source, obtain materialization permission,
   preserve displaced bytes, and journal descriptor-relative publication and
   recovery. Never mutate the original successful result.

This is one delivery objective, not a PR per decoder or test seam. Internal
commits can advance individual invariants, but isolated schemas or a read-only
result endpoint do not constitute the completed package. Do not substitute the
legacy Transaction/validator/shell path for trusted execution.

### B. Complete agent behavior and ecosystem (I3)

Connect the existing ordinary tool approval/input reducers and all necessary
read/search/edit/bash capabilities. Complete ordinary child Runs with bounded
allocation and exactly-once settlement, dependency setup, stateless MCP,
supported provider paths, signed managed local inference, and frozen skills.
Use the same Run/Journal/Checkpoint and no second runner, authority ledger or
client-owned recovery loop. Preserve the three independent trust/permission/
sandbox layers and all existing UNKNOWN/no-redispatch rules.

### C. Product transition and release qualification (I4)

Complete four thin clients and Session continuity; legitimate runtime upgrade
and pinned-version relaunch; descriptor-relative business persistence; complete
graph migration and marker-last rollback; bounded retention/GC; Windows
export-only; scale/performance and cross-platform installation. Execute the
RFC's 24-hour, 50-repository, at-least-10-crash-location campaign and every
package gate before deleting legacy composition and switching defaults.

## Parallel work and evidence boundaries

- Start A now; I1's entire exact fault matrix is not its implementation
  prerequisite. Keep those missing cuts explicit and add safe real validation
  alongside the relevant functionality. Never retry the previously blocked
  pause/tracer approaches or manufacture death/rollback evidence.
- Descriptor I/O, bounded large-state fixtures, generated protocol/client work,
  platform implementation and provider eligibility preparation can proceed in
  parallel. Full migration must consume the final authoritative artifact graph,
  not a temporary partial import or dual-write design.
- Reuse agreed real StateStore, installed entry/v1 UDS, private-generation and
  native lifecycle validation. Data regressions prove data invariants only;
  they neither mint native authority nor replace installed qualification.
- Preserve the original two-second stop, five-second observation freshness,
  cumulative three-observation retirement budget, fixed request/resource limits,
  scan bounds and free-runner policy. Passing tests cannot relax these gates.
- A controlled HTTPS responder qualifies mechanisms only. Real model
  capability and independently supported billing ceilings require a selected
  provider/model, explicit execution budget and authorized credentials. The
  owner has selected official direct DeepSeek, `deepseek-flash`, with a total
  CNY 200 experiment ceiling and explicitly authorized its dedicated key.
  Never put that key in the repository, logs or CI. A manual provider request
  does not qualify the installed broker or establish a trusted billing ceiling.
- Supported macOS qualification requires a controlled Apple Silicon
  Virtualization.framework host and signing/notarization authorization. Reboot,
  large-state and Windows-export qualification require their actual environments.
  These external requirements block the corresponding release claim, not all
  independent implementation work.

## Completion rule

Update this plan with the implemented consumer path, immutable tested source
and direct evidence as work lands. Keep implementation, component validation,
installed validation and release qualification distinct. No automatic apply,
paid model experiment, public release, final default switch or PR merge is
authorized by an implementation status label.

## Current implementation boundary (2026-10-18)

The new StateStore path derives the exact non-Git candidate from its original
sealed worker and supports an explicitly consented, empty-verifier
`verify → finalize → completed_unverified` result. Candidate/result/Session
provenance, restart/replay, cancellation and deadline invariants are being
validated through the existing real SQLite/CAS seam with retained offline
signed model/seal data. These are component regressions, not installed or
native qualification. Nonempty verifiers, dependencies and Git projection
remain explicitly rejected; no verified success or delivery is implemented.

Do not enable the installed candidate producer until its original physical
retirement/publication owner survives joined storage failures, monotonic stop
races and two-phase shutdown without rebuilding death observations or resetting
the cumulative three-observation limit. Result-limit failure must acquire its
own closed, reproducible evidence rather than borrow context-exhaustion truth.
All related real Linux cases belong to the same delivery campaign.

The installed final-turn handoff must retain one original completion owner. If
a validated monotonic Stop wins, its same prepared seal may commit only a
nonproductive Checkpoint at the original snapshot's Checkpoint id, with the
original context/items/Journal/frontier and already-accounted workspace. It
must not append a candidate, start verification or publish a result. Persist
deadline Stop before taking that branch; preserve the original freshness
budget, and then use the existing worker-free terminal stop. This narrowly
scoped Stop-only revalidation must be clarified in the RFC alongside its
implementation. Ordinary SIGTERM without Stop is not this branch: finish the
eligible original candidate or leave its uncommitted cut for successor recovery.

Required verification follows the existing signed `guest_toolchain` contract;
do not add a runtime-bundle verifier or borrow host shell, Node, PATH or modules.
The earliest engineering risk is making the complete signed image/toolchain
usable by the non-root Linux recipe without new host privileges. First prove
that path with a dependency-free real `node:test` project, then connect exact
authorization, process outcome/output, whole-containment death, source rehash,
receipts, bounded retry/repair and result recovery as one delivery capability.
An edit adapter's `ok/error` result is not a verifier exit/receipt contract.

The owner approved immutable first descriptors with independently validated
uses: an ordinary file may contain exactly the bytes of a canonical JSON
artifact. Content hashes are not type-domain-separated. The catalog now retains
the first descriptor verbatim, rejects conflicting byte lengths, and permits
multiple uses only through their own complete hash/length and closed-schema
checks. The real regression is green through candidate, result and reopen;
no labels grant authority and no new ledger or schema migration is introduced.
The Linux negative-refusal campaign now compares all original descriptors,
not a label-filtered subset, and permits only the independently decoded exact
successor-owner closure to be newly registered. Its physical assertions remain
unchanged; the modified campaign still needs real Linux execution.

Session compaction is a later consumer obligation: when it is implemented,
historical terminal-result verification must rewalk the immutable terminal item
and its compaction provenance, not require today's Session projection to retain
the initial one-item raw segment forever.

Local verification of this development batch: `npm run build` passed; the
serial five-file candidate/result campaign passed all 36 tests with no skips,
cancellations or todos. The frozen implementation's full `npm test` run passed
all 2,146 tests in 649,544 ms, with no failures, skips, cancellations or todos.
Design-contract regressions passed 9/9; the full design drift check, native
source guard, strict campaign TypeScript check and existing campaign/workflow
guards also passed. No new Linux qualification or completed delivery package
is claimed; the work branch is being submitted to the existing free workflow,
not opened as a separate foundation-only PR.

One authorized, memory-only manual request to the official DeepSeek endpoint
confirmed that `deepseek-flash` is listed and returns a normal response with
default thinking enabled. There were no retries. Provider-reported usage was
35 prompt and 13 completion tokens (11 reasoning); the visible balance delta
was zero at account precision, which is not proof of zero charge. This is not
installed-Run, native, tool-roundtrip or billing qualification. The installed
path still needs faithful thinking continuation, qualified model configuration,
CNY budget accounting, endpoint eligibility and complete real lifecycle proof.
