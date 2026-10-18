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

The StateStore path derives the exact non-Git candidate from its original
sealed worker and supports an explicitly consented, empty-verifier
`verify → finalize → completed_unverified` result. The installed scheduler now
drives that path without another model request or a productive worker for
verification/finalization. This consumer integration is implemented, not yet
qualified on Linux. The development branch now connects the exact fixed Node
verifier subset to the same lifecycle and result transactions; dependencies,
Git projection and other verifier recipes remain explicitly rejected. Verified
success still lacks actual Linux qualification, and explicit delivery is not
implemented.

The original final-turn owner is established before physical quiescence and
retains its one checkpoint/source/candidate publication plan through positively
joined CAS failures and rolled-back SQL commits. It shares the existing
received-completion lifecycle with tools, including two-phase Store shutdown;
it does not introduce another recovery owner or redispatch permission. Component
regressions cover same-owner retry, monotonic cancellation/deadline upgrades,
concurrent joining, exact replay and rejected proof substitution. A final
source exceeding its frozen changed-path or changed-byte limit now records a
closed `result_source_limit_exceeded` StopIntent. Its evidence is independently
rederived from the original completed final model, prompt projection, context,
Checkpoint and complete source measurement; it is not context exhaustion.
The same completion owner retains the already-accounted workspace and performs
only the nonproductive Stop checkpoint, then the existing worker-free failed
terminal transaction. It publishes neither a candidate nor a successful result.

The native campaign now exercises real edited workspaces, final workers,
D0/snapshot/D1 and candidate-publication failure followed by resume, cancel or
Store close/reopen, plus changed-path and changed-byte resource failures. It
also requires real storage delay to exhaust three D1
observations, including a pending D1 publication retried after ENOSPC without
resetting that budget. Offline final-model data in this campaign is explicitly
not provider qualification. All new native assertions still need Linux execution.
Installed campaigns independently check complete final source bytes and exact
diffs; existing lease/capacity checks move to a genuinely settled UNKNOWN that
still owns its worker, rather than depend on a completed final turn holding the
worker forever. Neither UNKNOWN cancellation nor terminal cancellation refusal
qualifies the unobserved received-before-candidate cancellation cut.

The installed normal journey additionally requires two independent final
source-limit Runs, exact original final-turn/Checkpoint evidence, actual private
edit and worker retirement, unique Session outcomes, and unchanged replay after
Supervisor restart. These new physical cases are not qualified until their
Linux campaigns complete.

The installed final-turn handoff must retain one original completion owner. If
a validated monotonic Stop wins, its same prepared seal may commit only a
nonproductive Checkpoint at the original snapshot's Checkpoint id, with the
original context/items/Journal/frontier and already-accounted workspace. It
must not append a candidate, start verification or publish a result. Persist
deadline Stop before taking that branch; preserve the original freshness
budget, and then use the existing worker-free terminal stop. This narrowly
scoped Stop-only revalidation is specified in the RFC alongside its
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
unchanged; that modified campaign passed on the previous exact source below.

Session compaction is a later consumer obligation: when it is implemented,
historical terminal-result verification must rewalk the immutable terminal item
and its compaction provenance, not require today's Session projection to retain
the initial one-item raw segment forever.

Local verification of this development batch: `npm run build` passed; the
candidate/result/publication component campaign passed all 42 tests and the
existing tool/freshness/owner scheduling regressions passed all 27 tests. The
first frozen production implementation's full `npm test` run passed all 2,152
tests. After final-source resource failure and credential workload partitioning,
a fresh `npm run build` and full `npm test` passed all 2,163 tests in 753,482 ms,
with no failures, skips, cancellations or todos. All three modified Linux
campaign entrypoints pass strict TypeScript including library checks
(only the existing `postject` package's missing declaration is supplied in
memory). Design-contract regressions, full drift check, native source guard
and existing workflow/client guards pass.

Previous pushed source `8eaae4d670a79123d90c73b37dde907b08fc0872` has
[CI run 39089005603](https://github.com/cogine-ai/cliq-agent/actions/runs/39089005603):
15 jobs succeeded and credential diagnostics hit the unchanged 20-minute job
limit. It is not all green. The credential campaign continued through
`revoked_endpoint_admission` near timeout; no completed journey, cleanup or
after-baseline report exists. Those missing reports cannot be inferred from
other green jobs. An exact-SHA evidence manifest binds the 65 retained original
allowlisted JSON reports to their run/attempt/artifact digests; raw logs,
credential material and mixed state bundles were not retained. This old run
does not qualify the newly integrated producer or revised campaigns. The work
branch remains on the existing free workflow, with no foundation-only PR.

To keep the unchanged 20-minute free-runner limit, the independent negative
model-credential input cases now run in their own real installed job. They keep
every original enrollment/rotation refusal, platform readback, service identity,
cleanup, join and bounded secret-scan assertion. The authority-lifecycle job
retains the original remaining cases; both jobs must pass. This is test workload
partitioning, not a production performance fix or a weaker qualification gate.

One authorized, memory-only manual request to the official DeepSeek endpoint
confirmed that `deepseek-flash` is listed and returns a normal response with
default thinking enabled. There were no retries. Provider-reported usage was
35 prompt and 13 completion tokens (11 reasoning); the visible balance delta
was zero at account precision, which is not proof of zero charge. This is not
installed-Run, native, tool-roundtrip or billing qualification. The installed
path still needs faithful thinking continuation, qualified model configuration,
CNY budget accounting, endpoint eligibility and complete real lifecycle proof.

### Fixed Node verifier request and permission projection (in development)

Previous pushed checkpoint `e9dfa3342a754145c4bdd712519e90d6fc0f6761` has
[CI run 39095867253](https://github.com/cogine-ai/cliq-agent/actions/runs/39095867253):
13 of 17 jobs passed, four failed. The exact full, request-resource,
admission-stop and received-tool-stop reports remain failures, not inferred
successes. All 15 allowlisted report categories are retained with the immutable
source/run/job/artifact identity; the final capture digest is
`9b8cc4c08ab22a3f5712678aed5d7417094f6f4bf1fa50016549d31945c90bc7`.
Raw logs, mixed state bundles and credential material were not retained.
Two scenario-specific health/clean-restart assertions have been corrected
locally; the other failures receive bounded fixed diagnostics without changing
their original time limits or required outcomes. These corrections and the
new verifier integration are not qualified by that older run.

Latest pushed checkpoint `2bff50a9b0abac4fc4f7dd15b0c8c3e0c613e5e9` has
[CI run 39097677773](https://github.com/cogine-ai/cliq-agent/actions/runs/39097677773):
15 of 17 jobs passed, two failed. The original admission-stop and
request-resource cases are now green. The full journey fails at `secret_corpus`:
its output scanner reports no match or exceeded limit, but the retained corpus
operation did not produce its complete result. No cause or clean corpus is
inferred. The received-tool successor reaches queued/finalize with all nine
Journal rows settled, but does not complete within the unchanged 30 seconds;
its later cleanup also exceeds the unchanged stop bound. Neither is treated as
test flakiness. Fixed stage/count diagnostics are being added, without raw
content or relaxed checks. Final evidence binds 72 allowlisted JSON reports
across 15 categories to this exact run/attempt/source; capture digest
`d7774426d88e774dd43a7a55eee864d3d57e308993b0ce95c31ed8fa57ce4475`.
No raw logs, archives, state/WAL or credentials are retained.

The first nonempty verifier path selects only the signed guest Node identity;
it does not borrow host Node, PATH, modules or the ordinary edit adapter. The
identity-read authorization is consumed once by the original Run admission,
in the same transaction as its Run and initial Checkpoint. Required and
advisory entries retain their exact command/environment/spec bytes. An
advisory-only Run still needs the original authenticated explicit unverified
consent. Replays and reopen validate those original sources without recreating
missing CAS objects or resolving an old public toolchain id against today.

`VerifierRequestV1` and `VerifierTargetV1` are closed internal projections of
that frozen graph. Their own digest omits only its own digest member. The
target binds candidate, result source/digest, plan/spec, ordered entry, exact
command/environment and frozen attempt ceiling. The stable operation id is
`H('cliq-verifier-operation-v1',runId,candidateItemId,verifierPlanRef,String(index))`.
Attempts remain separate Journal facts under that operation, not new request
identities. The policy channel is the RFC's `named-action` with the literal
`verifier/<verifierId>` key; its full candidate/plan identity is also retained.
The same snapshot validation and fixed rule precedence used by ordinary tools
recompute the exact evidence. Only a direct allow may produce the separate
`verifier_launch` operation grant; neither Workspace Trust nor the identity-read
grant grants execution. Templates and interactive verifier approval remain
explicitly unsupported until their own consumers exist.

The launch reader consumes the owning preparation, current verify frontier,
original WorkerLaunch/generation, retained signed policy/toolchain and exact
request/target/grant before minting its process-local brand. A clone, an ordinary
worker/edit closure, or caller-supplied artifact refs cannot mint it. The
implemented branch is agent/finalize without dependency acquisition and uses
only the fixed read-only Node test recipe with no requested environment values
or writable roots. These local StateStore/policy/retained-data regressions are
not physical execution, containment-death or installed Linux qualification.
The development branch connects the supported nonempty-verifier preflight to
execution, receipt, recovery and result consumers, retaining every identity,
permission and resource check. A dedicated real installed campaign must pass
required success, actual repair, advisory-only unverified completion, and
timeout/retry exhaustion, plus exact budgets, original worker/child retirement,
result/diff inspection, reconnect and Supervisor restart. These are not yet
Linux-qualified. The new authenticated result/diff queries expose only the
successful transaction's immutable descriptors; stopped or live Runs return
the exact closed `RESULT_UNAVAILABLE` cut, never a failed candidate or delivery
permission. There is no partial progress PR; explicit delivery remains a
required connected part of package A.

The first fixed Node recipe also rejects unsupported resource declarations
before admission. `maxProcesses` must be at least the shared fixed minimum 32;
ordinary worker support at 8 processes does not qualify Node's test runner.
`maxSingleFileBytes` must cover the complete signed guest image byte count and
remain no greater than the fixed 256 MiB recipe limit. The raw image is a
conservative bound for every extracted executable/library that bubblewrap
copies under this same file limit; no unsigned builder inventory or special
copying exemption can authorize a smaller envelope. Caller values are never
clamped or enlarged. Defaults remain 256 processes and 256 MiB per file. Exact
boundaries and refusal/unused-grant behavior have StateStore regressions;
physical execution at the declared boundary still requires the real Linux
campaign and is not inferred from these inert signed-data fixtures.
