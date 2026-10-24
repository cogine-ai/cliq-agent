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

## Current implementation boundary (2026-10-19)

The StateStore path derives the exact non-Git candidate from its original
sealed worker and supports an explicitly consented, empty-verifier
`verify → finalize → completed_unverified` result. The installed scheduler now
drives that path without another model request or a productive worker for
verification/finalization. This consumer integration is implemented, not yet
qualified on Linux. The development branch now connects the exact fixed Node
verifier subset to the same lifecycle and result transactions; dependencies,
Git projection and other verifier recipes remain explicitly rejected. Verified
success still lacks complete Linux qualification. Explicit delivery now has
consumer-connected development code, but its full installed campaign and
bounded publication shutdown/recovery remain incomplete as recorded below.
The development production composition now connects the fixed supported Linux
Delivery subset, including no-op projection and claimed Stop drain; the real
campaign has no feature override. Its separate standard free Linux job retains
the original twenty-minute budget and all prior jobs. This enables genuine
installation testing, not an installed/release qualification claim. Git,
nonempty frozen ignore rules, includes and dependency contracts remain refused
where their complete implementation is absent. The newly approved late-return
and registered-namespace branches still require their actual installed cuts.

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

Earlier pushed checkpoint `2bff50a9b0abac4fc4f7dd15b0c8c3e0c613e5e9` has
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

Checkpoint `31f671e8a03f9cfe4e37bd87d74b90cfef888fd6` passed build and all
2,205 local tests, with no failures, skips, cancellations or todos. Its
[Linux/matrix run 39100392330](https://github.com/cogine-ai/cliq-agent/actions/runs/39100392330)
finished with five passing jobs and thirteen failures. All four TypeScript
matrix jobs and namespace/cgroup qualification passed; native and installed
coverage stopped at compilation, before the verifier cases. The final retained
report capture digest is
`4be060a3652cfce33fdc5f92a5a947b2f4d3bcc4bcc999abcef78a85f1af1433`.

The fixed receive helper now accepts the caller's actual FD capacity and
rejects/retires excess rights without lowering the forty-FD protocol maximum.
That fix, checkpoint `0c9bbe2df6b4fee37343e7f6e582b2176c433b0b`, again passed
build and all 2,205 local tests. Its
[run 39101759920](https://github.com/cogine-ai/cliq-agent/actions/runs/39101759920)
passed the real socketpair capacity/truncation/FD-retirement regression and
the original seccomp assertions. Image compilation then exposed a separate
extractor-private `revoke` name collision with the system declaration. The
local rename is not yet Linux-qualified; no installed verifier case is inferred
from the passing lower-level tests.

Checkpoint `67c7327a0df300804f004f3c6f1893a29ed05ae0` passed build and all
2,238 local tests, plus twenty design/protocol guard tests, without failures,
skips or cancellations. Its
[run 39102873007](https://github.com/cogine-ai/cliq-agent/actions/runs/39102873007)
finished with fourteen passing jobs and four failures; all four TypeScript
matrix jobs passed. Native image compilation passed. The native lifecycle
campaign explicitly passed twenty-four scenarios, then failed the original
`close-during-factory-open` assertion: shutdown supplied a default AbortError
instead of `LEASE_FENCED`. The remaining seven scenarios did not execute.
The separate guest campaign built its image, then rejected the extractor
fixture's incomplete RuntimeBundle before extraction. The installed verifier
campaign stopped earlier, constructing its guest package: root extraction
preserved the checksum-pinned archive's publisher uid, which the existing
protected-source check correctly refused. Neither verifier campaign supplies
execution or artifact-download qualification.

The received-tool campaign's original service and all retained writers now
join successfully, with the original graceful-release/successor-owner lineage
intact. Its successor still fails the unchanged thirty-second completion
deadline: the last cut is queued/verify, nine Journal rows are completed, and
no finalize cut was observed. This is not evidence of a result-finalizer or
stop-timeout failure. The independent full journey reached its retained-corpus
scan, but CAS inventory entry 1,025 triggered the unchanged 1,024-entry guard;
no clean corpus is inferred. The final closed-report capture digest is
`64aa935dd09b66d219d1301951c54858c8aee89fcd80b84a3596054a50d0b71b`.
Only allowlisted JSON reports are retained, not raw logs, archives, StateRoot
contents, WAL or credentials. Local fixes and further diagnostics still need
their own exact-source Linux validation.

The follow-up retains every original acceptance bound and full corpus scan.
Ordinary `run.get` polling now reuses its authenticated connection rather than
creating three fresh identity objects per poll. Planned rotation includes the
hello in the unchanged 1,024-frame client budget, joins the old connection,
and shares the original read deadline; socket failures never trigger reconnect
or replay. Explicit fresh-client, admission-replay and actual-restart checks
remain separate. Failed campaigns also retain the existing closed shutdown
phase/count observation when their original process stops successfully. That
observation describes the real stop boundary, not the earlier timeout cut.
Neither change yet proves the CAS-overbreadth or successor-completion blocker
resolved on Linux. Repeated full-recovery reads are measured separately;
the sticky original-execution retirement gate and complete hashes remain.

Checkpoint `8c06e2de6e3a3a20822c694609978e72fa5092d1` passed build and all
2,238 local tests, plus thirty-two design/client/builder guards, with no
failures, skips, cancellations or todos. Its
[run 39105569017](https://github.com/cogine-ai/cliq-agent/actions/runs/39105569017)
finished with thirteen passing jobs and five failures; all four TypeScript
matrix jobs passed. All thirty-two actual native lifecycle scenarios passed.
The separate guest extraction failed at `guest_elf_strings`; this does not
erase the lifecycle evidence or qualify guest execution. The installed
verifier built its signed package, then failed initial installation before any
business verifier case. The original installer streams 1 MiB batches into a
CAS publisher whose unchanged maximum is 64 KiB; the local follow-up splits
only that publication stream, retaining the existing complete hash/copy I/O
window and every source identity/EOF/join check. Its new real installer/CAS
regression still requires Linux execution.

The normal installed journey passed its business assertions, including the
two final-source-limit Runs and their actual restart, then failed the complete
retained-corpus scan at the unchanged cumulative 4,096-stream ceiling. No
secret match was observed, but no clean corpus is inferred; the fallback
report does not identify whether SQL values or CAS names/files exhausted the
budget, nor prove that CAS inventory passed. The independent source-limit
pair is being moved to its own full installed StateRoot/campaign, preserving
its complete scan, original limits and every assertion. The shared
normal/UNKNOWN/lease/capacity/recovery/domain-death history stays together.
Both complete groups must pass; neither a budget reset nor an omitted value
or CAS object is permitted.

The received-tool successor still reached queued/verify without completing
within thirty seconds. Its original processes and retained writers joined
successfully. The closed stop diagnostic reported `drive_retirement`, but
that label previously survived later model work and final-completion joins;
it is not a stack sample or proof of the earlier timeout's exact await. The
local follow-up resets that existing label after retirement returns, without
removing any recovery/retirement validation. The separate credential-finalizer
campaign passed its genuine two-second original service stop, then failed a
successor-history read. The follow-up reuses the existing readiness observer
that treats only real SQLITE_BUSY as pending inside the unchanged deadline;
strict complete history/link verification remains mandatory afterward.

The final exact-source capture binds all seventeen report categories with no
pending/rejected category; its digest is
`a740b3ac25a108ba2ccd8ebfa2d5c7c69bed4affb93f97f8d99fb64a329ff9a0`.
Twelve report categories qualify their own bounded mechanisms. The other
five, including absent guest success reports, remain unqualified. Raw logs,
archives, StateRoot/WAL and credentials were not retained.

The guest ELF blocker is a real recipe-contract decision, not permission to
raise a guard. Independent memory-only inspection of the checksum-pinned
Node archive reproduced the exact CI Node digest
`7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c`:
its unique `DT_STRSZ` is 2,082,484 bytes, exceeding the current 1 MiB whole
string-table acceptance guard. Dependency names are already read individually
in at most 256-byte slices; windowed reading alone cannot preserve that
acceptance rule while admitting this same binary. Changing the extent rule
requires explicit owner approval, retained signed-file/unique-LOAD/bounds and
resource checks, malformed-ELF regressions and actual Linux execution. The
guard was unchanged at that checkpoint pending that decision; no compatibility
binary was silently substituted or modified. The owner has since explicitly
approved the bounded extent-contract revision. The implementation now checks
the complete table against its unique LOAD and signed-file extent, rejects
partial virtual/file aliases, and reserves every actual dependency-name read
against the fixed cumulative 262,144-byte budget before reading. The existing
256-byte name window and all file/count/hash/seal/close checks remain. Eighteen
malformed cases are wired to the original real native extraction campaign;
pure fixture tests are not their Linux execution evidence. This revision and
the normal signed extraction still require a new exact-source Linux run.

The connected client follow-up shares one canonical request/result decoder
between the original server and a genuine authenticated installed client.
The fourteen enabled methods are only those with existing server consumers;
recognizing another RFC method name grants neither an implementation nor
authority. The credential API is a thin wrapper over the same held-selection,
native peer, image, manager, socket and hello checks. Connections do not
automatically reconnect, replay a mutation, manufacture request ids, or start
the Supervisor from an observation query. The qualification-only child driver
and its scanned parent are being connected to actual Session/Run submission,
result/diff downloads, explicit reconnect and real Supervisor restart; their
local process tests do not qualify that Linux installation path.

Read pagination now budgets the complete response envelope, not just its
arrays, against the unchanged 1 MiB, 10,000-member and 32-container-depth
limits. An excluded entry never advances its cursor or permits a later stream
to jump over it; a single entry that cannot fit an otherwise empty response
is refused. The immutable RunSpec is validated before the final same-owner,
same-spec SQL snapshot determines all watermarks. Real UDS component tests
cover 1,000-entry Journal, Checkpoint and Event histories, continuous short
pages and the exact complete-frame byte boundary. This is not permission to
claim scale, installed-client or recovery qualification before those separate
campaigns pass.

The next consumer batch adds authenticated `artifact.get`: only registered
objects in the genuine principal's exact StateRoot are readable, and a complete
CAS hash/identity/resource join precedes every short response. Current pages
are at most 64 KiB within the unchanged 1 MiB frame. Each page still rehashes
the complete object, so a complete download costs roughly O(S²/64KiB) I/O;
large-artifact performance remains unqualified. Component tests cover exact
EOF, corruption outside the selected page, foreign roots, request snapshots,
and genuine close failure retaining StateOwner. The signed installed journey
requires fresh byte downloads across reconnect and actual restart; it has not
run successfully yet.

The deterministic text merger and non-Git B/S/A/M planner are data consumers,
not delivery authority. They preserve exact bytes, complete manifest identity,
structured conflicts, the A-to-M diff, strict M===S reuse and the distinct
normalized-A no-op test. Source validation is shared with the existing agent
candidate path. Full delivery admission, resource ownership, materialization,
permission, publication and recovery are still required. The owner approved
directory/type conversion and the admission timing revision: fully validate
and persist recoverable A/W_A before the atomic Run/initial-Checkpoint commit;
only the existing post-admission preparing lifecycle creates physical resources.
Touched multi-hardlink files must be refused before any publication write.
Those decisions authorize neither an early workspace-write probe nor a second
lifecycle, and do not establish physical publication qualification.

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

## Exact-source validation and current publication blocker

The complete A archive at tree
`0e941df3c6bc8deed8d853af0a564b6039daf5dc`, based on `3ec01eb`, now passes
its own `npm ci`, build, portable native contracts, shell syntax, strict
typechecking with actual dependency types, and unchanged full `npm test`:
2,543 tests, 2,542 passes, no failures/cancellations/todos and one original
conditional cross-device skip (888,884.786125 ms). Its relevant script union
passes 189 tests with four original Linux-only skips; all 26 tests in the
previously failing neighboring files pass. All 929 source blobs/modes in the
archive and main checkout match before/after validation, and every process
and pipe joined. The main helper remains unchanged. Final local record
SHA-256: `409d0ac519d16e495f25fff499a024823a6e88d471b61f75952e0f23b90b048f`.
This qualifies neither the skipped filesystem condition nor installed A.

Latest pushed source `3ec01eb759504398e93693ba2f53b46128b8ea8b`, tree
`6e12d3ebd717bbc7e354d4f3fdcb6bc3a69635cc`, completed
[run 39210509388](https://github.com/cogine-ai/cliq-agent/actions/runs/39210509388).
It contains only the seventeen-file diagnostic/fixture correction, not A.
Its own independent exact-source build, portable and strict checks and original
full test run passed 2,276/2,276 with no failures, skips, cancellations or todos
(780,264.649667 ms); the committed tree equals that tested tree. Final local
record SHA-256:
`f160f7a5d6d865035dc140f195cf17c9e02d56054a13d29bf96e33e94cb6ec77`.

That Linux/macOS workflow has fifteen successes and three failures. All four
TypeScript matrix jobs pass, including the original unchanged-deadline
portable scheduling regression. The ordinary installed Run/reconnect/restart
campaign and original finalizer, storage-refusal, admission, preparation and
request-resource campaigns also pass. The remaining failures are not waived:

- Installed verifier enrollment times out at 60,016 ms. The actual native
  `create_compare` settled in 183 ms; the last fixed credential phase is
  `finalize`, not a still-unentered platform call. Auth measured 43 installed
  revalidations started, 42 settled, 33,456,176,754 actual bytes read and
  27,631 ms inclusive span time. These counters are not CPU time and do not
  account for the whole deadline; process samples also show startup waiting.
- The native guest's last pre-READY stage is `node_check`, followed by the
  unchanged absolute five-second `ready_wait` expiry. It is not qualified;
  the missing guest success report is preserved as missing, not reconstructed.
- Received-tool SIGTERM exits successfully under the original stop contract,
  but its successor is still queued at `verify` after 30,019 ms. All nine
  original Journal rows are complete. The final progress label is
  `result_basis`, which can also cover the subsequent verification publication;
  it is not proof that this function consumed the entire wait. The 224 public
  queries are not 224 reads of the 64 MiB candidate.

Final append-only `capture-004.json` retains eighteen closed categories,
zero pending/rejected categories and one metadata-only artifact; the native
guest category explicitly lacks its success report. SHA-256:
`1ef9085ca7c62c87b480e99029e7af1a94f3bde8d422530afeed13c1b8538e5d`.
No raw logs, ZIPs, StateRoot, WAL or credentials are retained.

The next complete candidate includes two measured throughput changes, without
reducing any check or revalidation count: only the discard-only image verifier
reuses its private one-MiB scratch buffer; the portable SHA-256 updater feeds
complete blocks directly, retaining the identical transform/finalization and
partial-tail semantics. Retaining consumers still receive independent bytes.
The original and optimized updater pass 266 fixed-vector/chunk combinations
and 1,300 independent Node-crypto differential cases; the candidate also passes
sanitizer checks. Local
M4/Node-24.21.0 measurements show about 1.58x memory-hash and 1.61x real-file
throughput; they are not Linux five-second/sixty-second qualification. New
multi-MiB bundle/CAS tail-corruption regressions and a new full-tree validation
must run with this candidate; the earlier A result is not borrowed for it.
Late audit, registered-namespace recovery and all retained physical fault cuts
remain unqualified. No PR is opened.

### Earlier immutable attempts

The complete-development archive at tree
`29e44364973c08249c084f1a10f2e9c2ed22c026` did not pass its full local test
run: 2,533 tests, 2,527 passes, five failures and one explicit cross-device
skip. Four assertions failed; the fifth failure records the controlled
termination of an owned test whose obsolete `readFile` barrier never observed
the real chunked `read`. All processes and pipes subsequently joined. This
failed attempt is retained, not reused as a validation precondition. The
replacement race now pauses the actual read and passes its three focused
tests; the workflow contract now follows the exact verifier consumer into
its shared implementation and passes all five tests without removing any
original limit assertion. The remaining failures require independent current
source verification before a new complete-tree run. Neither those local
repairs nor the late-audit/namespace components qualify real Linux recovery.

Earlier pushed source `9fbd0949c8d463acb38a2ab0b0161cf67739ab87`, tree
`55c462828bca64d49993c87ac375617cda055e4a`, completed
[run 39199348670](https://github.com/cogine-ai/cliq-agent/actions/runs/39199348670).
It contains only thirteen fixed pre-READY diagnostic/GCC fixture files, not
the development delivery implementation. It retains the same single absolute
five-second READY deadline across bounded fixed progress packets and EINTR;
stage/poll/elapsed data never authorize READY, release, identity or retirement.
The private packet revision changes together within the signed candidate; the
public v1 UDS contract does not change. Failure JSON adds only six fixed
enum/integer fields, not logs, filenames or process output.

Its independent short-path archive passed its own real `npm ci`,
`npm run build`, portable native contracts, the original five strict script
roots with actual dependency types and `skipLibCheck=false`, fifteen diagnostic
regressions and unchanged full `npm test`: 2,274/2,274, zero failures, skips,
cancellations or todos (791,374.958916 ms). All 840 tracked blobs/modes and
thirteen main selected blobs match the tested tree, independently rechecked by
the root before staging. The actual committed tree equals that exact tested
tree. Every process/pipe joined and the main native helper remained unchanged.
Final local record SHA-256:
`c5fe5a79caa645128bd2f51598bb68d4c3f99046328c76428b5b5fde18592c8f`.
The new separate bounded evidence collector passed 185 contract checks, two
original-JSON-byte retention cases and nineteen malicious ZIP/JSON classes;
historical collector/captures are unchanged. This is not Linux GCC, real READY,
installation, publication or complete A qualification. No PR is opened.

The final workflow result is fourteen successes and four failures. Both
Ubuntu TypeScript jobs now pass, so the original GCC empty-digest fixture
failure is resolved on those actual runners. macOS/Node 22.13 instead exposes
an unrelated new portable-test scheduling assumption: the forked test child
did not deliver both delayed bytes within the parent's 150 ms window
(`verifier-setup.test.c:92`). A local correction synchronously queues those
bytes and additionally proves an expired original deadline neither polls nor
consumes queued data. The original 150 ms/2 s test assertions, EINTR, fixed
5 s cancellation and production deadline remain unchanged. That correction
was pending at that capture; its completed exact-source validation and push
are recorded under `3ec01eb` above.

The real native guest has progressed past READY and execution/output/source
checks to `guest-verifier-native.ts:173`. That fixture incorrectly equates
the original D0 death ref in the receipt with the later actual D1 ref rooted
in WorkerLaunch SQL. The RFC and production retained reader require the full
D0 → snapshot → D1 → commit graph, not equality of distinct observations.
The fixture correction validates the actual complete CAS graph,
original worker/containment/inspector identity, causal order and unchanged
5 s freshness; it does not remove production refresh or declare the whole
guest campaign qualified from the earlier passed assertions.

The ordinary signed installed Run journey passes this run, including its
existing reconnect/restart checks; its previous failure remains historical
evidence, not erased. Received-tool SIGTERM successor validation instead
fails its original bounded wait at queued `verify`, with all nine original
Journal entries complete and no result; it is not qualified. Installed
required/advisory verification still stops during enrollment at 60,013 ms,
last fixed phase `platform_store` at 58,156 ms. That marker precedes another
five complete installed revalidations and does not prove D-Bus create_compare
has begun. Repeated full validation is a measured byte-volume hypothesis,
not yet a per-function causal measurement or permission to cache authority.
The latest auth sample is 27,640,001,753 logical bytes and zero `readBytes`.

Final append-only `capture-003.json` retains eighteen closed categories,
zero pending/rejected categories and one metadata-only artifact; SHA-256
`e26413044036efeb48fdf785187896ac08db5bc7f0186a81ac5941c07a082571`.
Raw CI logs/ZIPs/StateRoot/WAL/credentials remain unretained. Neither this
run nor its earlier successful checks qualify complete I1, I2 or A.

Previous pushed source `c935f18ec0a5e54019283e2d30118479a9bc9c1c`, tree
`3b6a302cd565b5eff3e438a819db7a94cea0ee4e`, completed
[run 39158658035](https://github.com/cogine-ai/cliq-agent/actions/runs/39158658035).
It contains only the five-file canonical guest-Node correction, not the
development delivery implementation. Its independent short-path archive
passes real `npm ci`, `npm run build`, portable native contracts, the original
five strict script roots with actual dependency types and `skipLibCheck=false`,
and the unchanged full `npm test`: 2,274/2,274, zero failures, skips,
cancellations or todos (811,155.398458 ms). All 838 tracked blobs and modes
match the candidate before/after validation; the root reviewer independently
rechecked the complete archive and exact selected source blobs. Final local
record SHA-256 is
`b2903684169e9b78826d7bd171774767f82621b52e7b3f1dfc2bc3f5f16bce78`.
Original namespace, image-integrity, syscall and time bounds are unchanged.
The final result is thirteen jobs passing and five failing. Both Ubuntu
TypeScript jobs fail before build/test at the portable C fixture: GCC rejects
the one-byte empty string passed to a `digest[65]` parameter with
`stringop-overread` under the unchanged `-Werror`. The local correction uses a
real 65-byte buffer containing the same invalid empty value; production guards
and the empty-value refusal remain unchanged. At that capture it had only
portable local coverage; the later exact candidate above includes it.

Actual extraction, the 2,082,484-byte ELF string table and all eighteen malformed
ELF refusals pass. The real guest now fails before READY with the fixed
`CLIQ_SPAWN_READY_WAIT` status (1011). This status alone cannot distinguish a
five-second timeout from poll HUP/error, and supplies no Node-body or boundary
evidence. The old ENOENT is not proven to have recurred. Fixed readiness
phase/poll/elapsed diagnostics are required before choosing another repair;
the five-second limit and resource/retirement gates must not be loosened.

Installed verifier enrollment again expires at 60,025 ms: first Supervisor
stage at 8,687 ms, secret input at 53,443 ms, second Supervisor at 53,447 ms,
platform store at 57,900 ms, and no finalize marker. The logical read sample is
27,874,947,402 bytes with zero physical `readBytes`; this is not per-function
hash timing. The ordinary installed Run restart also remains failing. The
received-tool SIGTERM campaign passes this time; that does not erase its
previous failure or establish a shared cause for the enrollment/guest failures.

Final append-only `capture-003.json` retains all eighteen closed categories,
zero pending/rejected categories and one metadata-only artifact; SHA-256
`389ee575913f0071e3b5007368a94e18b46fc43347a66e2e3d9b572d15db61ac`.
No raw logs, ZIPs, StateRoot, WAL or credentials are retained. Real Linux
self-spawn, confinement and installation qualification is still incomplete;
this does not qualify the local delivery WIP and no PR is opened.

Previous pushed source `414048c5ac3b3fd7ac40b3cfcd980e64dbce1d21`, tree
`92c420d6a71a165afdec3ef77656c7dd824f98f6`, completed
[run 39153652710](https://github.com/cogine-ai/cliq-agent/actions/runs/39153652710).
It contains only the five-file startup-poll/reporter correction below, not
the development delivery implementation. Its supported short-path archive
passes its own real `npm ci`, build, strict checking and unchanged full
`npm test`: 2,274/2,274, zero failures/skips/cancellations/todos
(950,713.497209 ms). All 836 tracked blobs and modes and all five selected
main-worktree blobs match the immutable validated tree. Final local record
SHA-256: `56f0695299bbd0c843d75f3b1ee0a07270afc742c0d6ef5c7dc49221feeb0884`.
This is not Linux or complete delivery qualification; no PR is opened.

Fourteen jobs pass and four fail. The closed default-`spec` diagnostic now
reports `spawn`, `ENOENT` and `deleted_canonical_node` (1,789 stdout bytes,
zero stderr bytes, absent test-body marker). This identifies the reported
self-spawn target; it is not a successful Node or containment qualification.
The actual extractor and all eighteen malformed ELF refusals still pass.
The five-file candidate under independent local validation gives only the
canonical Node a namespace-private named copy of the original sealed image,
checks its full authenticated bytes and exact held/named metadata, then binds
that same held inode before the unchanged readonly/noexec/executable-mount,
capability and syscall restrictions. Its real-file regressions are not a
substitute for the pending real Linux self-spawn and boundary campaign.

Enrollment still misses its unchanged 60-second limit (60,023 ms): the first
Supervisor stage begins at 8,700 ms, secret input at 52,985 ms, the second
Supervisor stage at 52,989 ms and platform-store work at 57,593 ms. No finalizer
or retirement stage is observed; all actual process/input/pipe joins complete.
Its last bounded read sample is 28,151,052,835 bytes, not proof that startup
performance is now acceptable. The ordinary journey reaches
`completed_unverified` and actual original-worker retirement, but its restart
request still exhausts the original budget (220 ms remaining, twelve frames).
The received-tool successor remains queued at `verify` after 222 cuts and
30,009 ms, with no finalize cut; its original two-second stop and joins remain
valid, not permission to extend either limit.

Final append-only `capture-002.json` retains all eighteen closed categories,
zero pending/rejected categories and one metadata-only artifact; SHA-256
`a2e6fa1e490df641ff43e0cd2f7420dada2996fb3af16b4af058fe66ffb2862d`.
The guest failure record SHA-256 is
`b541eae021207946cd9aa701e91e469135590c12cba5340a27f8ed07e36b5886`.
No raw log, ZIP, StateRoot, WAL or credential was retained. These failures
remain failures; the development publication implementation is not in this
pushed source and no complete delivery qualification or PR is claimed.

Previous pushed source `d39dd9a94ce80f73ab55defedf32c36adcd528b9`, tree
`db19c1fed421168890eabc30af74299293b6f6f2`, completed
[run 39143189861](https://github.com/cogine-ai/cliq-agent/actions/runs/39143189861).
Its own fresh archive, real `npm ci`, build and all 2,274 tests pass
(1,426,677.799542 ms; zero failures, skips, cancellations or todos). Five
script roots pass strict checking against actual dependency types, with
`skipLibCheck=false`; nine focused guest diagnostic regressions pass. All
836 tracked source blobs and modes match the validated tree. The final local
validation manifest SHA-256 is
`ce1234b58964a5f38462355bcbfdda9802011e55cd61f93eb3df70e15d67beae`.
This exact seven-file batch retains the original control connection and
performs full hello plus fresh before/after installation checks, including the
actual active-StateOwner/closing check. It neither reconnects nor resends a
credential mutation. The guest failure diagnostic adds only fixed syscall and
target enums from a complete reported Node ENOENT block; it does not retain a
raw path or prove a native cause. Original deadlines remain unchanged. The
development publication implementation is not in this pushed candidate and no
PR has been opened.

Fourteen CI jobs pass and four fail. Required-verifier enrollment still times
out at 60,009 ms before secret input: `first_supervisor` begins at 9,926 ms,
and the same credential process has read 36,920,066,291 bytes by its 57,010 ms
sample. This is not evidence of a Secret Service write/finalizer failure.
The ordinary journey again reaches real result/restart, then exhausts the
original request budget (73 ms remaining). The received-tool successor also
misses its original 30-second cut: it retains all nine completed Journal rows,
two owned HTTPS requests and an active original-owner lineage, but remains
queued at `verify` after 231 public cuts; no finalize cut was observed. Its
original service stop and actual process/pipe joins pass, so this is not
evidence that a longer two-second stop is acceptable. The pending-model and
retained-startup campaigns still pass. Native extraction and all eighteen
malformed ELF refusals pass; Node remains pre-body `ENOENT` with 1,788 stdout
bytes and both reported spawn enums `other_or_absent`. No specific target or
native cause is established by those unknown enums.

Final append-only capture `capture-004.json` retains all eighteen closed
categories, no pending/rejected category, and one metadata-only artifact;
SHA-256 `ddf6604da57570fb955bf77d9269fd23bb8502b64d69200b8aa5c374df117ff2`.
Its collector remains the frozen pre-reporter-extension version. No raw log,
ZIP, StateRoot, WAL or credential was retained. Local reproduction using the
fixed verified Node 24.21.0 has since shown that its default reporter is `spec`,
whereas the first diagnostic regression explicitly forced TAP. The diagnostic
must cover the actual default format without changing execution arguments;
this explains a coverage gap, not the underlying runtime ENOENT.

A five-file follow-up was frozen at tree
`92c420d6a71a165afdec3ef77656c7dd824f98f6`. It removes full installation
rehashing from negative socket polls without granting authority from that
hint, and extends only the closed guest diagnostic to the actual reporter.
Its own real `npm ci`, build, strict script checking and twelve diagnostic
regressions pass, but its first complete local test run has 2,273 passes and
one failure out of 2,274 (1,227,450.301417 ms; no skips or cancellations).
That attempt did not retain a fixed failure location; it is not a passing
validation. Its append-only local validation SHA-256 is
`879cc8e04f313096e9d2a461660cf01b87cc3f77021a9a640ad3af969411b75a`.
A second unchanged full run retained 2,271 passes and three failures. Its
append-only SHA-256 is
`c53e2e21f512c5762744fe65fa30abb36977cd9567bdd523cdae564d09743391`.
The repeated artifact-query failure was the actual native fixed socket-path
limit: the long archive produced 104 path bytes plus its terminating NUL,
exceeding Darwin's 104-byte `sun_path`. Neither the test nor native guard was
changed. The additional two lease failures are retained without claiming a
confirmed cause. A fresh shorter archive of the exact same tree passed the
original artifact test, all eleven affected focused lease/recovery tests and
the complete third run reported above. Both previous failed attempts remain
retained and are not relabeled as passes.

Previous pushed source `666fc58df4d825eaf5e0f7a876fe83ba04d7d81b`, tree
`4ee3abd1a601a967a16a017fad8ee80ce1c9a08b`, completed
[run 39139337290](https://github.com/cogine-ai/cliq-agent/actions/runs/39139337290).
Its own fresh archive, real `npm ci`, build and all 2,265 tests pass
(946,924.714166 ms; zero failures, skips, cancellations or todos). Five script
roots pass strict checking against the actual dependency types; six guest
diagnostic regressions pass. The exact thirteen blobs were independently
reviewed and compared with the validated tree before the normal commit/push.
Cancelled superseded candidates are not counted as successful validation.

The observer now retains its actual selected native platform while preserving
each fresh profile/manager observation and the original installation checks
before and after it. A credential scope must reject both before lazy loading
and before entering the later serialized borrow; the real Linux scope race
uses the signed actual platform addon and is not yet qualified locally. The
guest report adds only bounded byte counts, a fixed marker-status enum and
allowlisted reported error-code tokens from fully verified receipt output.
It retains no raw TAP, stack, path or credential. This batch includes no
development delivery implementation, and no PR has been opened.

Fifteen jobs pass and three fail. The received-tool, pending-model and retained
startup SIGTERM campaigns now all pass their unchanged assertions. Installed
verifier enrollment still times out at 60,014 ms: first-Supervisor spans
8,963–53,203 ms, followed by secret input and a second connection acquisition;
all original input/process/pipe owners join. The normal journey reaches the
actual Supervisor restart after a real result, then exhausts its original
request budget (46 ms remaining at the final failed request). Neither is
qualified by changing a deadline. Native extraction passes, including the
2,082,484-byte ELF string table and eighteen malformed-input refusals. The
first Node verifier fails before the first body marker; its fully verified
output projects to 1,789 stdout bytes, zero stderr bytes, absent markers and
the reported literal `ENOENT`. That literal alone does not identify the
failing syscall or justify changing arguments, isolation or acceptance.

The final capture retains all eighteen closed report categories, with none
pending/rejected and one metadata-only artifact. Manifest SHA-256:
`cb8e7be1dad759900ef9a7edefc292494349fc71cc7d80a49fcfa6bcc01784fc`.
No raw logs, ZIPs, StateRoots, WALs or credentials were retained. The next
credential optimization must keep the current active-StateOwner/closing check
inside hello; fresh manager/PID observations alone cannot replace it.

Previous pushed source `91b2873d9580e511ac82b62c090e89b15a22fb20`, tree
`121d1c47e66b8760d1f01faafc0bf35c0168fac2`, completed
[run 39131868935](https://github.com/cogine-ai/cliq-agent/actions/runs/39131868935).
Fourteen jobs passed and four failed. Admission SIGTERM and original credential
finalizer SIGTERM now both pass with the unchanged two-second stop contract.
The received-effects campaign preserves and joins its real effects and service
stops but misses its original thirty-second successor-result deadline; the
snapshot is queued at verification, not a completed result or proof of deadlock.
Installed verifier enroll again exceeds sixty seconds, with all original input,
process and pipe owners joined. Its first-Supervisor phase spans about 48 seconds;
logical reads and CPU counters progress, but do not by themselves identify which
full validation consumes that time. The native guest and normal installed
journey also remain failed. No failed qualification is counted as complete.

The final capture retains all eighteen closed report categories, with none
pending or rejected and one metadata-only artifact. Its manifest SHA-256 is
`50b24bfb44042df39906b0f598db1e4f6a808b8904d8da58fe11dee39b5fe88e`.
No raw logs, archives, StateRoots, WALs or credentials were retained.

Its own fresh Git archive and real `npm ci` passed build and all 2,265 local
tests (966,791.194583 ms; no failures, skips, cancellations or todos). The
focused script batch has 34 passes and four explicit Linux-only skips; strict
script checking passes with actual dependency types and no skipped checks.
This seven-file source batch prewarms the separate read-only admission observer,
confines the credential phase banner to its actual verifier fixture consumer,
and adds finite source-owned guest boundary markers. The actual guest script's
assertions, isolation, deadlines and output limits are unchanged; marker output
failures are contained and raw TAP/error/output bytes are not retained. A
boundary stage is diagnostic data, never native or installed qualification.
No delivery implementation is included in this commit, and no PR is open.

Previous source `475da21a8069a1a310fd84be4a034d1424260464`, tree
`670a7d05dcd1a8373e01640bcd386df21517e432`, completed
[run 39128460344](https://github.com/cogine-ai/cliq-agent/actions/runs/39128460344).
Thirteen jobs passed and five failed; this is not a Linux pass. Its own fresh Git archive and real `npm ci` passed
build and all 2,265 local tests (814,834.776458 ms; no failures, skips,
cancellations or todos). The separate script batch has 118 passes and four
explicit Linux-only skips, and strict script type checking passes without
skipping dependency checks. Only the fixed eight credential-phase observations
and seven client-stage observations may enter closed diagnostics; original
secret scanning, deadlines, frame limits, real input/process/pipe joins and
execution decisions remain unchanged. A diagnostic output refusal is contained
and cannot skip the original resource close order.

The guest verifier now reads the real retired WorkerLaunch, full seal/death CAS
closure and original invocation identity rather than looking for it in the
public recovery view's deliberately non-retired set. This history API does not
pretend to have made an earlier live observation and is not execution authority.
The original live-identity API retains its additional prior database/source
identity checks. No delivery implementation is included in this diagnostic
commit, and no PR has been opened.

The final bounded capture retains all eighteen closed report categories, with
none pending or rejected and one metadata-only artifact. Its manifest SHA-256
is `9ebfe850001853e19c54b4f4826abe7cd99cc0b570f0d0fbd6a4ef1f508e7b3b`.
No raw logs, archives, StateRoots, WALs or credentials were retained.

The received-tool/model SIGTERM campaign passes without changing its assertions.
The normal installed journey now reaches Supervisor restart after its actual
result, but a later request exhausts its remaining original deadline. The
verifier enroll finishes in 58,926 ms within its unchanged 60-second limit;
its next client authentication reaches the original five-second deadline with
no frame. Its roughly 72 GB `rchar` is logical bytes read, not physical disk
I/O (`readBytes` remains zero in the samples). Repeated complete installation
closure validation is under investigation; metadata-only caching or deleting
authorization-cut checks is not an accepted fix.

Two other failures are in test orchestration: admission loses its observed
resource before SIGTERM, and the fixture credential marker pollutes another
campaign's original single-JSON stderr. Local corrections preserve the actual
resource checks, two-second stop limit and strict stderr decoder; neither is
counted as a Linux pass until exact-source validation succeeds. The native guest
campaign gets past the retired-worker lookup and now reports an actual
`assertion_failed` where the successful-script scenario requires `passed`.
Source-owned finite boundary diagnostics are being added without retaining raw
guest output or changing that assertion. Full publication integration and
qualification remain incomplete.

Previous pushed source `8238346954345fb51d93cdad944b0f6bccc41982`, tree
`29beab5869d835cc291899a7fad44496362c5ca4`, has
[run 39125571188](https://github.com/cogine-ai/cliq-agent/actions/runs/39125571188)
completed with fourteen successful jobs and four failures. Its fresh Git
archive with its own real `npm ci` passed build and
all 2,263 local tests (782,003.659167 ms; no failures, skips, cancellations or
todos). This two-file commit corrects the verifier settlement Journal cut and
the endpoint observer test ordering, not the uncommitted delivery
implementation. No PR has been opened.

In that previous run, the new installed verifier campaign fails before any verifier scenario:
the real enroll command reaches its unchanged 60-second deadline. The original
credential PID/start/image, complete input write, process and pipes were joined;
the same process had read about 42 GB by the final 57-second sample. The
Supervisor's real StateOwner first appears in the bounded samples at 45 seconds.
These counters do not identify which credential phase consumed the deadline,
and do not authorize a cached or metadata-only substitute for full verification.

The normal installed client now fails at its original five-second readiness
deadline with no response frame, rather than the previous SEA-only loader
refusal. The received-tool campaign preserves its real original snapshot and
all nine completed model/tool Journal entries; both observed service stops
succeed under the original two-second limit. Its remaining failure is the
successor's thirty-second completion deadline: the Run is queued at verification
and shutdown observes `drive_retirement`, not a completed result or a proven
deadlock. The native guest lifecycle now completes the original verifier
settlement, then fails a test assertion that searches the recovery view's
explicitly non-retired worker set for a retired verifier. The correction must
read the actual original retirement row and validate its death/seal/identity
graph; absence is not retirement evidence and the production recovery view
must not be widened. The endpoint observer campaign now passes on Linux; its
absence-before-read and private-directory type/owner/mode checks retain all
original no-Run/StateOwner/keeper/socket and CAS assertions.

The final capture retains all eighteen closed report categories, with none
pending or rejected and one metadata-only artifact. Its manifest SHA-256 is
`51a5dcdf162a016138cf8b06807d9ef79ef1aa4d1a903f4220408914e0a34824`.
No raw logs, archives, StateRoots, WALs or credentials were retained. Neither
these diagnostic fixes nor the corrected fixture declaration qualify the full
verifier or delivery lifecycle, and the failed run is not treated as green.

The completed [Linux/macOS workflow for `6c9ff54`](https://github.com/cogine-ai/cliq-agent/actions/runs/39115284729)
tested full SHA `6c9ff5440cfbbceb0c112a41ccf1614068a78078`, tree
`81b57329e2b42d45c0a9b9eda4188b5f326126e4`. Fourteen of eighteen jobs passed,
including all four Node 22.13/24 Linux/macOS TypeScript matrices, the original
credential-finalizer SIGTERM/successor checks, and source-limit qualification.
A fresh archive of that exact tree, with its own `npm ci`, passed build and all
2,260 tests locally (887,373.570125 ms; no failures, skips, cancellations or
todos). This does not qualify the uncommitted delivery implementation.

The signed guest extraction passed the owner-approved ELF string-table
contract and eighteen malformed-ELF cases. Its subsequent native failure is
now identified: the guest campaign's existing 512 MiB filesystem exceeds its
signed fixture's incorrectly declared 256 MiB generation limit. The original
native capacity guard correctly refuses before guest verifier execution. The
guest-only signed test declaration must match its actual backing volume;
ordinary fixtures and production resource limits remain unchanged. The later
guest-verifier phase is not thereby qualified.

The normal installed client's new fixed diagnostic identifies authentication,
not a ready timeout: its read-only manager observation incorrectly enters the
SEA-only credential-authority loader. A same-installation, read-only manager
capability is being validated without changing the full credential loader's
SEA/version gate, peer authentication or hello checks. The verifier campaign
enrollment reaches the unchanged 60-second deadline. Static analysis identifies
substantial repeated complete image verification, but its runtime cause is not
yet measured. Bounded diagnostic observation must not replace hashes, extend
the deadline or turn failure into success. All four failed jobs remain failed.

The original received-tool result and its model/tool Journal completions were
retained. The successor was still queued at verification, and shutdown observed
`result_recovery` in `completeVerification`; this identifies the incomplete
stage, not a measured root cause. Repeated complete CAS verification is visible
in the code, but no performance diagnosis or metadata-only hash shortcut is
authorized by that fact. Minimal fixed-stage/elapsed/join diagnostics and
independently joined native campaign stages are being validated separately.

The closed terminal evidence capture retained all eighteen report categories,
with no pending or rejected artifacts. Its manifest SHA-256 is
`d0bb9c25c1edb9c8ac6ab9637e61a091dee7a7141a33f190a7ca188e950d35b8`.
The archive retains only allowlisted bounded report bytes and provenance, not
raw logs, ZIPs, StateRoots, WALs or credentials. A source-limit collector success
predicate was corrected to require that its observer did **not** exit before
release; the producer and acceptance assertions were unchanged.

New real native fault regressions expose a publication design blocker, not a
passed capability. Directory `mkdirat` and symlink `symlinkat` do not return a
birth descriptor: concurrent replacement before the first open can substitute
an unrelated inode. Even a descriptor-held regular staging file can be
substituted at its workspace pathname between the check and `rename`, and a
quarantine pathname can be substituted between its check and `unlink`. A
post-syscall refusal cannot undo having published or deleted the foreign inode.
Empty checks, extra `stat` calls, equal bytes and equal targets do not solve
these races.

The owner approved one integrated private-area contract: keep **all** staging
and quarantine objects in a StateRoot-controlled publication arena, owned by
the same original Journal claim, through the atomic effect and exact cleanup.
The development implementation now uses that arena and an all-operation
read-only same-filesystem preflight before any workspace write. Component
regressions show that substitution of the old workspace-side transient names
does not publish, adopt or delete those unrelated objects. Actual arena birth,
slot absence, parent fsync, directory retirement and descriptor close remain
separate required evidence; protected StateRoot is not claimed to fence a
malicious same-UID actor. This is not installed publication qualification.

Cross-filesystem publication remains explicitly unsupported/unqualified, with
no workspace-side fallback. Supporting it requires a separately justified
controlled-birth mechanism. The owner explicitly retained the RFC's
captured-object/quiescent-workspace boundary: a detectable prior drift refuses
before release, but an ancestor moved after the final check can receive the
first descriptor-relative effect on the same captured inode outside its current
workspace path. Subsequent drift detection refuses success and additional
semantic release and retains the original claim's physical evidence. This is
not an atomic current-path ancestry fence. The original stronger
`outsidePublished: false` assertion remains a historical RED, not a passed
capability. A separate regression for the approved boundary verifies the exact
captured inode/effect, foreign-object preservation and refusal of further
semantic release; it does not prohibit correctly fenced same-claim maintenance
after identities are restored. All twenty-three native fault tests now pass
locally, including exact-empty abort-directory maintenance, foreign
empty-directory replacement and post-check content creation. The combined
native/data/planner batch has 78 passes and one real cross-device Linux-only
skip. Neither result qualifies installed Linux publication or the production
SQL cleanup barrier.

Actual displaced-preimage retention now has a strict retained-data wrapper:
the original claim/birth, fixed private slot, physical identity and complete raw
CAS bytes remain linked even for an UNKNOWN effect. Twenty-six local decoder
and full-byte reader regressions pass. This grants no cleanup, forward release
or physical success and does not replace the missing live producer. Complete
capture under the original frozen non-Git projection now has 24 passing actual
directory/CAS component regressions, including new paths, payload-time inode
drift, cancellation and structural-handle refusal before CAS access. The
original rule refs are retained, not reparsed from live repository files; no
snapshot, terminal-projection or permission authority is inferred from this
component result.
The development consumer now connects no-op finalization, forward publication,
typed path settlement, preparation retirement, Stop maintenance and the sole
RunResult/Session or Stop writer. Closed unclaimed preparations require their
complete original native retirement and once-only zero settlement; a failed
phase or refunded budget is not enough. The abort terminal path uses a fresh
partial-root projection and shares the original M retirement owner and seal
budget. It does not invent an abort item for a file-only Plan.

With the rebuilt production macOS helper, a focused physical/component batch
has 64 passes and one explicit second-filesystem Linux-only skip. The later
combined preparation/Stop/decoder/execution batch has 41 passes; project type
checking passes. These overlap earlier component batches and must not be added
as distinct qualification coverage. Independent review found and fixed two
prepare-return cancellation gaps: register the original completion before the
revoked claim gate drains its genuine preparation. No synthetic authority is
used to turn those refusal/component tests into an installed positive case.

The production capability remains disabled pending complete integration and
real installed Linux evidence. The approved same-invocation known-result
handoff is now connected: the original producer atomically roots its actual
claim, receipt, arena/slot retirement and M seal in an excluded-control item
and resource Checkpoint, without settling or advancing the publication
frontier. Only then may the separate read-only projection cancel and join. A
successor validates that complete graph and freshly captures the root before
the sole terminal settlement; it cannot reconstruct a native owner, reopen M,
redispatch or reseal. A distinct terminal Checkpoint preserves the immutable
resource Checkpoint. Same-owner storage retries retain their original token
and single BudgetSettlement. Stop retains the real receipt and selects the
existing abort branch. Missing evidence or storage failure remains recovery,
not replay permission or success.

The sole worker-preparation boundary now accepts Delivery only after complete
source/allow/prefix validation and an exact unchanged SQL cut; handoffs,
unsettled operations and closed fixed-attempt preparations cannot open a new M.
Driver prefix reads use the existing cancellable, joined Store read scope even
before an execution scope opens; reads entering after shutdown are refused
before CAS access. Two genuine Store/CAS regressions cover cancellation/join
and that closed entry, not a positive Delivery or a two-second installed stop.
The installed campaign additionally binds handoff data to the original actual
readonly SQL worker/generation/snapshot and independent process-retirement
checks, on initial inspection, reconnect and restart. Its local data/SQLite
regressions are not execution of those installed cuts.

Real handoff commit, shutdown, Stop/storage-failure and cold successor
once-settlement cuts remain unqualified. UNKNOWN same-claim successor
reconciliation, unclaimed fixed-attempt replacement, ambiguous native-open
windows, cross-filesystem publication and unobserved crash cuts remain explicit
qualification/implementation gaps. Package A is incomplete and no PR is opened.

The owner-approved late-result and registered-namespace branches are now
connected in the development producer, same-Continuation audit writer, full
retained readers and sole finalization/abort consumers. Actual completion time
is retained separately from an earlier raw path observation; deadline-late
facts never become timely probe evidence. A committed audit updates both
original task caches synchronously without changing the wait/nonce, Journal,
frontier or BudgetSettlement. A later true probe cannot reuse its old fact.
New current-namespace retirement never synthesizes old slot-parent FDs or
unlink witnesses; absent/empty and original registered-preimage cases have
disjoint native behavior. The normal installed campaign continues requiring
its original uninterrupted descriptor branch rather than pretending to test
successor recovery.

A fresh combined component/retained-data/refusal batch passes 101/101 tests,
zero skips/failures/cancellations/todos (22,362.930625 ms); project TypeScript
and diff checking pass. The independent actual native fault addon passes
11/11, including real cleanup-before-fsync and rmdir-before-fsync failures,
foreign identity/extra entries, complete desired bytes, strict preimage
routing and sticky temporary-descriptor close failure. Its initial close-
failure RED exposed a genuine swallowed StateRoot revalidation close error;
the new role now uses the existing retirement-error sink throughout, not a
shifted fault ordinal. The old publication constructor/arm/cleanup/retirement
guards remain unchanged. The main helper was not rebuilt during fixtures.
These batches overlap earlier checks and do not qualify a real installed
Delivery, original-owner takeover, late return/new nonce, once settlement or
two-second stop. Full exact-source local and independent Linux evidence
remains required before enabling the installed capability or opening a PR.

The approved directory-not-created correction retains a present original `A`
file/symlink as a leaf, with full-byte hash/raw file mode or exact link target;
it grants no deletion or cleanup authority. Eleven real read-only observation
regressions pass locally, including the unchanged conversion leaf, bounded
reads, actual mutation refusal and close-failure priority. The public result
query now derives local/inherited selection from the real RunSpec and rejects
Agent results carrying Delivery-only proof fields; its genuine StateStore/UDS
batch has 28 passes. These are component/negative checks, not a genuine
installed Delivery success or conversion/cancellation qualification.

The exact `4c7dbae36de2d15159fbf803c2e6d01fb63145f5` tree passes its
isolated local build and original full test command: 2,549 passes and one
original conditional cross-filesystem skip, zero failures/cancellations/todos.
Its Linux workflow run `39258706081`, attempt 1, finishes with nine successful
and ten failed jobs. This is not installed Delivery or recovery qualification.
In particular, the Delivery journey fails authentication before entering its
publication cuts: the fixed five-second readiness deadline remains unchanged.
The verifier journey separately reaches the original sixty-second credential
enroll timeout. A process-image observation during timeout cleanup does not
establish that timeout's cause. The next repair batch addresses verified
fixture-contract and real-I/O-hook drift, strengthens the guest-process
observation, and attempts bounded read/hash overlap without removing any
complete-image revalidation. All positive installed recovery and timing cuts
above remain unverified until the corresponding actual campaigns pass.

The next exact tree, `f2d117ef05a1ab5b7bba8937132bf3e60cd6bc74`, also passes
its isolated original build and full test command: 2,549 passes and the same
single conditional cross-filesystem skip, zero failures/cancellations/todos.
Linux run `39266723237`, attempt 1, finishes with sixteen successful and three
failed jobs. The native lifecycle step passes, and the received-tool shutdown
journey observes the original service exit within two seconds and the cold
successor's once-only settlement within the original thirty seconds. Neither
result qualifies Delivery publication or the remaining exact crash cuts.

The three remaining failures are distinct. Delivery's first client still
exceeds its original five-second authentication deadline, before publication
starts. The verifier job fails a newly added natural-zombie fixture before
running its installed journey: the fixture's five-second lifetime cannot
cover the monitor's existing six-second sample schedule. That fixture needs
repair, not an extension of production enroll, readiness or stop deadlines.
The guest verifier separately reports `node_check` at its original five-second
READY timeout; this observation alone does not identify hash CPU, throttling,
memory pressure, a particular test case, or successful Node execution.

The closed final capture retains eighteen report categories, with zero rejected
artifacts; the verifier journey report was never generated because its earlier
fixture failed. Its manifest SHA-256 is
`948094edb84d93f26994fe068adc2b41a38f0f474d111837436514c35362132d`.
Complete-image revalidation, fixed resource limits and all original deadlines
remain required. Local parallel-hash measurements and source-level performance
hypotheses are not installed Linux qualification. Package A and I1 remain
incomplete; no PR is opened on the strength of those measurements.

At `7dd954e`, the development discard-only reader used fresh bounded workers
for each original revalidation; no revalidation call, independent inode or byte
was deduplicated. At least two original files of 8 MiB each were needed to
start workers: two lanes normally, four for at least four large files.
Main-isolate discard batches shared one cancellable permit and one MiB of
live discard hash scratch, including idle workers. Each worker had fixed
old/young/code-range/stack limits of 16/4/2/1 MiB, with additional Node/native
overhead. Every actual worker exit preceded permit release and FD retirement.
Other isolates and retaining reads kept their original pipeline; these bounds
were not a process-wide RSS or arbitrary-isolate allocator.

The native SHA-256 reader also retains its original portable implementation.
Only a real per-context CPUID check for SHA, SSSE3 and SSE4.1 selects the local
hardware transform; unsupported CPUs retain portable compression. Complete
bytes, padding, identity, seals, publication snapshots and resource/deadline
guards are unchanged. Local portable vectors, independent digest comparisons
and exact Node 24.21 ordinary/SEA worker mechanisms do not qualify real SHA-NI,
musl, installed publication or the original Linux readiness deadline. The
existing free native job must execute the actual musl-built algorithm vectors
before running its unchanged guest campaign. No capability is enabled by these
optimizations alone.

The exact `7dd954ed5a759a4e3fed920f09b6a8f34cad6886` tree passes the original
isolated local build and full test command: 2,549 passes and the same original
conditional cross-filesystem skip, zero failures/cancellations/todos. Linux
run `39279571752`, attempt 1, has a closed artifact capture with fourteen
qualified and five failed report categories, zero rejected artifacts. These
are report categories, not terminal job counts: both available job-metadata
API shapes still returned queued jobs without steps at capture time. The
capture SHA-256 is
`324df397d8209d44276621bc86ae27277a9844948164e89fefc2c34c441ea60b`.

The native musl vector executable reports `portable_and_sha_ni`. The actual
guest campaign advances through its four ordinary scenarios, then fails a
controlled-stop assertion incorrectly equating the original quiescence death
reference D0 with the final SQL death reference D1. The repair uses the same
complete S/D0/D1/Checkpoint association as ordinary completion, including
matching original containment/worker/inspector identities, full CAS hashes,
`D0 <= S <= D1 <= C` and the existing five-second final freshness bound. It
uses the original verifier Checkpoint, never the later terminal Stop
Checkpoint. The real Node execution, two-second stop, exact claim, accounting,
source-integrity and no-replay assertions remain unchanged. Its local data
regressions are not a replacement for rerunning that real Linux campaign;
the guest verifier success report was not generated in this run.

Both installed Delivery and verifier journeys still fail before their actual
cases at the original five-second client readiness limit. They observe
thirteen complete revalidations and a real hello reply; the subsequent fresh
manager/peer observation still requires three more complete revalidations.
No post-hello result is replaced with an earlier observation. Separately,
credential qualification fails its original cumulative trace-file-count guard
without reporting the actual count. The received-tool successor preserves
ordinary service exit and owner lineage but does not reach its required final
cut within thirty seconds. Neither failure is reclassified as success or
attributed to an unmeasured cause. All previously listed late-result,
cleanup-before-acknowledgement and full installed Delivery cuts remain open.

The next development repair changes only the private hash executor lifetime,
not any complete-byte verification cut. Every revalidation still reads each
original independent FD from byte zero through EOF, computes a fresh SHA,
checks parent named/held and worker held identities, and completes the original
directory/package/version barriers. Successful jobs return only after actual
reads and stats have returned and the worker task has cleared its FD reference;
only fixed code, threads and scratch remain idle. No hash, observation or result
is reused. Unique job identities reject old replies, old abort listeners are
removed, and idle failures cannot be cleared by silently replacing the pool.

The executor is process-private, main-isolate-only and limited to four workers
under the same FIFO permit. Large batches send small files through that same
scratch too. A standalone discard pipeline, a batch with fewer than two large
files, or a lane-count change first joins every old worker exit, so idle and
parent discard scratch never overlap beyond one MiB. Cancellation and failure
also join actual exits before returning. Scope close retains the original
accepted-borrow/tail join, then joins registered jobs and a FIFO executor-exit
barrier before closing original FDs; a result ACK is not executor retirement.
Fixed worker limits, embedded CJS, all sixteen client revalidations and all
production deadlines remain unchanged. This is an explicit resource-lifetime
change, not a claim that retaining threads is risk-free or that Linux passed.

An exact Node 24.21 Mac experiment over sixteen complete reads of the same
four original files measures 12.1% lower wall time and 17.0% lower CPU time for
four retained workers versus fresh workers. Separate real-FD mechanism checks
exercise fresh reads, old-signal isolation, idle death, old-packet refusal,
cancellation and actual exits. They do not exercise the production Linux
descriptor path, global FIFO/Scope integration, total traced TID bound or the
original five-second client and two-second stop qualification. Those real
Linux regressions and both installed publication/recovery branches remain
required before Package A or I1 can be declared complete.

Received-tool recovery now reports six fixed retirement await boundaries in
the existing shutdown diagnostic: history, quarantine closure, native
retirement, workspace observation, retirement commit and resource join.
Observer exceptions cannot affect execution; no public method, authority,
deadline, history check or retry changes. These labels locate an unfinished
await, not its cause or a positive retirement/recovery proof.

The exact `b88fdc3bb1a531509dbc779d091ab55371e2e865` Linux run
`39285975957`, attempt 1, is terminal: seventeen jobs succeed and two fail.
All nineteen report categories are retained, with no missing or rejected
artifacts; the final capture SHA-256 is
`00171a11262198e53ee8b51b76a512fe10fdaa9db777d9e69bee9ce92cac0b02`.
The native verifier's five real scenarios, including in-flight cancellation,
the full credential campaign and received-tool successor recovery now pass
their original assertions. The latter recovery takes 29,744 ms against the
unchanged 30,000 ms limit; this small margin is not a scale qualification.
The exact local build and full test command also pass with 2,549 passes and
the same original conditional cross-filesystem skip.

Delivery still fails during its first source Run, before `run.apply`; its
owned HTTPS responder discarded the actual rejection. The minimal diagnostic
repair retains only the first error in memory and feeds it through the existing
bounded, fixed-source-frame projection and secret scanner, never publishing
request bytes or raw error text. All response and outcome assertions remain.
The installed verifier fails an executable-image observation after the real
credential retire marker, not the sixty-second enroll deadline. Its current
report cannot distinguish a positively foreign inode from a missing exe link.
Linux can remove that link in `exit_mm` before the task becomes a zombie.
The observation repair treats only an already-identified, identity-matching
task with an actually missing exe and `PF_EXITING` as unavailable for this
sample: no input, new identity, death proof or join is granted. A positive
foreign image or missing image without that exit flag still refuses. Actual
parent reap, process disappearance and every output/resource join remain
required. Pure decoder regressions do not prove this exact OS exit window or
establish the cause of the failed run; both real installed journeys must rerun.

The approved late-result storage fixture is restricted to a disposable Linux
environment and its own test volume. Its complete device-mapper identity,
original loop/image ownership, actual fsync interval and normal resource joins
must be checked before it can produce evidence. It must cross the original
probe deadline in real post-gate resource work, not in CAS persistence or a
changed clock. No experiment, late-result qualification or Package A completion
is implied by approval of this fixture; the original stop/probe limits remain.

The fresh awake validation of tree
`d63f7a5617362ffe837e2bf8008553f2cc1c065a` passes the original build and
full test command: 2,549 passes, one original conditional cross-filesystem
skip and no failures, cancellations or todos. This does not erase the earlier
sleep-interrupted failure. Its final local validation SHA-256 is
`e097a46621de9cffd30ecf3c8b16b4c3f5707a27c0eda8134de7d43fdb94ac46`.

Linux run `39970997194`, attempt 1, on exact commit
`b6140b57836e19b0fb937327af449e8138f47eca` is terminal with seventeen
successful and two failed jobs. All nineteen closed report categories are
retained with no pending, incomplete or rejected category. The final capture
SHA-256 is
`81d7f5959eab9bd9a85c961248439cf3cb1db45a99e825e438f522665df11e7d`;
all 89 original JSON files (445,142 bytes) were independently rehashed.
Both owned enrollments complete and join. Neither result proves the precise
pre-zombie `PF_EXITING` cut. The Delivery and verifier failures now retain
their first responder error: an original 5,000 ms request deadline with two
complete client frames (hello and `run.get`). The next ordered request is
`supervisor.status`, while the owned HTTPS response is still pending. This is
not a readiness failure, and the deadline remains unchanged. Full installed
Delivery, late-result storage and precise retirement-stop qualification are
still required; these failures are not a successful Package A or I1 result.

The responder wait is a real dependency cycle: credential dispatch holds the
business borrow while awaiting its external response, and the responder's
`supervisor.status` was queued behind that same borrow. The repair gives only
the fixed immutable manager observation a separately joined lifetime; it does
not grant a general callback or bypass the business FIFO. Status retains all
three fresh full-image revalidations and the original root, CAS, owner and
channel checks. Close and execute abort and join every submitted observation
before retiring original descriptors. A fixed baseline experiment must observe
the exact five-second assertion on the original code; import, platform, helper
or unrelated assertion failures cannot count as that RED. The candidate's
Linux GREEN and both complete installed journeys remain independently required.

The controlled storage campaign uses one frozen 50 ms read/write/flush table
for the complete disposable home. Before activation and each later use it
checks the unique mapper identity, original loop and image, and after an
ordinary unmount/remove it must observe actual resource disappearance. Its
real loop-descriptor handoff is recorded before opening the mounted device;
missing or partial handoff evidence is retained, never adopted by pathname.
The separate free hosted-VM job neither replaces an original campaign nor
changes its twenty-minute limit. A requested profile is not a physical receipt.

Fixed native retirement diagnostics record only the first actual fsync
interval for each original parent, its outcome and complete join. Normal
dispatch and current namespace probes have different diagnostic-key domains;
neither invents a probe nonce for the other. These clock observations cannot
authorize work or replace CAS/progress/death/retirement evidence. In particular,
the 50 ms profile does not guarantee that a real post-gate fsync crosses the
original thirty-second probe deadline. Late-result and in-flight-stop flags
remain false until their own actual cuts and complete independent recovery
assertions have passed; ordinary Delivery success is not a substitute.

The exact next source, `5ad50f301bf5f38a673652f664e053464f75996d`,
passes the original local build and full test command: 2,557 passes, one
original conditional cross-filesystem skip and no failures or cancellations.
Final validation SHA-256:
`1897d8d0bd63dd1af74c8c87137b2548d477adc73419b7550ccae5606596de30`.
Its Linux run `39984099584`, attempt 1, actually reproduces the fixed original
five-second status assertion on baseline `b6140b5`; the closed 611-byte RED
report SHA-256 is
`1a682a1682a33f7799bc68afcd0e3cc1596926674ac5ae6ed5732a0fc160c148`.
This is not the candidate's installed Delivery qualification.

That run exposes an earlier common volume-fixture defect before its Run
reports: util-linux formats BACK-MAJ:MIN with internal width padding, and its
raw table encodes those spaces as `\x20`. The assertion compares that raw
representation with the same canonical `259:1` identity and rejects it.
The fixed in-memory log projection retains only known error codes, exact
eval source positions and strictly numeric device cells; no raw log is saved.
The source log SHA-256 is
`0ec8bae10b9212cfcf13e315ea0ec378629b0d46d893241fccaa80028ddfd721`.
The repair decodes only those formatting spaces in that one column and still
requires exactly six cells and the exact original device, inode, offset,
size limit and AUTOCLEAR. Different identities, other escapes, extra cells
and encoded inode padding remain refused. Existing failure/cleanup evidence
is retained; neither runner UID 1001's legitimate pre-existing manager nor
an orphan fixture is adopted or removed to make a test pass.

The delayed-volume job also explicitly runs the two root-only protocol-child
regressions under its actual root test invocation. A non-root six-test result
cannot be counted as those eight tests. This exercises actual process/pipe
lifetime only; it does not run the C SIGTERM actor or qualify a native stop.

The exact next commit, `dd4fcf13d73177ab8322f3af7723fa959ccf59f0`,
passes the unchanged complete local build and full test command: 2,557 passes,
one original conditional cross-filesystem skip, no failures, cancellations or
todos. Its final local validation SHA-256 is
`0e6f262a80586c997979415a55c8c7f4adfa712433a0392c770a352f0dfc9d36`.
Linux run `39988808942`, attempt 1, is naturally terminal: seventeen jobs
succeed and three fail, including four successful TypeScript matrices.
All twenty-one report categories are retained with zero schema rejection;
all 93 original JSON files (444,589 bytes) were independently checked again
for complete bytes, size, hash, ownership, regular-file/no-follow identity
and the closed schema. Final capture SHA-256:
`9fb054a83deb6d9d2767bd4ba0a9ae1ca64dc11e0b9737437b00bf20e66da556`.
The delayed-volume category retains its missing filesystem/journey reports
and two cleanup errors; it is not qualified by retaining the other reports.

The normal Delivery client fails its original five-second ready deadline
before any business request. Its actual fixed authentication observations
end at the real hello response: thirteen complete revalidations, each reading
798,744,981 returned bytes, and no completed final manager/peer cut. The
complete already-running path still requires sixteen revalidations; the
remaining three cannot be replaced with earlier observations. These logical
read counts and elapsed spans do not identify physical I/O, CPU or scheduler
cost. The verifier separately passes its first required case but exceeds
the original ninety-second terminal bound during required repair. Neither
partial success qualifies its whole installed journey.

The delayed-volume failure is earlier: libmount rewrites the supplied
`/dev/dm-N` source to its mapper alias, while the original mountinfo guard
correctly requires the exact frozen canonical source. A bounded in-memory
projection confirms those two spellings and the original assertion location;
the 72,126-byte source log SHA-256 is
`b3aa562c054676245d95c50d4f75ede993f4e55d0104ed1781b7216ccd576aab`.
The [fixed util-linux implementation](https://raw.githubusercontent.com/util-linux/util-linux/v2.37.2/lib/canonicalize.c)
performs that spelling change. The candidate preserves the already fully
checked absolute device and home
paths by requesting `mount --no-canonicalize` for this one real delayed mount.
It does not accept a mapper alias, follow an unverified link, skip mount(2),
or change any device/UUID/loop/image/mount/cleanup/deadline assertion.
The added regression observes the original missing-option failure and keeps
both owned and foreign aliases refused by the original identity guard.
Actual delayed mounting and complete normal retirement must still rerun.
The terminal-deadline diagnostic projects only the already returned public
cut's fixed enums and counts. The original ninety-second assertion, its sole
clock sample and its thrown error remain unchanged; diagnostic failure cannot
replace that error, query state again or provide any execution/recovery proof.
Independent review also reproduces string-coercible arrays passing the shared
Journal discriminators. The repair requires primitive strings for `opKind`,
`replayClass` and `phase` in that one decoder, rather than duplicating rules in
the diagnostic. The wire and retained-storage error projections both reject
the malformed input without invoking coercion. Valid literals, all original
phase rules and retained safe-bigint numeric compatibility remain unchanged.

The separate original-publication-stop candidate reuses the complete normal
Delivery journey and a fresh StateRoot, then adds one same-source publication.
Its actual SIGTERM must fall strictly inside the first original arena-parent
fsync in both clocks, and the real original process must die and join within
two seconds from signal entry. It requires the original normal receipt,
durable sealed-M handoff, graceful owner release, genuine successor, complete
CAS/result/projection/public replay and independent original worker lifetime
and arena retirement observations. It cannot reuse the UNKNOWN-crash reader
or count the pure-data/actor protocol tests as physical qualification. Normal
and UNKNOWN campaigns remain separate; the late-result cut and all other
previously unverified acceptance boundaries remain explicitly open.

The exact local tree `1e52734c25182c0aaa30d0d5fabbf0e2a0bb460b`
completed build and the original full test command with 2,558 passes, zero
failures and the original one conditional cross-filesystem skip. Its commit
was stopped by `git diff --cached --check` for one surplus final blank line;
no commit, push or CI run was made for that tree. That record is preserved,
not counted as validation of the corrected, subsequent candidate.

The subsequent qualification driver samples `process.resourceUsage()` once
inside each existing authentication phase callback. The fixed V2 marker labels
four cumulative whole-process counters, including threads: `userCPUTime` and
`systemCPUTime` are microseconds; `fsRead` and `fsWrite` are raw getrusage
counters, not bytes or a per-hash measurement. Unavailable sampling retains
the original V1 marker. The closed reader preserves counter monotonicity
across intervening V1 phases. The original seven-phase, 512-byte marker,
64-KiB stderr and five-second authentication limits, complete image checks,
secret scanner and actual process/pipe joins remain unchanged. Portable
regressions and independent review pass; the combined candidate still needs
its own complete validation and real Linux observations before any performance
cause or installed qualification can be claimed.

The corrected exact commit `e19edf5cc60da8cce5c6c76c285c6ac0983fe1bc`
subsequently passes build, strict checks with the actual postject JavaScript,
and the unchanged complete local test command: 2,558 passes, one original
conditional cross-filesystem skip, no failures, cancellations or todos. Its
final local validation SHA-256 is
`c64f5f76ea28d5f9d9c746275aaa37db67ee911741fc65dfb0da5869743523a1`.
Linux run `39999805623`, attempt 1, terminates with sixteen successful jobs
and five failures. All twenty-two report categories and 100 original JSON
files (491,785 bytes) are retained and independently rechecked, without
filtering their bytes or reading the excluded preflight artifact. Final
capture SHA-256:
`604469cc89c07d035e9a395e853edb433307b9bf0fae478494f2fb98ddda7208`.
All twenty cleanup reports have zero cleanup errors. The real owned delayed
mount and its complete device/loop/image identity checks now pass; this does
not qualify a publication fsync, late result or stop cut.

Normal, delayed and original-stop Delivery still miss the original first
five-second ready bound. The normal authentication reaches the actual hello
response after thirteen complete revalidations; the recorded whole-process
CPU increase is about 9.26 CPU seconds over 3.19 seconds of phase wall time.
It is not per-hash CPU or proof of a single cause; zero raw getrusage fs
counters do not mean zero logical image reads. The original full path still
requires sixteen complete revalidations. Required verifier repair separately
exceeds ninety seconds, with seven claimed and seven completed Journal rows
and no remaining claimed/unknown row in the actual last public cut. Those
counts alone establish neither deadlock nor sufficient performance. The
credential journey also fails its original thirty-second completed-revocation
replay with stdin deliberately left open and unwritten and all services
absent. That fixture has no guest image, so reducing image padding cannot be
assumed to fix it. All five failures and the unexecuted physical cuts remain
open; added diagnostics are not substitute qualification evidence.

The next combined candidate makes the shared publisher's default image layout
compact while retaining every measured file, the original reserve, all full
image revalidations and the unchanged maximum-image qualification path. It
also adds a dedicated free Linux late-result campaign on the same fixed
50-ms owned delayed volume. That campaign must capture two real public cuts
(first in-flight and sole late audit), one same-nonce continuous native parent
fsync crossing its original UTC deadline, the actual old-task join and timeout,
the original backoff and a distinct fresh probe, then the complete original
claim/accounting/CAS/result/replay/retirement/secret-scan closure. A missed cut
fails; a terminal prefix, pure tuple test, delayed CAS or a complete journal
group by itself cannot qualify it. Every journal query is a whole unfiltered
window bracketed by the actual live successor's PID/start and full image.
An exact complete first group may remain explicitly pending within the same
five-second budget, but fragments and different windows are never assembled.

Two fixed failure observations remain diagnostic only: relative timestamps
already present in the public verifier cut, without reading a live clock;
and bounded phase/work markers from the original joined offline revoke
command. They change neither the original ninety/thirty-second assertions
nor stdin, service access, recovery authority or production revoke behavior.
All new physical cuts and both compact and maximum performance remain
unverified until the exact combined source executes on Linux.

The exact combined commit `5d093c473dbf22a31bf78424cb9e1a47d3141ce7`
passes build, strict checks and the unchanged full local test command with
2,558 passes, one original conditional cross-filesystem skip and no failures
or cancellations. Final local validation SHA-256:
`29d7a4df05d0ee2bba610523f1f8dd36ef87151a0b274ae63696d1bc1e316aaa`.
[Linux run 40010944047](https://github.com/cogine-ai/cliq-agent/actions/runs/40010944047),
attempt 1, is terminal: sixteen jobs succeed, including all four TypeScript
matrices, and six fail. All twenty-three report categories are retained with
no missing or rejected category. Final capture SHA-256:
`7fb233a575b5d0b857f96e1858799e16c39ed21f7da7110851e6456ca4d45e6e`.

Normal Delivery now reaches a verified source with the compact 160-MiB image,
but its first `run.apply` is refused; the missing fixed refusal observation
must be restored before attributing a cause. The maximum-image verifier still
exceeds its original ninety-second repair bound, and received-tool successor
completion exceeds its original thirty-second bound. The delayed, original-stop
and late-result jobs still fail their original five-second authentication
bound before any publication cut. Their owned volume cleanup succeeds, but
none qualifies its physical cut. The complete credential campaign, including
offline completed-receipt replay, succeeds this time; a single pass does not
establish that the previous intermittent timeout has been repaired. These
failures remain open, with no complete Delivery, I1 or release claim.

The development follow-up reuses complete bounded CAS verification for
discard-only recovery reads, preserving the original byte/hash/metadata checks,
read cancellation and actual descriptor joins instead of retaining whole-object
buffers. It also retains the existing fixed Delivery refusal observation and
the public waiting reason. Only the explicitly signed delayed-test images
subscribe to fixed server authentication spans. Their bounded original-server
journal is read after the unchanged stop and joins, never before them. These
are JS-await diagnostics, not native fsync timing, authentication authority or
evidence that any previously failed deadline or physical cut now passes.

The follow-up commit `687df3b38564c4944e84abfc18a126f81885a6dc` passes
the unchanged local build and full test command: 2,580 passes, one original
conditional cross-filesystem skip, no failures or cancellations. Its complete
local validation SHA-256 is
`f660d0091e63d85b97363eaf4b008ffa32fdb15735f4d610b93fad211bcf4b0f`.
[Linux run 40019768969](https://github.com/cogine-ai/cliq-agent/actions/runs/40019768969),
attempt 1, is terminal with seventeen successful and five failed jobs; all four
TypeScript matrices pass. All twenty-three report categories are retained,
without pending or rejected categories. Final capture SHA-256:
`cb99a2a2e00bea4f05ec0ac0457a473a0c65690538bd007f97b20c83455c2b33`.

Received-tool shutdown and successor completion now pass the unchanged
two-second stop and thirty-second recovery assertions, reaching the original
terminal result in 27,354 ms with one tool claim/charge and one publication.
This observed improvement does not establish a single performance cause.
Normal Delivery still refuses its first `run.apply` with `INTERNAL`; this
does not establish whether admission committed before continuation loading.
Maximum-image repair still exceeds ninety seconds. Its last complete public
cut is queued/agent, without an active worker or wait, and has seven claimed
and completed operations with no failed/unknown operation. This is neither
proof of a deadlock nor proof that the scheduler has no retained error.

All three delayed-volume jobs still fail their original first five-second
ready bound. Each has a joined-original-server authentication observation:
native image hashing spans 88--110 ms; the four CAS awaits total about
3.69--3.81 seconds. These are independent complete JS-await spans, not single
fsync durations or evidence of completion before the client deadline. None
enters the publication cut, so physical original-stop and late-result
qualification remain open. The next local shutdown follow-up adds only the
existing native-current checks between those original serial operations;
its eight real-peer logical-return cuts and three Node-version neighbor
suites pass, but do not qualify in-flight fsync or physical two-second stop.
On 2026-10-24, option A explicitly approves four bounded concurrent original
artifact publications, with every artifact durably published, fully verified
and joined before the final native-current check and channel activation. The
canonical RFC, accepted control-peer clarification and WP04/WP06 now share
that contract. Precomputed full-byte refs are expected values only, not
authority or substitutes for actual publication. The implementation and its
complete local/Linux/storage validation remain a follow-up, not evidence from
the preceding run. The first-apply refusal and maximum-image repair failure
also remain open pending minimal original-failure diagnostics. No complete
Delivery or I1/release claim follows from this run.

The approved authentication implementation freezes and closed-decodes the four
canonical artifacts, then joins their four original complete CAS publications
and checks every actual returned ref/length/media type/schema kind before the
final native-current check. Independent development regressions on Node
22/24/26 each pass 77 neighboring tests without skips or cancellations,
including connection/Store closure, mismatched real return metadata, real
written-byte corruption and resource-retirement-error precedence. Actual
delivered CAS handle ownership peaks at eight (two per operation) and all
observed handles close; this is not a full-Supervisor descriptor measurement.
These checks do not qualify the original Linux five-second authentication,
two-second physical stop or delayed-storage/late-result cuts. The combined
candidate still requires full local validation and immutable Linux evidence
before a complete PR.

The normal Delivery and maximum-verifier test images additionally opt into a
fixed original-Store failure summary: the first actual apply/scheduler error's
closed stage/class/code, event counts and pre-revocation task/phase counts.
Original errors and scheduler behavior are retained; no message, stack, path,
request, credential, Run id or new time sample enters the summary. Ordinary
images create no diagnostic tracker. The trusted test image emits at most
sixteen lines/four KiB at actual process exit, within the unchanged stop bound;
the whole original-sender/invocation journal is read only after the real stop
and join. Missing, overflowing or unbound observations stay unavailable. This
is diagnosis, not a new status API, retry permission, recovery evidence or
substitute for the still-missing Linux acceptance results.

The approved four-publication candidate, commit
`659ec343d96d92a88fc1dd8eca9139a86bed8814`, passes its original local build
and full `npm test`: 2,605 passes and one original conditional cross-filesystem
skip, with no failures, cancellations or todos. Immutable Linux run
`40100034278`, attempt 1, finishes with seventeen successful and five failed
jobs. The three delayed-volume campaigns now pass the original first
five-second ready/authentication bound, but each fails its first
`authorization.create` with `INTERNAL`, before source Run admission. None
therefore reaches its physical publication cut. This is progress past the
authentication blocker, not delayed-storage, original-stop or late-result
qualification.

The normal Delivery's bound, joined original-Store summary locates its
`RECOVERY_REQUIRED` at `postcommit_load`, after admission returned. Its
inherited installed-broker assembly was incorrectly interpreted by an
Agent-only model-history recipe. The follow-up routes Delivery through the
existing complete model-free invariant, including its actual child-allocation
cut, before excluding that Agent-only reader. Agent recipe, original claim,
token and process-domain-death checks remain unchanged. Pure-data routing
regressions do not qualify the corrected installed `run.apply` path.

The maximum-image verifier still fails its original ninety-second repair
window in reconciliation after seven completed invocation settlements. Its
original two-second stop also fails, so its Store summary correctly remains
unavailable with `original_join_missing`. The follow-up gives preparation and
read-only projection/recovery their owning cancellation signals while keeping
received-result settlement on its original independent catalog and resource
owners. Cancellation is not a join receipt. The physical stop and repair
claims remain open until a fresh immutable Linux run passes unchanged limits.

Authorization failure diagnosis is extended only within the existing trusted
qualification composition: one optional fixed first-error/count pair records
the original authorization phase and closed error classification. It adds no
closing guess, timestamp, grant, retry or wire method; original authorization
guards and operations are unchanged. The delayed images use the same prior
live image/start/invocation binding and original-stop/join gates as the normal
images. `INTERNAL` alone does not establish a canonical-time-fence race, and
the time-fence contract is not relaxed on that hypothesis.

The next immutable follow-up, commit
`eef99ccc7be6be1c213929b9da26df8fcadb8787`, passes the original local build
and full `npm test`: 2,620 passes and one original conditional
cross-filesystem skip, without failures, cancellations or todos. An earlier
full run's single failure is retained: shutdown now correctly cancels the
original spec read with non-retryable `LEASE_FENCED`, rather than reaching
the old platform-refusal assertion. The corrected regression requires that
exact typed refusal, the original memoized close, unchanged recovery closure
and a genuine successor owner; neighboring no-close platform checks remain.

[Linux run 40108486097](https://github.com/cogine-ai/cliq-agent/actions/runs/40108486097),
attempt 1, finishes with seventeen successful and five failed jobs. All
twenty-three categories and 105 original JSON reports are retained, with no
pending or rejected categories. Final terminal capture SHA-256:
`9ad62e3bcc881a7fc585c91be2ba65148ec4c70e3ee605d60dca4506428df474`.
The normal Delivery source Agent completes, but the actual accepted Delivery
still exceeds its original ninety-second terminal window and fails its
two-second stop. No last-public-cut diagnosis was retained for that Delivery
loop, and the unjoined original-Store summary remains unavailable. The first
post-admission loader refusal is no longer the observed blocker; complete
publication is not yet qualified.

The maximum-image repair still exceeds ninety seconds, but its original
two-second stop and writer joins now succeed. Its actual joined-Store summary
records `drive_agent / REVISION_CONFLICT`; the last complete public cut has
seven completed invocations, no active worker and reconciliation waiting.
Code inspection identifies a separate deterministic defect: the cached Agent
retains its first final-candidate owner for the whole Run, so a verifier repair
cannot establish its second candidate. The minimal follow-up releases only
the exact current owner after its original completion succeeds. Incomplete,
CAS/SQL failure and retirement-uncertain attempts retain their owner; the
original completion transaction and replay checks remain unchanged. Local
reducer tests cannot substitute for the real Linux two-candidate repair.

The delayed-volume report instead stops before source admission: a strict
read-only owner-history observation encounters SQLite `BUSY`. The
original-stop and late-result reports reach the original five-second READY
deadline before any source Run or authorization request. Their observed
original servers do join; these are not successful publication cut attempts.
The four original CAS operations remain concurrent, fully synchronized,
verified and joined; their JS-await spans are not individual fsync timings.
These failures do not confirm the earlier authorization/time-fence hypothesis
and do not authorize an integrity cache, longer deadline or removed barrier.

The harness follow-up treats only a real SQLite primary `BUSY` as an
unfinished read-only observation; each attempt still closes its complete
transaction and every other error propagates. Initial status and full history
share the original five-second absolute budget, and restart history uses its
existing thirty-second deadline. It adds no database busy timeout. Actual
Delivery terminal failure now synchronously projects its already obtained
public cut, including the closed `agent`/`delivery` operation discriminator;
the same original assertion is rethrown with no additional query, clock,
timer, CAS read or pre-stop wait. Such data is not a native task/join proof.
The candidate-owner and harness components respectively pass 51 and 57
neighboring tests on each of Node 22/24/26, with strict real-dependency checks.
Those component runs are not the combined full build/test or fresh installed
Linux acceptance required before another push or complete PR.

Two additional contract choices remain pending, not implemented: a genuine
worker-probe shutdown cancellation must durably close only its original joined
task without impersonating timeout or worker death; a fixed four-object CAS
stage batch would need to preserve each original durability/crash boundary,
partial-failure cleanup and independent-publisher recovery. Existing in-flight
StateOwner guards and per-object CAS semantics remain unchanged until those
choices are resolved. Neither the full Linux Delivery/repair goal nor the
controlled delayed-storage, original-stop or late-result cuts is complete;
no complete PR or release claim follows from this run.

The next immutable candidate, commit
`8a94bffab3fc709f5e73368d0372c1517665d4a6`, passes the original local build
and full `npm test`: 2,622 passes and one original conditional
cross-filesystem skip, with no failures, cancellations or todos. Its complete
local validation SHA-256 is
`c06a2e346aa35ff69dac030243ab693597dd029e24c7fdaa73ea65f64ba6ea6e`.
[Linux run 40112630205](https://github.com/cogine-ai/cliq-agent/actions/runs/40112630205),
attempt 1, is terminal with seventeen successful and five failed jobs. All
twenty-three categories and 105 original JSON reports (478,072 bytes) are
retained; their lengths and hashes independently match the final capture.
There are no pending, incomplete or rejected report categories. Final capture
SHA-256:
`fbdaddc7f31fe9a47092240bd6fd95bf7f53bfe8317eb83f22abbe8dc5dbf1ac`.

The actual normal Delivery still exceeds ninety seconds. Its last complete
public cut is running/delivery, revision nine, with an active worker, four
items, four Checkpoints and no Journal entry or wait. This time its original
two-second stop and all writer joins succeed. The joined Store summary has
two scheduler errors, but its first `drive_verify` error is process-wide and
cannot be attributed to this Delivery; the second may have occurred during
Stop. Neither the cut nor that summary proves a new execution defect or a
deadlock. More precise fixed publication-stage and error-window diagnosis is
needed before changing the production path.

All three delayed-volume campaigns pass the original five-second READY bound,
then fail their first authorization before source admission. Each joined
original-Store summary identifies `transaction / kernel / REVISION_CONFLICT`.
On the actual create path this uniquely identifies the guard requiring the
time fence not to advance beyond the immutable pre-publication grant time.
It does not identify the advancing transaction or exclude a later real clock
regression. Separating preparation time from actual commit time requires an
explicit creation/revocation/history contract decision; it is not permission
to remove the guard, reuse an old fence timestamp, extend TTL or retry effects.
The additional four-object CAS stage batch is not needed to explain this
observed blocker and remains unimplemented; original per-object durability
boundaries are retained.

The maximum-image verifier report is only a false-qualification fallback:
the unchanged scanner reaches its cumulative 4,096-stream bound, closes all
4,096 streams and reports no secret match. It retains no original execution
phase, so it cannot establish that repair, terminal completion or Stop passed.
The final copied-SQLite scan opens a separate stream for each logical value,
but this code fact alone does not locate the actual exhaustion. Fixed failure
stage and pre-corpus counters are needed; no stream may be merged, omitted or
relabeled to evade the original budget. Normal Delivery, verifier repair,
controlled-storage, original-stop and late-result qualification remain open.
No complete PR has been opened.

The next local diagnostic follow-up preserves the actual execution path and
adds six closed publication work labels only in subscribed qualification
images. Its original bounded exit summary also retains the actual failure
count at Stop entry and the final scheduler error, without replacing the
first error or attributing any error to a Run. Scanner refusal retains only
its first fixed failure stage, the original pre-corpus byte/stream counts and
the existing closed corpus error code. Every scan, independent stream, limit,
original error and close/join requirement remains in force. Component build,
strict checks and focused regressions pass; a deliberately reversed scanner
close/observer order fails the corrected regression. These diagnostics do
not establish a production root cause or complete local/Linux qualification.
Creation/revocation preparation-versus-commit time and genuine worker-probe
shutdown cancellation still require their separate contract decisions.

### Approved complete closure follow-up, 2026-10-25

The owner has now approved all three contracts together: genuine original
worker-probe shutdown cancellation with unchanged original deadline/backoff;
the fixed-four CAS stage batch preserving every durability/crash boundary;
and immutable authorization preparation P versus actual fenced commit C.
The canonical RFC, control-peer clarification and WP01/WP04/WP06 specify those
same rules. Local genuine Store/CAS/SQLite regressions, real file-operation
failure prefixes and pure-data closure decoders validate their respective
layers; controlled Date samples are not real Linux wall-clock evidence.

The old cancelled-recovery campaign paused a controller and waited for the
thirty-second timeout. Its replacement observes the original signed unpaused
controller, then requires actual Store.close/resource join within two seconds
and a genuine pre-deadline cancellation closure for the same nonce. Missing
the live cut fails qualification rather than accepting an idle close. The
later fresh-probe recovery still observes the original deadline/backoff and
independently proves physical retirement. This is not installed Supervisor
SIGTERM evidence. No blocked pause scheme is retried by this replacement.

At this point the combined full build/test and new immutable Linux run are
still pending. Normal Delivery, maximum-image repair, controlled-storage,
original-stop and late-result qualification remain incomplete. No complete PR,
full I1, provider, macOS, reboot, I2-I4 or final Kernel-Cut claim follows from
these contract approvals or local component tests.

The approved combined candidate, commit
`0be8c22fe945ef7529bba25b64705e372a4d40cb`, passes the original local build
and full `npm test`: 2,651 passes and one original conditional
cross-filesystem skip, without failures, cancellations or todos. Its complete
local validation SHA-256 is
`869981d205ba388a6de211bb76f57c5a0989b5c2f4c5fd6a98f62ccc2ea19ce7`.
[Linux run 40121392186](https://github.com/cogine-ai/cliq-agent/actions/runs/40121392186),
attempt 1, finishes with sixteen successful and six failed jobs. All four
Linux/macOS Node 22.13/24 test jobs pass. Twenty-two report categories and 100
original JSON reports (484,691 bytes) are retained and independently verified;
the original-stop job fails its portable source-wiring preflight and produces
no physical-cut report. Missing reports are not counted as passing. Final
terminal capture SHA-256:
`f81b761e9ad165154bead617467a9e0d6af23a64aad87d9ec655ecfa40425235`.

The unpaused worker campaign reaches the original live task, genuinely joins
Store.close in 61.136 ms, durably closes the same nonce before its original
deadline, then independently completes successor physical recovery. The whole
native job nevertheless fails a later existing retirement-uncertainty
regression: an earlier uncertain resource close remains sticky, but shutdown
could close its wait before ultimately rejecting that same uncertainty. The
minimal correction checks the retained original cleanup failure after genuine
task join and before durable nonce closure. It does not change the existing
Linux assertion, mint a task receipt or discard an uncertain resource owner.
The later real regression must pass before this correction is qualified.

The original-stop preflight still expected four independent CAS publishers.
Its correction checks the approved single fixed-four batch, complete canonical
bytes and metadata, full join and final native revalidation before channel
registration. All eleven workflow portable MJS suites pass locally (98 tests);
that is not a replacement for the previously skipped installed Stop campaign.

The verifier repair now fails the original strict retirement proof rather than
the terminal deadline. The report does not retain enough data to identify
which of its state, context or item-sequence checks rejects, so those three
existing checks gain fixed diagnostic substage labels only. Their operations,
order and original error are unchanged. Normal Delivery still exceeds ninety
seconds and fails its original two-second Stop. Both delayed-volume campaigns
pass five-second READY and proceed beyond the former authorization transaction
refusal, but later exceed a thirty-second request and fail Stop; their precise
internal admission blocker remains unknown. Cross-checking the complete fixed
first-source call prefix, the same client's response-count semantics and empty
completed-case list identifies the pending original `run.submit`; response
counts alone would not establish that method or its internal stuck operation.

Publication diagnosis now emits at most six distinct fixed first-arrival
labels, less than 512 bytes in total, immediately in the already subscribed
qualification image. They contain no Run identity, clock, result, latest-stage
or join claim. After an abnormal Stop, the harness may read only these labels
from the previously bound original process/invocation window, after actual PID
absence and within the existing bounded, independently secret-scanned journal
read. This does not satisfy successful Stop or writer join, replace its original
error, or unlock the old exit-summary parser; the latter retains its original
sixteen-line/4-KiB bounds and successful original-join requirements. New labels
and verifier substages are diagnostics, not evidence that any failed cut passed.
Full follow-up local and immutable Linux validation remain required; no complete
PR or broader qualification claim follows from these partial results.
