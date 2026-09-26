# Kernel Work Package Design Review — 2026-09-26

**Design verdict:** READY WITH RISKS for continued hidden integration.
**Release verdict:** NOT READY for Kernel Cut.
**Baseline:** Cliq `0f2fa1465fe577c09ca801b52c65a265d7d17f60` (`main`).
**Scope:** implementation design for the existing six work packages. This review
does not qualify a binary, run a paid provider experiment, or switch production.

The architectural direction remains appropriate: SQLite owns structured current
state, CAS owns immutable bytes, typed native calls express model intent, and a
detached Supervisor coordinates independently verified Runs. JSON still has
legitimate uses as wire encoding and canonical serialization. Replacing every
JSON representation is not a design objective.

The immediate engineering priority is an installed, recoverable execution path
through all six owners. More isolated schema or reducer work is useful only when
it closes a named gap in that path. The six packages are ownership areas, not
six sequential releases; the public product still has one Kernel Cut.

## 1. Authority and current implementation

The [August RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md) remains the
normative semantic/schema contract. Each work package owns its implementation
and acceptance details. This review owns the dated evidence baseline,
cross-package integration order and shared qualification workloads. A finding
here does not silently redefine a closed RFC field, state or guarantee.

| Owner | Verified source state at the baseline | Remaining integration boundary |
| --- | --- | --- |
| [WP01](../backlog/durable-verified-run-kernel/01-durable-state-and-migration.md) | SQLite/CAS admission and M2 state core; native owner lock, process-death takeover, worker-loss fencing and native quarantine relocation | Descriptor-relative SQLite/CAS I/O, complete recovery integration, import, rollback and large-store qualification |
| [WP02](../backlog/durable-verified-run-kernel/02-typed-runtime-and-provider-capabilities.md) | Gate A and substantial Gate B against real StateStore: model/context, tools, approvals, input, retry, root stop/resource/model-failure reducers | Trusted dispatch, remaining continuation families and live provider/billing qualification |
| [WP03](../backlog/durable-verified-run-kernel/03-trusted-execution-and-workspaces.md) | Platform qualification foundation and shared policy/identity primitives | Installed strong backends, private generations, broker, containment retirement and evidence integration |
| [WP04](../backlog/durable-verified-run-kernel/04-detached-supervisor-and-control-protocol.md) | Storage/control reducers and owner/worker-loss foundations | UDS peer capture, application services, OS service, scheduler, restart/reboot recovery |
| [WP05](../backlog/durable-verified-run-kernel/05-agentic-verification-and-recovery.md) | Detailed contracts; reusable legacy verifier/diff code | Real candidate-to-receipt-to-result path, repair, children and explicit delivery |
| [WP06](../backlog/durable-verified-run-kernel/06-ecosystem-surfaces-and-kernel-cutover.md) | Detailed contracts; existing clients/provider surfaces remain legacy | Signed installation, generated clients, platform/provider qualification, migration and production cutover |

Evidence: [M2 boundaries](m2-state-core.md#deliberately-still-open),
[WP02 integration](wp02-typed-runtime.md#gate-b-implementation-status),
[StateStore](../../src/state/store.ts),
[legacy production assembly](../../src/runtime/assembly.ts), and
[package contents/scripts](../../package.json). In particular, the npm file list
does not yet deliver the native StateOwner helper as a qualified installation.
Neither merged source nor a platform probe proves an installed end-to-end Run.

## 2. External evidence and applicability

Upstream default-branch heads were refreshed on 2026-09-26 (Taipei). These are
source observations, not claims about published releases or locally reproduced
runtime behavior. The old `badlogic/pi-mono` repository now resolves to
`earendil-works/pi`; keep the canonical repository and commit in future reports.

| Project and pinned source | Observed practice and maturity | Decision for Cliq |
| --- | --- | --- |
| OpenCode `adee738d1e4597a2d0d317ca61a1625eff289efa`: [V2 Session contract](https://github.com/anomalyco/opencode/blob/adee738d1e4597a2d0d317ca61a1625eff289efa/specs/v2/session.md), [coordinator](https://github.com/anomalyco/opencode/blob/adee738d1e4597a2d0d317ca61a1625eff289efa/packages/core/src/session/run-coordinator.ts) | Durable input admission precedes execution; replay cursors exclude live deltas. The V2 schemas are experimental; crash continuation and distributed execution fencing remain follow-ups. Active execution coordination is process-local. | Use admission/replay and display separation as comparison cases. Keep Cliq's existing Run/Journal and cross-process fencing; do not import the V2 event-sourced Session model. |
| Codex `58670eeac4b0bdb9fcb86929d8631c14aee0d9f6`: [daemon lifecycle](https://github.com/openai/codex/blob/58670eeac4b0bdb9fcb86929d8631c14aee0d9f6/codex-rs/app-server-daemon/README.md), [rollout recorder](https://github.com/openai/codex/blob/58670eeac4b0bdb9fcb86929d8631c14aee0d9f6/codex-rs/rollout/src/recorder.rs), [state database integration](https://github.com/openai/codex/blob/58670eeac4b0bdb9fcb86929d8631c14aee0d9f6/codex-rs/rollout/src/state_db.rs) | JSONL rollout persistence coexists with SQLite metadata. The daemon is experimental and documents package/version/environment behavior; update restart can interrupt active or queued work. | Test real packages, version skew and restart as one lifecycle. Do not infer that SQLite eliminates migration work, or copy embedded-runtime fallback into durable admission. |
| Codex [Linux sandbox](https://github.com/openai/codex/blob/58670eeac4b0bdb9fcb86929d8631c14aee0d9f6/codex-rs/linux-sandbox/README.md) | Bubblewrap, namespaces, seccomp and proxy routing are combined; filesystem-only isolation does not cover every IPC boundary. | Qualify the complete process/filesystem/network/IPC boundary using the shipped helper and actual policy. A backend name is insufficient evidence. |
| Pi `d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31`: [CLI Session format](https://github.com/earendil-works/pi/blob/d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31/packages/coding-agent/docs/session-format.md), [new SQLite backend](https://github.com/earendil-works/pi/blob/d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31/packages/session-backends/sqlite-node/README.md), [server](https://github.com/earendil-works/pi/blob/d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31/packages/server/README.md) | The CLI documents JSONL trees. The separate durable core has a SQLite backend and experimental server. That backend relies on the host for one writer and explicitly omits cross-process lease/fence/takeover. | Separate interface simplicity from ownership assumptions. Reuse Cliq's existing StateOwner rather than adopting Pi's unsupported cross-process-write assumption. |
| Pi [runtime simplification](https://github.com/earendil-works/pi/blob/d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31/packages/agent/docs/runtime-simplification.md), [tool durability](https://github.com/earendil-works/pi/blob/d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31/packages/agent/docs/tool-durability.md), [assistant durability](https://github.com/earendil-works/pi/blob/d6af72e1857cfb10b41d8ff8e69f0d72b4cf6d31/packages/agent/docs/assistant-durability.md) | Narrow mutation interfaces, observation-only caller cancellation, staged parallel tool outcomes and auxiliary partial output separate several concerns. These documents describe the newer harness. | Reduce caller sequencing and repeated decoding; retain real race checks. Keep sequential native batches for this cut. Partial output remains non-authoritative; no new durable streaming subsystem is required. |

Workspace Trust still follows this repository's CodeBuddy/Codex/Claude Code
reference policy. OpenCode and Pi runtime comparisons above do not change the
first-run trust gate or imply tool permission or OS containment.

## 3. Findings and resolved design changes

Priorities describe impact on implementation, not an assertion that an
unshipped feature is already a production defect.

| ID | Finding | Design disposition and owner |
| --- | --- | --- |
| KDR-01 / P1 | WP01's copied `ToolResultPayloadV1` lacks the invocation/user-input discriminator; copied `UserInputPayloadBaseV1` omits authenticated wait/request/revision/channel bindings present in the RFC. | Align the copies with the RFC. Add a repeatable shared-type consistency check. WP01 owns validation; WP02/WP04 consume the same user-input branch. |
| KDR-02 / P1 | RFC implementation summary still lists native owner takeover as open; WP05 instructs implementers to use fake storage until entire packages finish. | Correct the status and integrate new reducers against actual SQLite/CAS now. Fakes remain only at unreleased external execution boundaries. |
| KDR-03 / P1 | Local modules can pass independently while packaging, UDS, containment and verifier integration remain absent. | Move one installed vertical path to the next integration checkpoint. WP06 participates from its first commit; it is not an end-of-program packaging phase. |
| KDR-04 / P1 | Persistence correctness is detailed, but scale workloads and startup timing measurements are not operationally defined. Current recovery reads also use unbounded `Promise.all` over artifact refs. | Bound artifact I/O concurrency, measure startup/attach/recovery separately, and qualify small and large histories. Keep complete closure validation before execution. WP01/WP04. |
| KDR-05 / P1 | A signature cannot substantiate a provider's hard billing ceiling. This can block the entire billable path despite adapter correctness. | Require a release eligibility record per endpoint/model/adapter and test it before expanding the integrated path. Missing evidence stays `MODEL_COST_UNKNOWN`; a change to budget semantics needs a separate RFC. WP02/WP06. |
| KDR-06 / P2 | Large copies of shared schemas create multiple editing locations and have already drifted. | Replace only mechanically verified identical code blocks with section-specific RFC links. Retain package-owned definitions and surrounding requirements. Check remaining shared copies for structural equality. |
| KDR-07 / P1 | A caller could accidentally rebuild recovery/cancel/approval logic beside existing loaded-Run reducers. | One typed application-service path for live, replay and recovery entry. Keep mutable checks at StateStore/broker release boundaries; hide static validation in loaded modules. WP01–WP04. |
| KDR-08 / P2 | Adopting upstream streaming or parallelism wholesale would add queues, partial-result recovery and another transport contract. | Bound existing observer/display work; retain pull-based `run.attach` and sequential batches. Measure before proposing a new feature. WP02/WP04/WP06. |
| KDR-09 / P1 | Generic exit-code-only repair feedback may be too weak to deliver useful autonomous repair. The v1 redaction policy deliberately removes all verifier output. | Add an explicit repair-utility experiment using the actual v1 projection and frozen repair budget. Do not quietly inject raw logs. A bounded diagnostic projection amendment is the next design action if the experiment fails. WP05. |
| KDR-10 / P1 | Strong macOS support, provider eligibility and secure credential stores are necessary product prerequisites, not paperwork after feature completion. | Track their concrete qualification evidence at I1. A blocked prerequisite prevents release readiness; it cannot be hidden by a successful fake-provider demo. WP03/WP06. |

The changes deliberately add no aggregate, generic workflow framework, tool
plugin ABI, alternate persistence backend or new public protocol method.

## 4. Module boundaries and integration rules

| Module / owner | Interface responsibility | Hidden implementation and prohibited leakage |
| --- | --- | --- |
| StateStore / WP01 | Typed admission, loaded Run operations, consistent recovery reads, atomic typed commits | Own SQL, CAS reachability, owner/lease/revision checks and response replay. Callers do not construct arbitrary row patches or choose settlement amounts. |
| ModelSession and continuation / WP02 | Prepare one exact request; observe bounded wire input; return complete typed turns/plans | Own provider mapping, static assembly validation and context construction. No SQL, dispatch, credential acquisition or provider-specific Run branches. |
| Execution boundary / WP03 | Validate a frozen launch/request; perform authorized I/O; report exact observations | Own descriptors, native containment and broker transport. Do not create a second scheduler, lease store or business outcome reducer. |
| Supervisor application services / WP04 | Authenticate commands, invoke typed operations, schedule eligible work, drive reconciliation | Own service/timer lifecycle. Queue maps and notifications are rebuildable hints; Run/launch/Journal facts remain in StateStore. |
| Verification and delivery / WP05 | Construct candidate-bound plans, classify evidence, propose repair/result/delivery transitions | Own verification meaning. StateStore still enforces the sole terminal commit. A verifier exit or model final message cannot directly set success. |
| Clients and installation / WP06 | Generate schemas/clients, install pinned bundles, render snapshots and prescribed recovery actions | Own presentation and package lifecycle. No client persistence authority, privileged repair shortcut or alternate runtime when connection fails. |

Use existing `StateStore.loadAgentRun`, `ModelSession` and typed reducers before
introducing another facade. A new interface is justified when it hides a real
invariant or platform difference; a forwarding wrapper per work-package heading
is not useful. No public generic `advance`, `applyMutation`, event reducer or
caller-provided transaction callback replaces the closed operations.

Static closure validation may be retained inside one loaded immutable handle.
Current owner, revision, stop, grant, time and release-fence checks still run at
their authoritative boundary. Cache neither mutable permission nor process-death
evidence as if it were immutable model metadata. An I/O completion can race a
stop or takeover even if ordinary planning is serialized.

## 5. Internal integration checkpoints

These are implementation checkpoints inside the one Kernel Cut. Passing one
does not release a partial product, relax platform support, or mark all work
packages complete. Each checkpoint extends the same executable scenario.

| Checkpoint | Required real path | Exit evidence |
| --- | --- | --- |
| I1: installed execution and restart | Signed bundle/bootstrap → StateOwner → authenticated UDS → durable admission → actual strong containment/private generation → one typed local workspace operation → ready Checkpoint → client reconnect and Supervisor restart | Package manifest/digests, backend qualification, accepted Run identity, SQLite/CAS cut, old-containment death, fresh generation and unchanged external effect count. Start on qualified Linux; require the same path on supported macOS before I2 is considered cross-platform. |
| I2: verified result and explicit delivery | I1 plus a qualified model, required verifier, immutable candidate/receipts/result, result inspection, drifted private merge and explicit apply permission | Real `succeeded` proof, no-check `completed_unverified` counterexample, changed-result re-verification, preserved displaced bytes, independent delivery status; no model or verifier mock establishes this checkpoint. |
| I3: complete behavior and recovery | I2 plus approvals/input, denial/cancel/deadline, compaction, children, MCP, dependency setup, unknown effects and all registered provider paths | The fault table below passes, with exact budgets, full batch closure and no additional dispatch on replay. All required WP acceptance criteria remain applicable. |
| I4: release qualification and cutover | I3 from clean installed packages; upgrade/skew, migration/rollback, large-state workloads and all clients | Six package gates plus RFC's 24-hour/50-repository/10-crash-location campaign, supported-platform evidence and user outcome measurements. Only then remove legacy composition and cut over. |

Before real provider qualification, a scripted endpoint can exercise I1 transport
and failure mechanics; label it a fixture and keep I1's model evidence pending.
It cannot establish capability or spend bounds. Managed Ollama is an eligible
alternative only when its complete signed local-service/no-egress contract is
actually qualified, not merely because a loopback server responds.

The first installed bundle has one necessary ordering constraint: fresh-empty
StateStore genesis rejects a prepopulated CAS. The installer first verifies and
fsyncs an unselected candidate executable in a private staging directory. That
exact signed Supervisor runs the initial owner acquisition against the empty
StateRoot, imports the verified package graph into CAS while it owns the store,
and releases the owner. Only after a complete import and candidate self-test
may the installer publish the immutable `bundles/<bundleDigest>` directory and
select it through `active.json`. A crash before selection leaves no selectable
candidate; retry must reopen the same signed owner authority, inspect any
retained genesis and unrooted CAS objects, and finish or fail closed. Update
candidate self-tests remain read-only against an existing authoritative store.

The signed `supervisor` entry must cover the executed JavaScript as well as the
Node runtime. Hashing a plain Node interpreter while loading replaceable script
files would not bind the Supervisor implementation. The current packaging
direction is a Node 24 single-executable application with one bundled CommonJS
entry, no snapshot/code cache, and `execArgvExtension='none'`; native helpers
remain separate signed entries beside that executable. Sign/notarize the final
macOS image before recording its complete-file digest in the manifest. The SEA
fixture gates signed-package import and StateOwner restart with a disposable
test key; installed and production-signature qualification still require the
full I1 path.

Next implementation order within I1: finish WP03 containment/descriptor evidence
and WP04 UDS capture; connect the existing admission/worker-loss reducers; ship
that composition with WP06's stable bootstrap; then execute the restart scenario.
WP05 builds its result reducers on the same real store in parallel with that
work, rather than waiting for all of WP01–WP04 to finish.

## 6. Cross-package fault evidence

Every case records baseline commit, installed bundle/helper digests, platform,
starting Run revision/frontier, injected boundary, post-restart authoritative
closure and observed external effect count. Seed and fixture definitions belong
in the test repository; secret bytes do not belong in the evidence report.

| Boundary / owners | Required observation after restart or retry |
| --- | --- |
| Admission commit before reply / 01,04,06 | Same admission identity returns the accepted Run; changed intent conflicts. No second Run or new workspace capture on equal replay. |
| CAS publish before SQLite commit / 01 | No ready reference to missing bytes; an unrooted object grants no authority and remains subject to existing orphan retention. |
| Worker reserved, spawned, activated / 01,03,04 | No untracked productive worker; each predecessor is positively retired before replacement activation. |
| Claim before release; release before result / 01,03,04 | Exact no-release proof or typed ambiguity according to the existing Journal contract; absence of a reply never proves no effect. |
| Tool mutation before result/Checkpoint / 01,02,03 | Restore/reconcile the correct generation; no result over the pre-effect workspace and no blind replay. |
| Approval/input commit before reply / 01,02,04,06 | Same control response and one continuation; stale/different wait or channel identity cannot resolve a new wait. |
| Model stream interrupted / 02,03,04 | Partial calls remain inert; released spend remains conservatively settled and no complete candidate is fabricated. |
| Verifier assertion/infra/source mutation racing stop / 01,03,05 | Exact precedence, same-source receipt, no infra-driven model repair and no success before quiescence. |
| Child terminal while parent runs or waits / 01,04,05 | Exactly one allocation settlement; no unsolicited running-parent revision change; no lost wake after restart. |
| Publication exchange before receipt / 01,03,05 | Preserve displaced bytes; complete only the permitted leaf recovery/abort path. Original agent result stays immutable. |
| Event page / slow or disconnected client / 01,04,06 | Same read-cut bounds, ordered retained events and prescribed expiry reset; Run progression does not depend on client consumption. |
| Bundle selection, startup failure, reboot / 01,03,04,06 | One owner; compatible pinned recovery or `drain_required`; no embedded fallback, overwritten bundle or incompatible downgrade. |
| Import/rollback marker boundary / 01,06 | One authoritative generation, secret-free complete backup/archive, idempotent recovery and no synthetic legacy Runs. |

This table chooses integration cases; it does not replace the longer per-package
fault matrices. `test:fault` must fail if a required child suite is absent or
skipped, as the RFC already requires.

## 7. Scale and latency qualification

Use deterministic generated fixtures in addition to the 50 real repositories.
The sizes below are qualification workloads, not new admission limits or a
promise that every host supports them. A failed workload is recorded as a failed
gate; it is not silently reduced to make the report green.

| Workload | Sessions / historical Runs / items | CAS bytes | Purpose |
| --- | --- | --- | --- |
| Development | 100 / 1,000 / 100,000 | 1 GiB | Query plans, bounded artifact I/O, replay and fault regressions |
| Release | 10,000 / 100,000 / 10,000,000 | 50 GiB | Startup, import/rollback, event/list pagination, retained history and disk pressure |

Both include a full 128-entry runnable queue, waiting/unknown Runs, retained
launches, many small artifacts and a few large artifacts. Historical Run counts
are predominantly terminal; active work remains within RFC concurrency limits.
Vary artifact fan-out and deduplication independently of byte volume. Fixtures
must obey actual item/source bounds rather than bypassing admission schemas.

Record hardware, filesystem, free space, OS/backend, Node/native ABI and exact
fixture version. Use at least 1,000 attach samples under active writes and 30
fresh Supervisor starts per workload. Report warm-process and fresh-process
results separately; a restarted process is not proof of a cold OS disk cache.

- Preserve RFC p95 attach below 1 second and recovery scheduling beginning within
  5 seconds of startup. Measure startup from Supervisor process entry, including
  owner acquisition; measure attach from client request to a complete validated
  page. Report lock/startup refusal separately, without dropping failures.
- Also report time until each recovered Run is safely eligible, full closure
  validation time, WAL/SQLite write latency, CAS bytes read/written, RSS high-water,
  file-descriptor high-water and event-loop delay. Starting a scan is not proof
  that recovery completed or an effect was safe to resume.
- Keep startup/list/attach memory and work independent of unrelated terminal
  history. SQL uses bounded indexed reads. CAS validation uses a fixed-size I/O
  pool and bounded pending work, while still visiting the complete required
  graph. A single Run's required closure may be large and must be measured.
- Import is an explicit, resumable operation using the existing migration
  control phases. It has progress and disk requirements, not a small arbitrary
  startup timeout or a metadata-only success shortcut. No background dual write
  or partially imported authority is introduced.
- Test disk-full, denied I/O, missing/corrupt objects, WAL recovery and interrupted
  reachability walks. Incomplete validation never releases execution or GC.
  No new automatic deletion of authoritative history is permitted.

WP01 supplies fixture/integrity/query evidence; WP03 supplies materialization and
containment timing; WP04 supplies scheduling/attach measurements; WP06 runs the
installed-package campaign. Performance optimization may change indexes, I/O
batching and physical copies, never the recovery cut or success semantics.

## 8. Developer journey and release decisions

**Persona:** a maintainer installing Cliq on a supported machine and delegating
one small repository change with one explicit required verifier.
**Journey verdict:** READY WITH RISKS as a design; NOT READY in the current build.

The first useful result is an inspectable verified artifact after disconnect,
not a successful install, a streaming transcript or an accepted Run alone.
The install guide and generated-client example must exercise this exact sequence:

1. Install the signed client/runtime/bootstrap and obtain platform readiness.
2. Enroll one provider credential through the supported secure store, or select
   an actually qualified managed local model; see capability/budget eligibility.
3. Enter a supported repository, make the Workspace Trust decision, choose one
   objective and one required verifier, and review operation permission.
4. Submit detached; retain the returned Run id. Retry a lost reply with the same
   command identity. Do not invent a new admission key for transport retry.
5. Close the client, reconnect, inspect the authoritative state and retrieve
   the result/receipt. Apply is a later explicit operation and decision.

**TTHW design budget:** at most five documented command invocations from a clean
supported install to submitting and retrieving the first result, excluding
provider execution time and explicit interactive trust/permission choices;
zero hand-edited internal files, SQL fixes or manually copied artifact hashes.
Credential enrollment is at most one provider-account flow for this journey.
Record actual elapsed time and command/decision counts on clean-machine runs;
the five-command target is a UX acceptance target, not a measured current fact.
Repeat runs reuse valid setup and need only submit plus inspect/attach.

| DevEx finding | Required change | Owner / gate |
| --- | --- | --- |
| PDX-001 / P1: reply loss can tempt callers to create another Run | Generated example retains request/admission identity and demonstrates exact replay | WP04/WP06, I1 |
| PDX-002 / P1: setup failure is not actionable without its layer | Version/eligibility errors name the failing stage and one supported next action | WP06, I1/I2 |
| PDX-003 / P2: reconnect semantics can diverge between clients | Example drains a read cut and performs the prescribed cursor-expiry snapshot reset | WP04/WP06, I1 |
| PDX-004 / P1: source builds hide installation/update failures | Exercise documentation using shipped artifacts on both supported platforms | WP03/WP06, I1/I4 |

Three prerequisites must be evidenced early: a signed working macOS backend,
credible billable-provider ceilings (or a genuinely qualified managed local
path), and accessible supported credential stores on target Linux machines.
The repair-utility experiment is also a product gate: freeze its corpus,
selected model, scoring rules and minimum repair success threshold before
execution, then report every attempted case. On those repairable failures,
compare the v1 exit-code-only projection with the same
agent given actionable bounded diagnostics, using equal model and budgets.
Report solved tasks, extra inspection/model work and exhausted repairs; do not
claim a gain from a change in required verifiers or an enlarged repair budget.
This comparison requires separately authorized model execution when billable.

If these constraints make the intended product impractical, write a focused RFC
with a concrete replacement and its acceptance evidence. Do not relax sandbox,
billing or log-redaction guarantees inside an implementation PR. Parallel tools,
live push streaming, broader stateful MCP and Windows execution remain deferred;
none is needed to complete the currently agreed Kernel Cut.

## 9. Review maintenance

Run `node scripts/kernel/check-design-contracts.mjs` after schema documentation
changes. It checks shared TypeScript definitions structurally, ignoring comments
and formatting; it does not prove runtime implementation or wire compatibility.
Kernel foundation CI runs this guard and its focused regression suite
(`node --test scripts/kernel/check-design-contracts.test.mjs`) before the build.
Keep new shared definitions at their canonical owner and link to them. Existing
nonidentical prose still needs human review.

An implementation PR updates its owner's evidence and current status in the same
change. Record a gate as passed only with the relevant real-store, process,
installed-package or live-provider evidence. This prevents future reviews from
treating a design, a probe and a shipped behavior as the same accomplishment.

### Validation of this design revision

- All six package documents and the RFC status/integration pointer were updated.
- Twelve whitespace-normalized, verbatim RFC code blocks were replaced with
  links to their owning sections; package-owned definitions and surrounding
  behavioral requirements were retained.
- The consistency guard parses 380 RFC definitions, four explicitly
  package-owned definitions and the remaining 249 shared copies with no drift.
  A negative control using the unmodified baseline fails for exactly the two
  KDR-01 definitions, demonstrating that the check detects the original problem.
- Local Markdown file/section links and `git diff --check` pass.
- Shipping self-review corrected the guard's handling of type operators and
  template-fragment text. Its nine focused regressions pass, including missing
  or optionalized bindings, discriminator changes, operator/template drift,
  conflicting repeated definitions and invalid syntax. CI runs both the suite
  and the guard on the existing macOS/Linux Node matrix.
- `npm run build` passes. On macOS arm64 with Node v24.16.0,
  `env PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH" npm test` passes all 1,613 tests
  with zero failures or skips. The initial default-PATH run was stopped after
  independently reproducing MacPorts `/opt/local/bin/bash -lc pwd` blocking
  with open stdin; system `/bin/bash` completed that same probe. The final run
  changes only command-local PATH precedence, not repository behavior or user
  configuration.
- Runtime code and production composition were not changed. Installed-platform,
  live-provider, performance and repair-utility campaigns were not run; they
  remain implementation/release evidence beyond build and unit/integration tests.
