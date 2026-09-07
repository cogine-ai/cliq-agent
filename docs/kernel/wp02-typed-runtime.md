# WP02 Typed Runtime Implementation Design

This design implements [WP02](../backlog/durable-verified-run-kernel/02-typed-runtime-and-provider-capabilities.md)
under the [Durable Verified Run Kernel RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md).
The RFC owns shared durable schemas; this document owns implementation seams.

## One program, two review gates

1. **Gate A — trusted model attempt:** immutable loaded authority, exact native
   request bytes, incremental response observation, and one compiled result.
2. **Gate B — typed continuation:** direct tool inputs, whole-batch validation,
   ordered results, policy/context/UI integration, and durable compaction.

These are integration gates, not new product slices or independently evolving
protocols. Gate A does not switch production composition or claim that Gate B,
broker integration, or provider qualification is complete.

Gate A landed in PR #489 (`a153d47`); the model/context continuation landed in
PR #490 (`c29179f`), and direct tool-input contracts landed in PR #491
(`eb93f46`), and canonical tool policy/continuation landed in PR #492
(`04b2ba6`), followed by durable ordinary-tool approval in PR #494 (`3b0de21`)
and durable user input in PR #495 (`fafc940`), then model retry eligibility in
PR #496 (`b1f7ca6`) and the root cancellation/deadline stop core in PR #497
(`412d280`).
Gate B also includes the minimum WP01
companion work needed to exercise the real SQLite/CAS continuation. The user
approved that scope on 2026-09-05 and the minimum WP03 canonical tool
policy/profile/grant companion on 2026-09-06. This does not transfer storage or
security ownership to WP02 or include the rest of WP01 migration, WP03 brokers,
WP04 scheduling, WP05 verification, or WP06 production cutover. The follow-up
integrates the existing RFC ordinary-tool approval and user-input reducers as
minimum WP01/WP04 companion work, not separate product slices or new protocols.

The original M2 Journal reserved and settled budgets but had no model-turn,
tool-batch/result, or compaction commit reducers. Generic request/result
metadata is not validation of the retained typed model contract. Gate B must
bind the exact model request and full reservation before claim, commit a
completed observation together with its typed continuation, and recover that
continuation from the retained state. A mock state adapter cannot establish
these properties.

The implementation tests cross `ModelSession` and `StateStore`: whole-batch
prevalidation, one ordered result per call, denied/error continuation, stale
revision and duplicate completion rejection, and atomic context/Checkpoint
updates. Store methods derive changes from the current frontier and retained
artifacts; no public generic item append, frontier patch, or caller-selected
budget settlement is added. SQLite transactions and the existing CAS remain
the only durable implementation. Private transaction helpers may be shared
only after the typed reducers have validated their complete input closure.

### Gate B implementation status

The model-attempt/context lifecycle, direct tool-input projection and canonical
ordinary-tool continuation now connect to StateStore. These are integration checkpoints inside Gate B, not new work
packages or a declaration that Gate B has passed:

- `StateStore.loadAgentRun` loads the retained assembly against the actual Run
  admission/deadline/budget, then derives normal prompts from retained context.
  Its handle retains static authority only, never a second mutable Run state.
  Tool lifecycle results are detached, deeply frozen records; returned request,
  target and budget objects cannot mutate shared authority or budget templates.
  Input schemas compile once from the verified manifest using a pinned standard
  JSON Schema validator (Ajv, draft-07); validation consumes typed values without
  coercion, defaults, stripping, JSON repair, external schema loading, async
  schemas, or a caller-supplied resolver. Unknown dialects/keywords fail closed.
- `loadToolContracts` binds compiled builtin input semantics to the frozen
  name/version/schema/access/replay contract. `read`, `edit`, `bash`, `ls`,
  `find`, `grep`, `plan`, `todo`, and `request_input` accept direct typed inputs.
  The same normalized value determines display and the loop signature, plus
  policy intent for ordinary tools; `request_input` is a control transition.
  MCP uses its final exec-class contract and exact frozen registration/server
  tool identity, even if its exposed name matches a builtin. There is no tool
  executor or ambient skill activation behind this interface.
- `readToolInvocation` reads a SQLite recovery cut, revalidates **every** call
  in the retained batch, and checks that the frontier follows exactly its
  ordered result prefix. Its immutable result contains the current invocation
  and display, plus an action-free policy subject only for ordinary tools, not
  an OperationGrant or dispatch permission. Restart reproduces the same
  normalized input and loop signature.
- `prepareModel` derives the operation, zero-based Journal attempt, exact native
  body and full signed reservation. Generic invocation admission cannot bypass
  that path for typed Runs; generic completion/refunds cannot replace its checks.
  The shared permanent claim additionally binds the exact agent frontier,
  native request body/projection and ready context (or compaction source), then
  rechecks the cut inside the existing live-lease/highest-attempt transaction.
- `completeModel` independently reads/revalidates the retained result closure and
  commits settlement, model item, batch, synthetic results, context, frontier and
  Checkpoint in one transaction. Invalid batches dispatch nothing. Unusable
  observations retain their raw bytes and full charge, with no semantic retry.
- Recovery requires transitive model/input/result artifacts. Loading the agent
  reconstructs projections from their original immutable sources, reproduces
  retained native requests, and revalidates normalized inputs and continuation
  items. `readModelAttempt` returns the exact retained attempt and its Journal
  phase and Journal-derived retry readiness; neither grants permission to
  resend a claimed or settled request.
- `prepareModel` selects the greatest safe whole prefix under the frozen
  compaction equations, protecting the recent suffix and complete tool batches.
  Source text is JCS of the existing model-visible message array, with no audit
  refs or extra instruction framing. The compaction plan/frontier, request and
  full reservation commit together. Its result commits the summary item,
  replacement context and ready Checkpoint with an unchanged workspace state.
  Original items remain durable; control digests bind the normative ordered
  `{itemSeq,kind,payloadRef}` tuples. The complete next prompt must shrink.
- An impossible compaction publishes exact estimate evidence and makes no
  invocation. Invalid or ineffective executed compaction is fully charged,
  leaves the old context intact, and returns `context_compaction_failed` evidence
  without semantic retry. A valid but ineffective summary remains a usable
  observation in the Journal, not an accepted context summary.

### Canonical tool authority and continuation

The 2026-09-06 approved integration implements the following as one coherent
change, without adding public milestones:

- Trusted Supervisor composition may supply release public keys to
  `loadAgentRun`. Loading verifies a real Ed25519 RuntimeBundle signature, its
  exact selected builtin/worker/provider entries, and the sole non-executable
  policy profile with its empty structured-member closure. Complete-byte CAS
  refs and self-omitting semantic digests remain separate. Keys never come from
  Run/repository/worker input. Once a Run retains any policy decision or tool
  approval wait, loading
  it requires those keys even for read-only tool projections; missing keys are
  `RECOVERY_REQUIRED`, not permission to skip decision replay. This verifies
  selected authority, not bundle installation, every other structured-root kind,
  or the running executable.
- The fixed `tool-policy` evaluator uses the RFC mode table and rule precedence,
  reproduces channel evidence from the normalized call and exact request/target,
  and derives ordinary-tool grants from direct allows or exact retained user
  approvals over an `ask`. The entire winning
  evidence is compared, including unsafe-allow downgrades and the real winning
  rule id. Source refs, builtin denies, workspace/principal, frozen execution
  contract, retry ceiling and Run lifetime cannot be substituted.
- `prepareTool` reads the current SQLite frontier, publishes evidence, and
  commits a direct allow's policy item, grant, one-call reservation and Journal
  preparation together. A deny closes exactly its current call with a ref-free
  `TOOL_CALL_DENIED` result and no Journal/charge. An ask returns
  `approval_required` evidence plus a planned WaitingSubject/checkpoint identity
  without grant, claim, cursor advance or mutable Run change. The trusted caller
  then quiesces the worker and commits `waitForToolApproval`; ask detection alone
  is not permission to leave a worker alive while showing an approval prompt.
- `claimTool` independently reproduces the grant, then permanently claims only
  the current exact request under the live lease, revision, time fence, expiry
  and attempt ceiling. Generic StateStore claim/settlement methods cannot bypass
  typed tool validation. No broker release gate or target I/O occurs here.
- `completeTool` accepts a retained observation ref, not a caller result/charge
  or success boolean. It binds request/target/grant/dispatch, validates bounded
  output against the frozen schema, and atomically commits Journal settlement,
  model-safe result, context, ordered frontier and Checkpoint. A received tool
  error is a **completed, fully charged observation**, not proof of no release.
  Invalid output becomes a retained protocol-error observation; diagnostics and
  authorization records are not added to the model-content envelope.
- Non-read tools must retain the post-effect workspace, snapshot and positive
  retirement proof in that observation. The proof binds the checkpointing
  generation, exact launch/containment and current inspector process/lock and
  signed Supervisor identity. Completion seals the generation, retires the
  worker and queues the Run in the same transaction. Read-only completions
  preserve workspace state. Generic sealing cannot skip a claimed tool result.
  Recovery checks each completion's historical Checkpoint, not just the latest
  workspace, so a pre-effect snapshot cannot masquerade as its result.

Tests use real SQLite/CAS, actual Ed25519 signatures with explicitly injected
test roots, concurrent/stale/duplicate admission and claim cases, substituted
authority and retirement evidence, restart, and transaction fault injection.
The containment/snapshot fixtures are offline records, not actual OS inspection
or proof that a tool, broker, sandbox or release bundle is qualified.

### Durable ordinary-tool approval

The loaded Run adds only two mutators: `waitForToolApproval` and `approveTool`.
They operate on the current SQLite cut and the same fixed policy, request,
normalized call and ordered frontier. No caller-selected grant, parse, result,
budget charge, generic wait clear or legacy callback is accepted.

- `waitForToolApproval` consumes the exact planned wait and, if a worker exists,
  current-inspector containment death plus snapshot proof. The workspace must
  equal the existing ready checkpoint: asking cannot adopt unaccounted edits.
  Generation seal, worker retirement, unchanged context/checkpoint and the
  revision-checked waiting Run commit together. A worker-free queued Run can
  wait without another seal. Competing reserved/preactivated workers prevent
  the commit; the owning launch reducer must close them first.
- `approveTool` authenticates the local in-process channel and principal, then
  validates the exact revision/wait/frontier and canonical `run.approve` request.
  It commits the ApprovalDecision, policy item, optional grant or one denied
  result, checkpoint, Run snapshot, event and control-request row together.
  Allow preserves the result-less call; deny advances exactly one call. Both
  leave the Run queued without a worker. Resume uses fresh generation/lease
  activation, never the retired worker or an implicit tool dispatch.
- Identical request IDs replay their original immutable response, including
  after restart or after later progress, using a freshly authenticated channel.
  Different request bytes conflict. Historical decisions are checked against
  their retained channel identity and exact durable control-row/response owner;
  old process evidence is audit history, never authentication for a new request.
- Default TTL is one hour capped by the Run deadline; an explicit positive
  integer TTL is capped at 24 hours and the deadline. Expiry before preparation
  returns the same call to a new wait. After preparation but before claim,
  `prepareTool` returns a new wait plan; committing it atomically appends a
  State-derived `cliq-tool-grant-expiry-v1` no-dispatch failure, refunds the
  reservation and seals the generation. The next approval uses a new grant and
  the next zero-based Journal attempt. Once claimed, expiry cannot erase the
  effect: completion still validates authority at claim time. There is no
  automatic reapproval, implicit replay or result fabricated for an expired grant.
- Recovery validates wait/decision/checkpoint ownership, same-call renewals,
  grant lifetimes and dispatch ceilings across renewals, with approval and audit
  refs excluded from model-visible content. Tests exercise real SQLite/CAS
  close/reopen, fresh offline worker activation, duplicate/concurrent/stale and
  foreign requests, all three expiry cuts, and transaction rollback including
  the no-dispatch refund. Unknown and abandoned tools are independently reopened
  while their result-less frontier and original workspace remain unchanged.

Gate B still needs trusted builtin/broker execution and repair/child
projections. Existing attempts are not silently redispatched; the tool grant
renewal above proves that the expired preparation was never claimed.
WP04 still owns recovery of prepared tools after worker loss, reconciliation of
claimed-then-`unknown` tools, and authenticated manual abandonment/terminal drain;
none of those recovery reducers is implemented here. An `unknown` or low-level
Journal `abandoned` row leaves its call open: it cannot become `completed`,
advance the batch, or authorize generic generation sealing. That sealing path
adopts workspace bytes and requeues the Run, whereas RFC section 8.3 requires
manual abandonment to terminate as cancelled with an identity-matched
`ToolAbandonedItem`, never a fabricated result. This is an explicit fail-closed
handoff, not a completed recovery/liveness guarantee. Actual
tool/MCP I/O, containment implementation, the second immediately-before-I/O
gate, non-tool approval subjects, UDS/public control transport and UI, scheduling,
bundle installation, paid-provider
qualification and production cutover remain outside this change. Neither Gate B
nor WP03 is declared complete.

### Durable user input

`request_input` closes the native-call -> durable wait -> authenticated answer
-> ordered continuation loop through the existing loaded Run. `prepareTool`
returns an `input_required` prompt and planned wait/checkpoint identity; the
only added mutators are `waitForInput` and `submitInput` (`run.input`).

- The frozen builtin has `access='control'` and no policy subject, operation
  grant, Journal dispatch or tool-budget charge. It cannot be substituted by
  a same-named MCP tool. Native input carries prompt text, text/JSON response
  kind, an explicit byte bound and a JSON response schema only when needed.
  The response schema is checked during whole-batch prevalidation using the
  RFC's closed, non-executable JSON-Schema-2020-12 subset, via the existing Ajv
  dependency. No coercion, defaults, regex, references or remote loading.
- Waiting seals a live worker using the existing current-inspector death and
  unchanged-workspace snapshot proof. The request item, context/checkpoint and
  revision-checked wait commit together. A worker-free queued Run can ask the
  next question directly; reserved/preactivated competitors still block it.
- Answering validates the exact prompt, typed value, byte bound, principal,
  live in-process channel, waiting ref and revision. Input payload, input item,
  one ordered ToolResult, context/checkpoint, Run/event and immutable control
  response commit atomically. Same request bytes replay the original response
  through a newly authenticated channel; different bytes conflict. Distinct
  request IDs racing one wait have exactly one committed winner.
- The RFC now explicitly separates executed `invocation` results from
  `user_input` results, and binds the latter's payload to its original control
  request/channel. No fake Journal completion is used for user answers.
  These are pre-Kernel-Cut schema changes, not a legacy compatibility layer.
- Recovery reconstructs prompts and replies from retained native input,
  checks their full artifact/control/checkpoint ownership, and keeps all
  authority refs out of model content. Model messages defer the user-input
  projection until the entire native batch's tool results are emitted;
  compaction uses the same order and cannot split an open batch.

Tests exercise real SQLite/CAS, text and bounded schema-matching JSON, restart,
fresh worker activation, ordered multi-call continuation, duplicate and racing
requests, malformed/stale/foreign/cancelled/expired requests, worker/response
substitution and transactional rollback. Death/snapshot records remain offline
fixtures. UDS transport, UI, actual brokers, worker-loss recovery, terminal drain,
repair/child integration and production cutover remain their owning packages'
work. This completes the input interaction, not all of Gate B or WP04.

`candidate_required` and `stop_required` describe the retained
observation's handoff to WP05/WP04; they are not permission to mark the Run
successful or bypass stop arbitration/drain. Completed handoffs survive restart
through `readModelAttempt`; `prepareModel` reports `AGENT_HANDOFF_PENDING` with
the disposition and retained evidence reference instead of a cursor TypeError
or a misleading retry attempt. Context exhaustion is reproducible from the unchanged
context and frozen policy. The resource-stop reducer below consumes deterministic
budget/context failures; candidate and generic runtime-failure handoffs still
require their owning reducers.
Broker/sandbox effects, scheduling, and production composition remain outside
this implementation. Restart does not revive an old worker lease.

### Model retry readiness and recovery

One pure Journal interpreter owns the frozen three-dispatch ceiling and
`[500ms, 2000ms]` backoff for both normal and compaction operations. Preparation,
the permanent dispatch claim, and recovery use the same rules; no mutable retry
counter, persisted timer, scheduler, public retry mutator, or transport callback
is introduced.

- A replacement uses the same opId and the next contiguous attempt. Every
  earlier attempt must already be settled. The delay starts at the first
  durable post-claim settlement timestamp; a later audit resolution or a
  pre-dispatch failure does not reset it. Pre-dispatch failures cost zero and
  do not count toward the three dispatched attempts.
- Retry keeps the original native bytes, provider/model/mode, output bound,
  reservation and compaction plan. Only the attempt and audit projection can
  change. Each admitted replacement reserves anew in the same transaction as
  its prepared row. The previous unknown's full pessimistic charge is retained.
  A received rejection/unusable response stays `completed`, never a transport
  retry; there is no SDK retry or response-header override in this path.
- `readModelAttempt.retry` is an immutable, restart-derived projection:
  `pending`, `backoff` with exact `notBefore`, `ready`, `completed`, or
  `exhausted`. Preparing too early returns `MODEL_RETRY_PENDING` with that
  timestamp and next attempt, without reserving budget or advancing state.
  Readiness is necessary, not sufficient: live owner/lease, stop/deadline,
  frontier and fresh budget checks still apply at the existing mutation gates.
- After the third failed/unknown dispatched attempt, reading returns
  `stop_required`; preparation returns `AGENT_HANDOFF_PENDING` with
  `reason='model_retry_exhausted'` and the retained failure evidence. WP04 must
  still create the RFC runtime-failure StopIntent and drain/terminate the Run.
  This gate does not manufacture a terminal result or refund an unknown.
- Recovery rejects historical backoff/ceiling violations and changed request
  bytes/authority. The first terminal row's time must equal its exact retained
  BudgetSettlement time at preparation, claim and recovery; changing only the
  Journal clock cannot shorten the delay. A late resolution of an older unknown does not change the
  highest attempt's eligibility. Existing completion checks still reject an
  older result instead of installing it over a newer attempt.

This is a retry **eligibility** gate, not transport failure classification or
proof that a previous dispatch is no longer live. It consumes existing Journal
settlement facts; WP03/WP04 still own authenticated ambiguity/no-release evidence,
broker-token revocation, dispatch closure, and the immediately-before-I/O gate.
The existing M2 generic unknown settlement seam is exercised only by explicitly
offline fixtures here. It is not claimed to satisfy those production evidence
contracts, and no real provider request is sent or automatically rescheduled.

Regression tests cross real SQLite/CAS for exact delay boundaries, zero-dispatch
replacements, racing preparations, rollback, full charges and budget exhaustion,
received rejections, late result rejection, corrupted retry history/request,
compaction, and close/reopen with fresh offline worker activation.

### Durable root-agent cancellation and deadline stop

PR #497 closes one lifecycle, from authenticated `run.cancel` or
canonical deadline expiry to a quiescent terminal Run and its Session outcome.
It reuses the loaded Run, existing control rows, Journal, worker seal and
continuation commit. There is no second lifecycle, generic Run patch, timer,
scheduler, new tool executor or compatibility bridge.

- `cancelRun` authenticates the in-process channel and owning principal,
  checks the exact revision, and atomically retains the RFC user StopIntent,
  monotonic cancellation fence, immutable response, control row and event.
  Same request bytes replay the original snapshot through a freshly
  authenticated channel, including after terminal/restart; different bytes
  conflict. Distinct requests racing one revision have one winner.
- `expireRun` derives only the RFC deadline intent from the canonical clock
  and immutable deadline. User cancellation outranks deadline; equal
  precedence keeps the first committed intent. With the resource integration
  below, a deadline also replaces a lower-priority runtime-context failure.
  Callers cannot select arbitrary reasons.
- Both preserve the current frontier and any input/approval wait while
  fencing productive work. The original worker may still be alive, and a
  positively returned claimed model/tool result may still settle against the
  current revision. A stopped Run does not regain dispatch authority when
  that result advances its continuation or seals its worker.
- `commitTerminalStop` independently revalidates the current cut. A live
  worker requires the existing signed current-inspector death/snapshot proof
  over the **accounted** workspace; a queued/waiting Run revalidates its
  historical seals against their owning inspector epochs. Unaccounted edits,
  pending launches, unsealed generations and unresolved dispatches block it.
- In one transaction, terminal drain refunds only preparations that were
  never claimed, appends every undispatched suffix call's ordered cancelled
  result, writes the context/checkpoint and exact stop-derived TerminalDetail,
  retires the worker, clears frontier/wait fields, and commits terminal truth.
  Claimed completed work keeps its real result and full charge. Cancelled
  calls create no fake Journal dispatch or answer, and their model content
  contains no control/authorization refs.
- The same transaction appends exactly one root `SessionRunTerminalItem`,
  extends its Session projection by one uncoalesced raw segment, and increments
  the Session cursor/revision. Concurrent roots preserve both outcomes in
  commit order. Retrying a committed terminal operation only reads its verified
  result; it cannot append another Session item. Recovery walks the reason,
  control owner, call closures, refunds, historical worker proofs and Session
  projection, not display events.

This implements root agent Runs at the existing agent/tool/input/ordinary
approval frontiers. Child Runs/allocations, MCP-server lifetime closure,
pending-launch recovery, unknown/manual/workspace-rollback reconciliation,
remaining runtime/integrity/verification stop evidence, candidate/results,
UDS/UI, scheduling and production composition remain their owning packages'
work. An unknown model attempt from #496 still cannot terminalize or be
refunded without authenticated dispatch-closure evidence. Unsupported cuts
fail closed; neither Gate B nor WP04 is complete.

Tests use real SQLite/CAS and offline signed containment fixtures, not actual
process termination, broker revocation or production sandbox qualification.

### Deterministic resource failure and terminal drain

The loaded Run adds one `stopForResourceFailure({expectedRunRevision})`
operation for the existing typed continuation. It takes no caller-selected
reason, estimate, reservation or evidence reference. The owner derives and
persists the exact RFC StopIntent, then uses the same `commitTerminalStop`
transaction and Session outcome as cancellation/deadline:

- Additive model-token/cost exhaustion uses the frozen model pricing and full
  next-request reservation, not a caught error or a reduced retry reservation.
  Tool-call exhaustion requires an undispatched ordinary call that policy
  currently allows, or its exact unexpired interactive approval. Denied calls,
  input calls and pending/expired approvals are not resource failures.
  Execution and resource-stop recovery share the complete approval verifier,
  including the authenticated control row, historical channel and response.
- Context exhaustion reproduces the whole-prefix planner from retained
  context and the frozen context policy. No legal prefix means no model call;
  the intent contains the exact manifest and token estimates.
- Executed unusable or ineffective compaction retains its completed result
  and full charge. The reducer reproduces the original plan and validates the
  response, or recomputes the before/after model-visible prompt to prove that
  the summary does not shrink it. It never installs a failed summary or adds
  a semantic retry.
- A shared reader rederives these facts on recovery, at the committed intent's
  canonical time. It also reconstructs the pre-drain tool cut from its ordered
  cancelled suffix. Missing retained pricing/context/response artifacts or
  substituted cause fields cannot produce a verified terminal result.
- User cancellation outranks resources; deadline/additive budget outrank
  runtime-context failures; equal precedence keeps the first committed intent.
  Stops fence dispatch immediately but still require the existing complete
  quiescence, accounted-workspace and atomic Session-publication checks.

This reader accepts only settled histories: unknown/claimed effects and reserved
attempts must reach their owning closure first, even if the next retry lacks
budget. It does not invent generic provider-failure evidence, implement repair
budgets, or complete candidate/verification, child/MCP, broker/worker-loss,
Supervisor scheduling or production cutover work. Model-visible context reading
is shared with compaction recovery, so terminal replay does not fabricate an
execution frontier. Journal attempt indexing is shared by stop/drain recovery;
this does not claim that all transcript recovery is linear-time.

### Received model failure and terminal drain

`stopForModelFailure({expectedRunRevision, inspectorIdentityRef,
inspectorIdentityDigest})` closes positively received but unusable **normal**
model responses through the same stop/drain core. The state owner reads the
settled Journal and constructs the RFC
`RuntimeFailureEvidenceV1(failureKind='model_unusable_response')`; callers cannot
select a failure reason or supply an arbitrary evidence artifact.

- The wrapper binds the latest normal-model operation, exact frontier and ready
  context, completed Journal result and unusable-response digest. Original
  response bytes and the full request charge remain unchanged. It adds no
  model turn, candidate, tool batch, summary or semantic retry.
- Its inspector must match the current state owner's complete runtime/entry,
  executable, instance nonce and process/lock identities, as well as the frozen
  runtime's Supervisor entry. Inspector validation is shared with worker
  checkpoint sealing. The observation is derived at canonical time and must
  still be within five seconds when the stop commits.
- Evidence metadata, the winning intent, Run revision and event commit together.
  The existing terminal reducer independently requires complete worker and
  invocation quiescence before atomic Session publication. Generic runtime
  `TerminalDetail.primaryEvidenceRef` names the **failure wrapper**, not the
  StopIntent or the provider response; reason-detail copies that same exact
  wrapper ref/digest and failing operation.
- Recovery rewalks the Journal/request/response/frontier and historical
  inspector owner. Freshness is checked at the original stop commit, so a
  restart or later drain does not invalidate an already committed observation.
  New observations require the new state owner. Deadline/budget and user
  cancellation keep their existing higher precedence.

The necessary bootstrap companion is
`openStateStore(stateRoot, {bundle, releaseKeys})`: trusted Supervisor composition
supplies the signed runtime before any Run or workspace configuration is loaded.
Bootstrap verifies the release signature, state-schema range and actual current
process image digest, then atomically binds the owner/acquisition to that bundle.
Reopening a signed owner requires explicit trusted roots and the same bundle;
it cannot silently upgrade the runtime or fall back to schema-only authority.
The earlier no-argument M2 storage-only bootstrap remains available to state-core
callers, but cannot supply a valid signed inspector. Tests now bootstrap matching
signed owners instead of mixing a schema-only owner with another runtime's
inspector. This does not qualify native OS-lock/containment enforcement, install
a release, or add runtime-upgrade/takeover handling.

Malformed, oversized, operation-invalid and provider-rejected received responses
all use this closure. Compaction failures retain their dedicated resource-stop
subtype. Prepared/claimed attempts, free pre-dispatch failures, usable candidate
handoffs and any unresolved `unknown` history cannot use it. In particular,
`model_attempts_exhausted` and `retry_unknown_exhausted` still require their
owning authenticated no-release/dispatch-closure implementation; this change
does not manufacture those proofs from a retry counter. Child/MCP closure,
credential/local-service failures, successful candidate/verification results,
actual broker/sandbox execution and production composition remain outside this
integration. Tests use real SQLite/CAS with offline signed inspector/containment
fixtures, not a live provider or qualified platform inspector.

The old Session/`ModelAction` runner remains isolated until WP06's single
Kernel Cut. There is no typed-to-legacy bridge. WP06 removes the old runner,
parser and repository command hooks; historical payloads remain opaque import
data. No permanent compatibility promise is introduced.

### Direct tool intent, not execution authority

Builtin input schemas and semantic checks live together in `builtin-inputs`;
no old action envelope, tool registry, host filesystem or session-plan store is
imported. Paths are lexical workspace-relative identities: redundant `.` and
separators normalize, omitted directory roots become `.`, and absolute paths,
drive paths, parent components, backslashes and NUL reject before batch admission.
Line ranges must be positive safe integers in ascending order. Plan operations
have distinct closed shapes; missing fields are not repaired or inferred.
Actual symlink/descriptor containment and effect handling still belong to WP03.

`PolicySubject` is action-free and still carries no grant. The retiring runner
keeps its existing mode/table/hook behavior. The canonical runtime does not
serialize that engine's decisions into proofs: it uses the fixed RFC evaluator
and `canonical-bash` parser instead. The new input preview and evidence use that
same parser; persisted evidence retains every recognized nested deny occurrence
in order, whereas the non-authoritative display subject needs only the first.
Its bounded literal-shell grammar is not a general shell interpreter. Unknown,
dynamic or ambiguous syntax loses the outer allow-rule key and remains unsafe;
no host parser or legacy fallback is consulted. Path-qualified executable words
retain their basename for deny matching but are unsafe for allow rules; a bare
command-name allow cannot authorize an arbitrary same-named path. Actual
executable/descriptor containment is independent of policy interpretation.

The loop signature hashes the full frozen manifest entry and normalized input,
excluding call ID/index. It is an observation key, not deduplication authority:
a repeated call must never be skipped or have a result reused on that basis.
`manifestEntryDigest` identifies that entry; it is not the nested MCP registry's
separate `execution.toolContractDigest`.

`skill`/`skillResource` are not exposed as builtin execution contracts yet.
Selected skill instructions continue to load from frozen CAS manifests; future
resource access must use that retained closure, not the old ambient activation
or live-file fallback. Unknown builtin identities fail loading explicitly.

Public loaded-state validation failures carry `KernelStorageError` codes and
their original cause. Invalid completion arguments are `INVALID_REQUEST`;
unreproducible retained state/authority is `RECOVERY_REQUIRED`. Existing lease,
revision, artifact and infrastructure errors retain their classification.

The non-blocking #490 review was checked against the implementation. Highest
attempt and permanent duplicate-claim checks already existed; the necessary
addition is current-frontier/context binding, not banning all model claims.
Candidate and unsupported stop branches remain WP05/WP04 work, with explicit
handoff errors here; deterministic resource stops use the loaded reducer above.
Broad per-handle CAS memoization is deferred: it could hide a lost or corrupted
retained artifact. History replay/compaction performance needs measurement;
no claim of linear-time recovery is made by this change.

## One loaded model module

`validateRunAssembly` loads and verifies the exact retained assembly closure.
Its successful result exposes only a `ModelSession`, not mutable configuration,
price tables, tool definitions, tokenizer functions or adapter callbacks.

```text
validateRunAssembly(retained material) -> ModelSession
ModelSession.prepare(typed projection, invocation) -> PreparedModelAttempt
  [WP01 publishes artifacts and claims the exact request; WP03 performs I/O]
ModelSession.start(prepared, response head) -> response
response.push(bytes) -> non-authoritative stream events
response.finish(time, tool-input resolver) -> events + usable/unusable result
```

The prepared object is an identity-bound handle owned by that loaded session.
A copied, forged, cross-session or deserialized handle is rejected. Recovery
reloads the retained assembly and prepares the retained projection again;
identical inputs must reproduce the exact request ref and body bytes. Public
byte getters return copies; nested authority and request fields are immutable.

Static evidence, signature roots, tool/schema closure, envelope members and
context equations are checked on load/recovery, not on every request.
Per-attempt work checks only changing invocation/projection data, serializes
the native body, estimates context size, and computes the fixed reservation.
The input resolver must return the exact frozen tool/schema identity; its
schema-normalized values are consumed by Gate B, never dispatched here.

A normal attempt publishes only the native body and one `ModelRequestV1`.
Compaction additionally publishes its typed two-message projection. There is
no framed-prompt, native-body wrapper, prompt profile, custom BPE vocabulary,
runtime golden-vector execution, or intermediate JSON encode/decode pipeline.
Adapter code is retained through the signed RuntimeBundle, as other executable
authority already is. Golden fixtures are independent build-time tests.

Tool arguments remain typed JSON values or explicitly retained malformed
fragments in memory and history. Only string-native provider fields encode
them; object-native providers receive the existing values without decoding
them again.

## Native provider boundary

Autonomous execution requires positive, matching native-tool evidence.
Valid negative/absent native capability means `text-only`; malformed, expired,
unsigned or identity-mismatched evidence fails admission. There is no
`constrained-ir` branch and no runtime downgrade or text-action repair.

- OpenAI uses Responses, `store:false`, explicit output bounds,
  `truncation:'disabled'`, and encrypted reasoning continuation.
- Anthropic uses Messages and preserves thinking signatures/redacted blocks.
- OpenRouter, OpenAI-compatible and Zhipu retain Chat Completions adapters.
- Managed Ollama retains Chat/NDJSON and deterministic invocation-bound call ids.

These are distinct protocol conformance cases, not six runner implementations.
The stream framer decodes UTF-8 across chunks, incrementally parses SSE/NDJSON,
and bounds retained bytes to 1 MiB plus one byte for an oversized observation.
It does not wait for EOF to deliver text/reasoning/tool deltas. End events and
usage are returned exactly once. Buffered tests use the same observer.

Only the central compiler may create a usable turn. Partial, contradictory,
filtered, truncated, rejected, oversized or mode-incompatible responses cannot
dispatch tools. Every identifiable call survives normalization, including a
missing name or malformed argument fragment. Missing/duplicate mandatory ids
invalidate the whole response before tool resolution. A missing tool name is
retained as empty in durable truth; native history uses the reserved,
unexposed `__cliq_missing_tool_name` placeholder only to close its result.

Provider-owned reasoning continuation is opaque, bounded, provider/model-bound
data. It is carried through the stored turn and next projection, never
interpreted as tools, permissions or instructions by the runtime. Streamed
signatures must not be lost. Gate B reconstructs this field from the retained
turn, not from a mutable provider cache.

`abort(time, stopIntentRef, resolver)` is only for a broker-confirmed abort
caused by an already persisted StopIntent. It cannot execute partial calls or
overwrite a complete response. WP01 independently validates the StopIntent
and decides whether a completed result may be published during stop drain.
Unknown network outcomes are Journal/recovery facts, not fabricated cancels.

## Estimates are not hard billing authority

Context planning uses a fixed, cheap byte estimate: text is
`ceil(UTF8 bytes / 3)`; normal messages add four estimate units each, and
native tool definitions/arguments/continuation also contribute. It is a
deterministic heuristic, not an exact remote tokenizer, a billable-token
measurement, or proof that a provider will accept the context. Provider usage
is observational telemetry, never settlement authority.

A billable request reserves the complete four-component
`ModelPriceTableV1.requestTokenCeiling` and its checked signed-table cost,
independently of that estimate and the smaller requested output limit.
The signed ceiling must cover **every request this retained adapter can release**,
including rejected and ambiguous outcomes, for its exact endpoint/model and
validity interval. A signature alone does not establish a true ceiling:
WP06 qualification must establish that fact from authoritative billing bounds.
A rate-only table, guessed tokenizer, empirical average, or unspecified bound
is ineligible for a hard-budget Run (`MODEL_COST_UNKNOWN`).

Input/output ceilings must cover admitted context and both output caps.
Cache ceilings are explicit components, not inferred from prompt estimates.
Observed component/output-cap violations are rejected, but detecting one
after release cannot retroactively guarantee spend; eligibility must be sound
before release. The conservative full reservation is consumed for released or
possibly released attempts; only proven no-release settles zero. This retains
WP01's settlement rule and may reduce the useful work admitted by small budgets.
No provider-hard-cap mutation or new pricing plugin is added.

Managed-local zero cost still requires the independent signed service/model,
no-egress boundary and live-instance checks. Its token reservation uses
admitted context plus the requested output cap, not a remote billing claim.

## Compaction remains a durable operation

Keep the RFC's fixed integer `C/O/H/T/R/S/K/P` policy, whole-prefix selection,
protected context, raw-item retention, and atomic plan/summary/context/checkpoint
commit. Context counters are estimate units; they are not hard token proofs.
`K` estimates the actual retained two-message envelope. Normal output `O`
and summary output `S` independently fit the model's maximum; `S <= O` is
not required.

Compaction disables tools and accepts only a nonempty, complete `end` summary.
The summary is at most `min(262144, 3*S)` UTF-8 bytes, so its text estimate is
at most `S` without a private tokenizer. Combined with source estimate
`>= S+512`, each successful replacement reduces estimated source content by
at least 512 units; Gate B also verifies that the complete prompt estimate
decreases after accounting for message overhead. Actual model output is
requested with cap `S`; reported
output beyond it is invalid. A provider can still reject an underestimated
context: stop explicitly, never silently truncate or repair/retry output.

## Ownership and verification

WP02 plans artifacts and typed outcomes; it owns no SQLite/CAS writes, Journal
claim, effect, retry or recovery scheduler. WP01 rehashes and atomically commits,
WP03 dispatches through permission/broker/sandbox, WP04 resumes/reconciles,
WP05 verifies, and WP06 qualifies releases and switches composition. Workspace
Trust still precedes configuration/runtime assembly; Tool Permission and the
OS boundary remain independent gates.

Regression tests cross the loaded-session seam: independently specified native
bytes; configuration mutation; forged handles; full schema substitution;
reload determinism; all calls and their next request; opaque continuation;
real chunked deltas; cancellation; output/usage ceilings; and compaction with
a small normal output limit. Focused codec/arithmetic tests cover edge cases
that cannot be reached economically through every integration fixture.

Gate A requires `npm run test:agent-runtime`, `npm run build`, and `npm test`.
Offline conformance does not certify a live model, true billing ceiling,
durable broker integration or the final Kernel Cut.

JSON remains at provider wire, native tool-schema and canonical persistence
boundaries. In-process execution passes typed values; assistant JSON-looking
text is inert. Minimal core means removing unnecessary interpretation and
authority layers, not eliminating a serialization format used by providers
and durable storage.
