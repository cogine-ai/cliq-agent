# Ordinary child Runs: complete integration design

Status: implementation in progress over the immutable TT1119 source snapshot
`/private/tmp/ttf.w8tfzfmu` (manifest `b7ecd37fedbdccaac8388508868ec40015884400e864b6a7b279455f979dcaf4`).
This is one vertical delivery, not completed child or platform qualification.
The initial analysis below describes that baseline. The implementation now
contains closed original admission/source readers, schema8 storage guards,
final release ancestry fences, ordinary child terminal allocation, worker-free
await/one-time settlement/reread, signed local merge authorization and atomic
CAS-only serial merge, Stop/finalization and registered parent revocation.
Real Store/SQLite/CAS regressions use the existing explicitly inert
worker/model evidence fixture. The installed composition and same-campaign
parent/child, wait/restart, nonempty patch/merge and cancellation cases are
implemented for combined Linux validation. These component checks do not
qualify native child execution or installed physical concurrency.

## Current code and the real missing work

- `kernel/types.ts`, `state/invariants.ts` and
  `repositories/child-allocations.ts` contain the three-state allocation row,
  its structural decoder and a SQL reader. `schema.ts` has its existing table.
  There is no allocation writer/admission/terminal/settlement reducer. Its
  recovery reader presently checks artifact existence rather than the complete
  parent/grant/child/result/budget equation.
- RFC section12/WP05 specify capability grants, delegate/await inputs,
  ChildHandle/WaitSet/Result/Merge items, ordinary child execution, conservative
  inclusive accounting, exact stop propagation and serial diff3 merges. Those
  contracts are not implemented by the current continuation/tool schemas.
- Final candidate, result basis/commit/recovery and stop explicitly reject a
  parentRunId, allocations or children. These are correct fail-closed guards;
  deleting them without complete replacement would manufacture support.
- Installed execution already supplies one ordinary Run scheduler, verified
  CAS workspace state, native preparing/activation, original lease/Journal,
  invocation/worker retirement and Stop recovery. Reuse all of them. Child
  execution gets no second runner, shared mutable directory or execution token.
- The current signed Supervisor control identity covers only request_input,
  with no grant or Journal. The actual diff3 kernel and Delivery's worker-free
  immutable merge planner exist, but neither is an internal claimed child-merge
  implementation. The native edit is a fixed single-file text edit, not a
  binary/directory/mode/symlink patch executor.

## One module and one lifecycle

Implement `loadChildContinuation` with the same genuine loaded Run authority,
StateOwner and typed tool cut as the ordinary reducer. Its small Interface
selects/commits the current delegate, awaits the current owned child set, and
settles an exactly satisfied wait. Internal admission/history/merge planning
hide the complete graph and SQL equations. Store consumes those operations in
its existing drive loop; it does not accept caller-supplied child authority.

The persistent spine remains:

`delegate call -> original local Journal admission -> ordinary queued child +
ChildAllocation(reserved) -> ordinary execution/terminal -> child_terminal ->
parent settlement(settled) -> ordered results -> serial successful patch merges
-> original batch or fresh agent frontier`.

The existing allocation is the only child accounting row. Artifact-first
publication and a single current-owner/time-fenced transaction establish each
edge; orphan data is never admission, settlement or proof. The parent/child
recovery reader independently reconstructs those same edges and unique ids.

### Admission and exact derivation

1. Normalize one complete DelegateRequest through the compiled typed batch.
   Bind op/admission/child ids to parent Run, original batch/call/index and
   complete normalized request. Request replay returns that exact child;
   different bytes conflict. It cannot bypass a winning stop or unresolved
   prepared/claimed/UNKNOWN original operation.
2. Evaluate the existing named-action child_read_only/child_mutating policy.
   Preserve the exact child_delegate discriminator/mode in evidence, approval
   and OperationGrant. Ask first retires the original parent worker through
   the existing seal/Checkpoint path; no pending old-epoch authority survives.
   Workspace Trust remains distinct from per-delegate permission and OS bounds.
3. Derive only immutable data from the original parent assembly/policy/CP.
   Filter byte-sorted exact builtin names/MCP revisions; read_only removes
   source-write, shell and mutating delegation. Every ungranted action is deny.
   Copy provider/model/runtime/guest/instruction/skill/retry/context/algorithm
   and pricing identities exactly. Recompute MCP/tool-retry/credential unions
   from the filtered closure and prove every member is a parent subset.
   No endpoint, registry, credential or price refresh occurs here.
4. Freeze parent model-visible context as bounded ModelText data, never raw
   policy/Journal/grant rows. Additional refs must already be positive members
   of the parent's verified model-visible context closure and decode ModelText.
   `parent_summary` selects a genuine owned retained summary; absent summary is
   an explicit input refusal, not an implicit paid summarizer or fake summary.
5. Produce a new child base SourceManifest and child-run-bound workspace state
   from the full original ready CP/CAS closure. Reuse immutable leaf bytes and
   frozen classification/ignore/private-Git graph; never reopen the live source
   or reuse a SourceInspection/native completion as child permission. Each new
   generation goes through its own existing real preparing/worker lifecycle.
6. Additive child ceilings are component-wise bounded by request and the
   direct parent's exact remaining `ceiling - consumed - reserved`. Include
   the delegate's own one-call charge, not just child capacity. Cap the absolute
   child deadline by the parent deadline; decrement remaining depth and enforce
   direct nonterminal child concurrency from actual child Run state. Ancestor
   reservations already cover the entire subtree; do not reserve it twice.
7. One admission transaction rechecks the original parent revision/CP/frontier,
   current grant/time/ancestry, resource/Run capacity, depth/concurrency and
   exact derived closure. It creates child/spec/context/initial CP, reserves
   parent capacity, stores the allocation and ChildHandle/normalized tool result,
   and closes the local admission Journal exactly once. Only committed child
   rows enter the ordinary scheduler. No installed image is borrowed for a
   merely queued child and no native child is created before admission.

### Wait, finalization and one-time accounting

- Await accepts nonempty unique direct owned handles in supplied order and
  freezes that order plus original call identity. A live parent first actually
  retires/seals/joins its original worker; queued waits create no worker. If
  all children are already terminal, use the same settlement without a wait.
- A child terminal transaction validates its own complete result-or-detail,
  raw/verification/retirement closure and inclusive usage, then changes its own
  Run and allocation only. It never writes Session or a running parent's
  revision. Failed/cancelled/UNKNOWN work is not free work.
- Recovery recomputes the complete equation from direct outgoing allocations
  only: reserved equals unsettled own Journal reservations plus each un-settled
  outgoing child's original grant; consumed equals settled own Journal use,
  authorized own repair use and each settled outgoing child's inclusive use.
  An incoming allocation belongs to the parent and never adds to the child's
  counters or suppresses their exact equality check. Inclusive child use already
  contains descendant settlement; grandchildren must not be added again.
- Settlement moves each full granted reservation out of parent reserved,
  adds actual inclusive usage once, records the exact unused difference and
  parent revision, and appends ordered ChildResult items/model-safe contents.
  Settled rows are immutable. Direct concurrency slots depend on child terminal
  status, while unused budget remains conservatively reserved until settlement.
- Only a lease-free parent on the exact current child subject can be woken
  asynchronously. The final child may settle that set atomically, or startup
  repeats the same expected-revision reducer. Both cannot win twice.
- A final no-tool model turn with outstanding children creates no candidate.
  Retain the real turn, freeze finalize_settlement in Run-id order, retire the
  parent and later return child_results to a new model turn. Do not project the
  premature final text as the final answer or finalize around a live child.
- Only successful patch-bearing mutating children produce stable serial merge
  calls in wait-set order. Failed/cancelled/read-only outcomes remain in the
  ordered result and never force an empty merge frontier. A conflict returns
  structured diagnostics and all known child outcomes, skips later merges and
  changes neither real workspace nor already committed parent history.
- The merge's local A-to-M diff is distinct from the RunResult's original-base
  to M diff. A new parent WorkspaceState always keeps the parent Run id,
  original RunSpec base, projection and complete private-Git closure. The
  current A source is merge input/provenance, never a replacement Run base.
- Every synthetic merge still evaluates the parent's per-action write policy
  for the complete recomputed patch path set and gets its own exact grant or
  approval. A delegate grant is not permission to publish or generally write
  the parent. The internal merge handler accepts only the current owned
  ChildMergeBatchItem/result/patch identity; arbitrary model calls/CAS refs
  cannot reach it. It never becomes a general exposed script tool.

### Stops, ambiguity and recovery

- A parent stop fences descendant release immediately in the original live
  dispatch checks by walking the bounded immutable ancestry/allocation chain.
  Durable parent_cancelled propagation and original physical revocation use
  existing Run owners; they do not wait for a second runner to notice a flag.
  A child cannot continue releasing a model/tool merely because its own stop
  row has not yet been updated. Apply that exact bounded ancestry check in the
  common dispatch claim/release cut, broker connect and body release, every
  preparing authority increase, worker activation/lease renewal, and local
  admission/merge commit. The last gate and native release have no intervening
  await. Existing released domains still require actual revoke/join; a refused
  future release never proves that a past release did not occur.
- Stop settlement retains any original await origin, cascades to all live
  descendants, and conservatively waits for their own physical/broker/UNKNOWN
  closure. Original UNKNOWN/full settlements are neither refunded nor resent.
  It emits audit-only child outcomes, one cancelled await result iff there was
  an await, closes the original batch suffix and never resumes the model.
- A concurrent original worker-recovery wait/probe is not discarded to install
  a child wait. The StopIntent retains the child settlement obligation until
  the existing worker-death/retirement path can safely reach the lease-free cut.
- Successor startup uses the existing single owner recovery order, reconstructs
  direct child links/full grants/results/usage, settles satisfied exact waits
  and schedules ordinary queued Runs. Missing graph, partial Journal, native
  uncertainty or descriptor failure remains recovery-required, never absence.
- A root terminal alone appends Session once using the existing compaction-aware
  terminal helper. Child terminal appends only allocation/parent-result state.
  Unverified helper results cannot be directly delivered; parent integration
  followed by its own verification is still required.

## Approved complete contract

1. **Signed local operations.** Keep request_input's existing control/no-grant
   meaning. Add a disjoint closed Supervisor local-operation identity for
   delegate and internal merge (real original signed Supervisor/version/digest),
   and add await_children as a fixed control handler. Delegate gets its exact
   local OperationGrant/Journal transaction; await never fabricates execution or
   native death. No JS data script is advertised as an executable tool adapter.
   The existing Journal treats `opKind='tool'` as process-spawning, so a local
   handler cannot borrow that branch with a fake SandboxLaunchSpec or native
   grant. Use explicit closed child_admission/child_merge local operation kinds
   in the same Journal, with forbidden sandbox/broker fields and dedicated full
   request/grant/current-owner reconstruction. The local claim and effect commit
   in the same SQL transaction; no physical dispatch or extra ledger is implied.
2. **Minimal merge timing (recommended).** The RFC currently requires a claimed
   workspace-rollback-retry merge with a physical post-effect CP. A general
   patch executor does not exist; extending edit to arbitrary binary/type/mode/
   directory operations would be new native write authority. Prefer the already
   established Delivery principle: after parent worker retirement, each claimed
   fixed diff3 merge fully verifies B(child fork)/S(child result)/A(current parent)
   and all CAS bytes, then atomically commits a new logical ready workspace CP.
   It never claims that an old M was physically modified/sealed. The next normal
   preparing lifecycle materializes and independently verifies that exact CP
   before execution. Preserve stable per-merge ids, ordering, exact charging and
   all prior real UNKNOWN/charged Journal facts. A CAS failure can leave only
   an orphan; an uncommitted SQL transaction can be recomputed with the same
   stable operation identity. Neither creates a physical UNKNOWN, native
   rollback requirement or permission to resend an earlier operation. Revise
   RFC/WP05's existing workspace-rollback-retry/physical-postEffect requirement
   through a separate closed logical-merge provenance branch, not by weakening
   the old tool Checkpoint guards.
   If physical mutation of existing M is retained, a new fixed native complete
   patch recipe plus real rollback/cancel/UNKNOWN qualification is a genuine
   dependency; do not simply remove the current refusal or use host filesystem.
3. **Storage version and inherited authorization.** The allocation table lacks
   SQL identity/state immutability constraints. Add unique delegate/admission
   identity and monotonic reserved->child_terminal->settled constraints in that
   existing table, with a new exact schema recipe/version and retained older
   recipes (no new ledger/table). Coordinate with root's existing6/7 history
   work. Child verifier/dependency execution authority cannot copy a parent-Run
   template as if it named the child: derive a closed child-bound provenance
   from the exact parent authority + delegate/capability grant, or use the
   child's ordinary exact approval path. Keep all original ordinal/expiry and
   Run/credential/price restrictions. No generic inheritance boolean.

MCP, dependency acquisition/scripts, managed-local provider and macOS execution
remain only their real existing backend capability. Pure subset derivation can
cover those retained shapes, but cannot advertise or qualify an unimplemented
launcher/broker. The first installed positive campaign uses the signed existing
remote controlled endpoint and ordinary builtin tools; no paid call is needed.

## Complete acceptance and validation

Deliver the types/closed history, local operation permission/actual consumers,
SQL admission/accounting, ordinary scheduler, child wait/finalize/stop/recovery,
root-only Session projection and serial merge together. Do not expose tools or
remove child refusals until their whole replacement path exists.

Pure tests may prove only projection/intersection/digest/schema/diff3 arithmetic.
Real SQLite/StateOwner tests must exercise the existing actual Store interface,
not manufacture Run rows/authority/native brands. Cover duplicate admission and
replay conflicts, depth/concurrency/overflow, conservative ancestor budgets,
read-only escalation, foreign context/credential/registry/price/template refs,
out-of-order simultaneous terminals, exact waiting wake, root final-turn gate,
failed-mutating-only zero-merge, serial disjoint/conflicting patches, stopped
await/no-await/grandchild propagation and UNKNOWN preserving full charge.

The existing real installed campaign first keeps the whole original eight-case
prefix, then verifies independent ordinary parent/child generations/leases/
Journal/Checkpoint, worker-free waits, actual restart and explicit input replay,
one-time inclusive settlement, nonempty serial merge followed by the parent's
ordinary preparing/final result, and real parent cancellation propagation.
The current unique scheduler retains its original single-worker slot. Actual
two-controller physical concurrency requires the separately reviewed aggregate
resource envelope and remains unqualified; two admitted children do not prove
parallel execution. No verifier is invented for the none/explicit-consent
campaign: successful results remain completed_unverified.
The closed evidence profile is
`verifier_eight_plus_children_merge_restart_and_cancel_v1`: ten ordered cases,
24 actual POSTs and sixteen independent full result/diff downloads. The final
two cases are `ordinary_children` and `ordinary_children_cancel`. The successful
child and parent deliberately share the exact same canonical B-to-S diff bytes,
so those sixteen downloads have fifteen unique CAS references. Both shared-diff
downloads remain independent bounded scanner streams; no hash deduplication,
merged stream or extra campaign resets the original corpus budget. The normal
child row records four downloads and three unique refs; cancellation records
zero of each. The original eight-case/fifteen-POST/twelve-download prefix and
all its assertions remain intact. This is an executable installed campaign
contract, not evidence that this author has run or qualified Linux.

An installed input/approval wait with an actual registered StopIntent must
continue into the original terminal drain. A pending child wait returns to
maintenance, and a reconciliation wait remains behind its original physical
recovery proof even after Stop. Cancellation flags alone never bypass a wait.
The common client's Run list captures the complete optional parent cancellation
reference through its original bounded source projection and final comparison.
Child list entries retain their parent handle. A child wait display validates
the captured Run, original wait/set bytes, closed purpose and ordered bounded
handles before rendering; the merge approval separately retains its complete
original changed-path checks. These are read-only presentations, not ownership,
permission, completion or physical-quiescence proofs.
Retain unhit crash cuts as unverified. Stop2/READY5/request30/terminal90, every
original resource/JSON/IPC/Run cap, and the single4096-stream/512MiB/60s corpus
remain unchanged. Source build/necessary focused tests are allowed here; root
owns the later combined full gates/Linux run. No PR, push, host fallback or paid
provider request is part of this author.
