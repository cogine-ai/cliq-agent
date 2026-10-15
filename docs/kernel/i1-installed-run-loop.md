# I1 — Linux installed Run vertical loop

This change composes the existing state, broker, worker and control contracts
through the signed installed entry. It is one integration deliverable, not
completion of I1, I2, the six work packages or default CLI cutover.

Normative sources are the [RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md)
and its [WP06 contract](../backlog/durable-verified-run-kernel/06-ecosystem-surfaces-and-kernel-cutover.md).
The existing [credential acceptance gaps](i1-credential-authority.md) remain.

## Production composition

- A post-bundle, independently signed companion imports the complete catalog,
  price and detached-signature closure before the existing single active
  selection is published. It breaks the Bundle/endpoint hash cycle without a
  second authority ledger. Admission selects current discovery data; recovery
  verifies the Run's frozen members against its exact signed Bundle.
- The actual authenticated v1 control channel creates a Session, captures a
  trusted source and admits a Run. Frozen instructions, tool contracts,
  capability, full-vector price ceiling, endpoint and credential bindings are
  checked together. Workspace trust does not grant tool permission or replace
  the sandbox. Request replay retains the exact public request core in CAS,
  rooted by the existing request digest, not by a second lifecycle table.
- One Supervisor-owned serial lane drives the retained Run. Client disconnect
  neither owns nor cancels execution. Model and tool operations use the same
  actual worker lease and strongly contained private generation. A nonretired
  launch keeps the single worker slot even after productive driving yields.
  Joined maintenance enforces queued deadlines and renews only a genuinely
  held live lease; initial lease expiry is capped inside its activation
  transaction. Deadline control is loaded before productive scheduling, not
  behind an active broker. Each maintenance cut checks the existing time fence;
  regression fences the lane and revokes/joins producers without healing time.
- The fixed native broker redeems the actual Secret Service item locally,
  claims before network work, then repeats current authority and native worker
  checks before releasing the request body. Raw keys stay outside Supervisor
  JavaScript. The initial recipe is nonstreaming JSON, exact TLS/SPKI, no
  redirects and one bounded native operation deadline, including retirement.
- A real private edit produces a ready automatic Checkpoint. Host source is
  not edited. Reconnect and Supervisor restart read the same durable Run,
  Journal and Checkpoint; they do not resend a completed or ambiguous call.
- Quarantine is not retirement or sealing. Generation retirement requires
  original containment death, joined native tree/mount owners and genuine
  broker quiescence, followed by the existing fenced SQL cut. A successor can
  resume this physical retirement for an already queued quarantine. Terminal
  stop accepts only fully validated sealed or proof-backed retired rows.
  Fully charged installed-model unknowns can retain their exact ambiguity and
  frozen witnesses during physical quarantine only with genuine current broker
  quiescence rechecked before the move and at SQL commit. This branch permits
  no replacement, retry, effect resolution, new Checkpoint or terminal closure.

An ordinary provider refusal is local to its Run. Uncertain physical resource
retirement remains a process-wide failure that retains ownership; it cannot be
turned into successful cleanup or permission to continue.
The public `maxSingleFileBytes` default is 256 MiB, matching the unchanged
Linux worker recipe limit. Installed admission rejects an explicitly larger
value before source capture or admission; it never silently clamps that intent.
The generic 1 MiB..16 GiB input range remains available to other recipes.
After a validated terminal Run, its joined driver task closes the original
launcher/sealed-image owners before evicting memory caches. This reclaims no
durable history and does not treat a candidate, unknown or wait as terminal.

## Validation boundary

The Linux journey uses a disposable real user manager, signed installation,
Secret Service, native broker and an owned scripted HTTPS endpoint on a free
standard Ubuntu 22.04 runner. It calls the installed entry and existing v1 UDS,
not private Store, native-owner or authority factories.
For final exit-history observation only, a test observer retains the two actual
unit objects on one continuous user-bus connection before ordinary stop/show,
then releases both references, closes and joins. It does not change the production
profiles or substitute for normal-exit, process-absence or secret-scan assertions.
Its disposable HOME requires a real bounded ext4 filesystem: the native
generation and controller gates check total filesystem capacity, not free
space. Providing this physical limit for the experiment does not qualify an
ordinary host filesystem, an automatic quota installer or per-generation
storage isolation. The installed executable still has to run from that volume;
the worker's separate filesystem, permission and network gates are unchanged.

Its required positive chain is model → private edit → model, with nine exact
prepared/claimed/completed Journal rows, byte-verified ready Checkpoint,
unchanged source, disconnect/reconnect, exact and fresh-nonce replay,
Supervisor restart without a repeated effect, and proof-backed cancellation.
The model's final response is an I2 candidate handoff, **not** verified success.
The same experiment observes that candidate's original worker for at least
65 seconds, then verifies a capacity-blocked Run reaches its own three-second
deadline with zero effects. A separate 45-second Run verifies real activation
and cancellation. Fixture wall time covers these added experiments; existing
phase limits, runner timeout, scan bounds and safety assertions are unchanged.
Public status and launch identity across 65 seconds alone do not prove a lease
was renewed. The agreed diagnostic additionally takes two independent, short
read-only SQLite cuts before and after that interval, tied to the public Run and
its exact activated WorkerLaunch. Both the version and expiry must advance,
the second observation must cross the first expiry while retaining a live lease,
and the complete non-lease launch projection, database identity and Supervisor
process must remain unchanged. The diagnostic creates no StateOwner, writes no
database and provides no clock, dispatch or physical recovery authority. Its
regressions do not qualify actual renewal; only an executed exact-SHA installed
journey with these assertions establishes that narrow claim.

The negative endpoint response exercises native secret-reflection refusal.
Only a real released request with joined resources can produce the existing
exact broker ambiguity branch. Its unknown Journal charges the full reservation
to consumed budget, clears the reservation and uses the actual settlement timestamp. The fixed
`broker_response_refused` log correlates that refusal to the actual claim; it
contains no secret or dynamic provider diagnostic and grants no authority.

This document describes the implemented composition and its validation boundary;
it does not certify a source revision. Qualification requires the exact-SHA
evidence set described below. The journey's bounded reports cover only assertions
that actually execute. Pure-data codec, corruption and local resource tests do
not establish physical Linux authority.

Still unverified by this scope: real-provider capability and billing,
streaming, macOS strong execution, cross-reboot recovery, live updates,
unexecuted credential finalizer/producer/ABA and exact crash cuts, and I2
verification/result publication. No blocked pause workflow is retried. The
legacy default path is not cut over or used as a fallback for this entry.
The queued deadline experiment does not qualify a live worker's exact deadline
or a clock-regression-during-release cut; those remain unverified.

Cancellation of an already materialized, healthy but never-launched replacement
generation remains unsupported: there is no implemented positive no-launch
discard-retirement branch. Completed candidate handoff avoids creating an
unused replacement; this does not qualify that distinct cancellation case.
The 30-second native deadline bounds operation eligibility and cancellation,
not hard real-time disappearance under arbitrary OS scheduling. Completion
and retirement receipts still require the actual worker and callback joins.

## Evidence

Qualification evidence is indexed in the associated complete PR's Evidence
section and preserved in its retained evidence archive. The manifest identifies
the exact tested source SHA, workflow run and attempt, bounded journey report,
cleanup report and artifact SHA-256 hashes. Generated run identifiers and hashes
are not committed back into source.

A passing claim requires the matching immutable-SHA workflow and complete reports
to satisfy the existing acceptance criteria, including successful writer/resource
joins, retained-secret scanning and outer cleanup. Missing, failed or incomplete
evidence establishes no qualification. The manifest must retain every explicitly
unverified boundary: a passing installed-loop run does not imply complete I1,
real-provider capability/billing, macOS or I2 qualification. Lease renewal requires
the explicit read-only observations above, not public retention alone.
