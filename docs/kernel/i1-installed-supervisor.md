# I1 Installed Linux Supervisor

## Backlog Ready Spec

### Verdict

READY WITH RISKS: the user confirmed A and the installed-startup/v1-control
test seam on 2026-10-11. Native image binding and the persistent-anchor OS
prerequisite have passed component qualification. The next implementation joins
trusted installed startup to the production native controller/monitor birth
chain; control-service composition, admission assembly and first model dispatch
remain open. This is not a completed I1 claim or a release artifact.

### Source

Baseline: main `3292f1e87cdd56aaef7babb193658135923b87c4`, merged PR #519.
The user requested continued high-quality progress with no unnecessary slices.
The normative contract remains the [Kernel RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md),
especially sections 9 and 15, and the [I1 integration checkpoint](2026-09-26-design-review.md#5-internal-integration-checkpoints).

De-duplication: GitHub issue searches across open and closed issues, limit 50
per query, succeeded on 2026-10-11 (Asia/Singapore). `supervisor`, `durable run`,
`bootstrap`, and `installed supervisor` returned no matches. `runtime bundle`
returned #99, #101, #104, #127 and #433, covering local-model catalog/setup and
skill resources/package coverage, not this installed Supervisor composition.
These bounded searches do not claim exhaustive issue coverage. Reuse the
existing WP01-WP04/WP06 specs; do not create a new live issue for this draft.

### User Outcome

An authenticated client submits through an independent installed Supervisor,
can disconnect without cancelling the accepted Run, and can reconnect after
Supervisor restart. One real private-workspace edit survives with the same Run,
Journal and budget history; the external workspace remains unchanged.

### Problem

- At the baseline, `StateStore.open` checks a signed Supervisor against a pathname hash of
  `process.execPath`. The existing Linux test bundle signs Node, not the
  application code. Neither fact qualifies an installed Supervisor image.
- `captureSubmittedSource` produces a real retained capture, not an accepted
  Run. `admitRun` currently hashes internal-reference inputs, whereas inline
  `run.submit` preserves its original request digest and normalized intent.
  Simply forwarding capture to that input conflates their replay domains.
- `RunExecution.executeCurrentTool` requires an existing queued tool frontier.
  A newly admitted agent frontier still needs real worker activation, model
  preparation, durable claim, broker transport and typed completion.
- `RunAssemblyValidationMaterial` has trusted resolver callbacks, but no
  non-testing installed assembly producer. Legacy assembly is not a substitute.

### Scope

In: one integrated Linux installation/startup/control/admission/execution/restart
capability, reusing the existing store, reducers, native execution and recovery.
Start with the implemented non-Git source recipe and builtin edit operation.

Out: default CLI cutover, real release publication/key provisioning, Git-source
support, macOS qualification, paid-provider qualification, model/spend-bound
claims, candidate verification/delivery, children/MCP and complete I2-I4.
A scripted endpoint is explicitly fixture transport, not a qualified provider.

### Proposed Implementation Direction

Confirmed A: bundle fixed Node and all Supervisor JavaScript into one signed
executable image. Keep the RuntimeBundle manifest detached to avoid self-hash
cycles. Preserve the existing process-image digest domain and client Node
minimum. Separately signed native addons continue verified held-FD loading.
Do not add a separate unsigned import path or a general closure loader.

The Linux systemd user service must execute the stable StateRoot bootstrap,
not a replaceable npm path or directly the selected Supervisor. That fixed
trusted bootstrap verifies the manifest, installation identities and selected
image bytes before executing application code, holding/revalidating the image
through execution. Retain immutable version directories and durable atomic
selection independently of client replacement.

Use a fixed qualified embedded Node/toolchain; close ambient preload and
dependency-loading routes before authority is released. Independently bind
the actual running image with native descriptor/process observations, rather
than treating `process.execPath` as an image witness. Installation paths, keys,
helpers, inspector facts and validation callbacks are never client inputs.

Reuse `src/state/store.ts`, `native-owner.ts`, `control-channel.ts`,
`source-target.ts`, `source-inspection-owner.ts`, `reducers/admission.ts`,
`reducers/agent.ts`, `run-execution.ts`, `src/model/run-assembly.ts` and
`model-session.ts`, and `src/policy/runtime-authority.ts`.

Keep one admission reducer. Bind original inline request bytes, normalized
intent and the resolved captured closure in its existing durable transaction.
Authenticated replay precedes live source reopening; equal replay cannot
capture another workspace or admit another Run. Resolve assembly and perform
initial model I/O behind trusted Supervisor composition, not a client facade.
Queue maps are hints only; no new mutable authority ledger is introduced.

Preserve Workspace Trust before workspace-controlled reads, independent Tool
Permission, strong Sandbox enforcement, time/revision/owner fencing, existing
typed error/recovery branches and uncertain-retirement resource ownership.

### Acceptance Criteria

- [ ] A clean installation binds signed complete Supervisor/helper bytes to
  actual running processes; changed/foreign-owned bytes fail closed.
- [ ] Actual systemd-user startup/restart runs the stable bootstrap and selected
  signed image under delegated cgroups. A parent-owned detached child cannot
  qualify this requirement; unavailable OS-manager evidence remains pending.
- [ ] Real native UDS authentication and compatible `control.hello` precede
  every state request; clients cannot supply retained provenance as authority.
- [ ] Fresh inline submission really captures trusted non-Git source and
  atomically persists the accepted Run, initial Checkpoint and response.
- [ ] Equal request/admission replay, including commit-before-reply and after
  reconnect/restart, preserves identity and effects; changed intent conflicts.
- [ ] A real initial model transport produces the native tool frontier, then
  existing strong execution performs one private edit and ready Checkpoint.
  No offline batch, fixture worker activation or fake death proof substitutes.
- [ ] Client exit does not cancel the Run. Restart preserves the authoritative
  cut and budgets, proves predecessor containment retirement before fresh
  activation, and never replays the completed edit.
- [ ] Concurrent startup yields one owner. Incompatible handshake, unsigned
  installation, unresolved death and resource-join failure grant no capability.
- [ ] The campaign checks unchanged host bytes/device/inode, native process
  join and exact cgroup cleanup, and records source/bundle/image identities.

### Validation

Automated: focused public-interface RED-to-GREEN regressions, `npm run build`,
`npm test`, `git diff --check`, and the existing design-contract guard/tests.
Extend actual Linux qualification on free standard GitHub-hosted runners; use
real independent processes, SQLite/CAS, UDS and containment, not mock authority.
The proposed new test seam is installed startup plus the existing v1 control
protocol. It catches package/ownership/replay/execution/restart composition;
it does not qualify macOS or an actual provider's model/charging behavior.

Manual/release: maintainer-controlled signer/public-key/channel and production
provider qualification remain separate. Never request private keys in chat or
publish a test-root-signed image as a Cliq release.

### Current Implementation Gate

Before composing admission/model execution, establish the actual-image and
service-lifecycle prerequisites. This gate is part of I1, not a substitute for
its unchecked acceptance criteria or a mandatory separate product slice:

- Native self-observation takes no path/PID input and binds actual mapped image,
  process credentials/start identity, held descriptor and independent path.
  A cached digest always requires fresh native revalidation. Image replacement
  and deletion fail before StateRoot mutation.
- Every self-observation resource is consumed before retirement; uncertainty
  remains process-wide and cannot disappear through a new capture or finalizer.
  Real close/fclose failure tests immediately reuse the retired FD and verify
  that unrelated bytes remain readable. The final cut follows temporary cleanup.
- `qualify-supervisor-image.ts` uses official Node **24.21.0** archives with
  fixed SHA-256, esbuild **0.28.2**, postject **1.0.0-alpha.6** and matching
  native headers. The client engine remains **Node >=22.13.0**. Complete
  application imports are bundled; only `node:` builtin imports remain external.
  Its compiled-in ephemeral public root signs final full image/helper bytes;
  unused manifest roles grant no admission/execution qualification.
- Seven component cases cover signed-image open, changed app's own signature,
  changed app with the old signature, a proven ordinary-Node preload ignored by
  SEA, writable helper, missing helper with a valid cwd decoy, and changed helper
  bytes. All run outside the checkout cwd; refusal leaves StateRoot empty.
- `qualify-systemd-user.sh` compares actual delegated user services with an
  independent persistent anchor for empty and live dummy workers under manual
  and automatic restart. It uses a new UID, frozen root-owned resource ledger
  and exact runner before/after baseline. A test-only C helper requires genuine
  non-root `clone3(CLONE_INTO_CGROUP)` before controller exec; it has no
  fork-then-migrate fallback. The keeper initializes its delegation, then only
  stays alive; each Supervisor creates and retires its private worker subtrees.
  Root explicitly provisions the fresh UID's `user@UID.service` with an
  instance-specific `Delegate=cpu memory pids` drop-in. Results establish
  non-root birth/retirement under that authorized delegation, not support in
  every distribution's defaults or administrator-free installation.
  Missing/changed cgroup paths are negative prerequisite facts, never death
  authority. Provisioning, incomplete observation and cleanup failure fail the
  diagnostic. The ordinary Node dummy is explicitly not a signed Supervisor.

Local build, all 1,840 portable tests, focused real native regressions and the
seven SEA cases passed on macOS; this is not macOS execution qualification.
The same seven image cases and all eight actual user-manager A/B cases
passed on free standard Ubuntu 22.04 at source
`85e7232a2ae1b62dc3400f41358de93a4a580191` in
[run 38088093224](https://github.com/cogine-ai/cliq-agent/actions/runs/38088093224).
Systemd 249.11 on kernel 6.8.0-1064-azure again removed every original direct
service/worker cgroup, corroborating the initial four-case result at
`f3d1879e35f75890d7ef01eb9e7cf7ec11a9faaf` in
[run 38086725642](https://github.com/cogine-ai/cliq-agent/actions/runs/38086725642).
In A, held descriptors still named the old inodes with ` (deleted)` and each
restarted service had a different inode. In B, the Supervisor service inode
was likewise deleted, but the independent anchor and exact old worker scope
remained on cgroup device 29:

| Layout / dummy worker / restart | Root inode before → after | Old worker scope inode / outcome |
| --- | --- | --- |
| A / empty / manual | 6954 → 7101 | 7052 / deleted |
| A / empty / automatic | 7269 → 7416 | 7367 / deleted |
| A / live / manual | 7584 → 7791 | 7682 / deleted |
| A / live / automatic | 7959 → 8106 | 8057 / deleted |
| B / empty / manual | 8274 → 8274 | 8519 / retained, empty |
| B / empty / automatic | 8274 → 8274 | 9058 / retained, empty |
| B / live / manual | 8274 → 8274 | 9597 / retained, non-root retired |
| B / live / automatic | 8274 → 8274 | 10136 / retained, non-root retired |

All four B worker-parent inodes (8470, 9009, 9548, 10087) stayed unchanged,
as did keeper PID 2848/start ticks 30449 and InvocationID
`38253acac9c94b00b2825c9681371992`. The real common ancestor was the new UID's
`app.slice`, inode 6807, whose `cgroup.procs` belonged to UID/GID 20000 with
mode 0644. Source and destination used cgroup namespace `4026531835`.
These metadata are observations; actual non-root clone3 success verifies birth
access, not a permission-mode inference or root-assisted migration.

In both live B cases, the successor independently observed the old worker and
grandchild with their original PID/start identities still alive and non-zombie
after controller IPC EOF. UID 20000 then wrote `cgroup.kill` through the held
exact old scope; `populated` became zero and all three recorded original
lifetimes, including zombies, disappeared without deleting that scope.
Cleanup reported zero errors and the runner's complete before/after baseline
was identical: UID 1001, manager PID 899/start ticks 857, manager InvocationID
`b7006721924b41c5b9673aeac6fd931e`, cgroup inode 5848.
The bounded reports are retained as
[artifact 11682906299](https://github.com/cogine-ai/cliq-agent/actions/runs/38088093224/artifacts/11682906299)
for seven days; zip SHA-256 is
`23ee4904c66a8e7124094c2d234b9ff1f3855ef5ed00e4195ca9d4fb49e545e8`.

This qualifies the tested OS prerequisite, not production native worker birth,
all-descendant death evidence or signed keeper startup. Full installed/control/
admission/execution/restart I1 and the credential/TLS dependencies below remain
open. The test-only launcher stays in the Supervisor service; it is not the
production controller or a durable reservation witness.

### Installed Anchor Chain Implementation Notes

After merged PR #519, implement signed installed startup and the complete
production native birth/recovery chain together. These are implementation notes
inside I1, not a new micro-slice or a claim that public control, admission or
model execution is implemented. First establish a genuine failing regression
through the existing public native launcher and real Linux process behavior,
then qualify the completed chain through the actual installed entry. The initial
HELLO-time placement test does not prove atomic birth; a kernel first-fork stop
must additionally exclude fork-then-migrate. A simulated fork, synthetic witness
or dummy OS launcher cannot satisfy either native qualification.

Reuse the same SEA with closed bootstrap, keeper and Supervisor modes. The
stable executable is `${stateRoot}/runtime/bootstrap`; user services select
only its fixed bootstrap-keeper or bootstrap-supervisor mode. Compiled release
keys, not argv/environment/control inputs, authenticate the detached manifest.
The keeper is an internal mode of the sole signed `supervisor` entry, not an
extra manifest entry with duplicate complete-file bytes or a new role.

Keep one installed-runtime deep interface: initial installation, opening the
selected held runtime, and executing that runtime in one of the two fixed
roles. Initial installation creates a new private StateRoot and stages entries
without adopting an existing active selection or database. Descriptor-relative
no-follow walks verify the root and every signed entry, including type, owner,
mode, link count, exact count/digest and metadata stability around the read.
The current initial installer supports Linux only. A real macOS experiment
showed that `/dev/fd/<directory-fd>/<child>` does not provide this traversal;
unsupported hosts refuse before any StateRoot write. There is no absolute-path
fallback, and the refusal test is not a Linux installation qualification.
CAS import borrows the exact held Linux root through
`/proc/self/fd/<directory-fd>/.`, retaining the ordinary CAS durability protocol
without returning to the mutable original path. The caller keeps that descriptor
open for the entire operation; accepting locator syntax does not verify a root.
Complete the supported structured-root/member walk and ordinary CAS import
before publishing; unsupported kinds fail closed rather than being ignored.
This does not claim the remaining WP06 closure/upgrade matrix is complete.

The user approved `fresh_installed` genesis on 2026-10-11. Initial installation
does not open StateStore or acquire StateOwner; trusted startup borrows its
still-held verified installation into the existing first StateOwner transaction.
Before genesis staging, the business/authority database is empty and the CAS is
all-and-only the complete signed manifest/imported structured-root/member seed.
Startup revalidates the same held StateRoot and installation; extra/missing or
changed objects and structural lookalikes cannot substitute authority. The birth
manifest records exact seed refs/counts/bytes/root; immediately before commit,
only that seed plus the specifically staged genesis objects may exist. Their
metadata and epoch one commit together, without another ledger or acquisition
operation. Generation origin binds the installation's bundle ref and manifest
digest, and `stateSchemaVersion` reflects the actual schema (currently 4), not
the V1 structure version. Ordinary `fresh_empty` retains its strict empty-CAS
requirement; restarts use existing successor acquisition rather than bootstrap
again. Approval is a contract decision, not completed Linux installed-startup,
migration/cutover, admission or execution qualification.

The initial-owner gate additionally compares the actual SQLite catalog with
the fixed DDL compiled by the same SQLite engine, both before genesis staging
and inside its first transaction. Correct version numbers and empty business
tables alone do not establish a pristine schema: an extra trigger can otherwise
write business state during owner insertion. Refusal preserves the unowned
schema rather than repairing or adopting it. Successor acquisition is unchanged.

Installed startup borrows the fixed signed native helper from the selected
version's already-held descriptor, not an adjacent bootstrap path. Repeated
loads use positional bounded reads and retain the same owning scope through
every in-flight load, including an unawaited one. No helper path or descriptor
selector is added to the public installed handle.

The current installed control composition is read-only. Its status reads the
actual owner, schema and queue cut and verified initial installation, but
reports `degraded` with capacity zero. A nonterminal Run requires a trusted pin
observation that this composition does not yet provide, so status refuses
rather than inferring compatibility or reporting an unverified zero. Real
inline admission and upgrade composition must precede that remaining behavior;
the current startup qualifier is not their qualification or complete I1.

Production controller HELLO-time placement and retained-reservation recovery
passed 25 actual Linux campaign cases at `5b47b93` in
[run 38094701623](https://github.com/cogine-ai/cliq-agent/actions/runs/38094701623).
The four real close-queue/retirement/prompt-closure regressions found in that
run passed at `a036847` in
[run 38095743801](https://github.com/cogine-ai/cliq-agent/actions/runs/38095743801);
both Linux Node matrix jobs still failed the new installed-genesis positive
case. These are component results, not first-fork-stop, installed SEA startup,
persistent signed keeper, or complete I1 qualification.

At `6512543`, [run 38102710091](https://github.com/cogine-ai/cliq-agent/actions/runs/38102710091)
passed the actual bootstrap-to-selected SEA inode exec, signed held helper,
`fresh_installed` genesis, read-only UDS/reconnect and graceful release, plus
32 focused Linux boundaries. Its independent OS tracer observed the first
native controller clone in the protected leaf before user-space setup, joined
the tracer before same-lifetime HELLO/image verification, and retired the
controller; all 25 existing real worker campaign cases and scoped cleanup also
passed. These remain separate component qualifications: the SEA used the test
composition, while the first-fork campaign used its explicit offline prefix.
Neither proves a persistent signed keeper/systemd installed execution chain,
public admission, a provider request or complete I1.

Publish immutable side-by-side directories under
`runtime/bundles/<bundleDigest>/`, where `bundleDigest` is the complete signed
manifest's ArtifactRef, not its distinct self-omitting `manifestDigest`.
Directories remain same-owner `0700`; published data/manifest files are `0400`
and executable/helpers `0500`. File and directory fsync precede selection.
The same-owner single-link `0600` `runtime/active.json` is a closed bundle-digest
locator, published through same-directory exclusive temp creation, file fsync,
atomic rename and directory fsync, never a symlink. No selected bundle is
overwritten or removed. This round supports only initial installation: an
existing selection cannot be switched under nonterminal Runs; compatible
activation, drain and rollback require the canonical upgrade transition later.

Bootstrap derives its StateRoot from the fixed installed location, holds and
revalidates the selection/manifest/entry descriptors, then loads only the
verified native helper through its held FD. A small existing-helper extension
executes the held on-disk Supervisor image with fixed role/root/bundle locators;
these locators are revalidated by the selected image, never taken as authority.
Do not use the worker's sealed memfd for this image: actual Supervisor image
binding still requires its original filesystem identity and independent path.
The systemd unit closes native-loader environment routes before the first ELF
startup; native exec independently uses a fixed environment and FD whitelist.
SEA's ignored `NODE_OPTIONS` alone does not exclude `LD_PRELOAD` or alternate
native library loading. There is no general spawn/import facade.

The independent anchor service owns this delegated topology:

```text
anchor root/
  keeper/
  controllers/<native-created-unique>/
  cliq-<worker-reservation>/
```

Keeper observes its actual service cgroup, moves only itself to `keeper`,
initializes delegation, then stays alive. It never opens StateStore, holds a
StateOwner lock, or manages Run/broker state or a second ledger. Sharing the
Supervisor UID is not an additional OS-level database-access isolation claim.
Ready metadata is only a locator: the Supervisor independently verifies the
actual keeper lifetime/image, namespace and exact held anchor identity. Only
the Supervisor/native execution owner creates or retires execution subtrees.
The service dependency is one-way; Supervisor restart must not stop the anchor.

Keep `LinuxWorkerInstallation.cgroupParent` as the held anchor-root seam;
do not add a separately caller-selected controller parent. Internally,
`openController(helper, cgroupRootFd)` creates the unique private controller
leaf and requires non-root `clone3(CLONE_INTO_CGROUP)` before the first
controller instruction. No fork-then-migrate or root-assisted fallback is
allowed. The monitor is born inside that protected leaf; retain the existing
durable MONITOR -> exact worker placement -> barrier release -> durable READY
ordering. Controller leaves stay outside each worker's `cliq-*` kill scope,
so Supervisor-service cleanup cannot erase the producer or original worker
scope halfway through recording physical birth.

Consume each resource before retirement and never retry a possibly reused FD.
Any uncertain close/join blocks exec, READY or fresh activation rather than
being erased by a new handle, finalizer, cache or success-shaped cleanup. Exec
failure must not resume a Node event loop whose descriptors were destroyed.
Recovery keeps the original scope inode and reservation closure and uses the
existing fresh native all-descendant death proof; neither a missing path,
controller EOF alone, timeout nor the ready metadata can substitute for it.

Qualification runs the actual signed installed entry under the real systemd
user manager on a free standard Linux runner. Extend the accepted test-only OS
tracer to stop real processes at controller birth/HELLO and monitor fork before
READY, then kill the real Supervisor. The oracle independently observes actual
PID/start/image and cgroup placement, durable reservation phases, unchanged
scope identity, positive descendant join and exact cleanup; it never manufactures
evidence or adds a production fault switch. Exercise normal and automatic
restart, empty/live descendants and damaged-witness refusal. Anchor loss or a
new boot still waits for recovery when the original death cannot be proved.

### Risks And Dependencies

SEA bundling, fixed helper locations, preload control and actual-image binding
must be qualified together. Public admission is not a wrapper around internal
reference inputs. First model dispatch requires a trusted assembly/broker path;
missing capability/cost authority must remain a refusal, not a fabricated grant.
The explicit CI release root is compiled into the trusted test bootstrap/image,
never supplied by a control client. A scripted endpoint still requires installed
signed adapter/catalog/price objects, principal-bound endpoint/credential
registration and actual TLS/broker claim-before-send. Offline credential JSON,
always-true validators and fictitious Ollama zero-cost provenance are forbidden.
Actual systemd MainPID-death diagnostics confirmed that service cleanup removes
the original cgroup inode, which the current retained-death inspector requires.
No missing cgroup can be relabeled as the old containment's empty observation.

Required sequence: establish signed installed startup;
bind real capture to original admission; drive first model and existing edit;
qualify reconnect/restart and fault cuts; independent review before a normal PR.
These are implementation steps inside one capability, not mandatory tiny PRs.

Rollback: this hidden integration does not migrate or activate existing user
state and does not change the default CLI. Keep installation/state fixtures
separate. Runtime upgrades across signed-owner identity remain unsupported
until the existing canonical upgrade transition is implemented.

### Open Questions

Single-image A and the integration-test seam remain confirmed. After the real
negative lifecycle result above, the user additionally approved **first
qualifying an independent persistent containment anchor** on 2026-10-11.
Reuse the same signed image with a fixed keeper role; it has no StateOwner,
Run, database or broker authority and adds no second lifecycle ledger. Only
the current Supervisor manages its delegated execution subtrees after a
bounded initialization handoff.

The OS A/B campaign above passed. Next integrate the fixed keeper role into
trusted signed startup and atomically protect the production controller/monitor
birth chain, not only a worker moved after fork. Preserve actual non-root
`clone3(CLONE_INTO_CGROUP)` placement before the first controller birth, with no
fork-then-migrate fallback or root-assisted permission workaround. Across
Supervisor restart, validate exact retained identities before attempting the
existing native death proof. Dummy OS results do not qualify production native
READY/birth-witness fault cuts, which still require the real signed controller,
reservation, monitor, namespace worker and existing OS tracer campaign.

Anchor loss or machine reboot remains explicit recovery waiting when original
containment death cannot be proved. The user accepted this boundary; a strict
new-boot or retired-containment evidence branch requires a separate normative
design, not an ENOENT/timeout shortcut.
Exact embedded runtime/build pins are engineering qualification work; release
key/channel ownership is needed only before real publication, not CI fixtures.
