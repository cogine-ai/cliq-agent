# I1 Installed Linux Supervisor

## Backlog Ready Spec

### Verdict

READY WITH RISKS: the user confirmed A and the installed-startup/v1-control
test seam on 2026-10-11. Native image binding has passed component qualification;
trusted installed startup, persistent containment, admission assembly and first
model dispatch still require implementation and real qualification. This is not
a completed I1 claim or a release artifact.

### Source

Baseline: main `0b26675c23ce6bbefd133d9a20d93569513e65cc`, merged PR #518.
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
