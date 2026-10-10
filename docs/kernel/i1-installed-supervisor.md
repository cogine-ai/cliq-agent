# I1 Installed Linux Supervisor

## Backlog Ready Spec

### Verdict

READY WITH RISKS: the user confirmed A and the installed-startup/v1-control
test seam on 2026-10-11. Native image binding, actual systemd-user operation,
trusted admission assembly and first model dispatch still require implementation
and real qualification. This is not a completed I1 claim or a release artifact.

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
- `qualify-systemd-user.sh` diagnoses actual delegated user services for empty
  and live dummy workers under manual and automatic restart. It uses a new UID,
  frozen root-owned resource ledger and exact runner before/after baseline.
  Missing/changed cgroup paths are negative prerequisite facts, never death
  authority. Provisioning, incomplete observation and cleanup failure fail the
  diagnostic. The ordinary Node dummy is explicitly not a signed Supervisor.

Local build, focused real native regressions and the seven SEA cases have
passed on macOS; this is not macOS execution qualification. Free standard
Ubuntu 22.04 CI runs both the image component and actual user-manager diagnostic;
the Linux results and full-suite validation must be recorded before this gate
is considered verified. Full installed/control/admission/execution/restart I1
and the credential/TLS dependencies below remain open.

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
Test systemd MainPID death with an active worker early: service cleanup may remove
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

No remaining product choice for this capability. A and the integration-test
seam are confirmed.
Exact embedded runtime/build pins are engineering qualification work; release
key/channel ownership is needed only before real publication, not CI fixtures.
