# Ecosystem Surfaces And Kernel Cutover

## Backlog Ready Spec

### Verdict

READY WITH RISKS

The ecosystem and cutover decisions are closed. The work is implementable, but it is the final integration package: protocol compatibility, state migration, and removal of the legacy runtime create a high blast radius. It may be built in parallel, but it cannot ship as the default until work packages 01-05 and every RFC release gate pass together.

### Source

Brief / issue / roadmap item:

- Work package 06 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: **Delegate. Detach. Return to verified work.**
- [Issue Supersession And Dependency Map](issue-supersession-map.md).

Related issues:

- #76 must consume durable Run state from this control client; its visual banner work remains a dependent TUI issue rather than a competing state model.
- #62 and #63 are absorbed where policy and sandbox claims become executable runtime behavior.
- #46 is superseded by Run verification and delivery.
- #65 and #67 remain native-Windows prerequisites for a future runtime RFC; they do not preserve attached execution or weaken the Kernel Cut's no-execution Windows matrix.
- #99-#107 remain a separate `cliq-models` product epic. They must use the typed provider interface, and #105 must not reuse the kernel term `Supervisor` for a model service manager.

Related code:

- `src/model/types.ts`, `src/model/registry.ts`, `src/model/index.ts`, and `src/model/providers/*` implement the current OpenAI, Anthropic, OpenRouter, OpenAI-compatible, Zhipu, and Ollama providers.
- `src/policy/mcp-placeholder.ts`, `src/policy/network-placeholder.ts`, `src/policy/*`, and `src/protocol/model/actions.ts` contain partial MCP/network permission vocabulary without an executable MCP runtime.
- `src/skills/loader.ts`, `src/skills/types.ts`, `src/instructions/*`, and `src/runtime/assembly.ts` implement `SKILL.md` discovery/injection and configured instruction files; automatic `AGENTS.md` compatibility is missing.
- `src/extensions/loader.ts` imports repository JavaScript in-process and must not remain an untrusted extension boundary.
- `src/headless/contract.ts`, `events.ts`, `jsonl.ts`, `rpc.ts`, and `run.ts` contain reusable envelope and adapter concepts but currently own in-process Run lifetime.
- `src/cli.ts` and `src/tui/*` are the existing user surfaces to convert into clients.
- `src/session/store.ts`, `src/session/checkpoints.ts`, `src/workspace/transactions/*`, `README.md`, and `package.json` contain the legacy persistence/runtime claims and migration inputs.

### User Outcome

The same durable Run is visible and controllable from CLI, TUI, JSONL, and local RPC. Disconnecting any client does not stop it. The current provider set, MCP tools, `AGENTS.md`, and `SKILL.md` work through one typed thin waist. Users can inspect cost, latency, retries, tools, checks, immutable results, and receipts without exposing prompts or secrets. Existing local Sessions are imported once, and the product switches to the new kernel in one auditable cut rather than carrying two conflicting runtimes.

### Problem

Today each surface is coupled to an in-process Session runner. stdio RPC allows one active process-owned run and cancels it when the transport closes. JSONL events use process-local semantics. The TUI owns execution rather than attaching to durable state. MCP has policy placeholders but no tool runtime. Skills exist, but `AGENTS.md` does not have a first-class compatibility contract. Legacy JSON Session persistence, Transaction state, free-text `ModelAction`, and public README claims would remain competing truths unless cut over and removed together.

### Scope

In:

- Expose the work package 04 Unix-domain-socket control protocol through one generated client/schema package with `CONTROL_PROTOCOL_VERSION = 1`, `HEADLESS_SCHEMA_VERSION = 3`, strict request/result/event validation, and an explicit compatibility handshake.
- Use the complete v1 method surface: `control.hello`; `session.create|list|get|fork|compact|handoff.create`; `run.submit|list|get|attach|cancel|approve|input|reconcile|diff|result|apply`; `authorization.create|list|revoke`; `mcp.register|refresh|list`; `artifact.get`; and `supervisor.status`. Authorization/MCP administration is Supervisor-owned and request-id fenced, not adapter-specific Run lifecycle. Attach uses a monotonic committed `eventSeq` cursor.
- Freeze generated v1 wire schemas for every method, result, event, and the closed error union. Every mutator carries an authenticated `requestId`; Session/Run mutations carry the exact expected revision and waiting/cursor identity required by that method; all strings, ids, refs, arrays, integers, inline payloads, cursors, and frames are bounded before state access. Same authenticated principal+method+requestId+request digest returns the first committed response, while request-id reuse with different bytes is `REQUEST_ID_CONFLICT`.
- Keep Session context-only. There is no public `session.append`, `session.items`, handoff import, bookmark mutation, global active-Session setter, Session lease, or Run-Checkpoint mutation. `session.get` is the bounded item read; only root Run terminal publication may append internally through the Session state service. Compaction preserves raw items; fork copies only an immutable context prefix; handoff creation produces deterministic immutable JSON/Markdown artifacts. `cliq resume` composes `session.get` with a new `run.submit` and never claims to resume an old execution. Imported legacy bookmarks/handoffs appear as typed legacy Session items/artifact refs through `session.get` plus `artifact.get`; standard `session.fork` may use their preserved cursor, but no hidden compatibility mutation method exists.
- Convert CLI commands to Supervisor clients: `cliq run [--detach]`, `cliq list`, `cliq status <runId>`, `cliq inspect <runId>`, `cliq attach <runId>`, `cliq cancel <runId>`, `cliq approve <runId>`, `cliq input <runId>`, `cliq reconcile <runId>`, `cliq diff <runId>`, `cliq result <runId>`, and `cliq apply <runId>`.
- Map Session surfaces without a second protocol: `cliq session create|list|show|fork|compact` and `cliq handoff create`. `cliq resume` composes the same generated `session.get` and `run.submit` clients. Retained legacy bookmark/handoff inspection commands read migration artifacts only; no alias restores execution, imports context into an existing Session, or writes legacy JSON/SQLite directly.
- Make attached `cliq run` submit then attach. Make `--detach` return only after durable admission and print the `runId`; client exit never requests cancellation.
- For `--detach` with no required verifier, interactive admission must present trusted suggestions or require explicit confirmation of an unverified Run; noninteractive/JSONL/RPC submission must set `allowUnverified=true`. Absence of a verifier is never hidden behind the product promise.
- Convert the TUI to the same client library. It must render queued/running/waiting/terminal state, authoritative terminal reason/detail, verification state, approvals/input/reconciliation, child relationships, budget usage, diff/result, and resumable event history. TUI process death never changes Run state.
- JSONL and stdio JSON-RPC become schema-v3 adapters over the local control protocol, not Run owners. Closing stdin/stdout detaches the adapter and does not abort an admitted Run.
- Expose no general `artifact.put`. Client objectives, Session summaries, approval/input/reconciliation data, and admission/delivery options use only their method-specific bounded inline schemas; after authentication/trust/policy validation the Supervisor canonicalizes and publishes those bytes to CAS and binds them into the request/admission digest. In particular `run.submit.objective` becomes exact NFC `RunObjectiveV1` (`1..262144` UTF-8 bytes, no NUL/unpaired surrogate) and `RunSpec.objectiveRef` is its sole durable source.
- Preserve a stable envelope with protocol/schema version, `runId`, `eventSeq`, timestamp, event type, and typed payload. Incompatible clients fail the handshake with an upgrade message; event meanings never change silently.
- Integrate the six WP02-owned typed provider adapters—OpenAI, Anthropic, OpenRouter, OpenAI-compatible, Zhipu, and Ollama—through the generated control/setup surfaces; this package does not independently implement or refactor `src/model/providers/*`. Ollama is supported only through the Kernel-owned minimal signed `local_inference` RuntimeBundle service and attested no-egress boundary; arbitrary third-party/raw loopback Ollama endpoints are not durable zero-cost authority. Models without verified native tool calling or constrained structured output remain text-only.
- Implement MCP **tools only** over stdio and Streamable HTTP. Include user-initiated registration/refresh, initialization/capability discovery, `tools/list`, behaviorally stateless-per-call `tools/call`, cancellation, timeout, containment-safe relaunch, and structured result/error mapping.
- Store endpoint/executable identity, initialize/capability/tool-schema digests, `stateModel='stateless_per_call'`, per-tool `McpRecoveryContract`, registration proof, and lifecycle limits in a user MCP registry created only by explicit `cliq mcp register/refresh`. Trusted `.cliq/config`, loaded after Workspace Trust, may request registered ids but cannot define commands, URLs, environments, recovery adapters, or credentials. Unknown ids/tools, stateful-session dependence, and schema drift fail closed. Remote credentials are brokered grants; raw secrets never enter workspace config, worker environment, events, or receipts.
- During explicit stdio registration/refresh, use the durable `admin_operations` fence: persist prepared, powerless preactivate a one-shot strong containment, probe with no workspace/secret/network, prove full death, then atomically publish the receipt, immutable registry revision, and control response. Startup never adopts a probe and no duplicate request may launch a second containment before death proof.
- Freeze the exact immutable registry revision into each Run. Every stdio **tool call** gets a fresh call-scoped process/containment, empty private `HOME`/`TMPDIR`, read-only retained signed executable closure, no persistent writable mount/network/workspace/state/credentials, and mandatory teardown/death proof before its `McpServerStoppedItem`, visible ToolResult, budget settlement, and frontier advance commit together. No process is Run-scoped or reused. Launch `opId` binds Run, batch item, call index/id, registry digest, and `lifecycleSeq`; replacement after a completed early stop increments lifecycle sequence, while an ambiguous launch may retry the same op only after death proof and frozen bounds.
- Route Streamable HTTP through the trusted broker and Journal each call according to user-registered recovery metadata. Missing metadata is `manual`, never inferred from a tool name or schema annotation.
- On macOS strong execution, freeze a signed content-addressed `GuestToolchainManifest` into `assemblyRef`: guest image, architecture, kernel/userspace ABI, Cliq worker, shell, Git, Node/package manager, search tools, and every admitted executable path/digest/version. Resolve tools/verifiers against guest Linux identity, not host Mach-O paths. Reject host-only/native-incompatible identities with `UNSUPPORTED_EXECUTION_IDENTITY`; never imply host `node_modules` run in the guest.
- Add `AGENTS.md` compatibility only after Workspace Trust. A held-root no-follow scan publishes exact `WorkspaceInstructionSourceManifestV1` plus the canonical all-and-only `WorkspaceInstructionManifestV1`, then renders one deterministic all-scopes JCS prompt block whose entries retain their root-relative path and subtree label. This is context-only configuration authority: it never widens source selectors or enters SourceManifest, a generation, result/diff, or publication. It never selects an unstored “applicable” subset from a later target path; descriptor/source/content/digest equality is independently recoverable from the frozen artifacts.
- Preserve current `SKILL.md` discovery for `.cliq/skills` and `.agents/skills` at project/user/built-in scopes. Every selected skill has exact `SkillSourceIdentityV1`: workspace/user files bind the authenticated identity and held owner-only root capture, while bundled files bind an acyclic signed non-executable RuntimeBundle `skill_bundle` entry plus exact `BundledSkillClosureV1`. Freeze all-and-only `SKILL.md`/resource bytes and their omission digests into `assemblyRef`; skill instructions are source-labeled in the prompt and never enter SourceManifest or grant tools, network, MCP, or sandbox access.
- Remove repository JavaScript extensions and repository command hooks from the Kernel runtime. Migration reports each unsupported entry. Replace their supported use cases with declarative instructions/policy, skills, user-registered MCP tools, explicit built-in Bash tool calls, or frozen verifiers. Workspace config cannot define or auto-launch executable code. No arbitrary repository code is imported into the Supervisor or executed merely because the workspace is trusted.
- Expose local, run-scoped telemetry for wall/model/tool/verifier latency, token/cost usage, retries, tool/MCP counts, repair attempts, waits, recovery count, child Runs, and terminal outcome. Telemetry derives from authoritative Run/Journal/receipt facts and never drives recovery.
- Store no prompt text, tool body, source content, secret, or raw path in telemetry fields. No remote telemetry exporter is part of the Kernel Cut.
- Add stable artifact inspection for Checkpoints, Journal receipts, verifier receipts, RunResult, diff, stdout/stderr, and migration records, subject to local access controls and redaction.
- Perform the RFC one-time migration under a cutover sentinel and all known legacy locks: prove process/open-descriptor quiescence with platform inspection, detect unresolved active transactions, double-scan the locked inventory, create and validate a timestamped read-only backup, import Sessions/items/compactions/plans/handoffs, import old checkpoints only as `legacy-bookmark` artifacts, normalize ownerless stale Session lifecycle fields, and transactionally mark schema/import completion.
- Run migration automatically on first invocation of the Kernel Cut binary. If a blocker exists, make no authoritative change and print the exact process/transaction to resolve. The importer is idempotent after interruption.
- While migration is blocked, expose only state preflight/export and the exact importer-owned legacy `cliq tx status`/`abort`/`apply` remediation commands; do not admit new work through the legacy runner. Remove this narrow remediation writer path immediately after successful cutover.
- Reuse the work package 01 commands `cliq state migrate --check`, `cliq state migrate`, `cliq state export`, and `cliq state rollback --to-legacy <migrationId>`. Rollback sends exact `RollbackToLegacyRequestV1` through the authenticated current Supervisor so it reuses the already-held state-owner token rather than deadlocking on self-acquisition, then holds the one canonical order—exclusive Kernel global/cutover gate plus that current state-owner token, local-model registry/object-store, legacy auth-store, byte-sorted legacy Session/transaction/plan locks, then credential-authority—gates every public mutator/broker release, and refuses nonterminal Runs. Its exact `MigrationControlV1` is the global rollback fence. Before restoring bytes it terminalizes admin/cycle authority without new productive release, death/no-spawn proves and retires every worker/invocation/admin/local-inference containment/launch, closes broker/control, and proves no credential write remains. Any unknown or unprovable authority blocks. While `rollback_draining` remains current it publishes the exact globally quiescent `ArchivedKernelDatabaseImageV1`, final complete CAS manifest, and their acyclic `ArchivedKernelGenerationManifestV1`; only then may it restore legacy bytes and advance to `rollback_restoring`. It selects the exact restored-absent/nonsecret/credential auth outcome, stages and binds receipt/marker bytes, gracefully terminalizes the active StateOwner as the last Kernel transaction, publishes the legacy-root marker first and state-root global legacy marker last, and exits. A recovery successor remains fenced, republishes only those bound bytes, and gracefully terminalizes itself. Future Kernel re-entry is a fresh migration generation, never reuse/merge.
- Import the RFC/WP01 `MigrationFilesystemRootIdentityV1`, `LegacyAuthFileIdentityV1`, `LegacyAuthStoreObservationV1`, `LegacyAuthNonSecretProjectionV1`, `KernelDatabaseImageIdentityV1`, `CasNamespaceManifestV1`, `KernelGenerationIdentityV1`, `ArchivedKernelDatabaseImageV1`, `ArchivedKernelGenerationManifestV1`, complete inventory/credential-ready/round-trip/backup/candidate/legacy-generation auth-outcome graph, `RollbackToLegacyRequestV1`, plaintext-consent/auth-marker/receipt/authority-marker, and `MigrationControlV1` phase union without a WP06-local marker format. Credential and local-model entrypoints participate in that exact protocol through shared-gate/held-lock tokens; only WP01 advances control/authority state.
- Remove the old runtime path, whole-Session JSON writes, future-facing Transaction execution, free-text action repair, in-process RPC/TUI Run ownership, and contradictory README/package claims in the same Kernel Cut. Do not retain long-term dual write or a public legacy-runtime flag.
- Install Kernel runtimes as immutable, signed, content-addressed `RuntimeBundle` directories side by side. `assemblyRef` pins the exact bundle/toolchain identity for each Run, and the user-service definition points to a stable state-root bootstrap plus an atomically selected versioned Supervisor bundle rather than a replaceable global npm path. Upgrade never overwrites a bundle: stage/self-test first, prove the candidate Supervisor is compatible with every nonterminal Run schema/assembly and can launch each pinned worker bundle, then switch through the bootstrap with rollback-on-startup-failure. If compatibility is not proven, keep the current Supervisor active across reboot and report `drain_required`; never kill or replace it under incompatible active Runs.
- Perform no automatic deletion of Sessions, Session items, Runs, RunSpecs, RunResults, Checkpoints, Journal facts, worker-launch/control-request-response facts, verification receipts/provenance, grants/waits, migration archives, MCP registry/registration receipts, or referenced runtime/guest-toolchain artifacts; expose no `run.delete`. Keep all display `run_events` while a Run is nonterminal; terminal-Run display events may prune only after 30 days while publishing explicit earliest/latest cursor bounds. Quarantined generations require whole-containment-death proof plus retention checks, and CAS GC may remove only unreachable orphans older than seven days after a complete authoritative-root reachability walk.
- Add and wire `test:fault`, `test:sandbox`, `test:migration`, and `test:e2e` scripts required by the RFC. Root `test:fault` is the mandatory aggregator: it runs WP01's `test:state-fault` plus every WP03-WP06 fault matrix, propagates failures, and treats a missing or skipped child suite as failure.

Out:

- New providers beyond the current six, and every broader `cliq-models` catalog/download/routing/product surface beyond the minimal signed local-inference bootstrap required for the Ollama adapter.
- MCP resources, prompts, sampling, marketplace/discovery service, OAuth product UX, or arbitrary MCP protocol parity beyond tools.
- Stateful MCP server recovery, hidden server-memory Checkpoints, cookie/session affinity, or treating `manual` recovery as stateful support.
- Secret-bearing, direct-network, or workspace-mutating stdio MCP servers; repository-defined MCP executable/URL/environment/credential configuration.
- A general in-process plugin ABI or arbitrary repository extension execution.
- Repository-defined command hooks or executable command-tool registration; these are not compatibility obligations of the Kernel Cut.
- Cloud app server, remote worker cluster, distributed queue, accounts, teams, billing, or multitenancy.
- ACP, multi-language SDKs, Desktop/Web/mobile applications, workflow YAML, DAG scheduling, or provider-count competition.
- Remote telemetry upload or collection of prompt/source/tool payloads.
- Native Windows execution, Supervisor/control transport, new Kernel SQLite/CAS creation, importer, inspection/configuration, or a weak sandbox fallback. Native Windows exposes only descriptor/handle-safe `cliq state export --output <absolute-new-file>` plus its state-free `--verify` reader. Export emits exact `LegacyPortableHandoffV1` container bytes and `LegacyPortableHandoffExportReceiptV1`; verify emits exact self-contained `LegacyPortableHandoffVerificationResultV1`. Neither establishes Kernel authority, and the archive contains only schema-projected context and no structured credential authority. Every other Kernel command returns a typed unsupported-platform error. WSL2 follows the Linux probes.
- Long-term legacy compatibility, dual write, or conversion of legacy bookmarks into recovery Checkpoints.
- In-place runtime-bundle overwrite, two concurrent authoritative Supervisors, automatic authoritative Run deletion, or a product retention/delete policy without a later RFC.

### Proposed Implementation Direction

Likely files/modules:

- Consume and complete the `src/control/*` client/contract modules created by work package 04. Add `src/control/v1/source.ts`, `generate.ts`, generated TypeScript validators/JSON Schemas under `src/control/v1/generated/`, golden fixtures, and surface conformance tests; do not hand-maintain parallel adapter types.
- Refactor `src/cli.ts` command parsing/dispatch and add CLI integration tests for every Run and public Session/handoff command, detach semantics, request-id replay, bounded pagination, and typed errors.
- Refactor `src/tui/app.tsx`, `src/tui/store.ts`, `src/tui/approval-bridge.ts`, transcript/status components, and integration tests into control clients.
- Replace the process-owned contracts in `src/headless/contract.ts`, `events.ts`, `jsonl.ts`, `rpc.ts`, and `run.ts` with schema-v3 adapters; preserve artifact/event formatting concepts.
- Consume WP02's completed typed capability adapters from `src/model/types.ts`, `registry.ts`, `index.ts`, and `providers/*`; WP06 owns setup/control wiring and cross-provider integration fixtures only, not a second implementation of those modules.
- Create `src/auth/endpoint-registry.ts`, `src/auth/credential-bindings.ts`, `src/auth/platform-secret-store.ts`, `src/auth/legacy-auth-migration.ts`, and tests for the append-only same-user endpoint/credential authority and fail-closed platform-store migration.
- Create `src/local-models/registry.ts`, `src/local-models/enroll.ts`, `src/runtime/local-inference.ts`, `src/runtime/local-inference-service.ts`, and fault tests for the signed local-model registration/object import, exact service spec, durable launch rows, bounded join/start, blocked activation, containment-bound evidence, takeover retirement, and model dispatch gate.
- Create `src/mcp/types.ts`, `registry.ts`, `register.ts`, `recovery.ts`, `client.ts`, `stdio-lifecycle.ts`, `streamable-http.ts`, and tests; remove `src/policy/mcp-placeholder.ts` after enforcement exists.
- Consume work package 03's `src/sandbox/guest-toolchain.ts` verifier/resolver and microVM manifest API. Add RuntimeBundle packaging plus WP06 integration fixtures for signed `GuestToolchainManifest` identity; do not add a second guest verifier or probe host executables.
- Create `src/runtime-bundle/types.ts`, `manifest.ts`, `install.ts`, `activate.ts`, `compatibility.ts`, and tests for immutable side-by-side bundles and single-owner Supervisor handoff. Extend `supervisor.status` with active/installed/pinned bundle identities.
- Consume work package 04's `src/supervisor/retention.ts` and work package 01's reachability APIs, adding changes in those owning packages as explicit dependencies rather than direct adapter-table writes. WP06 adds cross-package tests for no-authoritative-delete invariants, 30-day event pruning, seven-day orphan grace, and worker-launch/control-response/runtime/toolchain/MCP registry roots.
- Create `src/instructions/agents.ts` and tests; extend `src/runtime/assembly.ts` and `src/skills/loader.ts` to freeze instruction/skill manifests after trust.
- Remove repository dynamic imports from `src/extensions/loader.ts` and command execution from `src/hooks/runner.ts` in the new runtime; add migration diagnostics for every unsupported legacy extension/hook entry.
- Create `src/telemetry/run-telemetry.ts` and tests as a redacted projection over Run/Journal/receipt facts.
- Consume `src/state/migrate-legacy.ts` and `src/state/rollback.ts` from work package 01; add final cutover/fault/idempotency coverage without creating a second migration implementation.
- Update `src/index.ts`, `README.md`, `CHANGELOG.md`, `package.json`, help text, and historical-doc supersession notes at cutover.

Implementation notes:

1. `src/control/v1/source.ts` is the sole authored protocol source. It defines `CONTROL_PROTOCOL_VERSION = 1`, `HEADLESS_SCHEMA_VERSION = 3`, method names, request/result/event discriminators, bounds, and the error union. `generate.ts` deterministically emits the server validators, client types, JSON Schemas, adapter codecs, and golden fixtures into `src/control/v1/generated/`; generated files carry a source digest and are never hand-edited. `npm run generate:control` regenerates them, and `npm run check:control-generated` fails CI on any diff.
2. `control.hello` is the only pre-handshake method. Its request is `{protocolVersion: 1, clientBuild, controlSchemaRange, headlessSchemaRange, requestedFeatureIds}` with at most 64 feature ids; the response returns server build, both supported schema ranges, capabilities, Supervisor instance, and active RuntimeBundle identity. No Session, Run, artifact, or state query occurs before compatibility and same-user peer authorization pass. Incompatible ranges return `INCOMPATIBLE_PROTOCOL` with both supported ranges and an upgrade action.
3. Freeze these v1 method contracts in the generated source; no adapter may widen them:

   | Method | Required request | Result and bound |
   |---|---|---|
   | `session.create` | `requestId`, admission key+digest, bounded workspace/source fields | idempotent Session snapshot |
   | `session.list` | optional workspace filter, opaque cursor, limit | Session summaries plus next cursor; default 50, maximum 100 |
   | `session.get` | Session id, `afterItemSeq`, limit | snapshot plus ordered item refs and next cursor; default 100, maximum 1,000, encoded item metadata maximum 1 MiB |
   | `session.fork` | `requestId`, admission key+digest, source Session id, expected context revision, bounded source cursor | idempotent new Session snapshot containing only the selected immutable context prefix |
   | `session.compact` | `requestId`, request digest, Session id, expected context revision, bounded item range, UTF-8 summary | idempotently replayable post-commit Session snapshot; summary maximum 256 KiB and raw items retained |
   | `session.handoff.create` | Session id, expected context revision, optional bounded cursor | deterministic immutable JSON and Markdown artifact refs |
   | `run.submit` | `requestId`, `admissionKey`, Session id, expected context revision, workspace path/identity, NFC UTF-8 objective normalized into exact `RunObjectiveV1`, bounded typed model/budget/policy/verifier/source options, canonical request digest | authoritative Run snapshot after Supervisor validation/capture/publication; objective is 1..256 KiB and its artifact ref is frozen in RunSpec; identical admission key+digest returns it |
   | `run.list` | bounded status/Session filter plus opaque cursor/limit | authoritative snapshots plus next cursor; default 50, maximum 100 |
   | `run.get` | Run id plus independent item/Journal/Checkpoint cursors and limits | authoritative snapshot, ordered typed item refs, Journal metadata/evidence refs, Checkpoint refs, and next cursors; each limit default 100/maximum 1,000 and combined encoded metadata maximum 1 MiB |
   | `run.attach` | Run id, `afterEventSeq`, batch limit | one-transaction authoritative Run snapshot, earliest/latest/high-water event bounds, ordered retained events through that high-water, and next cursor; batch 1..1,000, `earliest-1` is valid, older is cursor-expired, and future cursor is invalid |
   | `run.cancel` | `requestId`, Run id, expected Run revision | post-reducer Run snapshot |
   | `run.approve` | cancel identity fields plus exact waiting ref, `allow` or `deny`, optional bounded TTL | post-reducer snapshot and decision ref |
   | `run.input` | cancel identity fields plus exact waiting ref and inline kind-matched UTF-8/JSON input | decode exact `InputPromptV1`/`InputResponseSchemaV1`, publish `UserInputPayloadV1`, then atomically append identity-matched UserInput/ToolResult plus post-reducer snapshot; input maximum 1 MiB |
   | `run.reconcile` | cancel identity fields plus exact waiting ref and `probe_now|abandon_run`; no caller adapter/evidence payload, and abandonment is allowed only for an invocation frozen as `ReplayClass='manual'` | trusted frozen-contract probe or exact attestation plus post-reducer snapshot |
   | `run.apply` | `requestId`, `admissionKey`, verified source Run id, exact expected source `Run.resultRef`, bounded inline delivery options | newly admitted delivery Run snapshot; Supervisor resolves/publishes refs |
   | `run.result` / `run.diff` | result-bearing terminal Run id (`succeeded|completed_unverified`) | immutable artifact refs; nonterminal/failed/cancelled is exact `RESULT_UNAVAILABLE` and never selects a failed candidate |
   | `authorization.create` | `requestId` plus exactly one RFC-discriminated workspace read, execution identity, verifier execution, or dependency-script target and bounded TTL | opaque principal-owned grant id; no target execution and no caller-authored ArtifactRef |
   | `authorization.revoke` | `requestId`, grant id | active becomes revoked; revoked replay is stable; consumed returns the immutable consumed summary with `already_consumed` and no transition |
   | `authorization.list` | bounded kind/state filter plus cursor/limit | opaque grant metadata only; no secret bytes |
   | `mcp.register` | `requestId`, registration id, retained stdio execution-identity grant or HTTP endpoint registration/credential ids, stateless assertion, bounded per-tool recovery request | death-proven probe receipt plus immutable registry revision |
   | `mcp.refresh` | `requestId`, registration id, expected registry revision | copy the exact current immutable transport/recovery/lifecycle inputs, reprobe them, and append the next immutable revision; no target/id replacement and admitted Runs retain old refs |
   | `mcp.list` | bounded cursor/limit | immutable registry-revision summaries |
   | `artifact.get` | artifact digest, safe-integer offset, length | digest-verified base64 bytes, next offset, total size/digest, EOF; chunk maximum 4 MiB |
   | `supervisor.status` | `protocolVersion: 1`; no other request fields | health, queue capacity, state schema, active/installed bundle identities, and pinned-bundle compatibility summary |

   The exact state-changing request types are:

   ```ts
   type MutationBase = {
     protocolVersion: 1
     requestId: string
     requestDigest: string
   }

   type BudgetOptions = Partial<RunSpec['budgets']>

   type NonSecretEnvValueRequest = {
     kind: 'non_secret_literal'
     value: string
   }

   type NonSecretArgumentRequest = {
     kind: 'non_secret_literal'
     value: string
   }

   type SourceSelectorRequest = {
     path: string
     scope: 'entry' | 'subtree'
     readGrantId?: string
   }

   type VerifierRequest = {
     id: string
     version: string
     required: boolean
     executable:
       | { kind: 'toolchain'; toolId: string }
       | { kind: 'workspace_script'; path: string; expectedDigest?: string }
     argv: NonSecretArgumentRequest[]
     cwd: string
     env: Record<string, NonSecretEnvValueRequest>
     writableEphemeralPaths: string[]
     identityReadGrantId: string
     executionGrantId?: string
     timeoutMs?: number
     retries?: number
     outputLimitBytes?: number
   }

   type DependencyRequest =
     | { mode: 'none' }
     | {
         mode: 'locked'
         registryEndpointIds: string[]
         credentialGrantIds: string[]
         allowInstallScripts: boolean
         installScriptsGrantId?: string
         maxPackages?: number
         maxDownloadBytes?: number
       }

   type RunModelRequest =
     | {
         provider: 'ollama'
         model: string
         endpoint?: never
         modelCredentialGrantIds?: never
       }
     | {
         provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
         model: string
         endpoint: { kind: 'registered'; endpointRegistrationId: string }
         modelCredentialGrantIds: string[]
       }

   type RunSubmitRequest = MutationBase & {
     method: 'run.submit'
     admissionKey: string
     sessionId: string
     expectedContextRevision: number
     workspacePath: string
     objective: string
     model: RunModelRequest
     policyMode: 'default' | 'accept-edits' | 'plan' | 'yolo'
     budgets?: BudgetOptions
     sandboxResources?: Partial<SandboxResourceSpec>
     verifiers: VerifierRequest[]
     dependency: DependencyRequest
     sourceIncludes: SourceSelectorRequest[]
     sourceExcludes: Array<Omit<SourceSelectorRequest, 'readGrantId'>>
     maxChangedPaths?: number
     maxChangedBytes?: number
     registeredMcpServerIds: string[]
     skillIds: string[]
     allowUnverified: boolean
   }
   ```

   `RunModelRequest` rejects forbidden members rather than ignoring them. Ollama carries neither endpoint nor credential ids and resolves only the same-user active signed local-model registration/service. Every remote provider requires an explicit registered endpoint id; a bundled default is an ordinary immutable registration whose id came from `cliq auth`, not a hidden lookup. Every billable branch has 1..32 unique model-purpose credential ids bound to that exact endpoint/owner/TLS through the Run deadline. Any missing/empty/extra/duplicate/cross-target field fails before capability negotiation or I/O and remains in request/admission digest normalization.

   ```ts
   type RunCancelRequest = MutationBase & {
     method: 'run.cancel'
     runId: string
     expectedRevision: number
   }

   type RunApproveRequest = MutationBase & {
     method: 'run.approve'
     runId: string
     expectedRevision: number
     waitingOnRef: ArtifactRef
     decision: 'allow' | 'deny'
     ttlMs?: number
   }

   type RunInputRequest = MutationBase & {
     method: 'run.input'
     runId: string
     expectedRevision: number
     waitingOnRef: ArtifactRef
     input: { kind: 'text'; value: string } | { kind: 'json'; value: unknown }
   }

   type RunReconcileRequest = MutationBase & {
     method: 'run.reconcile'
     runId: string
     expectedRevision: number
     waitingOnRef: ArtifactRef
     resolution:
       | { kind: 'probe_now' }
       | { kind: 'abandon_run'; acknowledgeExactRisk: true }
   }

   type RunApplyRequest = MutationBase & {
     method: 'run.apply'
     admissionKey: string
     sourceRunId: string
     expectedRunResultRef: ArtifactRef
     budgets?: { wallTimeMs?: number; toolCalls?: number }
     verifierExecutionGrantIds?: string[]
   }

   type SessionCreateRequest = MutationBase & {
     method: 'session.create'
     admissionKey: string
     workspacePath: string
     name?: string
   }

   type SessionForkRequest = MutationBase & {
     method: 'session.fork'
     admissionKey: string
     sessionId: string
     expectedContextRevision: number
     throughItemSeq: number
     name?: string
   }

   type SessionCompactRequest = MutationBase & {
     method: 'session.compact'
     sessionId: string
     expectedContextRevision: number
     fromItemSeq: number
     throughItemSeq: number
     summaryMarkdown: string
     retainedItemIds: string[]
   }
   ```

   The same generated source imports verbatim the RFC's `ControlQueryRequestV1|ControlMutationRequestV1|ControlRequestV1`, discriminated `AuthorizationCreateRequest|AuthorizationRevokeRequest`, `McpRecoveryRequest|McpRegisterRequest|McpRefreshRequest`, and the complete result side: `ArtifactDescriptorV1`, `SessionSnapshotV1`, `SessionSummaryV1`, `RunSnapshotV1`, `RunItemReferenceV1`, `AuthorizationGrantSummaryV1`, `McpRegistrySummaryV1`, `RuntimeBundlePublicSummaryV1`, the method-discriminated `ControlResultV1`, `ControlErrorV1`, and `ControlApplicationResponseV1`. Those unions are the only public request/result/error source: every method maps to exactly one listed variant; query filters/cursors and list/get/attach arrays retain the RFC bounds; authorization/MCP summaries use its redaction; consumed authorization revoke is the exact `already_consumed` no-op variant. It must not expose an ArtifactRef where the public request uses an opaque grant/registration id. `run.get/list/attach`, `session.get/list`, `authorization.list`, `mcp.list`, `artifact.get`, `run.diff/result`, `session.handoff.create`, and `supervisor.status` are read-only and reject `requestId`. Handoff imports exact `SessionHandoffEntryV1|SessionHandoffV1`: omitted cursor means the captured projection cut; explicit cursor is zero or a current segment end; one snapshot walks visible run-terminal/summary entries and excluded ranges. JSON is exact JCS and Markdown uses the fixed LF/indented-entry renderer with no time/random/path option. Both descriptors rehash those bytes, so identical Session/revision/cursor returns identical CAS refs.

   `session.get` and `run.get` implement the RFC snapshot-pagination algorithm, not adapter-local cursor conventions. One SQLite snapshot captures the returned snapshot and all sequence/Checkpoint high-waters; numeric cursors default to zero and are exclusive, rows are strict `(after,highWater]`, and `next` is the last returned cursor or the supplied cursor for an empty stream. Session items and Run items/Journal facts are sequence ordered; Checkpoints are `(createdAt,id)` ordered and use the exact unpadded-base64url canonical-JCS cursor bound to the Run and a retained row. Future, malformed, wrong-Run, or nonexistent cursors are `INVALID_REQUEST`. `session.get` applies its 1 MiB JCS-array cap; `run.get` applies the combined cap to `JCS({items,journal,checkpoints})` in deterministic items-then-Journal-then-Checkpoint priority while retaining independent next cursors. Equality to the captured high-water means caught up through that cut; a later read captures new rows. No client infers end-of-stream from an optional field, treats `next` as next-unread, or invents a Checkpoint token.

   `session.list|run.list|authorization.list|mcp.list` instead use the RFC exact 15-minute materialized `ListReadCutV1`, never a live keyset query. A cursorless request normalizes principal/method/filters/limit into `normalizedFilterDigest` and atomically materializes at most 100,000/64-MiB exact typed summaries in `(createdAt,bytewise stableId)` order; MCP includes exactly one current head per registration. Each entry/whole cut has the exact digest equations, and later inserts/status changes/grant transitions/MCP refresh cannot alter it. The opaque cursor is canonical-JCS/base64url `ListCursorPayloadV1` carrying cut id/last-returned ordinal plus HMAC-SHA-256 under that cut's retained 256-bit secret. Principal/method/filter/limit, canonical bytes, constant-time MAC, cut/row digests, issued ordinal, and expiry all match or the server returns stable `INVALID_REQUEST`; no caller field is authority. Page replay is byte-identical; `nextCursor` is absent exactly at the materialized end, and restart preserves the cut. Expired cuts and their artifact roots may be deleted; they never affect authoritative reducers. Golden fixtures cover tie timestamps, concurrent mutation, forgery/mismatch/expiry/restart/capacity and all filters.

   Every id/ref/key is a normalized bounded string, every integer is a safe integer, unknown object fields and enum values are rejected, and each decoded control frame is capped at 8 MiB before state access. There is no public `artifact.put`: method-specific inline bytes are canonicalized and published only by the authenticated Supervisor and are included in request/admission digests. A mutator stores and replays the first committed result by authenticated principal+method+`requestId`+canonical request digest. Reusing that tuple with different bytes returns `REQUEST_ID_CONFLICT` and performs no reducer/broker call.

   String ids are NFC UTF-8, 1..128 bytes; `requestId` is UUIDv7; admission keys are base64url, 22..128 bytes; and digests are lowercase SHA-256. Workspace paths are absolute UTF-8, at most 4,096 bytes, contain no NUL, and are canonicalized/authorized by the Supervisor rather than trusted. Objective is 1..262,144 bytes. Verifier ids are unique (maximum 32). Every public/retained non-secret argv or env literal is well-formed Unicode-scalar NFC, contains no U+0000, and is measured after UTF-8 encoding; argv has at most 128 entries/8,192 bytes each. Env has at most 64 entries; names match ASCII `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, are unique/byte-sorted, and values are at most 8,192 bytes. Reject an unrepresentable Node/POSIX value before publishing any grant/command/launch/admission artifact. Writable ephemeral paths maximum 32; registered MCP ids maximum 128; skill ids maximum 64; model credential grant ids maximum 32; dependency/MCP credential ids use their separate maximum 32 arrays; source include/exclude arrays maximum 128 each; Session compaction retained ids maximum 256. Inline text/JSON is at most 1 MiB after canonical encoding, maximum depth 32, and maximum 10,000 object members/array elements in total. Omitted numeric options use the RunSpec/sandbox/verifier defaults; explicit zero follows those contracts' defined disable semantics.

   For any `MutationBase`, `requestDigest = SHA-256(JCS(request with requestDigest omitted))`. `session.create|session.fork|run.submit|run.apply` additionally compute the canonical RFC admission-intent projection over authenticated principal, method, and the normalized request with protocol/request/admission-key envelope fields omitted. `(principalId,method,admissionKey)` lookup occurs before reopening workspace state, rereading Session revision, revalidating a source Run, or capturing delivery A; the same intent returns the prior committed result and different intent is `ADMISSION_KEY_CONFLICT`. The final admitted digest binds every Supervisor-resolved artifact. `run.apply.expectedRunResultRef` must equal the exact source Run `resultRef`, never a SourceManifest/diff digest. Public clients cannot substitute artifact refs for the inline fields. Reconciliation accepts no caller adapter id or evidence payload: `probe_now` atomically persists the request-bound user dispatch plus replayable `probe_enqueued` result/snapshot and returns before the frozen no-new-effect inspection begins; later evidence changes Run state/events but emits no second control response. `abandon_run` is schema-legal only when the exact waiting invocation is frozen as `ReplayClass='manual'`; every other waiting subject rejects it.

   Principal, channel, and time authority are never wire strings. The server imports canonical `LocalPrincipalIdentityV1`, `LocalSocketPeerObservationV1`, `LocalControlChannelIdentityV1`, and `CanonicalTimeFenceV1`; in-process clients use trusted effective uid/process identity. RPC holds the listener/accepted descriptors, verifies the literal state-root socket and its 0600 uid/device/file identity, obtains Linux `SO_PEERCRED` or macOS `getpeereid+LOCAL_PEERPID` twice around exact native-pid `PlatformProcessIdentityV1` capture, and publishes the closed peer observation before the channel. Any pid reuse, descriptor/path replacement, uid mismatch, or unavailable credential API closes the connection. The handler injects the resulting principal/channel digest into admission, consent, approval, abandonment, MCP-risk, and rollback producers, while generated public request schemas reject those fields. Every timestamp emitted/accepted by a generated adapter is fixed UTC millisecond form and every duration uses checked millisecond arithmetic. A retained clock-regression fence blocks admission, dispatch, lease renewal, grant/credential redemption, and expiry extension until wall time reaches the persisted high-water; no client adapter supplies time or clears that fence.

   `session.create.workspacePath` and `run.submit.workspacePath` are locators into the canonical RFC `WorkspaceIdentityV1`, not independent identity strings. The Supervisor performs no-follow descriptor traversal, records the exact principal/platform/canonical root/device/file/owner plus optional repository identity, and verifies the JCS/SHA-256 identity digest. Run submit must reproduce its Session's ref/digest. `run.apply` deliberately has no path field: it reopens the source Run Session's retained canonical root and rejects owner/device/file/repository drift. Every policy/grant/source/verifier/dependency/delivery workspace digest equals that one ref; cwd/realpath hashes and replacement directories cannot retarget an accepted Session. Wire source selectors never carry an authority ref: no-grant tracked/nonignored bytes receive canonical `SourceIncludeAuthorizationV1(kind='builtin_nonignored')`, while ignored bytes require an atomically consumed exact read-scope grant and receipt-bound branch. Both bind the Run/Session/live workspace/selector/admission intent; repository config cannot manufacture or reuse them.

   `run.submit` never accepts an `assemblyRef`. After decoding the bounded public fields, the Supervisor resolves immutable endpoint/credential bindings, negotiates capabilities, freezes pricing evidence, builds the canonical ordered tool schema set and post-Trust instructions/skills, selects retained RuntimeBundle/GuestToolchain identities, and emits the RFC-exact `RunAssemblyV1`. Its endpoint/mode/tool/retry/prompt/tokenizer/compaction/runtime cross-fields and `assemblyDigest` validate before Run admission; the final admission digest, RunSpec, initial ContextManifest/Checkpoint, worker bundle, and every recovered model request name the identical ref. Unsupported pricing, execution identity, capability, tokenizer, or arithmetic fails before Run creation rather than widening the assembly.
4. Generate a discriminated error response, not a string envelope. Its closed v1 codes are `INVALID_REQUEST | INCOMPATIBLE_PROTOCOL | NOT_FOUND | REVISION_CONFLICT | WAIT_SUBJECT_MISMATCH | REQUEST_ID_CONFLICT | ADMISSION_KEY_CONFLICT | AUTHORIZATION_REQUIRED | POLICY_DENIED | MODEL_COST_UNKNOWN | BUDGET_EXHAUSTED | RESOURCE_EXHAUSTED | RESULT_UNAVAILABLE | RUN_TERMINAL | CANCEL_REQUESTED | UNSUPPORTED_PLATFORM | UNSUPPORTED_EXECUTION_IDENTITY | ARTIFACT_MISMATCH | RECOVERY_REQUIRED | EVENT_CURSOR_EXPIRED | RATE_LIMITED | INTERNAL`. Each variant freezes `retryable` and exposes only applicable bounded typed state: a revision conflict inlines exact current Session/Run snapshot, a wait mismatch returns the exact current `WaitingSubject` ref/digest, and cursor expiry inlines the authoritative `RunSnapshotV1` from the same SQLite cut. Other branches expose only their closed resource/ref/range/cursor/retry metadata and optional redacted detail/error id. No branch returns a stack, raw path, secret, request payload, or provider body.

   | Error codes | `retryable` | Required typed metadata |
   |---|---:|---|
   | `REVISION_CONFLICT` | `true` | current revision plus exact inline Session-or-Run snapshot discriminator |
   | `WAIT_SUBJECT_MISMATCH` | `true` | current revision plus exact current `WaitingSubject` ref/digest pair |
   | `RESOURCE_EXHAUSTED` | `true` | closed resource kind including `local_inference_activation_cycle`, and required `retryAfterMs` |
   | `RESULT_UNAVAILABLE` | `true` for `queued|running|waiting`; `false` for `failed|cancelled` | Run id/status; nonterminal also current revision, terminal also exact terminal-detail ref |
   | `RECOVERY_REQUIRED` | `true` | closed recovery kind plus bounded same-principal `detailRef`; no current ref or retry-after field |
   | `RATE_LIMITED` | `true` | `retryAfterMs` |
   | `INTERNAL` | `false` | opaque bounded `errorId`; no stack and no automatic retry promise |
   | `INCOMPATIBLE_PROTOCOL` | `false` | exact supported protocol/schema ranges and upgrade action |
   | `EVENT_CURSOR_EXPIRED` | `false` | earliest/latest retained cursor and inline authoritative `RunSnapshotV1` from the same read cut |
   | all other closed codes | `false` | only the code-specific bounded ids/enums/digests and optional redacted detail ref |

   This matrix is the RFC discriminated `ControlErrorV1`: literal retryability and required/forbidden metadata validate in schema, not a permissive optional-field object. A revision conflict's `resourceKind` selects the matching inline snapshot and its revision; a wait mismatch's pair closed-decodes exact `WaitingSubject` and equals the current Run wait. No generic `currentRef` or snapshot artifact exists. Retryable `RESULT_UNAVAILABLE` alone carries the other current revision, and `retryAfterMs` occurs only for resource/rate errors. `run.result|run.diff` succeed only when `Run.resultRef` exists and otherwise return the exact `RESULT_UNAVAILABLE` branch. `INVALID_REQUEST` may include at most 64 inline `{path, issueCode}` entries and never echoes rejected values. A known method error names the closed method discriminator; an unknown/removed method returns only its SHA-256 method digest plus the invalid-request parse variant. A retryable flag never authorizes an effect retry: the Journal recovery contract and request-id/admission fences remain authoritative.
5. Session methods call only the work package 01 Session state service. They cannot write Run status/frontier, leases, Checkpoints, Journal facts, permissions, or workspaces. Root Run terminal publication remains the sole internal append and commits the idempotent `SessionRunTerminalItem` with terminal Run state. `cliq resume` reads bounded Session context and submits a new Run; it never reactivates an old Run or restores workspace execution state. Imported legacy bookmarks/handoffs are typed items/artifact refs, and only ordinary `session.fork` may start a new context lineage at their preserved cursor. JSONL/RPC/TUI/CLI adapters never write SQLite, CAS metadata, or legacy JSON directly.
6. Keep `run_events` as a durable non-authoritative display spool. `eventSeq` is monotonic per Run; attach captures the authoritative Run snapshot plus earliest/latest/high-water event bounds in one SQLite snapshot and returns one bounded page strictly after `afterEventSeq` and no later than that high-water. The earliest valid cursor is `max(0, earliestRetainedEventSeq-1)`: initial zero and exact earliest-minus-one are valid, smaller is `EVENT_CURSOR_EXPIRED`, and a cursor above the captured high-water is `INVALID_REQUEST`. Equality returns an empty page with the same cursor. If `nextEventSeq < highWaterEventSeq`, every client repeats `run.attach(afterEventSeq=nextEventSeq)` until equality; only then may a later request capture a newer high-water. Public v1 has no implicit push subscription or out-of-band event frame, and transports must not skip the remainder of an older cut. A terminal Run retains at least its terminal state-change row as a nonempty cursor anchor. Transport loss discards only the in-flight page request; cancellation requires an explicit revisioned `run.cancel`.
7. Provider and MCP differences terminate at typed capability/tool adapters; neither may add provider-specific Run statuses, Checkpoint fields, waiting subjects, or recovery branches. The six existing providers must report frozen capability evidence at admission; unsupported native tool calling or constrained output negotiates text-only rather than creating an untyped fallback.
8. The user MCP registry is immutable and versioned by the canonical digest of this secret-free entry and its referenced receipt. Public endpoint/credential ids are resolved before the admin probe into immutable bindings:

   ```ts
   type EndpointRegistrationV1 = {
     schemaVersion: 1
     format: 'cliq-endpoint-registration-v1'
     endpointRegistrationId: string
     registrationKind: 'bundled_default' | 'user'
     ownerPrincipalId: string
     purposes: Array<'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'>
     target: { scheme: 'https'; hostAscii: string; port: number; basePath: string; redirectPolicy: 'reject_all' }
     tls: {
       serverNameAscii: string
       minimumVersion: 'TLSv1.3'
       trustStoreRuntimeBundleRef: ArtifactRef
       trustStoreRuntimeBundleManifestDigest: string
       trustStoreEntryId: 'default_https_trust_store'
       trustStoreRef: ArtifactRef
       trustStoreDigest: string
       spkiSha256Pins: string[]
     }
     endpointIdentityDigest: string
     tlsPolicyDigest: string
     createdAt: string
     registrationDigest: string
   }

   type CredentialExternalSubjectV1 = {
     schemaVersion: 1
     format: 'cliq-credential-external-subject-v1'
     endpointIdentityDigest: string
     subject:
       | {
           kind: 'provider_verified'
           providerNamespace: string
           accountSubjectDigest: string
           scopes: string[]
           audiences: string[]
         }
       | {
           kind: 'opaque_generation'
           opaqueSubjectId: string
           scopes: ['endpoint_exact_only']
           audiences: []
         }
     observedAt: string
     subjectDigest: string
   }

   type EndpointCredentialGrantBinding = {
     schemaVersion: 1
     credentialGrantId: string
     authorityRevision: number
     credentialServiceRevision: number
     ownerPrincipalId: string
     credentialHandleIdentityDigest: string
     secretGeneration: number
     externalSubject: CredentialExternalSubjectV1
     externalSubjectDigest: string
     purpose: 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'
     endpointRegistrationRef: ArtifactRef
     endpointIdentityDigest: string
     tlsPolicyDigest: string
     createdAt: string
     expiresAt?: string
     bindingDigest: string
   }

   type EndpointAuthorityRecordBaseV1 = {
     schemaVersion: 1
     endpointRegistrationId: string
     authorityRevision: number
     ownerPrincipalId: string
     sourceRequestId: string
     sourceRequestDigest: string
     registration: EndpointRegistrationV1
     expectedRegistrationArtifactRef: ArtifactRef
     createdAt: string
   }

   type EndpointAuthorityRecordV1 = EndpointAuthorityRecordBaseV1 & (
     | { state: 'active'; revokedAt?: never; revokedByRequestId?: never; recordDigest: string }
     | {
         state: 'revoked'
         revokedAt: string
         revokedByRequestId: string
         revokedByRequestDigest: string
         recordDigest: string
       }
   )

   type EndpointAuthorityCommandCoreV1 =
     | {
         schemaVersion: 1
         kind: 'register'
         ownerPrincipalId: string
         registration: EndpointRegistrationV1
         expectedRegistrationArtifactRef: ArtifactRef
         commandDigest: string
       }
     | {
         schemaVersion: 1
         kind: 'revoke'
         ownerPrincipalId: string
         endpointRegistrationId: string
         expectedAuthorityRevision: number
         commandDigest: string
       }

   type EndpointAuthorityOperationV1 = {
     schemaVersion: 1
     operationId: string
     requestId: string
     requestDigest: string
     commandCore: EndpointAuthorityCommandCoreV1
     ownerPrincipalId: string
     kind: 'register' | 'revoke'
     endpointRegistrationId: string
     disposition: 'registered' | 'already_registered' | 'revoked' | 'already_revoked'
     committedAuthorityRevision: number
     resultRecordDigest: string
     committedAt: string
     operationDigest: string
   }

   type CredentialAuthorityRecordBaseV1 = {
     schemaVersion: 1
     credentialGrantId: string
     authorityRevision: number
     credentialServiceRevision: number
     ownerPrincipalId: string
     purpose: 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'
     endpointRegistrationRef: ArtifactRef
     endpointIdentityDigest: string
     tlsPolicyDigest: string
     credentialHandleIdentityDigest: string
     secretGeneration: number
     externalSubject: CredentialExternalSubjectV1
     externalSubjectDigest: string
     platformItem:
       | { kind: 'macos_keychain'; service: 'ai.cogine.cliq.credentials.v1'; accountId: string }
       | { kind: 'linux_secret_service'; schema: 'org.freedesktop.Secret.Generic'; collection: 'default'; itemId: string }
     createdAt: string
     expiresAt?: string
   }

   type CredentialAuthorityRecordV1 = CredentialAuthorityRecordBaseV1 & (
     | { state: 'active'; revokedAt?: never; revokedByRequestId?: never; recordDigest: string }
     | {
         state: 'revoked'
         revokedAt: string
         revokedByRequestId: string
         revokedByRequestDigest: string
         recordDigest: string
       }
   )

   type CredentialAuthorityCommandCoreV1 = {
     schemaVersion: 1
     ownerPrincipalId: string
     kind: 'enroll' | 'rotate'
     credentialGrantId: string
     purpose: 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'
     endpointRegistrationRef: ArtifactRef
     endpointIdentityDigest: string
     tlsPolicyDigest: string
     expiresAt?: string
     secretSubmissionId: string
     externalSubject: CredentialExternalSubjectV1
     externalSubjectDigest: string
     credentialTargetDigest: string
     commandDigest: string
   }

   type CredentialAuthorityOperationBaseV1 = {
     schemaVersion: 1
     operationId: string
     requestId: string
     requestDigest: string
     commandCore: CredentialAuthorityCommandCoreV1
     attempt: 1 | 2 | 3
     ownerPrincipalId: string
     kind: 'enroll' | 'rotate'
     credentialGrantId: string
     credentialTargetDigest: string
     intendedAuthorityRevision: number
     intendedSecretGeneration: number
     intendedExternalSubjectDigest: string
     platformItem: CredentialAuthorityRecordBaseV1['platformItem']
     createdAt: string
     operationDigest: string
   }

   type CredentialAuthorityOperationV1 = CredentialAuthorityOperationBaseV1 & (
     | { phase: 'prepared' | 'secret_stored'; committedAuthorityRevision?: never; abortReason?: never; finishedAt?: never }
     | { phase: 'committed'; committedAuthorityRevision: number; abortReason?: never; finishedAt: string }
     | {
         phase: 'aborted'
         committedAuthorityRevision?: never
         abortReason: 'recovered_orphan' | 'platform_store_failed' | 'request_conflict'
         finishedAt: string
       }
   )

   type CredentialAuthorityRevokeCommandCoreV1 = {
     schemaVersion: 1
     kind: 'revoke'
     ownerPrincipalId: string
     credentialGrantId: string
     expectedAuthorityRevision: number
     credentialTargetDigest: string
     commandDigest: string
   }

   type CredentialAuthorityRevokeOperationBaseV1 = {
     schemaVersion: 1
     operationId: string
     requestId: string
     requestDigest: string
     commandCore: CredentialAuthorityRevokeCommandCoreV1
     ownerPrincipalId: string
     credentialGrantId: string
     credentialTargetDigest: string
     disposition: 'revoked' | 'already_revoked'
     committedAuthorityRevision: number
     revokedRecordDigest: string
     platformItem: CredentialAuthorityRecordBaseV1['platformItem']
     metadataCommittedAt: string
     operationDigest: string
   }

   type CredentialAuthorityRevokeOperationV1 = CredentialAuthorityRevokeOperationBaseV1 & (
     | {
         cleanupPhase: 'metadata_committed'
         cleanupEvidenceDigest?: never
         cleanupErrorCode?: never
         cleanupFinishedAt?: never
       }
     | {
         cleanupPhase: 'cleanup_complete'
         cleanupEvidenceDigest: string
         cleanupErrorCode?: never
         cleanupFinishedAt: string
       }
     | {
         cleanupPhase: 'cleanup_failed'
         cleanupEvidenceDigest: string
         cleanupErrorCode: 'platform_store_unavailable' | 'delete_denied' | 'delete_failed'
         cleanupFinishedAt: string
       }
   )

   type LocalModelObjectClosureV1 = {
     schemaVersion: 1
     format: 'cliq-local-model-object-closure-v1'
     stateRootIdentityRef: ArtifactRef
     stateRootIdentityDigest: string
     objectStoreRootRelativePath: 'local-models/objects'
     modelManifestRef: ArtifactRef
     modelManifestDigest: string
     objects: Array<
       | {
           kind: 'model_manifest'
           logicalPath: 'model-manifest.json'
           artifactRef: ArtifactRef
           artifactDigest: string
           sizeBytes: number
         }
       | {
           kind: 'tokenizer'
           logicalPath: 'tokenizer'
           artifactRef: ArtifactRef
           artifactDigest: string
           sizeBytes: number
         }
       | {
           kind: 'model_file'
           logicalPath: string
           artifactRef: ArtifactRef
           artifactDigest: string
           sizeBytes: number
         }
     >
     objectCount: number
     totalBytes: number
     closureDigest: string
   }

   type LocalInferenceServiceSpecV1 = {
     schemaVersion: 1
     format: 'cliq-local-inference-service-v1'
     serviceId: string
     ownerPrincipalId: string
     runtimeBundleRef: ArtifactRef
     runtimeBundleManifestDigest: string
     executableId: string
     executableVersion: string
     executableDigest: string
     modelManifestRef: ArtifactRef
     modelManifestDigest: string
     endpoint: { scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number }
     backend: 'macos_vm' | 'linux_namespace'
     sandboxProfileRef: ArtifactRef
     sandboxProfileDigest: string
     resources: SandboxResourceSpec
     createdAt: string
     serviceSpecCoreDigest: string
     serviceSpecDigest: string
   }

   type LocalModelRegistrationBaseV1 = {
     schemaVersion: 1
     format: 'cliq-local-model-registration-v1'
     ownerPrincipalId: string
     provider: 'ollama'
     model: string
     registryRevision: number
     serviceId: string
     serviceSpec: LocalInferenceServiceSpecV1
     expectedServiceSpecRef: ArtifactRef
     modelManifest: LocalModelManifestV1
     expectedModelManifestRef: ArtifactRef
     objectClosure: LocalModelObjectClosureV1
     expectedObjectClosureRef: ArtifactRef
     createdAt: string
   }

   type LocalModelRegistrationV1 = LocalModelRegistrationBaseV1 & (
     | { state: 'active'; retiredAt?: never; registrationDigest: string }
     | { state: 'retired'; retiredAt: string; registrationDigest: string }
   )

   type LocalModelRegistryHeadBaseV1 = {
     schemaVersion: 1
     format: 'cliq-local-model-registry-head-v1'
     ownerPrincipalId: string
     provider: 'ollama'
     model: string
     headRevision: number
     committedAt: string
     headDigest: string
   }

   type LocalModelRegistryHeadV1 =
     | (LocalModelRegistryHeadBaseV1 & {
         transition: 'initial'
         state: 'active'
         headRevision: 1
         predecessorHeadRef?: never
         predecessorHeadDigest?: never
         activeRegistrationRef: ArtifactRef
         activeRegistrationDigest: string
         retiredRegistrationRef?: never
         retiredRegistrationDigest?: never
       })
     | (LocalModelRegistryHeadBaseV1 & {
         transition: 'replace'
         state: 'active'
         predecessorHeadRef: ArtifactRef
         predecessorHeadDigest: string
         activeRegistrationRef: ArtifactRef
         activeRegistrationDigest: string
         retiredRegistrationRef: ArtifactRef
         retiredRegistrationDigest: string
       })
     | (LocalModelRegistryHeadBaseV1 & {
         transition: 'retire'
         state: 'retired'
         predecessorHeadRef: ArtifactRef
         predecessorHeadDigest: string
         activeRegistrationRef?: never
         activeRegistrationDigest?: never
         retiredRegistrationRef: ArtifactRef
         retiredRegistrationDigest: string
       })
     | (LocalModelRegistryHeadBaseV1 & {
         transition: 'reenroll'
         state: 'active'
         predecessorHeadRef: ArtifactRef
         predecessorHeadDigest: string
         activeRegistrationRef: ArtifactRef
         activeRegistrationDigest: string
         retiredRegistrationRef?: never
         retiredRegistrationDigest?: never
       })

   type LocalInferenceActivationParticipantV1 =
     | {
         kind: 'run_submission'
         requestId: string
         requestDigest: string
         runSubmitRequestRef: ArtifactRef
         admissionKey: string
         admissionIntentDigest: string
         joinedAt: string
       }
     | {
         kind: 'run_model_frontier'
         runId: string
         runRevisionAtJoin: number
         frontierRef: ArtifactRef
         joinedAt: string
       }

   type LocalInferenceActivationFailureV1 = {
     schemaVersion: 1
     activationCycleId: string
     ownerPrincipalId: string
     serviceId: string
     serviceSpecRef: ArtifactRef
     serviceSpecDigest: string
     finalAttempt: 1 | 2
     reason:
       | 'activation_timeout'
       | 'sandbox_launch_failed'
       | 'health_mismatch'
       | 'capability_mismatch'
       | 'containment_unprovable'
     launchIds: string[]
     evidenceRefs: ArtifactRef[]
     observedAt: string
     failureDigest: string
   }

   type LocalInferenceActivationCycleBaseV1 = {
     schemaVersion: 1
     activationCycleId: string
     ownerPrincipalId: string
     serviceId: string
     serviceSpecRef: ArtifactRef
     serviceSpecDigest: string
     cycleOrdinal: number
     participants: LocalInferenceActivationParticipantV1[]
     rowVersion: number
     createdAt: string
   }

   type LocalInferenceActivationCycleV1 = LocalInferenceActivationCycleBaseV1 & (
     | {
         phase: 'starting_launch'
         activationAttempt: 1 | 2
         launchIds: string[]
         currentLaunchId: string
         retryNotBeforeAt?: never
         boundaryEvidenceRef?: never
         failureDetailRef?: never
         finishedAt?: never
         cycleDigest: string
       }
     | {
         phase: 'retry_wait'
         activationAttempt: 1
         launchIds: [string]
         currentLaunchId?: never
         retryNotBeforeAt: string
         boundaryEvidenceRef?: never
         failureDetailRef?: never
         finishedAt?: never
         cycleDigest: string
       }
     | {
         phase: 'active'
         activationAttempt: 1 | 2
         launchIds: string[]
         currentLaunchId: string
         retryNotBeforeAt?: never
         boundaryEvidenceRef: ArtifactRef
         failureDetailRef?: never
         finishedAt: string
         cycleDigest: string
       }
     | {
         phase: 'failed'
         activationAttempt: 1 | 2
         launchIds: string[]
         currentLaunchId?: never
         retryNotBeforeAt?: never
         boundaryEvidenceRef?: never
         failureDetailRef: ArtifactRef
         finishedAt: string
         cycleDigest: string
       }
   )

   type LocalInferenceServiceLaunchBaseV1 = {
     schemaVersion: 1
     serviceId: string
     launchId: string
     ownerPrincipalId: string
     serviceSpecRef: ArtifactRef
     serviceSpecDigest: string
     supervisorInstanceId: string
     activationCycleId: string
     activationAttempt: 1 | 2
     activationNonceDigest: string
     containmentPlanRef: ArtifactRef
     sandboxLaunchSpecRef: ArtifactRef
     rowVersion: number
     leaseVersion: number
     createdAt: string
     activationDeadlineAt: string
   }

   type LocalInferenceServiceLaunchV1 = LocalInferenceServiceLaunchBaseV1 & (
     | {
         phase: 'reserved'
         processContainmentRef?: never
         boundaryEvidenceRef?: never
         leaseExpiresAt?: never
         quiesceId?: never
         retirementEvidenceRef?: never
         retiredAt?: never
       }
     | {
         phase: 'preactivated'
         processContainmentRef: ArtifactRef
         boundaryEvidenceRef?: never
         leaseExpiresAt?: never
         quiesceId?: never
         retirementEvidenceRef?: never
         retiredAt?: never
       }
     | {
         phase: 'active'
         processContainmentRef: ArtifactRef
         boundaryEvidenceRef: ArtifactRef
         leaseExpiresAt: string
         quiesceId?: never
         retirementEvidenceRef?: never
         retiredAt?: never
       }
     | {
         phase: 'revoking'
         processContainmentRef: ArtifactRef
         boundaryEvidenceRef: ArtifactRef
         leaseExpiresAt?: never
         quiesceId: string
         retirementEvidenceRef?: never
         retiredAt?: never
       }
     | {
         phase: 'retired'
         retirementKind: 'no_spawn'
         processContainmentRef?: never
         boundaryEvidenceRef?: never
         leaseExpiresAt?: never
         quiesceId?: never
         retirementEvidenceRef: ArtifactRef
         retiredAt: string
       }
     | {
         phase: 'retired'
         retirementKind: 'death'
         processContainmentRef: ArtifactRef
         boundaryEvidenceRef?: ArtifactRef
         leaseExpiresAt?: never
         quiesceId: string
         retirementEvidenceRef: ArtifactRef
         retiredAt: string
       }
   )

   type LocalInferenceBoundaryEvidenceV1 = {
     schemaVersion: 1
     format: 'cliq-local-inference-boundary-v1'
     ownerPrincipalId: string
     serviceId: string
     serviceSpecRef: ArtifactRef
     serviceSpecDigest: string
     serviceLaunchId: string
     runtimeBundleRef: ArtifactRef
     runtimeBundleManifestDigest: string
     executableId: string
     executableDigest: string
     modelManifestRef: ArtifactRef
     modelManifestDigest: string
     processContainmentRef: ArtifactRef
     containmentPlanRef: ArtifactRef
     sandboxLaunchSpecRef: ArtifactRef
     sandboxLaunchSpecDigest: string
     backend: 'macos_vm' | 'linux_namespace'
     externalNetworkEgress: 'denied'
     loopbackOnly: true
     stableServiceIdentityDigest: string
     inspectorSupervisorInstanceId: string
     inspectorIdentityRef: ArtifactRef
     inspectorIdentityDigest: string
     observedAt: string
     validThrough: string
     evidenceDigest: string
   }

   type LocalZeroCostProvenanceV1 = {
     schemaVersion: 1
     format: 'cliq-local-zero-cost-v1'
     ownerPrincipalId: string
     provider: 'ollama'
     model: string
     serviceSpecRef: ArtifactRef
     serviceSpecDigest: string
     stableServiceIdentityDigest: string
     endpoint: { scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number }
     endpointIdentityDigest: string
     boundaryEvidenceRef: ArtifactRef
     boundaryEvidenceDigest: string
     capabilityEvidenceRef: ArtifactRef
     capabilityDigest: string
     createdAt: string
     validThrough: string
     provenanceDigest: string
   }

   type RequestedMcpRecoveryV1 =
     | { kind: 'manual' }
     | {
         kind: 'retry'
         explicitRiskConsentRef: ArtifactRef
         explicitRiskConsentDigest: string
         safetyAssertionRef: ArtifactRef
         safetyAssertionDigest: string
         idempotencyKeyJsonPointer?: string
       }
     | {
         kind: 'reconcile'
         bundledAdapterId: string
         idempotencyKeyJsonPointer: string
       }

   type McpProbedToolInterfaceV1 = {
     name: string
     version: 'mcp-tool-interface-v1'
     description: string
     access: 'exec'
     inputSchemaRef: ArtifactRef
     inputSchemaDigest: string
     outputSchemaRef?: ArtifactRef
     outputSchemaDigest?: string
     interfaceDigest: string
   }

   type McpAdminProbeTargetV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-admin-probe-target-v1'
     ownerPrincipalId: string
     registrationId: string
     method: 'mcp.register' | 'mcp.refresh'
     expectedRegistryRevision?: number
     sourceRegistryRevisionRef?: ArtifactRef
     resolvedTransport:
       | {
         kind: 'stdio'
         executionIdentityGrantId: string
         executionIdentityConsumptionReceiptRef: ArtifactRef
         executionIdentityConsumptionReceiptDigest: string
         executable:
             | { kind: 'guest_toolchain'; toolchainManifestRef: ArtifactRef; toolId: string; executionPath: string; executableDigest: string }
             | { kind: 'runtime_bundle'; runtimeBundleRef: ArtifactRef; executableId: string; executionPath: string; executableDigest: string }
           argv: NonSecretArgumentRequest[]
         }
       | {
           kind: 'streamable_http'
           endpointRegistrationRef: ArtifactRef
           endpointIdentityDigest: string
           tlsPolicyDigest: string
           credentialGrantRefs: ArtifactRef[]
         }
     assertStatelessPerCall: true
     requestedToolRecovery: Array<{ toolName: string; recovery: RequestedMcpRecoveryV1 }>
     lifecycle: { launchTimeoutMs: number; callTimeoutMs: number; maxLaunchesPerCall: number }
     requestCoreDigest: string
     targetDigest: string
     createdAt: string
   }

   type McpToolContract = {
     name: string
     version: 'mcp-tool-contract-v1'
     description: string
     access: 'exec'
     inputSchemaRef: ArtifactRef
     inputSchemaDigest: string
     outputSchemaRef?: ArtifactRef
     outputSchemaDigest?: string
     interfaceDigest: string
     recovery: McpRecoveryContract
     toolContractDigest: string
   }

   type McpRegistryRevision = {
     schemaVersion: 1
     format: 'cliq-mcp-registry-v1'
     registrationId: string
     registryRevision: number
     ownerPrincipalId: string
     transport:
       | {
           kind: 'stdio'
           executionIdentityGrantId: string
           executionIdentityConsumptionReceiptRef: ArtifactRef
           executionIdentityConsumptionReceiptDigest: string
           executable:
             | {
                 kind: 'guest_toolchain'
                 toolchainManifestRef: ArtifactRef
                 toolId: string
                 executionPath: string
                 executableDigest: string
               }
             | {
                 kind: 'runtime_bundle'
                 runtimeBundleRef: ArtifactRef
                 executableId: string
                 executionPath: string
                 executableDigest: string
               }
           argv: NonSecretArgumentRequest[]
         }
       | {
           kind: 'streamable_http'
           endpointRegistrationRef: ArtifactRef
           endpointIdentityDigest: string
           tlsPolicyDigest: string
           credentialGrantRefs: ArtifactRef[]
         }
     initializeDigest: string
     capabilityDigest: string
     probedToolsListDigest: string
     toolsListDigest: string
     stateModel: 'stateless_per_call'
     tools: McpToolContract[]
     lifecycle: {
       launchTimeoutMs: number
       callTimeoutMs: number
       maxLaunchesPerCall: number
     }
     registrationReceiptRef: ArtifactRef
     manifestDigest: string
     createdAt: string
   }

   type McpRegistrationReceipt = {
     schemaVersion: 1
     format: 'cliq-mcp-registration-receipt-v1'
     registrationId: string
     registryRevision: number
     ownerPrincipalId: string
     requestDigest: string
     adminOperationId: string
     adminAttempt: number
     dispatchId: string
     probeRequestDigest: string
     adminProbeTargetRef: ArtifactRef
     adminProbeTargetDigest: string
     probeResultRef: ArtifactRef
     probeResultDigest: string
     probeClosureEvidenceRef: ArtifactRef
     probeClosureEvidenceDigest: string
     initializeDigest: string
     capabilityDigest: string
     probedToolsListDigest: string
     toolsListDigest: string
     registryCoreDigest: string
     createdAt: string
     receiptDigest: string
   }

   type McpServerInstanceIdentityV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-server-instance-identity-v1'
     runId: string
     batchItemId: string
     callId: string
     callIndex: number
     registrationId: string
     registryRevisionRef: ArtifactRef
     registryManifestDigest: string
     lifecycleSeq: number
     launchOpId: string
     launchAttempt: number
     launchDispatchId: string
     sandboxLaunchSpecRef: ArtifactRef
     processContainmentRef: ArtifactRef
     initializeDigest: string
     capabilityDigest: string
     probedToolsListDigest: string
     instanceNonceDigest: string
     initializedAt: string
     identityDigest: string
   }

   type McpServerLaunchReceiptV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-server-launch-receipt-v1'
     instanceIdentityRef: ArtifactRef
     instanceIdentityDigest: string
     preparedJournalSeq: number
     claimedJournalSeq: number
     completedJournalSeq: number
     budgetSettlementRef: ArtifactRef
     stoppedItemId: string
     containmentDeathEvidenceRef: ArtifactRef
     stoppedAt: string
     receiptDigest: string
   }

   type McpRetryRiskConsentV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-retry-risk-consent-v1'
     ownerPrincipalId: string
     registrationId: string
     serverToolName: string
     recoveryRequestDigest: string
     acknowledgedRisk: 'prior_attempt_may_have_succeeded_and_retry_may_duplicate_effect'
     channelIdentityRef: ArtifactRef
     channelIdentityDigest: string
     createdAt: string
     consentDigest: string
   }

   type McpRetrySafetyAssertionV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-retry-safety-assertion-v1'
     ownerPrincipalId: string
     registrationId: string
     serverToolName: string
     recoveryRequestDigest: string
     assertion: 'no_server_safety_claim_duplicate_effect_remains_possible'
     idempotencyKeyJsonPointer?: string
     assertionDigest: string
   }

   type McpRecoveryAdapterManifestV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-recovery-adapter-v1'
     adapterId: string
     entryId: string
     version: string
     executableDigest: string
     protocol: 'cliq-mcp-reconcile-v1'
     profiles: Array<{
       profileId: string
       serverExecutionIdentityDigest: string
       serverToolName: string
       initializeDigest: string
       capabilityDigest: string
       probedToolsListDigest: string
       effectToolInterfaceDigest: string
       statusOperationName: string
       statusOperationSemantics: 'signed_read_only_status_query'
       statusToolInterfaceDigest: string
       statusInputSchemaDigest: string
       statusOutputSchemaDigest: string
       staticArgumentsRef: ArtifactRef
       staticArgumentsDigest: string
       completedPredicateRef: ArtifactRef
       completedPredicateDigest: string
       failedPredicateRef: ArtifactRef
       failedPredicateDigest: string
       profileDigest: string
     }>
     adapterDigest: string
     publisherKeyId: string
     signature: string
   }

   type McpRecoveryStatusRequestTemplateV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-recovery-status-template-v1'
     adapterRef: ArtifactRef
     adapterDigest: string
     profileId: string
     profileDigest: string
     registrationId: string
     registryRevision: number
     adminProbeTargetRef: ArtifactRef
     adminProbeTargetDigest: string
     probeResultRef: ArtifactRef
     probeResultDigest: string
     serverToolName: string
     serverExecutionIdentityDigest: string
     initializeDigest: string
     capabilityDigest: string
     probedToolsListDigest: string
     effectToolInterfaceDigest: string
     statusOperationName: string
     statusOperationSemantics: 'signed_read_only_status_query'
     statusToolInterfaceDigest: string
     statusInputSchemaDigest: string
     statusOutputSchemaDigest: string
     idempotencyKeyJsonPointer: string
     staticArgumentsRef: ArtifactRef
     staticArgumentsDigest: string
     templateDigest: string
   }

   type McpRecoveryPredicateExpressionV1 =
     | { op: 'exists'; jsonPointer: string }
     | { op: 'equals'; jsonPointer: string; value: null | boolean | string | number }
     | { op: 'and' | 'or'; operands: McpRecoveryPredicateExpressionV1[] }

   type McpRecoveryPredicateV1 = {
     schemaVersion: 1
     format: 'cliq-mcp-recovery-predicate-v1'
     expression: McpRecoveryPredicateExpressionV1
     predicateDigest: string
   }

   type McpRecoveryContract =
     | { kind: 'manual' }
     | {
         kind: 'retry'
         explicitRiskConsentRef: ArtifactRef
         explicitRiskConsentDigest: string
         safetyAssertionRef: ArtifactRef
         safetyAssertionDigest: string
         idempotencyKeyInjection?: { jsonPointer: string }
       }
     | {
         kind: 'reconcile'
         adapterRef: ArtifactRef
         adapterDigest: string
         profileId: string
         profileDigest: string
         idempotencyKeyInjection: { jsonPointer: string }
         statusRequestTemplateRef: ArtifactRef
         statusRequestTemplateDigest: string
         completedPredicateRef: ArtifactRef
         completedPredicateDigest: string
         failedPredicateRef: ArtifactRef
         failedPredicateDigest: string
       }
   ```

   Work package 06 owns `src/auth/endpoint-registry.ts`, `src/auth/credential-bindings.ts`, the platform secret-store adapter, legacy-auth migrator, and their same-user `cliq auth` commands. This is a concrete append-only external credential/config authority, not Run state and not a hidden control-protocol method. macOS supports only login Keychain service `ai.cogine.cliq.credentials.v1`; Linux supports only the default freedesktop Secret Service collection/schema above. There is no plaintext file, environment-variable, arbitrary command, Run SQLite/CAS, or unavailable-store fallback. Secret-free metadata/operations use descriptor-protected `${stateRoot}/credentials/authority.sqlite` under one exclusive same-user lock; WP01's Run database never writes it. Every ordinary endpoint/credential register, enroll, rotate, revoke, cleanup, and recovery entrypoint calls `withKernelGlobalGate('shared')` first and, while holding that unforgeable token, calls `withCredentialAuthorityLock`; it holds both through platform-store and metadata commit. Migration/rollback already hold the global gate exclusively and pass both existing held-lock tokens through enrollment/revalidation/platform reads/marker publication. Token-requiring methods never reacquire/release, auto-lock entry points reject reentrancy or inverted order, and process/lock generation is validated, preventing self-deadlock or cutover-crossing rotation/revocation.

   That database stores `EndpointAuthorityRecordV1` as the sole external endpoint mapping and `EndpointAuthorityOperationV1` as its closed register/revoke replay boundary. Its inline registration is the canonical RFC object, row id/owner match it, `expectedRegistrationArtifactRef` is the content-addressed ref of those exact JCS bytes, and record/command/operation digests use the RFC omission equations. One metadata transaction appends operation plus registered/revoked revision or exact `already_registered|already_revoked` no-op; same request bytes replay, different bytes conflict. The same endpoint id can never change target/TLS/purpose, and revocation records both request id/digest monotonically. A credential operation may prepare only against an active endpoint row whose expected ref/identity/TLS/owner/purpose match. The Supervisor later publishes the exact inline bytes through WP01 CAS and requires the resulting ref equal the expected ref before it publishes any binding; the external authority itself never writes Run CAS. A combined CLI command may commit the secret-free endpoint first and then the credential operation, so a crash leaves at most a harmless replayable endpoint row—not an unbound active credential.

   Enrollment/rotation follows the exact RFC operation state machine and secret-free command core. The inline `CredentialExternalSubjectV1` rehashes with `subjectDigest` omitted. A provider-verifiable secret records its provider namespace, account-subject digest, and unique byte-sorted scopes/audiences from the fixed read-only validation query; a provider without that query gets a fresh 256-bit opaque subject restricted to `endpoint_exact_only`, never reused across generations. Target digest binds grant/owner/purpose/endpoint identity/TLS/expiry plus the external-subject digest; command digest is JCS with itself omitted and equals request digest; raw secret bytes are deliberately excluded. For contiguous attempt 1..3, append `prepared`, write a fresh generated platform item, round-trip/compare it only in memory, validate the exact subject or generate/compare the opaque subject, append `secret_stored`, then atomically append the active authority revision plus `committed`. Rotation increments authority revision and secret generation without changing target/handle identity and deletes the old item only after commit; a target change gets a new grant id. Startup deletes items named by incomplete operations and appends `aborted(recovered_orphan)` rather than promoting them. The same request/core may create only the next attempt; because no prior authority committed and no secret commitment is retained, resubmission is explicitly latest-secret-wins for that attempt. Committed replay returns the original result and discards supplied bytes without platform access; changing a **committed** secret requires new request/submission ids and rotation. Attempt 3 is terminal. Credential revoke uses its separate no-secret command/operation: the expected current revision/target and request digest atomically append the revoked record plus `metadata_committed`; redemption is denied immediately, same bytes replay, different bytes conflict, and a later request is `already_revoked`. Platform-item deletion then reaches exact positive `cleanup_complete` or closed evidenced `cleanup_failed`; crash resumes idempotently and cleanup failure never reactivates authority. `recordDigest`/`operationDigest` omit themselves. The broker rechecks the latest active record and immutable endpoint/binding before each redemption; raw bytes exist only in the platform-store read and trusted broker injection.

   Legacy `~/.cliq/auth.json` preflight uses exact `LegacyAuthStoreObservationV1` under the old auth lock/root descriptor: `present` holds and rehashes one same-owner regular-file/link-count-one/no-follow identity; `absent` proves descriptor-relative `ENOENT` and creates no file. Present recognized HTTPS entries receive deterministic endpoint/enrollment operations and round-trip evidence; both branches publish a complete secret-free `LegacyAuthNonSecretProjectionV1` plus `CredentialReadyManifestV1`, whose records are an all-and-only bijection with secret-bearing projection entries. The original raw file or absence remains authoritative and general backup excludes auth bytes. At final cutover, the exclusive global/state-owner token, local-model lock, legacy locks, credential lock, and exact `credential_cutover` control revalidate that branch, then replace/create the secret-free migrated marker and publish the exact Kernel receipt/authority marker last. A pre-authority crash restores normalized ProviderAuthStore-v1 semantics from projection/platform items for `present`, or unlinks/fsyncs/reproves `ENOENT` for `absent`; a post-authority crash validates marker cleanup. Unsupported entries, store/equality failure, replacement failure, or observation drift blocks publication.

   Rollback never restores the marker and starts an incompatible old parser. Every attempt retains exact `RollbackToLegacyRequestV1` bound to the current Kernel authority marker/generation and its cutover backup; `allowPlaintextLegacyCredentials=false|true` is explicit and the true branch alone derives `PlaintextLegacyCredentialConsentV1`. After global drain and before any restore, `rollback_draining` repeats that source identity while WP01 snapshots the exact closed/checkpointed current database to the derived read-only archive path, freezes the complete current CAS namespace, and publishes `ArchivedKernelGenerationManifestV1`; `rollback_restoring` and the legacy receipt repeat that archive ref/digest. Source absent selects `restored_absent` and removes/fsyncs the marker with no file/consent. Source present with zero ready records selects `rendered_nonsecret` and deterministically restores only the projection without consent. Source present with records selects `rendered_with_credentials`, requires exact consent, reads every still-active matching item, and stages/fsyncs/validates the `0600` file. Missing/revoked/unreadable/mismatched entries block. WP01 then binds the receipt and both identical marker bytes in `rollback_restoring`, gracefully terminalizes the active StateOwner as the last Kernel transaction, publishes the legacy-root marker first and state-root global marker last, and exits; a recovery successor remains fenced and gracefully terminalizes too. Raw keys are never backed up, and no secure-erasure claim is made.

   On Run admission or MCP administration, only the Supervisor resolves an id, canonicalizes the record, publishes exact secret-free `EndpointRegistrationV1`/`EndpointCredentialGrantBinding` artifacts through work package 01, and retains those refs in the admitted closure. `purposes` and pins are nonempty, unique, byte-sorted; HTTPS host/server name/path/port use the RFC normalization and `redirectPolicy` is literal `reject_all`. `tlsPolicyDigest = SHA-256(JCS(tls))`, `endpointIdentityDigest = SHA-256(JCS({target,tlsPolicyDigest}))`, `registrationDigest` and `bindingDigest` each omit only themselves. Every provider, capability-query, dependency, and Streamable-HTTP MCP client disables redirect following; a `300..399` response is a typed terminal response/error and the broker never resolves `Location` or resends credentials/body. Owner, purpose, endpoint ref/identity/TLS, handle identity, authority/service revisions, secret generation, external subject, expiry, and revocation are rechecked before every redemption. Only the exact frozen-generation item crosses the broker boundary; rotation or subject/scope/audience drift makes an older binding authorization-required with no I/O, and new work must publish a new binding instead of inheriting current bytes.

   `cliq models enroll --manifest <absolute-package-path>/model-manifest.json` is the sole local-model producer. It performs no download/network I/O and accepts only the RFC package layout: literal manifest basename plus sibling `objects/<64-lower-case-hex-ArtifactRef>` files. It holds the package root, manifest, object directory, and every same-owner regular file by no-follow descriptor; rejects link/special/owner/mode/replacement/extra/missing/ref/digest/size drift; and imports each exact object to `${stateRoot}/local-models/objects/<ArtifactRef>` with object and directory fsync. It first holds the Kernel global/cutover gate shared and then the external local-model registry/object-store lock through the final registry commit. Migration/rollback owns the global gate exclusively before that lock, so enrollment cannot cross inventory, archive, or authority publication.

   The transaction publishes exact `LocalModelObjectClosureV1`: current StateRoot identity, literal target-store path, signed manifest pair, and the all-and-only manifest/tokenizer/byte-sorted-model-file object sequence. Every object ref equals its full-byte digest, paths/sizes equal the manifest, counts/totals use checked arithmetic, and the closure self-digest plus expected closure ref rehash. Source descriptors are transient after the copy; an opaque source store id or pathname is never durable authority. The service producer selects only current signed RuntimeBundle entry `ollama_local_inference` with role `local_inference`; chooses the one probed strong platform backend; publishes the sole-owner local-inference sandbox profile with fixed default resource values; and chooses IPv4 loopback plus the smallest never-retained port in `49152..65535` under the registry lock. Callers choose none of these fields. Registration/service ids/digests and expected manifest/service/closure refs follow the RFC equations; one active revision exists per owner/provider/model, and changed model/spec creates a new immutable service id. Run submission resolves that row, has the Supervisor copy/verify the complete closure into WP01 CAS, and rejects missing/retired/digest-mismatched models before a launch or Run row. This minimal enrollment is not the broader download/catalog manager.

   Current selection is the immutable `LocalModelRegistryHeadV1` named by one mutable `(owner,provider,model)` pointer row, not the `state` spelling on every historical artifact. Initial publication has head/registration revision one and no predecessor. Replacement atomically publishes an exact retired copy of the predecessor active registration, the next active registration, and a `replace` head whose revision is old head plus one; retirement publishes that same closed retired projection and a no-active head; reenrollment is legal only from that retired head and publishes the next registration revision. Every predecessor/head/registration ref and digest rehashes, and artifact publication plus pointer CAS occurs under the same registry lock. Admission follows only a current active head. Old active bytes remain immutable/rooted for admitted Runs but become unselectable, so replacement never creates two current actives or rewrites a retained Run artifact.

   The Ollama adapter additionally owns `src/runtime/local-inference.ts` plus the service integration, but state/process authority remains in WP01-owned `local_inference_activation_cycles`/`local_inference_launches` and WP03/WP04 containment/Supervisor APIs. It publishes one immutable `LocalInferenceServiceSpecV1` for that registration and starts only the signed `local_inference` RuntimeBundle entry. If no fresh matching active launch exists, all initial submissions and exact queued agent frontiers join the one owner/service activation cycle, never a request-private launch. `activationCycleId = base64url(SHA-256(JCS({ownerPrincipalId,serviceId,serviceSpecDigest,cycleOrdinal})))`; retained participants make same-request replay return the old cycle outcome even when another request created it. The append-only participant list is unique/bounded to 128, and cycle/failure digests omit only themselves under JCS. Each cycle owns at most attempts 1 and 2 with fixed 120-second deadlines and a one-second retry edge after positive attempt-1 retirement; no disconnect, restart, new joiner, or in-flight Run resets it. Success atomically finalizes participant admissions/eligibility after exact active boundary evidence. Failure publishes `LocalInferenceActivationFailureV1`, stores the same replayable `RECOVERY_REQUIRED(local_inference_service)` for submission participants, and proposes typed `local_inference_unavailable` failure for still-matching existing Run frontiers. A service death during a Run uses this same cycle rather than an indefinite queue or adapter retry.

   The productive launch spine is `reserved -> preactivated -> active -> revoking -> retired(death)`; recovery also permits `reserved -> retired(no_spawn)` and `preactivated -> retired(death)`, with one unretired row per owner/service. Reserved stores the containment plan and SandboxLaunchSpec before spawn; preactivated is no-egress, credentialless, isolated, and blocked from model traffic; active requires inspected containment plus boundary/capability evidence; heartbeat changes only the launch lease version/expiry. Its launch uses the exact isolated-root/all-and-only model projection: read-only CAS manifest at `/models/model-manifest.json`, tokenizer at `/models/tokenizer`, and byte-sorted model files under `/models/files/`, with no host/source/store/writable extra mount. Fixed Supervisor code derives the literal RFC argv/cwd from the service spec and revalidates the same closure on recovery. A replacement Supervisor never adopts: it fences traffic, kills/proves the old exact plan/spec containment, retires it, then may create a fresh launch for the unchanged service spec. No-spawn retirement forbids process/boundary/quiesce fields; death retirement requires the containment/quiesce/death evidence and carries boundary evidence iff activation reached it. No model request reaches a preactivated, expired, revoking, unproven, or second launch.

   The endpoint port is `1..65535`, `endpointIdentityDigest = SHA-256(JCS(endpoint))`, and evidence/provenance digests omit only themselves. `stableServiceIdentityDigest` is the RFC JCS projection over owner/service/spec, signed RuntimeBundle entry, model manifest, backend, no-egress, and loopback-only identity. Provenance retains admission-time boundary evidence for audit; current launch/containment/plan/SandboxLaunch/inspector/time are dynamic. Each boundary inspector ref/digest must decode canonical `SupervisorInspectorIdentityV1`, equal its instance id and the active `StateOwnerRecordV1`, and satisfy the five-second freshness bound. Every dispatch requires a current active row and fresh boundary evidence whose stable digest/service spec/model/capability equal the provenance, while a death-proven replacement may change only dynamic launch fields. RunAssembly endpoint/pricing use the same provenance ref with no credentials. Broader model management stays outside the cut; raw/user-managed Ollama is rejected as zero-cost authority rather than silently grandfathered.

   Publication follows the RFC's acyclic digest order. For initial stdio registration, before probe I/O the Supervisor resolves the public execution grant id to one active principal-owned `execution_identity_read/mcp_stdio` grant, publishes the exact `AuthorizationConsumptionReceiptV1(consumer='mcp_registration',registryRevision=1)`, and atomically consumes the grant while inserting admin attempt 1. Target, executable and eventual registry revision retain grant id plus receipt ref/digest; later attempts reuse them. Refresh accepts no new grant and copies/revalidates this exact closure from the current revision. The Supervisor otherwise normalizes the public request/current revision into exact `McpAdminProbeTargetV1`; its `RequestedMcpRecoveryV1` values contain only manual, prepublished retry authority, or reconcile adapter-id/pointer intent. The probe publishes only byte-sorted `McpProbedToolInterfaceV1` rows and `probedToolsListDigest`, never a profile, template, final recovery contract, or registry digest. After the result is durable, every explicit requested name must match one raw interface, every unrequested interface becomes `manual`, and the reducer selects any signed profile, publishes the per-registration template, forms final tool contracts/list/core, binds the death-proven receipt, and finally publishes the revision/manifest. The receipt binds both raw and final list digests; no earlier artifact names a later digest.

   Each final tool copies the raw name/description/access/schema/interface digest, fixes `version='mcp-tool-contract-v1'`, appends recovery, and computes its full `toolContractDigest`; `toolsListDigest` covers the complete final array. RunAssembly reproduces those bytes and registry identities exactly. Every HTTP credential binding freezes owner, immutable handle identity/revision, purpose, endpoint, and TLS; rotation cannot retarget it and revocation/expiry blocks dispatch without rewriting history. Raw credentials never enter artifacts. Missing recovery metadata is `manual`; `retry` requires exact principal/registration/tool/request-bound risk-consent and no-safety-claim artifacts.

   `reconcile` is sharper: only a release-profiled stdio target is eligible. The signed profile key is `(serverExecutionIdentityDigest,serverToolName,effectToolInterfaceDigest)`, where the execution digest hashes the exact signed executable plus normalized argv. It repeats only pre-final initialize/capability/probed-list and effect/status interface/schema digests. Streamable HTTP and unprofiled stdio are `manual|retry` only. The per-registration template adds exact target/result refs, registration/revision, and the public pointer, but contains no registry/core/manifest/final-contract/list digest. Only after that template exists does the reducer form the final recovery contract and registry. An unsigned wrapper, target/interface/schema drift, same-name operation on another target, server annotation, ambiguous profile, or implementation default rejects reconcile. Both/neither predicates or any non-IR script remain unresolved. Each Run freezes the selected final revision; refresh copies transport and reconstructs the same pre-probe intent, reprobes it, and never re-resolves replacement ids or rewrites an admitted ref.
9. Support only structurally stateless-per-call MCP tools. Every stdio tool call starts a fresh strong containment with empty private HOME/TMP, retained read-only signed executable closure, no persistent writable mount/network/workspace/state/credentials, and no reuse across calls. Stable launch `opId = H(runId,batchItemId,callIndex,callId,registryManifestDigest,lifecycleSeq)`. Every launch has fresh prepared/reservation/claim and one tool charge. After initialize/capability/probed-tools-list validation it publishes exact `McpServerInstanceIdentityV1`, whose omission digest binds the full Run/batch/call/index, registry, lifecycle claim, SandboxLaunch, containment, nonce, and negotiated digests; only it may address `tools/call`. After teardown it publishes exact `McpServerLaunchReceiptV1`, binding that identity, all three Journal sequence facts, settlement, stopped item, and positive containment death. The one transaction commits Journal completed with identity result/launch receipt, the full-identity `McpServerStoppedItem`, ToolResult, settlement, and frontier advance. Unproven teardown waits with no completed launch or visible result; completed early stop increments lifecycle sequence; ambiguous preterminal launch retries only after death proof. HTTP uses a fresh no-cookie/no-session broker request. Grant expiry/exhaustion requires the exact batch/index-bound approval; takeover never adopts an instance.
10. The signed, content-addressed `GuestToolchainManifest` payload is exact:

    ```ts
    type GuestExecutableIdentity = {
      logicalName: string
      canonicalGuestPath: string
      digest: string
      version: string
    }

    type GuestToolchainManifest = {
      schemaVersion: 1
      format: 'cliq-guest-toolchain-v1'
      guestImageRef: ArtifactRef
      guestImageDigest: string
      guestImageByteCount: number
      guestImageFormat: 'raw-ext4-v1'
      architecture: 'arm64' | 'x86_64'
      kernelAbi: string
      userspaceAbi: string
      worker: GuestExecutableIdentity
      shell: GuestExecutableIdentity
      git: GuestExecutableIdentity
      node: GuestExecutableIdentity
      packageManager?: GuestExecutableIdentity
      searchTools: readonly GuestExecutableIdentity[]
      verifiers: readonly GuestExecutableIdentity[]
      admittedExecutables: readonly GuestExecutableIdentity[]
      publisherKeyId: string
      manifestDigest: string
      signatureRef: ArtifactRef
    }
    ```

    `manifestDigest` omits itself and `signatureRef` under JCS; that signature verifies through work package 03's bundled Cliq release trust store, and unknown/user/revoked keys fail closed. `guestImageRef` is the CAS address of the complete immutable `raw-ext4-v1` bytes, its digest equals their SHA-256/ArtifactRef, and byte count is exact. Paths are absolute canonical guest paths, logical names/paths are unique, and all strings/lists are bounded. Work package 03 verifies the signature, retained image bytes, and every executable digest before activation; plan/runtime binding/actual containment and GC repeat the same image ref/digest so reboot never consults a mutable installed-image path. Admission resolves all tools/verifiers against this guest identity and includes the manifest in `assemblyRef` and the environment fingerprint. A host Mach-O-only command, incompatible native dependency, or missing guest executable returns `UNSUPPORTED_EXECUTION_IDENTITY` before Run admission. Host `node_modules` are never assumed usable in the Linux guest. Any dependency acquisition is a separately approved, Journaled broker fetch of a locked digest into the private guest generation; the guest shell has no ambient network.
11. The signed, content-addressed RuntimeBundle payload makes compatibility a closed manifest decision backed by digest/file probes:

    ```ts
    type RuntimeBundleStructuredArtifactBaseV1 = {
      artifactId: string
      rootEntryId: string
      artifactRef: ArtifactRef
      semanticDigest: string
      memberRefs: readonly ArtifactRef[]
    }

    type RuntimeBundleStructuredArtifactV1 = RuntimeBundleStructuredArtifactBaseV1 & (
      | {
          kind: 'prompt_serialization_profile' | 'provider_request_profile' | 'tokenizer_profile' | 'system_prompt' | 'compaction_prompt'
          provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu' | 'ollama'
          model: string
          executableEntryId?: never
        }
      | {
          kind: 'mcp_recovery_adapter'
          provider?: never
          model?: never
          executableEntryId: string
        }
      | {
          kind: 'policy_engine_profile' | 'bundled_skill' | 'guest_toolchain' | 'legacy_portable_schema'
          provider?: never
          model?: never
          executableEntryId?: never
        }
    )

    type RuntimeBundleManifest = {
      schemaVersion: 1
      bundleVersion: string
      controlProtocolRange: { min: 1; max: 1 }
      headlessSchemaRange: { min: number; max: number }
      stateSchemaRange: { min: number; max: number }
      workerProtocolRange: { min: number; max: number }
      entries: readonly {
        entryId: string
        role: 'supervisor' | 'worker' | 'provider_adapter' | 'tool_adapter' | 'policy_engine' | 'prompt_serializer' | 'provider_request' | 'tokenizer' | 'system_prompt' | 'compaction_prompt' | 'skill_bundle' | 'guest_toolchain' | 'sandbox_root_profile' | 'mcp_server' | 'mcp_recovery_adapter' | 'mcp_recovery_profile' | 'local_inference' | 'trust_store' | 'schema' | 'platform_helper' | 'bundle_object'
        version: string
        relativePath: string
        digest: string
        byteCount: number
        executable: boolean
      }[]
      structuredArtifacts: readonly RuntimeBundleStructuredArtifactV1[]
      guestToolchainManifestRefs: readonly ArtifactRef[]
      publisherKeyId: string
      manifestDigest: string
      signature: string
    }
    ```

    `manifestDigest = SHA-256(JCS(manifest with manifestDigest and signature omitted))`; `signature` covers the literal ASCII domain `cliq-runtime-bundle-v1\0` plus that digest. The RuntimeBundle `ArtifactRef` hashes the complete signed manifest bytes, and public `RuntimeBundlePublicSummaryV1.bundleDigest` equals that complete-byte ref; every `runtimeBundleManifestDigest` field instead equals the decoded self-omitting `manifestDigest`. These complete-byte and semantic hash domains are never equated. `assemblyRef` pins the complete RuntimeBundle ref. `publisherKeyId` uses the same bundled Cliq release trust store/signature verifier as the guest manifest; an untrusted locally signed bundle is not eligible. Entry ids, relative paths, and complete-file digests are independently unique; `entryId`, role, version, path, executable bit, exact byte count, and digest are all signed. The manifest must contain exactly one Supervisor, at least one worker, exactly one **non-executable** `policy_engine` data profile, exactly one non-executable `trust_store` entry with `entryId='default_https_trust_store'`, and at least one non-executable `sandbox_root_profile`; `RunAssembly.runtime.workerExecutableId` resolves to a `worker` entry. For `policy_engine`, the entry's signed digest equals the complete-byte `profileRef`, while decoded `PolicyEngineProfileV1.profileDigest` is independently recomputed with only its own digest omitted and equals `RunPolicySnapshot.engine.profileDigest`; these two hash domains are never equated. Fixed signed Supervisor code interprets its evaluator/permission/Bash-parser protocols; it is never spawned or loaded as a plugin. The selected provider adapter resolves by id/version/digest to one `provider_adapter`, and every selected built-in tool adapter resolves the same way to one `tool_adapter`. Every assembly prompt serializer/tokenizer manifest resolves a non-executable signed `prompt_serializer`/`tokenizer` data-profile entry by exact id/version/complete-file digest and the tokenizer repeats the serializer ref/digest; fixed Supervisor code interprets only their canonical deterministic protocols, and both entries are retained as Run roots. For every selected bundled skill, the non-executable `skill_bundle` entry's signed digest equals the complete-byte `bundledClosureRef`, while decoded `BundledSkillClosureV1.closureDigest` is independently recomputed with only its own digest omitted and equals `bundledClosureDigest`; these two hash domains are never equated. That closure contains the all-and-only skill bytes and never points back to `SkillSourceIdentityV1`. Every `SandboxRootImageV1` resolves a signed non-executable `sandbox_root_profile` by exact bundle/id/version/digest; fixed Supervisor code alone materializes its fresh ephemeral empty-root protocol. Every `EndpointRegistrationV1` TLS block repeats the trust-store bundle/ref/manifest digest and this entry's CAS ref/digest exactly; user files, ambient OS roots, and custom CA commands are unsupported, while SPKI pins only narrow it. An authorization/registry target with purpose `mcp_stdio` may resolve only a `mcp_server` entry; a reconciliation adapter resolves only the signed `mcp_recovery_adapter` role with exact id/version/digest. Supervisor, worker, ordinary adapter, prompt serializer/tokenizer/system/compaction/skill/root profile, schema, policy-engine, local-inference, trust-store, and helper entries are never selectable MCP targets. A `LocalZeroCostProvenanceV1` may resolve only one executable `local_inference` entry and must repeat its bundle, entry id/version/digest plus the attested model/boundary identities exactly. Verifiers do not accept RuntimeBundle targets in Kernel Cut.

    `structuredArtifacts` is the signed discovery and transitive-byte closure, not advisory metadata. Records are unique and byte-sorted by `(kind,provider-or-empty,model-or-empty,artifactId)`. `rootEntryId` names exactly one non-executable entry whose complete-file digest equals `artifactRef`, whose count equals the complete bytes, and whose role is respectively `policy_engine|prompt_serializer|provider_request|tokenizer|system_prompt|compaction_prompt|skill_bundle|guest_toolchain|mcp_recovery_profile|schema`. Decoding those bytes under the kind-selected closed type recomputes exactly the displayed semantic digest (`profileDigest|textDigest|envelopeDigest|closureDigest|manifestDigest|adapterDigest`) and it equals `semanticDigest`; complete-byte ArtifactRef and self-omitting semantic digest are never compared to each other. `memberRefs` is the unique byte-sorted all-and-only transitive external ArtifactRefs reached from that decoded root, excluding the root itself. Every distinct member ref resolves to exactly one non-executable `bundle_object` entry with `entryId=H('runtime-bundle-object-v1',memberRef)`, `version='1'`, `relativePath='objects/sha256/' + first-two-hex + '/' + full-hex`, signed digest equal to the member ref, and exact byte count; no unused `bundle_object` entry is allowed. Sharing one identical member across roots is allowed only through that one entry.

    The kind matrix is exact. `system_prompt` and `compaction_prompt` records require provider/model and exactly one match per eligible assembly; the former decodes a nonempty `ModelTextV1`, while the latter decodes `CompactionPromptEnvelopeV1` and its members are exactly the three referenced `ModelTextV1` artifacts. `prompt_serialization_profile`, `provider_request_profile`, and `tokenizer_profile` likewise require provider/model and exactly one match; the provider-request root decodes exact `ProviderNativeRequestProfileV1` and has no members, while tokenizer members are exactly its vocabulary and merge artifacts. `bundled_skill.memberRefs` is exactly the closure's distinct raw file refs. `guest_toolchain.memberRefs` includes its signature and complete guest image refs, and `guestToolchainManifestRefs` equals the structured guest-root ref sequence. `mcp_recovery_adapter` requires `artifactId=decoded adapterId`, `executableEntryId=decoded entryId`, and exact equality of decoded version/executable digest to that executable `mcp_recovery_adapter` entry; the decoded adapter contains no RuntimeBundle ref/digest, and members are exactly the distinct static-argument/completed-predicate/failed-predicate refs. Public `bundledAdapterId` selects that unique record. `legacy_portable_schema` requires literal artifact/catalog id `legacy_windows_export_profiles_v1`, forbids an executable id, and members exactly the projection schema refs. Policy, system, compaction, skill, guest, and legacy records forbid `executableEntryId`; kinds other than the five provider/model prompt records forbid provider/model. Missing, duplicate, extra, wrong-role, wrong-member, or ambiguous selection rejects install/admission rather than consulting ambient files or a preseeded CAS.

    Installation holds the package root and destination descriptors, opens every signed relative path component-by-component with no-follow semantics, verifies type/owner/mode/count/digest twice around the full read, and completes the structured-root decoder/member walk before activation. On Supervisor platforms it publishes every structured root and member through the ordinary O_EXCL/hash/fsync CAS protocol before publishing the read-only `${stateRoot}/runtime/bundles/<bundleDigest>/` directory and active selection; a crash before the directory fsync leaves no selectable bundle. Native Windows export, which does not create/open Kernel CAS, resolves only these same verified held installed entries by ArtifactRef. Recovery on Supervisor platforms reads the imported CAS graph and never rereads a mutable package/install path. This makes fresh install sufficient for skill files, tokenizer data, guest images, MCP predicates/static arguments, and Windows projection schemas; no ambient download or preexisting object store can satisfy a missing member. The OS user service launches a stable state-root bootstrap outside replaceable npm/client files, and `${stateRoot}/runtime/active.json` is a same-owner regular file selected by same-directory atomic replace plus file/directory fsync, never a symlink.

    Candidate self-test and compatibility inspection cannot open authoritative state for write. Activation requires the current state schema to be accepted by both old and new bundles, checks every nonterminal Run schema/assembly, and proves the candidate can launch each pinned worker/guest bundle. Pre-health candidate startup may validate but cannot migrate authoritative state; a schema change is eligible only when work package 01's transactional migration leaves the prior bundle able to reopen the resulting schema through the startup-rollback window. Otherwise return `drain_required` and leave the current Supervisor and active selection untouched across reboot.

    For an eligible update, the current Supervisor gates new admission, persists its handoff point, and releases the exclusive state-owner lock; the bootstrap atomically replaces/fsyncs `active.json` and the OS service manager starts the selected Supervisor, which must acquire that lock and report health before activation commits. Startup timeout/failure restores the prior selection and restarts the prior compatible Supervisor. The exclusive lock and serial service transition prohibit two authoritative Supervisors. New Runs pin the selected bundle; existing Runs continue or relaunch with their own pinned compatible bundle. An external client/npm reinstall may replace clients but cannot delete a referenced runtime. Runtime bundles referenced by nonterminal Runs or retained audit/result roots are not garbage-collected.
12. Freeze repository instructions/skills/config only after Workspace Trust and bind their digests in `assemblyRef`, so detached recovery cannot silently pick up changes. Preserve declarative `AGENTS.md`/`SKILL.md` compatibility but remove repository JavaScript imports and command-hook auto-execution. Instructions and skills influence context only and never grant tools, MCP, network, sandbox reachability, or verifier exceptions.
13. Telemetry is a redacted projection over committed Run, Journal, budget, and receipt facts using opaque ids/digests. It is not a correctness projection and cannot drive recovery. No prompt/source/tool body, secret, raw path, provider response, or remote exporter is introduced.
14. Retention has no automatic authoritative deletion path and no `run.delete`. Keep every `run_events` row while its Run is nonterminal; terminal-Run event pruning may delete only display rows at least 30 days after terminal commit and must atomically prune all event artifact edges plus advance the retained earliest cursor. Every ArtifactRef in a retained event row is a CAS root. Quarantined generations require positive all-descendant death proof and reachability/retention checks. CAS GC considers only objects older than seven days and deletes only after a complete walk rooted at Sessions/items, Runs/specs/results, Checkpoints, RunJournal, retained RunEvent refs, worker/admin/local-inference activation-cycle and launch rows, control-request responses, receipts/provenance, grants/waits, migration archives, endpoint/service/model/capability/boundary evidence, MCP registry/registration receipts, RuntimeBundle manifests/binaries, GuestToolchain manifests/images, and every artifact reachable from those roots. Any incomplete/corrupt walk deletes nothing. Product deletion or shorter retention requires a later RFC.
15. Maintain one internal pre-cutover feature toggle only for development, migration fixtures, and fault testing. The public binary never dual-writes or admits work through the old runner. Remove the toggle when the Kernel Cut becomes default.

Reuse existing code:

- Reuse provider HTTP/streaming implementations, auth/config resolution, provider management UI, and capability metadata where they satisfy the typed contract.
- Reuse policy grammar/subjects for MCP authorization, but replace placeholder claims with broker and sandbox enforcement.
- Reuse current skill parsing, discovery precedence, resource containment, and instruction layering.
- Reuse headless envelope, event mapping, artifact views, JSONL writer, and JSON-RPC parser as adapters.
- Reuse TUI components and rendering, but not their ownership of live execution.
- Reuse Session JSON validation/migration readers and transaction recovery inspection only inside the one-time importer.

Preserve / do not touch:

- Preserve Workspace Trust -> config/schema -> permission -> sandbox ordering.
- Preserve Ollama as a current provider through the minimal signed Kernel `local_inference` service; reject or explicitly re-enroll raw third-party loopback endpoints, and keep broader `cliq-models` product expansion separate.
- Preserve historical documents and legacy backups as read-only evidence.
- Do not allow MCP, skills, `AGENTS.md`, provider adapters, or UI clients to define new control-plane truth.

### Acceptance Criteria

- [ ] CLI, TUI, JSONL, and RPC observe and control the same Run through one versioned local protocol; none executes the Run in-process.
- [ ] Supervisor, generated client, CLI, TUI, JSONL, and RPC all import the checked-in output of one `src/control/v1/source.ts`; regeneration is byte-stable and CI fails on generated drift or a hand-authored parallel wire type.
- [ ] The public method set is exactly `control.hello`; `session.create|list|get|fork|compact|handoff.create`; `run.submit|list|get|attach|cancel|approve|input|reconcile|diff|result|apply`; `authorization.create|list|revoke`; `mcp.register|refresh|list`; `artifact.get`; and `supervisor.status`. A conformance test proves that removed Session append/items/import/bookmark, general artifact upload, and adapter lifecycle methods are rejected before state access.
- [ ] Generated public requests use opaque user-owned grant/endpoint/registration ids and bounded inline non-secret literals, never caller-authored authority ArtifactRefs or raw credential bytes. Verifier execution-grant core digests omit the grant id to avoid a hash cycle; MCP registry core/receipt/final-revision publication is likewise acyclic and golden-tested.
- [ ] All v1 request/result/event fixtures pass strict schema validation and documented byte/count bounds. Every method emits exactly one RFC `ControlResultV1` variant inside `ControlApplicationResponseV1`; run/session cursors, inspection refs, artifact chunks, authorization/MCP redaction, and error metadata have no adapter-local shape. Mutator replay returns the byte-equivalent first committed response for the same authenticated principal+method+requestId+digest, while different request bytes under that tuple return `REQUEST_ID_CONFLICT` without a state, Journal, permission, or broker mutation.
- [ ] Authorization create/list/revoke use the exact redacted `AuthorizationGrantSummaryV1`. Revoking active returns `revoked`, replaying revoked returns `already_revoked`, and revoking consumed returns `already_consumed` with the unchanged consumption receipt/state; no result claims a consumed authority was revoked.
- [ ] Every query method validates one exact `ControlQueryRequestV1` discriminator and rejects `requestId|requestDigest|admissionKey`; every mutator validates UUIDv7/JCS `requestDigest` and the exact generated payload before state access. Golden fixtures cover every list/get/attach/handoff/artifact/status filter, cursor, limit, and unknown-field rejection. `run.submit` intent lookup occurs before workspace recapture, and no public client can substitute caller-created artifact refs for bounded inline fields.
- [ ] `session.get` and `run.get` capture snapshot plus all high-waters in one read transaction; sequence cursors are exclusive, Checkpoint cursors round-trip the exact Run/createdAt/id row, next cursors mean the last returned row, and high-water equality means caught up only through that cut. The deterministic JCS byte caps and run stream priority cannot skip, duplicate, loop, or disagree across CLI/TUI/JSONL/RPC; initial, empty, exact-end, truncated, future, malformed, and wrong-Run fixtures are byte-identical.
- [ ] `session.list|run.list|authorization.list|mcp.list` all use the exact 15-minute materialized-list-cut contract. A cursorless request atomically freezes authenticated owner, normalized method/filter/limit, exact typed summaries, current MCP heads, and `(createdAt,bytewise stableId)` ordinals; later pages are authenticated only by the canonical domain-separated HMAC cursor and never re-evaluate live state. Repeated/restarted pages are byte-identical, next cursor is absent exactly at empty/end, and golden fixtures cover equal timestamps, all filters, concurrent insertion/status/revision/MCP refresh, changed principal/method/filter/limit, malformed/forged/unissued/future/end/expired cursors, 100,000-row/64-MiB refusal, and expiry-only cache deletion.
- [ ] Generated schemas reject caller principal/channel/time authority; UDS adapters publish exact descriptor-held `LocalSocketPeerObservationV1` from the platform peer-credential APIs plus native-pid process identity, and UDS/in-process adapters inject exact `LocalPrincipalIdentityV1`/`LocalControlChannelIdentityV1`. Fault fixtures reject pid reuse, listener replacement, uid/API drift, and caller-supplied identity. Every durable time uses fixed UTC milliseconds, and clock rollback triggers the retained global fence rather than extending a lease, deadline, grant, consent, or credential.
- [ ] Replaying accepted `session.create|session.fork|run.submit|run.apply` with the same principal/method/admission key/intent returns the original committed result before mutable path/revision/source recapture; the same scoped key with a different canonical intent returns `ADMISSION_KEY_CONFLICT`. Apply additionally requires its exact expected source `Run.resultRef` before any capture.
- [ ] `run.reconcile` accepts `abandon_run` only for the exact waiting invocation frozen as `ReplayClass='manual'`; every other waiting subject rejects it without changing the Run.
- [ ] `run.reconcile(probe_now)` commits its request id/digest into `user_in_flight` plus the deterministic `probe_enqueued` result and `control_requests` row before returning or inspecting; replay joins that dispatch, later evidence advances only internal Run state/events, and no crash can duplicate a probe or require a response artifact that does not yet exist.
- [ ] Every closed error variant has a stable code/retryability and only its schema-approved bounded metadata; malformed requests, provider failures, and internal exceptions cannot expose a stack, raw path, secret, or payload.
- [ ] Session create/list/get/fork/compact/handoff behavior is context-only: compaction retains raw items, fork copies only the selected prefix, and handoff validates an exact segment-boundary cursor then emits canonical `SessionHandoffV1` JCS plus the fixed byte-exact Markdown rendering. Identical cuts return identical descriptors; root terminal publication is the only internal append, and no Session method can write Run, lease, Journal, Checkpoint, permission, or workspace authority.
- [ ] `cliq resume` performs a bounded `session.get` plus a newly admitted `run.submit`; it cannot reactivate an old Run, import into existing authority, restore a workspace/Run Checkpoint, or write SQLite/JSON directly. Legacy bookmark/handoff context is visible only as typed items/artifact refs, and a new lineage may use its cursor only through ordinary `session.fork`.
- [ ] Every surface reads the same authoritative `terminalReason`/detail reference from the Run snapshot and never reconstructs failure semantics from display events or text.
- [ ] Closing any client transport detaches without cancelling or orphaning an accepted Run.
- [ ] `cliq run --detach` acknowledges only after durable admission and returns a discoverable `runId`.
- [ ] `WorkspaceIdentityV1` is the sole workspace authority: Session creation no-follow captures principal/platform/canonical path/device/file/owner plus optional repository identity and exact digest; Run submit must match that Session, apply derives it without a caller path, and every policy/grant/source/verifier/dependency/delivery digest agrees. Path/root replacement is `ARTIFACT_MISMATCH`, never silent retargeting.
- [ ] Any admission without required checks requires explicit `allowUnverified` consent (or interactive confirmation) materialized as the storage-validated `RunSpec.unverifiedConsentRef`; no client, import, or unattended default can bypass it, and completion is visibly `completed_unverified`.
- [ ] Attach captures the authoritative Run snapshot plus earliest/latest/high-water event bounds in one read transaction and returns one bounded `(after,highWater]` page. Initial zero and `earliest-1` return the first retained event; `earliest-2` is `EVENT_CURSOR_EXPIRED`; `after=highWater` returns an empty page at the same cursor; `after>highWater` is `INVALID_REQUEST`. Every CLI/TUI/JSONL/RPC client repeats from `nextEventSeq` while it is below that page's high-water, treats equality as the cut boundary, and uses a later request for new events; no untyped push/subscription frame, duplicate, omission, reconnect, or Supervisor restart changes the sequence. Local p95 page latency is below one second.
- [ ] A cursor older than `earliestRetainedEventSeq-1` returns `EVENT_CURSOR_EXPIRED` with the authoritative snapshot and earliest/latest cursor from the same cut; terminal pruning retains a terminal event anchor and never changes recovery, authorization, or terminal truth.
- [ ] A protocol/schema mismatch fails during `control.hello`, before any state read or mutation, with separate supported control/headless schema ranges and an actionable upgrade message.
- [ ] The protocol exposes no `artifact.put`; public objectives, summaries, input, approval, reconciliation, and delivery options are accepted only through their bounded method schemas, canonicalized/published by the Supervisor, and included in idempotency/admission digests. `run.input` must match the exact waiting `InputPromptV1` text-or-JSON branch, deterministic schema subset and 1 MiB bound; its committed `UserInputPayloadV1`/item and ref-free ToolResult model content repeat the same Run/batch/call/index and canonical value.
- [ ] All six current providers pass capability conformance tests; Ollama uses only the signed Kernel `local_inference` service and exact no-egress `LocalZeroCostProvenanceV1`, while a raw/user-managed loopback service is rejected. Unsupported autonomous capability fails closed to text-only mode.
- [ ] `RunModelRequest` is a closed discriminator: Ollama forbids endpoint/credential members; every remote provider requires an explicit registered endpoint id; a bundled default is selected by its immutable registration id rather than hidden lookup; and every billable branch has 1..32 unique exact model-purpose bindings for that endpoint. Reject-vs-ignore/default behavior is golden-tested before I/O and the normalized branch is digest-bound.
- [ ] Endpoint enrollment has one concrete append-only WP06 owner. Admission/MCP administration publishes exact normalized `EndpointRegistrationV1` and principal/purpose/target-bound credential artifacts; target/id rebinding, TLS/owner mismatch, expiry, or revocation fails before I/O, and secret bytes remain only in the credential service/broker.
- [ ] macOS enrollment uses only login Keychain and Linux only freedesktop Secret Service; unavailable/locked/failed round-trip stores fail closed with no plaintext/env/command fallback. Fault tests cover exact endpoint register/revoke operation replay/conflict, every credential `prepared -> secret_stored -> committed` crash, orphan abort/delete, rotation to a fresh item before old cleanup, and the separate credential revoke `metadata_committed -> cleanup_complete|cleanup_failed` path. Revocation denies redemption before deletion, crash resumes idempotently, cleanup failure never reactivates authority, and no secret enters SQLite, CAS, logs, artifacts, responses, or child processes.
- [ ] Before general import, exact `LegacyAuthStoreObservationV1` records either a held/locked/no-follow present `auth.json` or locked descriptor-relative absence. Present HTTPS secrets enroll/round-trip with an all-and-only projection/ready-record bijection; absent yields empty projection/records and no file. Final cutover creates/replaces the exact secret-free marker and publishes Kernel authority last; pre-authority crash restores deterministic present semantics or exact fsynced absence. Rollback retains exact request/current-authority/backup identity and selects only `restored_absent`, consent-free `rendered_nonsecret`, or consent-required `rendered_with_credentials`; missing/revoked/mismatched items block, and no backup contains raw keys.
- [ ] Managed Ollama selection resolves the one current active `LocalModelRegistryHeadV1` by principal/provider/model, then its exact immutable registration and signed object closure; it rejects absent/retired/drifted heads before launch/Run state. Initial/replace/retire/reenroll head transitions are contiguous, ref/digest-valid, one-transaction pointer CASes; prior active bytes remain rooted but unselectable. Initial submissions and post-admission queued model frontiers join one retained `LocalInferenceActivationCycleV1`; cycle ids use the exact service/ordinal equation, participants are append-only/unique/max 128, and every already-joined request replay resolves that same terminal cycle. Each cycle has only attempts 1..2 with 120-second deadlines/1-second positive-retirement edge; no restart/new joiner can reset it. Success resolves every participant and failure returns exact submission error or typed existing-Run stop in one bounded finalization. Blocked preactivation releases no model traffic; reserved failure requires no-spawn evidence; any spawned launch retires only with exact death evidence; takeover never adopts; a new launch/cycle can replace an old one only after proof and with the same stable service identity digest. Every dispatch revalidates a fresh active row/lease/dynamic boundary whose stable projection equals the retained provenance.
- [ ] Local-model enrollment accepts only the literal descriptor-safe manifest/object package layout, publishes the exact StateRoot-bound all-and-only `LocalModelObjectClosureV1`, fixes signed runtime entry/backend/profile/resources/loopback-port selection, and retains no opaque source-store lookup. Every service launch mounts exactly that closure at the RFC `/models` paths with the fixed argv/cwd and no writable, host, source-package, or extra model mount.
- [ ] MCP stdio and Streamable HTTP tools support registered discovery, call, cancellation, timeout, and structured errors through normal grants/Journal semantics.
- [ ] Unknown MCP servers/tools fail closed, and a sandbox worker never receives MCP/provider credentials.
- [ ] `.cliq/config` can reference only user-registered MCP ids. It cannot cause process launch during config load or define a command/URL/env/credential; registration/refresh is explicit, sandboxed, digest-pinned, and receipted.
- [ ] The frozen MCP registry contains immutable transport/capability/tool-schema digests, exact endpoint registration plus principal/purpose/target-bound credential binding refs for HTTP, a registration receipt, lifecycle bounds, `stateModel='stateless_per_call'`, and exactly one typed `manual|retry|reconcile` recovery contract per tool. The receipt self-digest and exact admin id/attempt/released dispatch/probe request/target/result/closure ref-digest pairs revalidate `McpAdminProbeResultV1`, positive whole-containment-death evidence, normalized tool bytes, and the registry core without a response hash cycle. Each tool also retains bounded normalized description, literal contract version, conservative `access='exec'`, and full `toolContractDigest`; RunAssembly reproduces those bytes exactly. Golden tests prove id rebinding/target mismatch fail, rotation preserves binding identity, revocation blocks new dispatch, and no credential bytes, repository-defined adapter, unsigned profile metadata, generic queryability assertion, cookie/session affinity, mutable description, access downgrade, or hidden state is accepted.
- [ ] `retry` registration requires explicit risk consent plus a frozen safety assertion; `reconcile` requires a tested bundled Cliq-signed no-new-effect adapter with idempotency injection and completed/failed predicates; repository/user executable adapter bytes are rejected, and missing metadata maps to `manual`.
- [ ] Each stdio MCP call requires its own batch/index-bound permission, reservation, prepared/claim, fresh strong containment, empty private dirs, and retained signed executable identity; no process or client-held state is reused across calls, and it cannot read RunWorkspace, real workspace, Cliq state, credentials, network, another call, or prior state.
- [ ] Stdio initialization validates exact capability/`tools/list` digests. Call result/Journal completion/frontier advance is impossible until teardown death proof and `McpServerStoppedItem` commit atomically with it; ambiguous teardown waits, completed early stop increments lifecycle sequence, and grant expiry/exhaustion requires exact new approval.
- [ ] A runtime `tools/list`, capability, endpoint, executable, or recovery-contract digest mismatch fails before `tools/call`; takeover never reuses an old stdio instance, operation grant, or HTTP session.
- [ ] On macOS strong execution, admission verifies and freezes a signed `GuestToolchainManifest` covering the image, architecture, ABIs, and every executable path/digest/version. Host-only/native-incompatible identities fail with `UNSUPPORTED_EXECUTION_IDENTITY`, and no host `node_modules` or ambient guest network is used.
- [ ] No MCP resources/prompts/marketplace behavior or arbitrary in-process plugin loading is introduced.
- [ ] Repository extension and command-hook entries are diagnosed but never imported/executed by the Kernel; trusted workspace config cannot register executable code, and any replacement execution occurs only through an explicit built-in tool/verifier/MCP permission, sandbox, and Journal gate.
- [ ] Trusted root/nested `AGENTS.md` precedence and current `SKILL.md` scopes are deterministic, digest-frozen, path-contained, and loaded only after Workspace Trust.
- [ ] Skills/instructions cannot grant capabilities or weaken a required verifier.
- [ ] Run telemetry reports cost/latency/retry/tool/verification/recovery/child metrics without prompt, source, raw tool body, secret, or raw-path leakage.
- [ ] Installing an update creates a new immutable signed RuntimeBundle beside old bundles and leaves the active selection unchanged until file/signature self-test, state-schema overlap, and compatibility with every nonterminal Run/pinned worker succeed; candidate pre-health checks cannot mutate authoritative state.
- [ ] RuntimeBundle entries have signed unique `entryId`, role, version, path, executable bit, and complete-file digest. Assembly worker, provider adapter, and built-in tool adapter identities resolve byte-for-byte to exact executable `worker|provider_adapter|tool_adapter` entries. For the sole non-executable `policy_engine` and each selected non-executable `skill_bundle`, the signed entry digest equals the complete-byte ArtifactRef, while the decoded profile/closure independently validates its distinct self-omitting semantic digest; no validator equates the two hash domains. Fixed Supervisor code alone interprets the policy profile, and every bundled skill closure is acyclic. MCP stdio targets resolve only `mcp_server`; zero-cost Ollama resolves only the attested `local_inference` entry. Exactly one non-executable `trust_store` entry named `default_https_trust_store` supplies every endpoint's repeated bundle/ref/digest; ambient/custom CA paths are rejected and verifier/other roles cannot reuse executable ids.
- [ ] An incompatible candidate, or a schema migration that would prevent startup rollback, reports `drain_required` and the current Supervisor remains authoritative across reboot. A compatible activation atomically switches the stable bootstrap to exactly one new Supervisor, rolls back selection on startup failure, admits new Runs on the new bundle, and can continue/relaunch old Runs with their pinned bundles.
- [ ] Package/client reinstall cannot overwrite or remove a bundle referenced by a nonterminal Run or retained audit/result; `supervisor.status` reports active, installed, and nonterminal-pinned bundle identities and compatibility.
- [ ] No automatic path deletes Sessions/items, Runs/specs/results, Checkpoints, Journal facts, worker launches, control-request responses, receipts/provenance, grants/waits, migration archives, MCP registry receipts, or referenced runtime/toolchain artifacts, and the v1 protocol exposes no `run.delete`.
- [ ] Retention tests prove nonterminal Run events and every artifact ref reachable from them are rooted; only terminal-Run display rows plus their artifact edges at least 30 days after terminal commit, quarantined generations with positive whole-containment death plus satisfied retention, and unreachable CAS orphans older than seven days are eligible. Row/edge pruning is atomic; incomplete reachability, a live reference, missing death proof, or retention-window failure deletes nothing.
- [ ] Migration refuses active legacy transactions/processes without changing authoritative state, creates a validated read-only backup, and is idempotent at every injected crash point.
- [ ] Migration proves legacy-process/open-file quiescence and identical locked inventories twice; unavailable inspection or any intervening process/file change aborts, and post-cutover legacy divergence is reported rather than imported.
- [ ] Legacy checkpoints import only as `legacy-bookmark`; no nonterminal Run is synthesized from Session lifecycle.
- [ ] After cutover, SQLite/CAS are the only runtime authority; no Session JSON dual write or legacy runner path remains.
- [ ] Native Windows creates no Kernel SQLite/CAS, runs no importer/Supervisor/client inspection/admin path, and has no hidden attached runner. Only handle-safe `cliq state export --output` and its state-free `--verify` reader are available: held root/source handles, built-in projection schemas, all-and-only object closure, fixed binary container, credential exclusions, CREATE_NEW/no-replace flush protocol, archive digest, deterministic crash-replay receipt, and exact inline verification result pass golden/fault fixtures. All other Kernel commands fail typed unsupported-platform. WSL2 succeeds only through Linux Supervisor/probes.
- [ ] RuntimeBundle activation validates one acyclic exact `RuntimeBundleStructuredArtifactV1` graph. Each root entry's signed digest equals its complete-byte ArtifactRef, each decoded semantic digest is recomputed separately, and the kind-discriminated required/forbidden provider/model/executable fields and role matrix validate. The unique all-and-only transitive members map to signed `bundle_object` entries and are descriptor-rehashed/imported before selection; no root may point back to its containing bundle. Fresh-install/reboot tests cover prompt/provider-request/tokenizer profiles and golden vectors, system/compaction prompts, bundled skills, guest image/signature, MCP recovery profile/executable binding, Windows projection schemas, shared members, missing/extra/wrong-role members, complete-byte-versus-semantic digest confusion, and the former RuntimeBundle-to-MCP-profile-to-RuntimeBundle cycle. Every eligible provider/model has exactly one `provider_request_profile` root with literal role `provider_request`, exact `ProviderNativeRequestProfileV1` decoder, and no transitive members.
- [ ] Migration/credential integration imports every exact RFC/WP01 migration identity, source observation/projection, database-image/CAS-namespace identity, credential evidence, manifest, retained rollback request, control phase, receipt, and marker schema; ref/digest/generation/migration-id/ready-record equations validate, no raw secret enters them, and no WP06-local sentinel/existence/mtime heuristic can choose authority.
- [ ] `cliq state rollback --to-legacy <migrationId>` sends exact `RollbackToLegacyRequestV1` to the current Supervisor and reuses its already-held state-owner token; it then holds exclusive global/cutover -> local-model registry/object-store -> legacy-auth -> byte-sorted legacy-state -> credential-authority order, rejects every new mutator/dispatch/redemption/credential/local-model/service join, and refuses if a nonterminal Run exists. Exact rollback control terminalizes admin/cycle authority, death/no-spawn proves all four containment owners, closes control/broker, and blocks on unknown state. Before restoration it proves one exact globally quiescent archive: descriptor-copied read-only current database image plus complete final CAS namespace in `ArchivedKernelGenerationManifestV1`; the later receipt/control repeat its ref/digest and explicitly exclude only rollback bookkeeping/owner-terminal rows from the copied database. It restores the exact 3-way auth outcome, binds the prepared receipt and identical marker digest, gracefully terminalizes StateOwner as the last Kernel transaction, and publishes legacy-root marker first and state-root authority marker last. A crash successor remains fenced, republishes only the bound bytes, gracefully terminalizes itself, and never reopens productive Kernel work; re-entry creates a fresh generation.
- [ ] README, help, package description, and events no longer advertise free-text JSON actions, Session-owned Runs, transaction overlays, or an unsandboxed detach guarantee.
- [ ] Every release gate and product invariant in the canonical RFC passes before the default switch.

### Validation

Automated:

- `npm run build`
- `npm test`
- `npm run generate:control && npm run check:control-generated`
- `npm run test:fault`
- `npm run test:sandbox`
- `npm run test:migration`
- `npm run test:e2e`
- Protocol matrix covering every v1 method, strict unknown-field rejection, all documented bounds, every closed error discriminator, request-id byte-replay/conflict, handshake rejection before state access, artifact chunk digest/offset, and schema-v3 JSONL/RPC golden envelopes.
- Session conformance covering create/list/get/fork/compact/handoff idempotency and concurrency, exact list/get limits, raw-item preservation, deterministic handoff artifacts, internal root-terminal publication, typed legacy item reads plus ordinary fork from a preserved legacy cursor, and rejection of append/items/import/bookmark/lease/checkpoint methods.
- Provider conformance matrix for OpenAI, Anthropic, OpenRouter, OpenAI-compatible, Zhipu, and the signed managed Ollama boundary; raw loopback Ollama rejection, local-inference service replacement/drift, no-egress proof, endpoint/provenance digest mismatch, and RuntimeBundle entry mismatch are covered.
- MCP registration/recovery fixtures for `manual`, consented `retry`, trusted-adapter `reconcile`, absent/forged metadata, stateful-memory/cookie dependence, schema drift, unknown tool, cancellation, timeout, disconnect, stable call idempotency keys, and redaction.
- Stdio lifecycle fault matrix covering crash before/after spawn/initialize/registration/`completed`, ambiguous launch death proof, `McpServerStoppedItem`, incremented `lifecycleSeq`, bounded `maxLaunches`, grant expiry, lease takeover, and no cross-instance filesystem/process reuse.
- macOS guest-toolchain fixtures covering signature/image/ABI/executable digest verification, host Mach-O and native-addon rejection, pinned guest identity across recovery, and separately granted locked dependency fetch.
- RuntimeBundle tests covering immutable side-by-side install, unique role/id/version/digest resolution for worker/policy/provider/tool/MCP/local-inference entries, path/symlink/manifest/signature corruption, candidate self-test failure, compatible activation, incompatible/non-rollback-safe schema migration, `drain_required`, reboot selection, startup rollback, one-Supervisor ownership, old worker relaunch, external client reinstall, and pinned-bundle retention.
- Retention fault tests covering 30-day event cursor advancement, quarantined-generation death/retention proof, seven-day CAS grace, complete authoritative-root reachability (including MCP/runtime/guest roots), interrupted GC, and a fail-closed incomplete walk.

Manual:

- Submit from CLI, detach, attach from TUI, disconnect, reattach through JSONL/RPC, and verify one unchanged Run/result/event cursor.
- Exercise every Session command, verify `cliq resume` creates a new Run from bounded context, and confirm legacy bookmark/handoff inspection cannot mutate Session/Run state.
- Restart the Supervisor while multiple surfaces are disconnected and confirm all accepted Runs remain discoverable.
- Run one task on each current provider in negotiated autonomous/text-only mode and inspect its immutable `assemblyRef` capabilities.
- Register one behaviorally stateless stdio server and one brokered Streamable HTTP server, reference their ids from a trusted workspace, and verify launch permission, exact recovery manifest matching, call/cancel, forced relaunch, lease cleanup, and credential/session redaction.
- On supported macOS, admit a Run whose toolchain is fully present in the signed guest manifest, then attempt host-only/native-incompatible tools and verify typed rejection before admission and no guest ambient network.
- While a detached Run is active, stage a compatible RuntimeBundle and prove upgrade plus pinned old-worker recovery; then stage an incompatible bundle and prove `drain_required`, unchanged active selection across reboot, and continued Run progress. Inject new-Supervisor startup failure and prove automatic selection rollback with no second state owner.
- Advance a disposable clock/state fixture through event and CAS retention windows, inspect earliest attach cursor and the GC reachability report, and verify no authoritative Run/result/receipt or referenced bundle/toolchain artifact is automatically removed.
- Verify root and nested `AGENTS.md` plus project/user `SKILL.md` precedence in a trusted repo, then change the files mid-Run and confirm the admitted assembly does not change.
- Migrate a copy of real legacy state with `cliq state migrate --check` and `cliq state migrate`, interrupt every importer phase, rerun, validate backup/import counts, then exercise `cliq state rollback --to-legacy <migrationId>`.
- Inspect telemetry and artifacts for a real 30-120 minute Run and confirm useful metrics with no prompt/source/secret payload.

### Risks And Dependencies

- Depends on work package 01 for state/artifacts/migration transactions, 02 for typed provider/tool capability contracts, 03 for sandbox/broker/MCP execution, 04 for Supervisor/control server, and 05 for result/verification/delivery events.
- Work package 01 owns Session/Run/request-replay plus `local_inference_activation_cycles`/`local_inference_launches` persistence and CAS reachability; 03 owns guest containment, `SandboxLaunchSpecV1`, `GuestToolchainManifest` enforcement, broker grants, and MCP/local-service process death proof; 04 owns the UDS server, Supervisor lifecycle/retention loop, local-service cycle/launch orchestration, and OS service/bootstrap integration; 05 owns result/delivery artifacts. WP06 owns the generated public schemas/clients/adapters, endpoint registry and platform credential authority/legacy-auth migration, minimal signed local-inference adapter/service integration, MCP registry/lifecycle adapter, RuntimeBundle packaging/activation compatibility, and final cutover integration. WP06 calls the typed WP01/03/04 state/containment APIs and may not write their tables directly.
- Protocol drift across four clients can recreate split-brain semantics; all adapters must import generated shared types and golden fixtures, including the complete `MODEL_COST_UNKNOWN`, `RESOURCE_EXHAUSTED`, and `UNSUPPORTED_EXECUTION_IDENTITY` error variants.
- MCP servers are third-party processes/services. Fail closed on capability/schema/recovery mismatch and route every launch/call/reconcile effect through the same permission, broker, Journal, budget, lease, and containment contracts. Behaviorally stateful servers remain unsupported, even if a server advertises retry metadata.
- Runtime update correctness depends on a stable bootstrap outside replaceable npm/client files and on old bundle retention. Activation must refuse when worker/state compatibility cannot be proven; `drain_required` is an intended safe outcome rather than an upgrade failure to bypass.
- Retention deliberately favors durability over disk reclamation. The initial release provides no product deletion API; event/CAS GC must fail closed until reachability and quarantine-death coverage pass fault tests.
- Automatic first-run migration is hard to reverse operationally; global locking, backup validation, idempotency, and rollback tests are release blockers.
- Removing the legacy path in one cut increases release risk but avoids indefinite dual semantics. The 24-hour and 50-repository fault campaign is mandatory.

Required sequence:

1. Freeze the cross-package storage/broker/Supervisor/result interfaces and canonical v1 error union, then generate protocol v1/schema v3 once; 01-05 implement against those checked-in types rather than adapter-local substitutes.
2. In parallel, build all control clients/adapters, Session command composition, provider conformance, MCP registry/lifecycle, guest-toolchain consumption, RuntimeBundle publishing/activation, instructions, telemetry, and migration against authoritative fakes and golden fixtures.
3. Publish the current Kernel build as the first signed RuntimeBundle, install the stable state-root bootstrap, and integrate all six work packages behind the internal test-only toggle. Detached admission remains disabled until bootstrap recovery, pinned-bundle relaunch, and single-Supervisor ownership pass.
4. Run generation/build/unit, protocol, fault, sandbox, MCP, bundle-upgrade, retention, migration, end-to-end, 24-hour, and 50-repository gates.
5. Create validated legacy backups, switch every surface/service selection/document to the new kernel in one release transaction, remove the old runtime/toggle and all dual write, and publish one Kernel Cut.

Rollback (only for hard-to-reverse changes):

- Before default cutover, switch off the internal test-only path; no legacy state has been mutated except disposable migration fixtures.
- Before or after cutover, a failed RuntimeBundle update rolls the bootstrap selection back to the previously healthy compatible bundle; never overwrite/delete bundles or start a second Supervisor. An incompatible candidate remains staged and inactive until Runs drain or a compatible bundle is installed.
- After cutover, use only `cliq state rollback --to-legacy <migrationId>`; never install an old binary first or manually rewrite new state.
- Preserve former SQLite/CAS, RuntimeBundles/guest manifests, registration receipts, and exported terminal results as read-only archived history after rollback. Do not reactivate/merge them, delete referenced artifacts, or reverse-convert them into legacy execution fields; re-entry is a fresh migration generation.

### Open Questions

None. Adding another runtime owner, widening the Session method surface, adding product deletion, weakening the one-shot cut, retaining dual write, broadening MCP/plugin scope, or changing the support matrix requires a new RFC.

### GitHub Issue Body

```markdown
## Outcome

Implement work package 06 of the Durable Verified Run Kernel: one generated versioned protocol across CLI/TUI/JSONL/RPC, context-only Session continuity, current provider conformance, stateless-per-call MCP tools, signed guest/runtime identities, AGENTS/SKILL compatibility, redacted Run telemetry, retention safety, and the one-shot legacy cutover.

## Required behavior

- All surfaces are clients; transport loss detaches and never cancels an accepted Run.
- Generate the exact v1 Run/Session/artifact/Supervisor method, result, event, bound, replay, and closed-error schemas from one source; expose no public Session append/import/bookmark execution surface.
- Support the current six providers through typed capability adapters.
- Support user-registered behaviorally stateless-per-call MCP tools over strongly contained stdio and brokered Streamable HTTP with exact `manual|retry|reconcile` contracts, lifecycle grants, death proof, manifest pinning, fencing, and Journal semantics.
- Pin a signed macOS `GuestToolchainManifest`; reject host-only/native-incompatible execution identity before admission.
- Install signed immutable RuntimeBundles side by side behind a stable bootstrap. Activate only when all nonterminal Runs and pinned workers are compatible; otherwise keep the current Supervisor and report `drain_required`.
- Perform no automatic authoritative Run/Session/result/receipt deletion and expose no `run.delete`; limit GC to expired display events and proven-unreachable CAS orphans.
- Freeze trusted `AGENTS.md`/`SKILL.md` inputs into `assemblyRef`; instructions never grant authority.
- Import legacy state once with validated backup/idempotency, then remove the old runner and all dual write.
- Keep plugin marketplace, MCP resources/prompts, cloud, native Windows execution, and `cliq-models` expansion out of this Kernel Cut.

## Validation

Run `npm run generate:control`, `npm run check:control-generated`, `npm run build`, `npm test`, `npm run test:fault`, `npm run test:sandbox`, `npm run test:migration`, and `npm run test:e2e`; include MCP lifecycle, guest identity, RuntimeBundle upgrade/rollback, and retention fault matrices before the RFC 24-hour/50-repository release campaign.

## Dependencies

Work packages 01-05. This is the final integration package for the same one-shot Kernel Cut.
```
