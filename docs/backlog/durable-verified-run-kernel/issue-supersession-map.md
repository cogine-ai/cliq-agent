# Durable Verified Run Kernel: Issue Supersession And Dependency Map

**Audit date:** 2026-08-11
**Repository:** `cogine-ai/cliq-agent`
**Authority:** [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md)

This map is a local recommendation based on the live GitHub issue bodies and current code. It does not perform any GitHub mutation.

## Action Vocabulary

- **Absorb:** reuse the existing issue as part or all of a Kernel Cut work package; update its body so there is only one live implementation issue for that behavior.
- **Update:** retain the issue but rewrite conflicting assumptions, scope, or dependencies.
- **Depend:** keep the issue separate and make it consume the kernel contract rather than invent another one.
- **Supersede:** close the issue after linking the RFC/work package because its proposed architecture is intentionally removed.
- **Keep separate:** valid work outside the Kernel Cut; it is not a release blocker.

## Recommended Kernel Cut Tracking Issues

Create one architecture epic that links the final RFC and all six local backlog-ready specs. Do not create a duplicate work-package issue where this map assigns an existing issue as the implementation tracker.

| Kernel item | Recommended GitHub action |
|---|---|
| Architecture epic | Create `[Epic]: Implement the Durable Verified Run Kernel` and link the RFC, six specs, and release gates. |
| 01 Durable State And Migration | Create a child issue from `01-durable-state-and-migration.md`. |
| 02 Typed Runtime And Provider Capabilities | Create a child issue from `02-typed-runtime-and-provider-capabilities.md`. |
| 03 Trusted Execution And Workspaces | **Reuse and rewrite #63** as this work-package tracker; do not create a second sandbox issue. |
| 04 Detached Supervisor And Control Protocol | Create a child issue from `04-detached-supervisor-and-control-protocol.md`. |
| 05 Agentic Verification And Recovery | Create a child issue from `05-agentic-verification-and-recovery.md`. |
| 06 Ecosystem Surfaces And Kernel Cutover | Create a child issue from `06-ecosystem-surfaces-and-kernel-cutover.md`. |

The six work packages are parallel ownership boundaries, not product phases. None may switch the default runtime independently.

### Overlapping open pull request

[PR #469 — `docs: design agent tool execution boundary (#63)`](https://github.com/cogine-ai/cliq-agent/pull/469) is currently open, non-draft, and still declares `Closes #63`. Its optional/opt-in execution boundary is superseded by this RFC's mandatory strong Run isolation and conflicts with the planned rewrite of #63 as work package 03. Close #469 without merge after linking it to PR #479/the final RFC, and remove its issue-closing effect; no commit from #469 is a second architecture authority.

## Existing Issue Decisions

| Issue | Current intent | Relationship to the final design | Recommended update | Kernel blocker |
|---|---|---|---|---:|
| [#63 — Explore OS-level sandbox and execution boundary](https://github.com/cogine-ai/cliq-agent/issues/63) | Optional, opt-in platform sandbox research. | Directly overlaps work package 03, but its optional posture conflicts with the public detach promise. Every durable Run requires the signed Virtualization.framework Linux-microVM backend on macOS, or bubblewrap + private PID namespace + cgroup v2/subreaper on Linux; Seatbelt-only may protect non-Run inspection helpers but admits no Run, and plain worktrees/process groups are not boundaries. Every Run path uses a private independent workspace generation plus the trusted broker. | **Absorb.** Rename/rewrite #63 to the complete `03-trusted-execution-and-workspaces.md` contract. Remove “explore”, “optional”, and “opt-in” from the Run path. Keep Workspace Trust, tool permission, and OS sandbox as independent layers. | Yes |
| [#62 — Evolve tool permission and policy surfaces](https://github.com/cogine-ai/cliq-agent/issues/62) | Consolidate layer-two permission UX after Workspace Trust. | Its grammar, policy composition, approval subjects, and MCP channel are reusable. Durable grants, lease-epoch binding, child ceiling intersection, and broker enforcement belong to work packages 03/04/06 rather than a separate permission control plane. | **Partially absorb and update.** Cross-link the kernel packages, remove any claim that policy alone enforces network/process isolation, and retain #62 only for residual permission UX/convenience after the kernel contracts land. | Core behavior yes; residual UX no |
| [#76 — Persistent TUI top banner for workspace and run state](https://github.com/cogine-ai/cliq-agent/issues/76) | Add a compact persistent banner fed by current TUI/session state. | The visual feature remains valid, but its state source must be the versioned control client and durable Run/verification/waiting events. The TUI cannot own Run lifetime. | **Depend/update.** Keep #76 open, add work packages 04 and 06 as data/lifecycle dependencies, preserve its existing #74/#75 visual dependencies, and test reconnect/detach/verified versus unverified states. Do not make the banner itself a Kernel Cut blocker. | No |
| [#46 — Plumb overrides and reason into validate/approve pipeline](https://github.com/cogine-ai/cliq-agent/issues/46) | Extend the legacy Transaction validate/approve/apply chain. | The final architecture removes the Transaction aggregate, `activeTxId`, override-driven approval pipeline, and automatic real-workspace apply as the future execution model. Required verifiers and explicit delivery Runs replace it. | **Supersede.** Close as superseded by the RFC and work package 05; do not implement or silently port override semantics into verification receipts. Preserve legacy reading only for migration/audit. | No |
| [#65 — Windows-native/configurable shell](https://github.com/cogine-ai/cliq-agent/issues/65) | Avoid hard-coded `bash -lc`/WSL behavior on Windows. | A configurable shell alone is not a runtime owner, sandbox, or safe execution boundary. The Kernel Cut removes the legacy attached owner and supports no native Windows execution. | **Keep separate/block.** Reframe as one prerequisite of a future native-Windows Supervisor/sandbox RFC; do not implement it as a hidden attached fallback. WSL2 follows Linux behavior. | No |
| [#67 — Environment-aware Windows path discovery](https://github.com/cogine-ai/cliq-agent/issues/67) | Discover redirected Windows known folders before broad probing. | Useful future platform input, but broad probing or an attached-only reader would reintroduce a second runtime path. | **Keep separate/block.** Treat as another prerequisite of the future native-Windows runtime RFC. Kernel Cut native Windows exposes only handle-safe legacy export and creates no Kernel state; WSL2 follows Linux only after full probes pass. | No |

## `cliq-models` Epic Decisions

The broader `cliq-models` catalog/download/provider-management product is not one of the six Kernel work packages and is not a release blocker. The Kernel Cut nevertheless absorbs a deliberately tiny **blocking** subset of #102/#105: the signed `local_inference` RuntimeBundle entry, explicit preinstalled-model bootstrap, exact `local_inference_launches` Supervisor lifecycle, no-egress service boundary, and `LocalZeroCostProvenanceV1` needed to keep Ollama among the six supported provider adapters without trusting a raw loopback daemon. Everything beyond that boundary remains separate and must consume the typed adapter rather than add provider-specific control semantics or run a second model-service process owner.

| Issue | Recommended relationship and update | Kernel blocker |
|---|---|---:|
| [#99 — Add cliq-models as the Cliq-managed local model provider](https://github.com/cogine-ai/cliq-agent/issues/99) | **Keep separate/depend.** Retain as the product epic. Add dependencies on work package 02 provider capability contracts and work package 06 surface integration. It must not add Run statuses, Checkpoint fields, or provider branches to the kernel. | No |
| [#100 — Define cliq-models provider contract and safety model](https://github.com/cogine-ai/cliq-agent/issues/100) | **Update.** Adopt the typed provider contract, user-initiated installation boundary, brokered secrets/network, and the naming rule below. Keep provider identity separate from the managed model-service implementation. | No |
| [#101 — Add cliq-models metadata catalog records](https://github.com/cogine-ai/cliq-agent/issues/101) | **Depend.** Keep the curated catalog scope. Implement its provider/model metadata as an extension of work package 02 schemas without changing kernel control state. Catalog/download metadata is not `RunSpec` authority until a selected model is frozen into `assemblyRef`. | No |
| [#102 — Add managed Ollama-derived runtime installer and status probe](https://github.com/cogine-ai/cliq-agent/issues/102) | **Partially absorb.** Work package 06 owns the bundled/signed, explicit-user-installed executable/model identity plus health probe needed by the RFC service spec/evidence; repository-triggered install, catalog/download UX, arbitrary sources, and general desired-state management remain here. Installation never spawns the Run-serving process: the Kernel Supervisor exclusively launches it through `local_inference_launches`. Never execute the installer inside a sandbox worker or grant it through a skill. | Minimal signed bootstrap/probe yes; residual product no |
| [#103 — Integrate cliq-models into provider management](https://github.com/cogine-ai/cliq-agent/issues/103) | **Depend.** Build the broader management UX on #100-#102/#104 and work package 06 surfaces. Kernel Ollama selects only the attested managed service; existing raw/user-managed endpoints require explicit migration or remain unsupported for durable Runs. Provider setup must not become Run admission or Run-Supervisor ownership. | No |
| [#104 — Add cliq-models model download and selection flow](https://github.com/cogine-ai/cliq-agent/issues/104) | **Update/depend.** Preserve explicit, cancellable, checksum-verified curated downloads. Treat install/download/create as trusted, receipt-bearing user operations with Cliq-owned cleanup boundaries; do not expose credentials or arbitrary workspace-driven sources. They use RunJournal only when deliberately modeled as a Run. | No |
| [#105 — Add cliq-models runtime adapter and supervised Ollama-derived service](https://github.com/cogine-ai/cliq-agent/issues/105) | **Partially absorb, rename, and depend.** Recommended title: `[Feature]: Add cliq-models adapter and managed Ollama-derived model service`. The Kernel Supervisor exclusively owns start, blocked activation, lease, health evidence, fencing, shutdown, death proof, takeover, and replacement of the exact process serving Runs through `local_inference_launches`. A residual `CliqModelsServiceManager` may own install/catalog/desired-model selection only; it cannot spawn, adopt, monitor, or expose a second endpoint for that process and owns no agent Runs, Checkpoints, control socket, worker generations, or recovery scheduling. | Minimal service/boundary/lifecycle yes; richer manager no |
| [#106 — Make cliq-models the preferred local-first provider](https://github.com/cogine-ai/cliq-agent/issues/106) | **Keep separate/depend.** Ship only after #100-#105 and #107 are ready. Use work package 06 provider UX; do not silently migrate raw Ollama users—offer explicit enrollment into the signed managed boundary—and do not equate the provider with global Offline Mode. | No |
| [#107 — Harden cliq-models beta diagnostics and cleanup](https://github.com/cogine-ai/cliq-agent/issues/107) | **Update/depend.** Reuse redaction and local telemetry conventions from work package 06. Diagnostics cannot include prompts/secrets; cleanup removes only `cliq-models`-owned files and never Run/CAS artifacts or user-managed Ollama state. | No |

## Naming Rule For #105

The word **Supervisor** is reserved for the Durable Run Supervisor defined by the canonical RFC.

```text
Durable Run Supervisor
  owns: Run admission, queue, leases, workers, recovery, control socket, broker

CliqModelsServiceManager
  owns: install/catalog/desired-model metadata only

Durable Run Supervisor local_inference plane
  owns: process reserve/start/activate/lease/health endpoint/fence/death/replacement
```

The manager publishes only an immutable signed model/service selection consumed by the Kernel. They do not share mutable lifecycle state or process terminology, and the manager never starts a competing daemon. A local model service crash is handled by the Supervisor's exact local launch plane and becomes a provider/model invocation fact for affected Runs; it is not permission to mutate Run control state outside normal Journal and recovery transitions.

## Recommended Remote Edits (Not Performed)

1. Create the architecture epic and five new child issues listed above.
2. Close PR #469 without merge as superseded by PR #479/the final RFC, remove its `Closes #63` effect, then rewrite #63 as work package 03 and link it to the epic instead of creating a duplicate sandbox issue.
3. Update #62 and #76 dependencies/scopes.
4. Close #46 as superseded only after the epic and work package 05 links exist.
5. Split #102 and #105 checklists explicitly: mark the absorbed minimal signed
   bootstrap/probe and Supervisor-owned service/boundary/lifecycle criteria as
   Kernel Cut blockers, and mark only their residual catalog/download/richer
   manager product scope non-blocking. Add the naming correction to #105.
6. Add explicit “not a Kernel Cut blocker” notes to #65, #67, #99-#101,
   #103-#104, #106-#107, and only the residual non-absorbed portions of
   #102/#105.

No existing issue should be closed merely because implementation has started. Close or mark complete only after its retained acceptance criteria have passed.
