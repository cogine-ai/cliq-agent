# Trusted Execution And Workspaces

## Backlog Ready Spec

### Verdict

READY WITH RISKS

This work package is implementable without further product decisions. The visible risks are the signed macOS microVM supply chain, Linux cgroup delegation, Git edge cases, and workspace-image cost; none permits a fallback to host-process detached mutation.

### Source

Brief / issue / roadmap item:

- Work package 3 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: **Delegate. Detach. Return to verified work.**
- This package owns the trusted execution boundary, private `RunWorkspace` generations, source/recovery image separation, and trusted model/effect broker.

Related issues:

- GitHub issue `#63` (OS sandbox) is absorbed by this package. Its sandbox cannot remain optional for detached mutation.
- GitHub issue `#62` (tool permissions) remains relevant, but permission is an authorization layer above—not a substitute for—the sandbox.
- The [issue supersession map](issue-supersession-map.md) is authoritative for closure and dependency wording.

Related code:

- `src/session/trust.ts` implements persisted Workspace Trust decisions and canonical-path identity.
- `src/cli.ts` and `src/headless/run.ts` already gate `createRuntimeAssembly` and workspace permission loading behind Workspace Trust.
- `src/runtime/assembly.ts` currently loads repository-controlled config, instructions, skills, extensions, and hooks; work package 6 removes executable repository extensions/hooks from the Kernel path.
- `src/policy/types.ts`, `src/policy/engine.ts`, `src/policy/compose-runtime.ts`, and their tests provide policy modes, approval subjects, and permission composition.
- `src/policy/network-placeholder.ts` explicitly records that current network rules are intent-only without an OS boundary.
- `src/tools/bash.ts` currently runs `bash -lc` in the real workspace with `env: process.env`; this is the primary execution path to replace for detached Runs.
- `src/workspace/transactions/staged-view.ts` contains useful copy/reflink and symlink-escape lessons, but its bind-path behavior is not a security boundary.
- `src/workspace/transactions/diff.ts`, `snapshot.ts`, and `recovery.ts` contain reusable diff and crash-recovery knowledge.
- `README.md` correctly states that the current runtime is not sandboxed.

### User Outcome

A detached Run executes in a private, recoverable generation that cannot modify the user's real workspace, shared Git metadata, another Run, Cliq control state, or provider credentials. Git generations contain independent `.git`; non-Git generations use the same strong isolation without inventing Git metadata. The user may edit the real workspace while the Run is detached; Cliq returns an immutable result for later review and explicit delivery.

On macOS, every Run executes only inside Cliq's bundled, signed `Virtualization.framework` microVM. On Linux, every Run requires bubblewrap plus a PID namespace, a dedicated cgroup v2 subtree, and a trusted subreaper. Seatbelt may protect descriptor-safe non-Run inspection helpers but is never a Run backend. A non-Git workspace uses the same strong generation backend. Native Windows has no execution mode in this Kernel Cut; WSL2 qualifies only when it passes the complete Linux probe. Cliq never silently relabels a host process or workerless read path as a trusted Run.

### Problem

The current runtime cannot honor the detach promise:

- `bash` runs directly in `context.cwd`, inherits the full Cliq environment, and can reach provider keys and arbitrary user files.
- edit transactions isolate only selected declarative edits; Bash side effects still reach the real workspace.
- the staged-view implementation can bind paths back to the real workspace, which is explicitly incompatible with strong isolation.
- Git ghost checkpoints are bookmarks/recovery aids, not complete private execution images, and non-Git checkpoints are unavailable.
- policy can decide whether an action is allowed, but it cannot physically contain a malicious or compromised process.
- model clients and secret-bearing integrations currently live in the same process/environment as tool execution.
- a stale worker has no lease-fenced broker boundary and could continue producing side effects after takeover.

### Scope

In:

- Enforce the mandatory order `Workspace Trust -> repository state load -> schema validation -> Tool Permission / durable grant -> pre-effect Checkpoint and Journal prepared -> sandbox or broker dispatch -> Journal terminal fact -> Run item/state transition`.
- Add a bundled, signed `Virtualization.framework` microVM backend as the only macOS Run execution mode. Seatbelt is defense in depth for descriptor-safe non-Run inspection helpers and is never sufficient for Run admission, worker activation, shell, verifier, or stdio MCP execution.
- Enforce the managed `local_zero_cost` inference service as a separate top-level strong containment with exact signed `local_inference` RuntimeBundle/model identity, isolated root, loopback-only traffic, no external egress/credentials, durable blocked preactivation, boundary evidence, and whole-containment death proof; it is neither a Run worker nor an admin probe.
- Freeze a signed content-addressed `GuestToolchainManifest` into `assemblyRef` for macOS strong mode so the guest image/ABI and every worker/tool/verifier executable path, digest, and version—not host Mach-O identity—are authoritative.
- Freeze the Node-only `DependencyPolicy` in `RunSpec`, derive an exact `DependencyAcquisitionPlan` from every FinalCandidate into its `VerifierPlan`, and require one integrity-complete supported candidate lockfile, pinned guest package manager, registered broker endpoints/credential handles, bounded content-addressed downloads, networkless install, and install scripts off unless admission consumed the exact authorization into `DependencyInstallScriptsAuthorizationTemplateV1` and the candidate has an exact unused-ordinal `OperationGrantV1`. Keep the candidate source projection read-only with only declared dependency/cache/temp write roots, revalidate `resultSourceRef` before completion, quarantine integrity violations, and publish a post-effect Checkpoint only for unchanged source.
- Add a Linux strong backend that combines bubblewrap user/mount/network isolation, a PID namespace, a non-delegated per-lease cgroup v2 subtree, and a trusted PID-namespace init/subreaper. All four controls must pass startup probes.
- Freeze every strong process/VM creation into exact `SandboxLaunchSpecV1`, a digest-bound four-owner union that closes runtime/executable identity, purpose-specific `SandboxProcessInvocationV1` source/recipe/argv/cwd/stdio derivation, sanitized environment, filesystem/mount plan, resource/profile equality, containment plan, and owner-specific forbidden fields before the launcher acts.
- Freeze and enforce the canonical `SandboxResourceSpec` for process, memory, CPU, file, generation, output, and IPC ceilings on both strong backends; resource trips never manufacture no-effect evidence before whole-containment death and generation quiescence.
- Require every `run.submit|run.apply`, including read-only and text-only requests, to resolve `RunAssemblyV1.sandboxBackend` as exactly `macos_vm|linux_namespace` and pass the corresponding strong-backend, worker identity, and pinned-executable probes before Run creation. Reject native Windows and any supported host without a complete working backend. Non-Git roots use the same strong private-generation path rather than a weak read mode.
- Capture a content-addressed base workspace manifest without mutating the user's index or working tree.
- Consume only work package 1's exact immutable `WorkspaceIdentityV1.kind='live'` plus its exact `RepositoryIdentityV1` iff Git: descriptor-reopen the NFC absolute root and literal in-root `.git` no-follow for every capture/apply/publication, validate principal/platform/owner/device/file/object-format identities, keep 64-bit device/file ids as canonical unsigned decimal strings, fail root/`.git` replacement with `ARTIFACT_MISMATCH`, and reject `legacy_unavailable` Sessions/forks from execution.
- Freeze the RFC `SourceProjectionSpec` into `RunSpec.sourceProjectionRef`, including `cliq-exact-path-v1` selectors, frozen admission-time ignore rules, hard exclusions, authorization refs for ignored in-root includes, rejection of every outside-root selector, and result size/count ceilings.
- Materialize a unique private workspace generation for every mutating worker lease, with an independent `.git` directory and no writable alias to the real repository.
- Materialize every Run generation as exact immutable `WorkspaceGenerationIdentityV1` plus authoritative `WorkspaceGenerationStateV1`; require exact snapshot/quarantine/retirement evidence, restore every resumed lease only into a distinct generation from a ready Checkpoint, and never reuse a quarantined/retired identity.
- Separate `workspaceStateRef` (recovery state) from `resultSourceRef` (deliverable source state).
- Launch workers with a sanitized allowlisted environment and private `HOME`/`TMPDIR`; all secret-bearing inputs, provider credentials, and integration credentials remain outside the worker as opaque broker references.
- Add a trusted broker for Run-owned model calls, remote MCP calls, secret-bearing integrations, publication/materialization effects, and the separately fenced HTTP half of user-administered MCP registration probes.
- Enforce work package 2's durable Run-context compaction through the same Journal/lease/budget broker gates as an exact tools-disabled model call; never expose implicit provider truncation, compaction control as model commands, or a workspace mutation path.
- Provide a strong-sandbox launch profile for work package 6's user-registered stdio MCP tools in which every exact tool call receives a fresh call-scoped process/containment, fresh empty private `HOME`/`TMPDIR`, read-only registered executable/toolchain, no RunWorkspace/real-workspace/Cliq-state/persistent writable mount, no network or secrets, exact batch/call-index identity, and mandatory teardown/death proof. No stdio MCP instance is Run-scoped or reused across calls.
- Persist a `ProcessContainmentRef` for every preactivated worker, invocation sandbox, MCP admin probe, and managed local-inference service. Its closed owner union is exactly `worker_activation|run_invocation|admin_probe|local_inference_service`; it names an OS-enforced boundary containing every descendant and never forces admin or service lifecycle to invent Run identity.
- Fence every Run-owned broker and sandbox request by `runId`, `opId`, attempt, immutable request digest, `dispatchId`, current `leaseEpoch`, `activeWorkerLaunchId` plus exact launch-row lease/worker/containment/generation identity, exact `OperationGrantV1`, target, and expiry. Require both atomic `claimDispatch` and a post-claim `releaseClaimedDispatch` immediately before target I/O; an `AuthorizationGrantV1`, policy decision, approval payload, or authorization template is never a dispatch capability.
- Accept principal/channel authority only from exact Supervisor-injected `LocalPrincipalIdentityV1`/`LocalControlChannelIdentityV1` rooted in the signed in-process identity or exact held-descriptor `LocalSocketPeerObservationV1`; no sandbox environment, worker, broker payload, or caller field may provide them. Gate every grant/lease/deadline/release check through the current healthy `CanonicalTimeFenceV1`; clock regression fail-closes release and starts quiescence rather than extending authority.
- Enforce the canonical authorization target union before any executable identity enters a launch plan: verifier identity may be only signed guest-toolchain or exact workspace-script identity and never a RuntimeBundle entry; stdio MCP may use a signed guest-toolchain identity or a retained signed RuntimeBundle executable only when that manifest entry has role `mcp_server`.
- Give MCP admin probes the separate canonical `AdminProbeBrokerRequest` plus `claimAdminProbe`/`releaseAdminProbe` authority over the exact active `AdminOperation.probeDispatch`; no admin request contains or consults Run status, revision, budget, frontier, lease epoch, worker launch, or workspace generation.
- Deny direct arbitrary-shell network access in strong mode; network-capable operations use a brokered, target-authorized path and remain journaled.
- Add platform, escape, stale-worker, secret-exposure, workspace-drift, snapshot, and fault-injection tests.

Out:

- Native Windows execution, Supervisor transport, or sandbox support.
- A weaker non-Git, read-only, workerless, Seatbelt-only, or attached fallback path marketed as a Kernel Run.
- A weak Git-worktree mode marketed as safe detach.
- General-purpose containers or VM selection, remote workers, distributed sandboxes, or cloud execution. The one bundled local macOS microVM backend is part of the mandatory trusted boundary, not a user-selectable execution platform.
- A general secret manager, network service mesh, or universal exactly-once effect layer.
- Arbitrary external filesystem inputs or mounts, external Git/config includes, and raw secret inputs. Those require a separate RFC and cannot be authorized into this Kernel Cut.
- A general transaction filesystem or preservation of `activeTxId`/`Transaction` as the new execution model.
- Automatic application of Run results to the real workspace; delivery is owned by work package 5.
- Verifier semantics and bounded repair, except providing the isolated execution view they consume.
- Queueing, service installation, lease scheduling, preactivation intent persistence, and containment takeover orchestration, which are owned by work package 4.
- Deleting the legacy attached runtime before the Kernel Cut; work package 6 owns final cutover and removal.

### Proposed Implementation Direction

Likely files/modules:

- Add `src/sandbox/types.ts`, `launch-spec.ts`, `probe.ts`, `resources.ts`, `guest-toolchain.ts`, `environment.ts`, `seatbelt-inspection.ts`, `linux-containment.ts`, `microvm.ts`, `launcher.ts`, `mcp-stdio.ts`, `local-inference.ts`, and `quiesce.ts` for exact `SandboxLaunchSpecV1` construction/validation, backend-independent launch plans, resource enforcement, signed guest identity, descriptor-safe non-Run inspection, call-scoped stdio MCP isolation, managed local-service preactivation/boundary enforcement, whole-descendant containment, and platform implementations.
- Add the pinned macOS guest manifest/helper sources under `src/sandbox/microvm/` and release-time signing/notarization verification. Add the minimal Linux namespace-init/subreaper helper under `src/sandbox/linux/`; its digest is pinned by the installed Supervisor.
- Add `src/workspace/run-workspace/types.ts`, `manifest.ts`, `capture.ts`, `source-projection.ts`, `materialize.ts`, `snapshot.ts`, `result-source.ts`, `generation.ts`, and `gc.ts`.
- Add `src/broker/types.ts`, `client.ts`, `server.ts`, `authorization.ts`, `admin-probe.ts`, and `redaction.ts`; provider-specific transport remains behind existing model adapters.
- Update `src/tools/types.ts`, `src/tools/bash.ts`, `src/runtime/runner.ts`, and `src/runtime/workspace-writer.ts` so detached tools receive only a private generation and a lease-scoped execution capability.
- Update `src/model/index.ts`, `src/model/types.ts`, `src/model/registry.ts`, `src/model/providers/*`, `src/headless/run.ts`, and the future worker entrypoint so provider calls cross the broker instead of exposing credentials to workers.
- Update `src/workspace/config.ts` only for schema-validated sandbox profile, root-relative source selectors, declared ephemeral paths, and network target policy loaded after Workspace Trust. Reject every external path or mount request; do not add an external-input schema.
- Extend `src/session/trust.test.ts`, `src/runtime/bash-policy.test.ts`, `src/tools/bash.test.ts`, and `src/workspace/transactions/staged-view.test.ts` where old invariants remain relevant.
- Add focused tests beside every new module plus `src/sandbox/integration.test.ts`, `src/sandbox/containment.integration.test.ts`, `src/workspace/run-workspace/integration.test.ts`, and `src/broker/integration.test.ts`.

Implementation notes:

1. **Freeze the platform matrix and launch contract.** The launcher accepts only this versioned closed contract; there is no unversioned `SandboxLaunchSpec`, owner bag, arbitrary argv/env/mount variant, or backend-specific widening:

    ```ts
    type SandboxRuntimeBindingV1 = {
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      sandboxBackend: 'linux_namespace' | 'macos_vm'
      toolchain:
        | { kind: 'none' }
        | {
            kind: 'guest_toolchain'
            guestToolchainManifestRef: ArtifactRef
            guestToolchainManifestDigest: string
            guestImageRef: ArtifactRef
            guestImageDigest: string
          }
      launcher: {
        executableId: string
        executableDigest: string
      }
      runtimeDigest: string
    }

    type InterpreterIdentityV1 = {
      schemaVersion: 1
      format: 'cliq-interpreter-identity-v1'
      guestToolchainManifestRef: ArtifactRef
      guestToolchainManifestDigest: string
      toolId: string
      executionPath: string
      executableDigest: string
      version: string
      invocationProtocol: 'script_path_as_first_argument-v1'
      identityDigest: string
    }

    type SandboxExecutableIdentityV1 =
      | {
          kind: 'runtime_bundle'
          runtimeBundleRef: ArtifactRef
          runtimeBundleManifestDigest: string
          executableId: string
          role: 'worker' | 'tool_adapter' | 'mcp_server' | 'local_inference' | 'platform_helper'
          executionPath: string
          executableDigest: string
        }
      | {
          kind: 'guest_toolchain'
          guestToolchainManifestRef: ArtifactRef
          guestToolchainManifestDigest: string
          toolId: string
          role: 'worker' | 'shell' | 'tool' | 'verifier' | 'package_manager' | 'search' | 'mcp_server'
          executionPath: string
          executableDigest: string
        }
      | {
          kind: 'workspace_script'
          purpose: 'verifier'
          workspaceIdentityDigest: string
          canonicalRootRelativePath: string
          scriptDigest: string
          interpreterIdentityRef: ArtifactRef
          interpreterIdentityDigest: string
        }

    type SandboxCapturedStdioV1 = {
      stdin: 'closed'
      stdout: 'captured'
      stderr: 'captured'
      extraFileDescriptors: 'authenticated_operation_channel_only'
    }

    type SandboxProcessInvocationV1 =
      | {
          kind: 'worker_entrypoint'
          purpose: 'worker_activation'
          recipe: 'cliq-worker-entrypoint-v1'
          runtimeSource: 'launch_runtime'
          executableSource: 'launch_executable'
          argvSource: 'fixed_empty'
          cwdSource: 'generation_root'
          stdio: {
            stdin: 'closed'
            stdout: 'captured'
            stderr: 'captured'
            extraFileDescriptors: 'authenticated_worker_channel_only'
          }
        }
      | {
          kind: 'local_inference_entrypoint'
          purpose: 'local_inference_service'
          recipe: 'cliq-local-inference-entrypoint-v1'
          runtimeSource: 'launch_runtime'
          executableSource: 'launch_executable'
          modelManifestSource: 'service_spec'
          argvSource: 'trusted_recipe_decode_of_service_spec'
          cwdSource: 'isolated_root'
          stdio: SandboxCapturedStdioV1
        }
      | ({
          kind: 'run_request'
          requestRef: ArtifactRef
          requestDigest: string
          targetRef: ArtifactRef
          targetDigest: string
          argvCwdSource: 'trusted_recipe_decode_of_request_and_target'
        } & (
          | { purpose: 'tool'; recipe: 'cliq-tool-launch-v1'; stdio: SandboxCapturedStdioV1 }
          | { purpose: 'verifier'; recipe: 'cliq-verifier-command-v1'; stdio: SandboxCapturedStdioV1 }
          | {
              purpose: 'mcp_stdio'
              recipe: 'cliq-mcp-stdio-launch-v1'
              stdio: {
                stdin: 'mcp_framed'
                stdout: 'mcp_framed'
                stderr: 'captured'
                extraFileDescriptors: 'none'
              }
            }
          | { purpose: 'dependency'; recipe: 'cliq-dependency-launch-v1'; stdio: SandboxCapturedStdioV1 }
          | { purpose: 'publication'; recipe: 'cliq-publication-launch-v1'; stdio: SandboxCapturedStdioV1 }
        ))
      | ({
          kind: 'admin_probe'
          targetRef: ArtifactRef
          targetDigest: string
          probePayloadCoreRef: ArtifactRef
          argvCwdSource: 'trusted_recipe_decode_of_admin_target_and_probe_core'
        } & (
          | {
              purpose: 'admin_mcp_stdio_probe'
              recipe: 'cliq-admin-mcp-stdio-probe-v1'
              stdio: {
                stdin: 'mcp_framed'
                stdout: 'mcp_framed'
                stderr: 'captured'
                extraFileDescriptors: 'none'
              }
            }
          | {
              purpose: 'admin_mcp_http_probe'
              recipe: 'cliq-admin-mcp-http-probe-v1'
              stdio: SandboxCapturedStdioV1
            }
        ))

    type SanitizedSandboxEnvironmentV1 = {
      schemaVersion: 1
      format: 'cliq-sanitized-sandbox-environment-v1'
      controlledPath: string[]
      locale: { lang: string; lcAll: string }
      home: string
      tmpdir: string
      variables: Array<{ name: string; value: { kind: 'non_secret_literal'; value: string } }>
      inheritedHostEnvironment: false
      secretMaterial: 'none'
      brokerAccessAtSpawn: 'none'
      networkMode: 'none' | 'broker_ipc_only'
      environmentDigest: string
    }

    type SandboxFilesystemV1 =
      | {
          kind: 'run_generation'
          generationRef: ArtifactRef
          access: 'preactivated_readonly' | 'read_only' | 'read_write'
          sourceProjectionRef: ArtifactRef
          independentGit: true
        }
      | {
          kind: 'isolated_empty_root'
          rootImageRef: ArtifactRef
          rootImageDigest: string
          persistentWritableMounts: false
        }

    type SandboxMountV1 =
      | {
          kind: 'cas_artifact'
          artifactRef: ArtifactRef
          artifactDigest: string
          targetPath: string
          access: 'read_only'
          purpose: 'runtime' | 'input' | 'executable'
        }
      | {
          kind: 'run_generation'
          generationRef: ArtifactRef
          canonicalRootRelativePath: string
          targetPath: string
          access: 'read_only' | 'read_write'
          purpose: 'source' | 'dependency' | 'cache' | 'output'
        }
      | {
          kind: 'private_ephemeral'
          privateRootId: string
          targetPath: string
          access: 'read_write'
          purpose: 'home' | 'tmp' | 'dependency' | 'cache' | 'output'
        }

    type SandboxLaunchBaseV1 = {
      schemaVersion: 1
      format: 'cliq-sandbox-launch-v1'
      runtime: SandboxRuntimeBindingV1
      executable: SandboxExecutableIdentityV1
      environment: SanitizedSandboxEnvironmentV1
      filesystem: SandboxFilesystemV1
      mounts: SandboxMountV1[]
      mountsDigest: string
      sandboxProfileRef: ArtifactRef
      sandboxProfileDigest: string
      resources: SandboxResourceSpec
      resourcesDigest: string
      containmentPlanRef: ArtifactRef
      containmentPlanDigest: string
      createdAt: string
      launchSpecDigest: string
    }

    type SandboxLaunchSpecV1 =
      | (SandboxLaunchBaseV1 & {
          owner: Extract<ProcessContainmentOwner, { kind: 'worker_activation' }>
          purpose: 'worker_activation'
          processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'worker_entrypoint' }>
          operationGrantRef?: never
          requestRef?: never
          requestDigest?: never
          targetRef?: never
          targetDigest?: never
          parentWorkerContainmentRef?: never
          adminTargetRef?: never
          adminTargetDigest?: never
          probePayloadCoreRef?: never
        })
      | (SandboxLaunchBaseV1 & {
          owner: Extract<ProcessContainmentOwner, { kind: 'run_invocation' }>
          purpose: 'tool' | 'verifier' | 'mcp_stdio' | 'dependency' | 'publication'
          processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'run_request' }>
          operationGrantRef: ArtifactRef
          requestRef: ArtifactRef
          requestDigest: string
          targetRef: ArtifactRef
          targetDigest: string
          parentWorkerContainmentRef: ArtifactRef
          adminTargetRef?: never
          adminTargetDigest?: never
          probePayloadCoreRef?: never
        })
      | (SandboxLaunchBaseV1 & {
          owner: Extract<ProcessContainmentOwner, { kind: 'admin_probe' }>
          purpose: 'admin_mcp_stdio_probe' | 'admin_mcp_http_probe'
          processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'admin_probe' }>
          adminTargetRef: ArtifactRef
          adminTargetDigest: string
          probePayloadCoreRef: ArtifactRef
          operationGrantRef?: never
          requestRef?: never
          requestDigest?: never
          targetRef?: never
          targetDigest?: never
          parentWorkerContainmentRef?: never
        })
      | (SandboxLaunchBaseV1 & {
          owner: Extract<ProcessContainmentOwner, { kind: 'local_inference_service' }>
          purpose: 'local_inference_service'
          processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'local_inference_entrypoint' }>
          serviceSpecRef: ArtifactRef
          serviceSpecDigest: string
          operationGrantRef?: never
          requestRef?: never
          requestDigest?: never
          targetRef?: never
          targetDigest?: never
          parentWorkerContainmentRef?: never
          adminTargetRef?: never
          adminTargetDigest?: never
          probePayloadCoreRef?: never
        })
    ```

   `runtimeDigest = SHA-256(JCS(runtime with runtimeDigest omitted))`, `environmentDigest = SHA-256(JCS(environment with environmentDigest omitted))`, `mountsDigest = SHA-256(JCS(mounts))`, `resourcesDigest = SHA-256(JCS(resources))`, and `launchSpecDigest = SHA-256(JCS(the complete launch spec, including processInvocation, with launchSpecDigest omitted))`. `containmentPlanDigest` and `sandboxProfileDigest` equal the decoded referenced artifacts. Mounts are unique, byte-sorted by `targetPath`, nonoverlapping, and sourced only from verified CAS, the exact named Run generation, or a Supervisor-created private ephemeral root. Targets are absolute canonical guest/sandbox paths; generation source selectors are `cliq-exact-path-v1`. There is no raw host path, symlink-following source, writable runtime/CAS mount, persistent admin/MCP mount, ambient credential root, device, socket, or untyped mount.

   Owner equality is exhaustive. `worker_activation` owner bytes equal the reserved `WorkerLaunch` Run/intended epoch/launch id; its plan owner is identical, plan parent is absent, filesystem is the exact Run generation in `preactivated_readonly`, executable equals the Run assembly's signed worker identity (and the signed guest worker on macOS), and every invocation/admin/service field is structurally forbidden. Its `processInvocation` is exactly `worker_entrypoint`, selects only the launch's already digest-bound runtime/executable, fixes empty argv/generation-root cwd/captured output, and exposes only the authenticated worker channel, which remains activation-blocked until the launch CAS; the launcher accepts no caller-supplied process field. `run_invocation` owner bytes equal the permanent Journal claim and exact `OperationGrantV1`; its plan has the identical owner and `parentContainmentRef=parentWorkerContainmentRef` ending at the active worker containment. Its generation/filesystem/mounts equal the grant's typed target: verifier source is read-only with only declared ephemeral writes, stdio MCP is `isolated_empty_root` with no Run-generation mount, and a mutating tool can write only its activated generation. Its `processInvocation.kind='run_request'`, purpose equals the outer purpose, request/target refs and digests equal both the launch fields and exact grant, and recipe is the one closed purpose mapping above. `admin_probe` owner bytes equal the exact AdminOperation attempt/principal/method/request/target/Supervisor; its plan has that identical owner, no parent, `isolated_empty_root`, no Run generation, and every Run/lease/worker/frontier/Journal/`OperationGrantV1` field is structurally absent. Its `processInvocation.kind='admin_probe'`, purpose/target/`probePayloadCoreRef` equal the outer launch and exact `McpAdminProbeTargetV1` plus a static signed/typed probe program published before preactivation. That core contains no admin-operation phase, containment, lease, `probeRequestDigest`, or `dispatchId`; after containment and claim exist, `AdminProbeBrokerRequest.payloadRef` must equal this same core ref. Stdio uses only the exact target argv and MCP frames, while HTTP uses only the fixed signed trusted-adapter recipe. `local_inference_service` is top-level with `isolated_empty_root`; owner/service spec/launch/principal/Supervisor bytes equal the exact `LocalInferenceServiceLaunchV1`, its process kind is `local_inference_entrypoint`, and runtime/executable/model/profile/resources/loopback-only recipe equal the exact signed `LocalInferenceServiceSpecV1`. It has no Run, worker, Journal, grant, admin target, credential, or external-network field. Credentials remain broker handles outside environment/mount/payload bytes. The trusted launcher itself decodes the typed source artifacts using the named signed recipe and accepts no out-of-band argv, cwd, stdin/stdout/stderr mode, file descriptor, payload, or adapter IPC override. Any process source, recipe, argument, working directory, channel, or equality mismatch fails before containment creation.

   Runtime/executable/profile equality is also closed. RuntimeBundle and GuestToolchain refs/digests equal the admitted Run assembly, exact admin target closure, or exact local-inference service spec; the backend equals both that owner closure/profile and containment plan; executable path/id/role/digest resolves byte-for-byte from the signed manifest. Verifier cannot select RuntimeBundle; RuntimeBundle stdio MCP is only role `mcp_server`; a managed local service selects only a RuntimeBundle entry whose signed role is exactly `local_inference`. `resources` equals the decoded canonical `sandboxProfileRef`, with no caller-selected increase. Environment variables are unique and byte-sorted by name. `variables` rejects the exact names `PATH|HOME|TMPDIR|LANG`, every `LC_*`, `CLIQ_BROKER_*`, `CLIQ_CREDENTIAL_*`, `CLIQ_ACTIVATION_*`, and `CLIQ_SUPERVISOR_*` name; dedicated closed fields supply the non-secret runtime values, while trusted-broker secrets never become environment entries. Every path/home/tmp/locale/literal is profile-validated, and `inheritedHostEnvironment=false`, `secretMaterial='none'`, and `brokerAccessAtSpawn='none'` are invariant. Worker/admin/service preactivation remains blocked and powerless; each Run invocation or admin probe receives its exact release only after its second dispatch gate, while local model traffic begins only after its separate active launch/boundary-evidence CAS. Any digest, equality, forbidden-field, mount, executable-role, resource, or environment mismatch fails before containment creation or target I/O.

   On Linux, the trusted launcher enters bubblewrap user/mount/network namespaces and a new PID namespace, becomes PID 1 and a subreaper, and is placed before worker exec into a Supervisor-owned cgroup v2 subtree that is not delegated or mounted writable to the worker. Every worker, Bash command, verifier, and stdio MCP descendant remains in that subtree; daemonization, double-fork, and re-parenting do not escape it. Strong admission requires working `cgroup.kill`, `cgroup.freeze`, `cgroup.events`, PID-namespace identity, and descendant reaping.

   On macOS, the only Run backend is a local microVM created by the bundled, signed helper through `Virtualization.framework`, booting a pinned signed guest image and guest agent. The private generation is copied into a VM-owned disk; it is never a writable host share. A Git generation carries its independent `.git`, while a non-Git generation carries none. Broker traffic uses an authenticated host/guest channel bound to the VM instance and lease. Stopping the VM stops every guest descendant. Seatbelt may wrap descriptor-safe non-Run inspection helpers, but Seatbelt alone never admits a workerless, read-only, text-only, shell, verifier, stdio MCP, or mutating Run.

   `sandboxProfileRef` freezes this exact resource contract:

    ```ts
    type SandboxResourceSpec = {
      maxProcesses: number               // default 256; range 1..1024
      memoryBytes: number                // default 4 GiB; range 256 MiB..32 GiB, host-clamped
      cpuQuotaMicrosPerSecond: number    // default 400000; range 10000..1600000
      maxOpenFiles: number               // default 1024; range 64..8192
      maxSingleFileBytes: number         // default 2 GiB; range 1 MiB..16 GiB
      maxGenerationBytes: number         // default 20 GiB; range 256 MiB..100 GiB
      maxInvocationOutputBytes: number   // default 16 MiB; range 64 KiB..64 MiB
      maxIpcFrameBytes: number           // fixed 16 MiB
      maxQueuedIpcBytes: number          // fixed 64 MiB per Run
    }

    type SandboxProfileV1 = {
      schemaVersion: 1
      format: 'cliq-sandbox-profile-v1'
      backend: 'macos_vm' | 'linux_namespace'
      allowedOwners: Array<
        'worker_activation' | 'run_invocation' | 'admin_probe' | 'local_inference_service'
      >
      filesystemPolicy: 'typed_launch_spec_only'
      hostFilesystemReachability: 'none'
      networkAtSpawn: 'none'
      networkAfterRelease: 'typed_broker_only'
      credentialReachability: 'typed_broker_only'
      stateRootReachability: 'none'
      inheritedHostEnvironment: false
      resources: SandboxResourceSpec
      profileDigest: string
    }
    ```

   `profileDigest=SHA-256(JCS(profile with profileDigest omitted))`; `allowedOwners` is nonempty, unique, byte-sorted, and includes every launch owner using the profile. Admission selects the one probed strong backend, fills missing public resource values with the displayed defaults, fixes both IPC values, and rejects rather than raises a host-infeasible result. `RunSpec.sandboxProfileRef`, RunAssembly backend, every containment plan/launch ref+digest/backend, and the launch's inline `resources` all equal this artifact; admin/local-service producers use the same type with their exact owner set. Its fixed policies permit only a typed launch spec, no host filesystem/state-root/host-environment/network-at-spawn reachability, and typed-broker-only post-release network/credential access. No caller, worker, adapter, repository, or recovery path may increase/reinterpret/replace it. Values are safe integers; Linux enforces PID/memory/CPU/I/O with cgroup v2, `no_new_privs`, rlimits, namespace mounts, and quota-backed generation storage. macOS enforces the same guest-cgroup limits plus host VM memory/CPU/disk caps. PID/OOM/disk/output/IPC trips stop productive dispatch. They become positive infrastructure evidence only after the complete containment is dead and the generation is quiescent; until then the claimed attempt is `unknown`. Ordinary tools receive typed `RESOURCE_EXHAUSTED`; verifier classification remains work package 5. Output truncates only at its declared artifact boundary, never source/result state.

   macOS admission additionally freezes the signed content-addressed payload below. The signature covers canonical bytes with `signature` omitted and resolves only through the bundled Cliq release trust store; the CAS ref covers the complete signed bytes.

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

   `manifestDigest=SHA-256(JCS(manifest with manifestDigest and signatureRef omitted))`, and `signatureRef` verifies that digest only through the bundled Cliq release key. `guestImageRef` retains the complete immutable raw-ext4 bytes, `guestImageDigest` equals their SHA-256/ArtifactRef, and `guestImageByteCount` is their exact positive safe-integer length. Absolute guest paths/logical names are unique and bounded. Boot verifies image/signature/architecture/ABIs and each executable digest; `assemblyRef` plus the environment fingerprint bind the manifest. The containment plan, `SandboxRuntimeBindingV1`, actual containment, launch evidence, assembly GC, and reboot relaunch repeat and rehash the same retained image ref/digest; a digest-only reference or current installed-image lookup is invalid. Tools and verifiers resolve against guest Linux identity, never a host Mach-O path. Missing/host-only/incompatible native identities return `UNSUPPORTED_EXECUTION_IDENTITY` before admission, and host `node_modules` are never presumed usable. Dependency acquisition is only a separately granted, Journaled broker fetch of a locked digest into the private generation; the guest shell has no ambient network.

   Executable identity resolution accepts only the RFC-exact `AuthorizationGrantV1.target` union. For `execution_identity_read(purpose='verifier')`, the identity is either the exact signed `guest_toolchain` entry or an exact root-relative `workspace_script` with mandatory exact `InterpreterIdentityV1` ref+digest; a RuntimeBundle executable is invalid even if its digest is signed. The interpreter omission digest, retained guest-toolchain manifest, tool id/path/version/executable digest, and literal `script_path_as_first_argument-v1` protocol must match the consumed grant and later SandboxExecutable/VerifierCommand exactly. Shebang lookup, host PATH, ambient shell, caller-selected interpreter, or an optional/mismatched interpreter is unsupported. For `execution_identity_read(purpose='mcp_stdio')`, the identity is either the exact signed guest-toolchain entry or `runtime_bundle_executable`; the latter resolves against the retained signed RuntimeBundle manifest and is accepted only when the selected entry's signed role is exactly `mcp_server`. A Supervisor, worker, provider/tool adapter, policy engine, schema, platform helper, arbitrary host path, or workspace script cannot be selected for stdio MCP. Resolution/capture authority does not itself authorize execution: the eventual Run invocation still requires exact `OperationGrantV1` and both dispatch gates.

   The initial dependency boundary is deliberately Node-only. A candidate-specific execution plan has this exact shape:

    ```ts
    type DependencyAcquisitionPlanBase = {
      schemaVersion: 1
      format: 'cliq-dependency-acquisition-plan-v1'
      ecosystem: 'node'
      guestToolchainManifestRef: ArtifactRef
      packageManifest: {
        canonicalRootRelativePath: 'package.json'
        contentRef: ArtifactRef
        contentDigest: string
      }
      lockfileRef: ArtifactRef
      lockfileDigest: string
      registryEndpoints: Array<{
        endpointRegistrationRef: ArtifactRef
        endpointIdentityDigest: string
        tlsPolicyDigest: string
      }>
      credentialGrantRefs: ArtifactRef[]
      allowInstallScripts: boolean
      maxPackages: number
      maxDownloadBytes: number
      planDigest: string
    }

    type DependencyAcquisitionPlan = DependencyAcquisitionPlanBase & (
      | { adapter: 'npm-ci-v1'; lockfilePath: 'package-lock.json' }
      | { adapter: 'pnpm-frozen-v1'; lockfilePath: 'pnpm-lock.yaml' }
      | { adapter: 'yarn-immutable-v1'; lockfilePath: 'yarn.lock' }
    )

    type PackageCacheFetchAttemptV1 = {
      attempt: 1 | 2 | 3
      outcome: 'transport_failed' | 'http_error' | 'integrity_mismatch' | 'completed'
      httpStatus?: number
      receivedBytes: number
      observationDigest: string
    }

    type PackageCacheEntryV1 = {
      packageName: string
      packageVersion: string
      endpointRegistrationRef: ArtifactRef
      canonicalPackagePath: string
      integrityAlgorithm: 'sha256' | 'sha512'
      integrityDigest: string
      blobRef: ArtifactRef
      blobDigest: string
      blobBytes: number
      fetchAttempts: PackageCacheFetchAttemptV1[]
    }

    type PackageCacheManifestV1 = {
      schemaVersion: 1
      format: 'cliq-package-cache-manifest-v1'
      runId: string
      resultSourceRef: ArtifactRef
      dependencyPlanRef: ArtifactRef
      lockfileRef: ArtifactRef
      lockfileDigest: string
      entries: PackageCacheEntryV1[]
      packageCount: number
      totalTransferredBytes: number
      manifestDigest: string
      createdAt: string
    }

    type KernelIntegrityEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-kernel-integrity-evidence-v1'
      runId: string
      sourceProjectionRef: ArtifactRef
      workspaceGenerationRef: ArtifactRef
      inspectorIdentityRef: ArtifactRef
      inspectorIdentityDigest: string
      observedAt: string
      evidenceDigest: string
    } & (
      | {
          subjectKind: 'verifier'
          verifierOpId: string
          verifierAttempt: number
          resultSourceRef: ArtifactRef
          dependencyPlanRef?: never
          dependencyOpId?: never
          dependencyAttempt?: never
        }
      | {
          subjectKind: 'dependency_acquisition'
          dependencyPlanRef: ArtifactRef
          dependencyOpId: string
          dependencyAttempt: number
          verifierOpId?: never
          verifierAttempt?: never
          resultSourceRef?: never
        }
    ) & (
      | {
          observationKind: 'audited_write_attempt'
          processContainmentRef: ArtifactRef
          sandboxLaunchSpecRef: ArtifactRef
          operationRequestRef: ArtifactRef
          operationRequestDigest: string
          targetCanonicalRootRelativePath: string
          requestedAccess: 'create' | 'write' | 'truncate' | 'rename' | 'delete' | 'metadata_mutation'
          enforcementPoint: 'sandbox_filesystem' | 'trusted_broker'
          disposition: 'blocked_before_write'
          sourceBeforeRef: ArtifactRef
          sourceBeforeDigest: string
          sourceAfterRef: ArtifactRef
          sourceAfterDigest: string
          changedEntryDigests?: never
        }
      | ({
          observationKind: 'source_digest_drift'
          sourceBeforeRef: ArtifactRef
          sourceBeforeDigest: string
          sourceAfterRef: ArtifactRef
          sourceAfterDigest: string
          changedEntryDigests: string[]
          operationRequestRef?: never
          operationRequestDigest?: never
          targetCanonicalRootRelativePath?: never
          requestedAccess?: never
          enforcementPoint?: never
          disposition?: never
        } & (
          | {
              observationSource: 'trusted_out_of_containment_rehash'
              processContainmentRef?: never
              sandboxLaunchSpecRef?: never
            }
          | {
              observationSource: 'claimed_process_rehash'
              processContainmentRef: ArtifactRef
              sandboxLaunchSpecRef: ArtifactRef
            }
        ))
    )
    ```

   `RunSpec` freezes policy rather than an admission-time candidate plan:

    ```ts
    type DependencyPolicy = {
      schemaVersion: 1
      mode: 'none' | 'locked_node'
      allowedAdapters: Array<DependencyAcquisitionPlan['adapter']>
      registryEndpoints: Array<{
        endpointRegistrationRef: ArtifactRef
        endpointIdentityDigest: string
        tlsPolicyDigest: string
      }>
      credentialGrantRefs: ArtifactRef[]
      installScriptsPolicy: 'deny' | 'exact_lockfile_grant'
      installScriptsGrantRef?: ArtifactRef
      maxPackages: number
      maxDownloadBytes: number
    }
    ```

   `run.submit dependency.mode='locked'` resolves public endpoint/credential ids to immutable registration/grant refs, freezes canonical HTTPS endpoint and TLS-policy digests plus exact authority/service revision, secret generation, and external subject, and accepts exactly literal root `package.json` plus exactly one literal root lockfile and a compatible pinned guest package manager. `packageManifest.contentRef/contentDigest` and the lockfile ref/digest rehash those exact candidate `SourceManifest` entries. `package-lock.json` selects only `npm-ci-v1`; `pnpm-lock.yaml` only `pnpm-frozen-v1`; `yarn.lock` only `yarn-immutable-v1`. A `workspaces` member, nested package manifest or lockfile, second supported root lockfile, adapter/path mismatch, missing integrity, ambiguity, unlocked resolution, unsupported layout, or target mismatch fails before any package-manager process. `planDigest=SHA-256(JCS(plan with planDigest omitted))`. Re-registering an id cannot redirect an accepted Run; each FinalCandidate plan copies the frozen byte-sorted endpoint/grant projection unchanged and the broker redeems only the exact still-current frozen-generation item against that target. Rotation or subject drift returns authorization-required before I/O. Trusted code derives a fresh plan from that candidate's source/package manifest/lockfile under the policy and binds it into `VerifierPlan`; it never installs an admission-time plan against changed candidate bytes.

   If install scripts are admitted, the admission transaction consumes the exact active `AuthorizationGrantV1` whose target is `dependency_install_scripts` for the identical workspace/lockfile path/digest and publishes the RFC-exact `DependencyInstallScriptsAuthorizationTemplateV1`; `DependencyPolicy.installScriptsGrantRef` names only that template, never the user authorization row. The template must repeat the exact source receipt, guest toolchain, allowed adapters, lockfile ref/path/digest, registry-target digest, `maxCandidateGenerations = RunSpec.budgets.repairAttempts + 1`, `maxDispatchedAttemptsPerPlan=1`, and `expiresAt=Run.deadlineAt`. Every script-bearing candidate's `OperationGrantV1` uses only `provenance.kind='dependency_install_scripts_template'`, matches that policy/template/plan, and consumes one previously unused candidate ordinal in `0..maxCandidateGenerations-1`; there is no resettable counter. A changed lock digest, registry projection, toolchain, adapter, policy, or exhausted ordinal cannot reuse the template: scripts remain denied until an exact new candidate approval path exists, or fail in noninteractive deny mode.

   Defaults/maxima are 50,000/200,000 packages and 5/20 GiB download. Repository registry configuration supplies declarative endpoints only. The trusted broker fetches only HTTPS lockfile URL+integrity artifacts into CAS and may retry only the bounded integrity-GET exception, then the bundled adapter performs a networkless frozen-lockfile install in the private generation. Install scripts execute integrity-pinned package code inside the same secretless/networkless strong containment without host access.

   Acquisition is one built-in `opKind='tool'`, target `builtin:dependency-acquire`, `ReplayClass='workspace-rollback-retry'`, one tool-call reservation, and a request digest covering the whole plan. Throughout fetch/install/script execution, the exact candidate source projection is read-only; only disjoint plan-declared dependency, cache, and temporary roots are writable. Before completion, Cliq recomputes the candidate `resultSourceRef` under the frozen `sourceProjectionRef` and requires exact equality with the verify frontier's pre-acquisition `resultSourceRef`.

   A detected/audited source-write attempt or digest drift first publishes exact `KernelIntegrityEvidenceV1(subjectKind='dependency_acquisition')`. Its omission digest, Run/projection/generation/current inspector, dependency plan/op/attempt, and Journal/RunSpec identities match. `audited_write_attempt` may originate only at the strong sandbox-filesystem or trusted-broker blocked boundary, repeats the exact request/containment/SandboxLaunch/canonical target/access/enforcement point, and proves identical before/after source refs+digests. `source_digest_drift` rehashes unequal exact SourceManifests and a nonempty unique byte-sorted changed-entry-digest set; `observationSource='trusted_out_of_containment_rehash'` forbids containment/spec, while `claimed_process_rehash` requires both and they must equal the owning claim. The Supervisor then terminates/proves death, quarantines the generation, and publishes StopIntent `origin='kernel_integrity', reason='runtime_failed', source='dependency_acquisition'` whose branch `integrityEvidenceRef` and digest name that artifact; `StopIntentBase` has no generic evidence ref, and terminal primary evidence uses this branch ref. Dependency completion/readiness, generic CAS/text/adapter assertions, or a caught unaudited read-only error are forbidden. Partial downloads are unreachable CAS orphans; a partial install quarantines/discards that generation. Only an unchanged candidate may atomically publish exact `DependencyReadyItem`, post-effect ready Checkpoint, budget settlement, and `phase='verifiers'`. Its `planRef/opId/attempt/packageCacheManifestRef` equal the current plan and completed acquisition Journal; the cache ref decodes exact `PackageCacheManifestV1`, whose digest omits itself, decoded lockfile yields exactly the byte-sorted package/version/endpoint/path/integrity entries, every blob rehashes, attempts are contiguous 1..3 and finish completed, and count/total-transfer equations obey plan bounds. `readyCheckpointId` equals the same-transaction ready Checkpoint containing the item and completed Journal sequence. That Checkpoint's `workspaceStateRef` decodes exact `WorkspaceStateManifest`, its `entriesRef` decodes exact `WorkspaceEntryManifest`, and the item's `installedTreeDigest` equals that manifest's `treeDigest`. A pre-effect/independent Checkpoint or caller-supplied tree digest cannot establish readiness. Other ecosystems and unlocked/networked package-manager execution are rejected rather than hidden inside Bash.

2. **Probe before admission.** A backend probe runs an actual deny/allow and descendant-containment self-test, not a binary-presence check. Both strong backends must prove: generation write succeeds; real-workspace and Cliq-state read/write fail; undeclared home read fails; direct network fails; fork/daemon escape fails; full descendant enumeration works; forced termination yields an empty boundary; and the pinned worker plus every selected runtime/tool/verifier executable resolves to its exact signed identity. Linux additionally proves PID namespace, cgroup v2 ownership/freezing/killing, and subreaper behavior. macOS additionally verifies helper signature, guest-image digest/signature, authenticated guest boot identity, no writable host share, and VM stop evidence. Cache a successful probe only for the Supervisor process lifetime and invalidate it after backend/helper/image/executable change.

   `RunAssemblyV1.sandboxBackend` is a closed `macos_vm|linux_namespace` union. Without the selected complete backend, worker identity, or pinned-executable probes, every `run.submit|run.apply` fails before Run/control success with exact `UNSUPPORTED_PLATFORM` or `UNSUPPORTED_EXECUTION_IDENTITY`. Read-only intent, text-only provider mode, empty tool set, no required verifier, and non-Git source never authorize workerless or weak admission. Seatbelt inspection is outside the Run state machine and cannot create RunSpec, Checkpoint, WorkerLaunch, Journal, result, or event truth.

   A non-Git root is captured under the same root-relative `SourceProjectionSpec`, restored into the same strong private generation, and checked through the same worker/claim/Checkpoint lifecycle. Its `WorkspaceStateManifest.privateGitStateRef` is absent; no code invents a repository identity or `.git`, and no non-Git condition selects a weaker containment/profile/mount/network/permission path.

   `SourceProjectionSpec.schemaVersion` is literal `1`, `projectionDigest` omits itself under JCS, and SourceManifest/WorkspaceState projection values decode/repeat it. Its frozen-ignore ref/digest decodes only canonical `FrozenIgnoreRulesV1`: repository-bound or canonical non-Git empty form; descriptor-held `.git/info/exclude` then root-to-deep/path-ordered `.gitignore` sources; exact UTF-8 content refs/digests; contiguous parsed `cliq-git-wildmatch-v1` rules; ancestor-base applicability and last-match wins. Mutable files/ambient Git are never reread on recovery. Every `explicitIncludes[].authorizationRef` decodes only canonical `SourceIncludeAuthorizationV1`. Its principal/Run/Session/live workspace/selector/admission-intent fields and omission-rule digest must match admission. The builtin branch is legal only with the exact `SourceIncludeClassificationEvidenceV1` ref/digest: unique byte-sorted descriptor observations exactly cover the selected captured entries, each WorkspaceEntry digest/device/file/link identity matches the later SourceManifest, and each entry is proven either tracked by the identical retained Git index or nonignored by the frozen rules. An ignored selector requires the exact principal/workspace/path/scope `read_scope` grant and matching `AuthorizationConsumptionReceiptV1(run_admission)` whose consumer binds the same Run and pre-resolution `admissionIntentDigest`, never the final admitted digest. Consume/receipt/final-digest/projection/Run/Checkpoint/control response commit atomically. Missing/unnecessary/mismatched grants, cross-Run refs, and outside-root selectors fail rather than falling through.

3. **Capture one authoritative base manifest.** Before reading source, decode the Session's exact `WorkspaceIdentityV1` and require `kind='live'`; `legacy_unavailable` and every fork retaining it are context-only and cannot enter capture/admission/apply. Descriptor-walk `canonicalRootPath` without symlinks and require the same principal/platform/owner/device/file tuple. `rootIdentity.deviceId/fileId` are compared as canonical unsigned decimal strings and never converted through JS number; `ownerUid` is a safe integer. For Git, decode the exact `RepositoryIdentityV1`, require workspace ref+digest together, open literal in-root directory `.git` from the held root, and match its owner/device/file plus normalized `sha1|sha256` object format; `.git` file/link/outside/linked forms are rejected. Non-Git requires both repository fields absent. `run.submit.workspacePath` must descriptor-resolve to this same live identity. `run.apply` accepts no path and derives/reopens the source Run's live Session root. Root/`.git` move or replacement or any workspace/repository digest mismatch returns `ARTIFACT_MISMATCH`, creates no Run/effect, and requires a new Session.

   For Git, use NUL-safe plumbing plus `lstat`/content hashing to record repository identity, `HEAD`, index identity, every tracked working-tree byte (including dirty files), ordinary non-ignored untracked files, symlink targets without following them, executable bits, and configured root-relative explicit includes. Descriptor-read `.git/config` only to publish the exact closed artifact below; any unrecognized key rejects capture rather than being copied or interpreted:

    ```ts
    type GitIndexSnapshotV1 = {
      schemaVersion: 1
      format: 'cliq-git-index-snapshot-v1'
      repositoryIdentityDigest: string
      objectFormat: 'sha1' | 'sha256'
      canonicalIndexVersion: 2
      entries: Array<{
        canonicalRootRelativePath: string
        stage: 0
        mode: 33188 | 33261 | 40960
        objectId: string
        assumeValid: boolean
        skipWorktree: false
      }>
      canonicalIndexBytesRef: ArtifactRef
      canonicalIndexBytesDigest: string
      canonicalIndexByteCount: number
      indexTreeObjectId: string
      snapshotDigest: string
    }

    type GitObjectPackV1 = {
      schemaVersion: 1
      format: 'cliq-git-object-pack-v1'
      objectFormat: 'sha1' | 'sha256'
      packBytesRef: ArtifactRef
      packBytesDigest: string
      packByteCount: number
      packTrailerObjectHash: string
      packIndexBytesRef: ArtifactRef
      packIndexBytesDigest: string
      packIndexByteCount: number
      packIndexVersion: 2
      objectCount: number
      objectIds: string[]
      packDigest: string
    }

    type GitObjectClosureV1 = {
      schemaVersion: 1
      format: 'cliq-git-object-closure-v1'
      repositoryIdentityDigest: string
      objectFormat: 'sha1' | 'sha256'
      packs: Array<{
        packRef: ArtifactRef
        packDigest: string
        packTrailerObjectHash: string
      }>
      reachableObjectIds: string[]
      closureDigest: string
    }

    type SanitizedGitConfigV1 = {
      schemaVersion: 1
      format: 'cliq-sanitized-git-config-v1'
      core: {
        repositoryFormatVersion: 0 | 1
        fileMode: boolean
        bare: false
        logAllRefUpdates?: boolean
        ignoreCase?: boolean
        precomposeUnicode?: boolean
      }
      extensions?: {
        objectFormat: 'sha1' | 'sha256'
      }
      configDigest: string
    }

    type PrivateGitStateManifest = {
      schemaVersion: 1
      format: 'cliq-private-git-v1'
      head: { kind: 'unborn'; branch: string } | { kind: 'symbolic'; ref: string } | { kind: 'detached'; objectId: string }
      indexRef: ArtifactRef
      refs: Array<{ name: string; objectId: string }>
      objectClosureRef: ArtifactRef
      objectClosureDigest: string
      sanitizedConfigRef: ArtifactRef
      sanitizedConfigDigest: string
      manifestDigest: string
    }
    ```

   `configDigest` and `manifestDigest` omit only themselves under JCS; the manifest ref/digest rehashes that exact config. Only the displayed non-executable repository/object-format literals and booleans are legal. Every other Git key is absent, including hooks, remotes, credentials, `include`/`includeIf`, helpers, aliases, pagers, filters/process helpers, attributes/diff/merge drivers, `core.fsmonitor`, `core.sshCommand`, worktree paths, external `core.excludesFile`/`core.attributesFile`, and environment-driven configuration. Trusted startup supplies the private generation paths, explicitly disables system/global/environment config, and never copies repository/user config. Invoke only allowlisted read-only plumbing with explicit `GIT_DIR`/`GIT_WORK_TREE`, sanitized `HOME`, no optional locks, and no network/helper/hook/filter/fsmonitor/attribute/external-excludes processing. Read source bytes directly through held descriptors rather than any clean/smudge filter. Frozen ignore rules come only from descriptor-validated in-root `.git/info/exclude` and `.gitignore`; an external path is rejected before its target is opened or read, and no authorization can convert it into an admitted input. Non-Git capture uses the same no-follow root-relative projection with no repository/index/private-Git identity. In both branches every `workspaceIdentityDigest` equals the Session artifact. Revalidate root identity, `HEAD`/index/config when present, every in-root ignore source, authorization, and captured path after hashing; retry a bounded three times and return closed `RECOVERY_REQUIRED` with redacted `workspace_changed_during_admission` detail if a stable manifest cannot be observed.

   Manifest production uses only the canonical acyclic equations. For `WorkspaceEntryManifest`, counts equal the exact entry array and checked file-size-plus-symlink-UTF-8 sum, while `treeDigest=SHA-256(JCS({schemaVersion:1,format:'cliq-workspace-entries-v1',entries}))`. `SourceManifest.treeDigest` equals that decoded entry manifest and `manifestDigest=SHA-256(JCS(SourceManifest with manifestDigest omitted))`; Git presence equals the retained repository identity. Every Git index ref decodes exact `GitIndexSnapshotV1`: the held input parser accepts only versions 2/3/4 after checksum/full parse, rejects unmerged/gitlink/intent-to-add/any skip-worktree/split/sparse/unknown-mandatory/path-invalid/missing-object state, then fixed `cliq-git-index-normalize-v1` emits exact extension-free version-2 bytes with `skipWorktree:false`, zeroed stat fields, canonical path padding, and the declared checksum. `snapshotDigest` omits itself and the retained bytes/ref/count/tree/object-format/repository identity all revalidate. Every `GitObjectPackV1` rehashes exact pack/index-v2 bytes/counts and fixed trusted `index-pack` proves trailer, object hashes, delta closure, exact deterministic index, and unique byte-sorted object ids. `GitObjectClosureV1` has unique byte-sorted pack tuples, omission digest, and a reachable-object set equal to the disjoint union of every pack's object ids: no required object is missing and no unreachable object is retained. `PrivateGitStateManifest` revalidates exact Head/index, unique byte-sorted refs, that one exact object-closure pair, and the exact `SanitizedGitConfigV1` pair. `WorkspaceStateManifest` independently references the complete entry manifest and exact base SourceManifest, matches source projection, carries that private Git state iff Git, validates byte-sorted unique disjoint invalidated paths, and uses `stateDigest=SHA-256(JCS(WorkspaceStateManifest with stateDigest omitted))`. No digest includes itself or points cyclically back through a referenced manifest.

4. **Fail specifically on unsupported Git states.** The initial Kernel Cut rejects every Gitlink/submodule and Git LFS-filtered path, plus nested repositories, sockets/FIFOs/devices, case/path identities that cannot be represented on the host filesystem, and symlink or explicit-include escapes. The error identifies the path and reason. Ordinary hardlinked inputs are captured as independent regular-file bytes; hardlink identity, xattrs, ACLs, ownership, and timestamps are not source/result semantics. Capture must not run `git add`, alter the index, create a commit, or write repository metadata.

5. **Make the generation genuinely independent.** The generation's Git common directory resolves inside that generation. It has no alternates, linked-worktree metadata, symlink/bind mount to the source `.git`, or hard-linked writable files/objects. APFS clonefile, reflink, and CAS deduplication are allowed host-side materialization optimizations; byte copy is the portable fallback. A macOS generation is then copied into its VM-owned disk rather than exposed as writable virtiofs. A verification pass proves these invariants before preactivation.

6. **Persist whole-descendant containment identity.** `ProcessContainmentRef` is an immutable `ArtifactRef` to this minimum contract:

    ```ts
    type ProcessContainmentOwner =
      | {
          kind: 'worker_activation'
          runId: string
          intendedLeaseEpoch: number
          workerLaunchId: string
        }
      | {
          kind: 'run_invocation'
          runId: string
          intendedLeaseEpoch: number
          workerLaunchId: string
          opId: string
          attempt: number
          dispatchId: string
        }
      | {
          kind: 'admin_probe'
          adminOperationId: string
          attempt: number
          principalId: string
          method: 'mcp.register' | 'mcp.refresh'
          originalRequestDigest: string
          targetRef: ArtifactRef
          supervisorInstanceId: string
        }
      | {
          kind: 'local_inference_service'
          serviceId: string
          serviceLaunchId: string
          ownerPrincipalId: string
          serviceSpecRef: ArtifactRef
          supervisorInstanceId: string
        }

    type SandboxRootImageV1 = {
      schemaVersion: 1
      format: 'cliq-sandbox-root-image-v1'
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      entryId: string
      entryVersion: string
      entryDigest: string
      protocol: 'cliq-fresh-empty-root-v1'
      filesystemKind: 'fresh_ephemeral_tmpfs'
      fixedDirectories: ['/home/cliq', '/tmp', '/work']
      ownerUid: number
      persistent: false
      networkConfiguration: 'none'
      imageDigest: string
    }

    type ProcessContainmentPlanV1 = {
      schemaVersion: 1
      format: 'cliq-process-containment-plan-v1'
      owner: ProcessContainmentOwner
      filesystemBinding:
        | { kind: 'run-generation'; generationRef: ArtifactRef }
        | { kind: 'isolated-empty-root'; rootImageRef: ArtifactRef; rootImageDigest: string }
      parentContainmentRef?: ArtifactRef
      launchNonceDigest: string
      backend:
        | {
            kind: 'linux'
            cgroupPath: string
            cgroupNameReservationDigest: string
            pidNamespaceReservationId: string
            subreaperStartToken: string
          }
        | {
            kind: 'macos-vm'
            vmReservationId: string
            guestImageRef: ArtifactRef
            guestImageDigest: string
            guestBootNonceDigest: string
          }
      createdAt: string
      planDigest: string
    }

    type ProcessContainment = {
      schemaVersion: 1
      planRef: ArtifactRef
      sandboxLaunchSpecRef: ArtifactRef
      sandboxLaunchSpecDigest: string
      owner: ProcessContainmentOwner
      filesystemBinding:
        | { kind: 'run-generation'; generationRef: ArtifactRef }
        | { kind: 'isolated-empty-root'; rootImageRef: ArtifactRef; rootImageDigest: string }
      parentContainmentRef?: ArtifactRef
      launchNonceDigest: string
      backend:
        | {
            kind: 'linux'
            pidNamespaceReservationId: string
            pidNamespaceId: string
            cgroupPath: string
            cgroupId: string
            namespaceInitStartToken: string
            subreaperStartToken: string
          }
        | {
            kind: 'macos-vm'
            vmReservationId: string
            vmInstanceId: string
            vmProcessStartToken: string
            guestBootId: string
            guestImageRef: ArtifactRef
            guestImageDigest: string
          }
      createdAt: string
    }

    type PlatformProcessIdentityV1 = {
      schemaVersion: 1
      format: 'cliq-platform-process-identity-v1'
      platform: 'linux' | 'macos'
      pid: number
      processStartToken: string
      ownerUid: number
      executableImageDigest: string
      observedAt: string
      identityDigest: string
    }

    type StateRootIdentityV1 = {
      schemaVersion: 1
      format: 'cliq-state-root-identity-v1'
      platform: 'linux' | 'macos'
      canonicalAbsolutePath: string
      ownerUid: number
      deviceId: string
      directoryFileId: string
      mode: 448
      openedNoFollow: true
      layoutVersion: 1
      identityDigest: string
    }

    type StateLockIdentityV1 = {
      schemaVersion: 1
      format: 'cliq-state-lock-identity-v1'
      stateRootIdentityRef: ArtifactRef
      stateRootIdentityDigest: string
      canonicalRootRelativePath: 'runtime/state-owner.lock'
      deviceId: string
      fileId: string
      ownerUid: number
      mode: 384
      linkCount: 1
      identityDigest: string
    }

    type StateOwnerTransitionEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-state-owner-transition-evidence-v1'
      priorOwnerEpoch: number
      priorSupervisorInstanceId: string
      priorProcessIdentityRef: ArtifactRef
      priorProcessIdentityDigest: string
      stateLockIdentityRef: ArtifactRef
      stateLockIdentityDigest: string
      observedAt: string
      evidenceDigest: string
    } & (
      | {
          kind: 'graceful_release'
          releasingProcessIdentityRef: ArtifactRef
          releasingProcessIdentityDigest: string
        }
      | {
          kind: 'superseded_after_owner_death'
          priorProcessObservation: 'absent_or_start_token_mismatch'
          successorOwnerEpoch: number
          successorSupervisorInstanceId: string
          successorRuntimeBundleRef: ArtifactRef
          successorRuntimeBundleManifestDigest: string
          successorProcessIdentityRef: ArtifactRef
          successorProcessIdentityDigest: string
          successorInstanceNonceDigest: string
      }
    )

    type StateOwnerAcquisitionEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-state-owner-acquisition-evidence-v1'
      ownerEpoch: number
      supervisorInstanceId: string
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      processIdentityRef: ArtifactRef
      processIdentityDigest: string
      stateLockIdentityRef: ArtifactRef
      stateLockIdentityDigest: string
      instanceNonceDigest: string
      acquiredAt: string
      evidenceDigest: string
    } & (
      | {
          kind: 'genesis'
          kernelGenerationIdentityRef: ArtifactRef
          kernelGenerationIdentityDigest: string
          ownerTableObservation: 'empty'
          priorOwnerEpoch?: never
          priorTerminalRowDigest?: never
          priorTransitionEvidenceRef?: never
          priorTransitionEvidenceDigest?: never
        }
      | {
          kind: 'acquire_after_graceful_release'
          priorOwnerEpoch: number
          priorTerminalRowDigest: string
          priorTransitionEvidenceRef: ArtifactRef
          priorTransitionEvidenceDigest: string
          priorTerminalReason: 'graceful_release'
          kernelGenerationIdentityRef?: never
          kernelGenerationIdentityDigest?: never
          ownerTableObservation?: never
        }
      | {
          kind: 'takeover_after_owner_death'
          priorOwnerEpoch: number
          priorTerminalRowDigest: string
          priorTransitionEvidenceRef: ArtifactRef
          priorTransitionEvidenceDigest: string
          priorTerminalReason: 'superseded_after_owner_death'
          kernelGenerationIdentityRef?: never
          kernelGenerationIdentityDigest?: never
          ownerTableObservation?: never
        }
    )

    type StateOwnerRecordV1 = {
      schemaVersion: 1
      ownerEpoch: number
      supervisorInstanceId: string
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      supervisorEntryId: string
      supervisorEntryVersion: string
      supervisorExecutableDigest: string
      processIdentityRef: ArtifactRef
      processIdentityDigest: string
      stateLockIdentityRef: ArtifactRef
      stateLockIdentityDigest: string
      acquisitionEvidenceRef: ArtifactRef
      acquisitionEvidenceDigest: string
      instanceNonceDigest: string
      acquiredAt: string
      rowDigest: string
    } & (
      | {
          state: 'active'
          rowVersion: 1
          releasedAt?: never
          terminalReason?: never
          transitionEvidenceRef?: never
          transitionEvidenceDigest?: never
        }
      | {
          state: 'terminal'
          rowVersion: 2
          releasedAt: string
          terminalReason: 'graceful_release' | 'superseded_after_owner_death'
          transitionEvidenceRef: ArtifactRef
          transitionEvidenceDigest: string
        }
    )

    type SupervisorInspectorIdentityV1 = {
      schemaVersion: 1
      format: 'cliq-supervisor-inspector-identity-v1'
      supervisorInstanceId: string
      stateOwnerEpoch: number
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      supervisorEntryId: string
      supervisorEntryVersion: string
      supervisorExecutableDigest: string
      processIdentityRef: ArtifactRef
      processIdentityDigest: string
      stateLockIdentityRef: ArtifactRef
      stateLockIdentityDigest: string
      instanceNonceDigest: string
      activatedAt: string
      identityDigest: string
    }

    type ProcessContainmentNoSpawnEvidenceV1 = {
      schemaVersion: 1
      kind: 'containment_plan_quiescent'
      planRef: ArtifactRef
      sandboxLaunchSpecRef: ArtifactRef
      sandboxLaunchSpecDigest: string
      owner: ProcessContainmentOwner
      launchNonceDigest: string
      inspectorSupervisorInstanceId: string
      inspectorIdentityRef: ArtifactRef
      inspectorIdentityDigest: string
      backend:
        | {
            kind: 'linux'
            cgroupPath: string
            cgroupObservation:
              | { kind: 'absent' }
              | { kind: 'empty'; cgroupId: string; populated: 0 }
            pidNamespaceObservation:
              | { kind: 'never_created'; pidNamespaceReservationId: string }
              | { kind: 'dead_reaped'; pidNamespaceReservationId: string; namespaceInitStartToken: string }
            subreaperStartToken: string
            matchingLaunchNonceProcessCount: 0
          }
        | {
            kind: 'macos-vm'
            vmReservationId: string
            vmObservation:
              | { kind: 'never_created' }
              | {
                  kind: 'stopped_reaped'
                  vmInstanceId: string
                  vmProcessStartToken: string
                  guestBootId?: string
                }
            matchingLaunchNonceProcessCount: 0
          }
      observedAt: string
      evidenceDigest: string
    }

    type ProcessContainmentDeathEvidenceV1 = {
      schemaVersion: 1
      kind: 'containment_all_descendants_dead'
      containmentRef: ArtifactRef
      planRef: ArtifactRef
      sandboxLaunchSpecRef: ArtifactRef
      sandboxLaunchSpecDigest: string
      owner: ProcessContainmentOwner
      launchNonceDigest: string
      inspectorSupervisorInstanceId: string
      inspectorIdentityRef: ArtifactRef
      inspectorIdentityDigest: string
      backend:
        | {
            kind: 'linux'
            pidNamespaceReservationId: string
            pidNamespaceId: string
            cgroupPath: string
            cgroupId: string
            cgroupPopulated: 0
            namespaceInitStartToken: string
            namespaceInitDeadAndReaped: true
            subreaperStartToken: string
            remainingTrackedDescendants: 0
          }
        | {
            kind: 'macos-vm'
            vmReservationId: string
            vmInstanceId: string
            vmProcessStartToken: string
            vmProcessDeadAndReaped: true
            guestBootId: string
            guestRetired: true
          }
      observedAt: string
      evidenceDigest: string
    }

    type ProcessContainmentRef = ArtifactRef
    ```

   The reference identifies an enforced descendant closure, not a census taken at launch. Owner and filesystem/parent shape form an exact XOR matrix: `worker_activation` has `filesystemBinding.kind='run-generation'` and no parent; `run_invocation` has a mandatory parent whose verified chain terminates at the exact same Run/epoch/`workerLaunchId` activation, and its filesystem binding must equal the frozen invocation contract; `admin_probe` and `local_inference_service` are top-level, `isolated-empty-root`, and have no parent. A run invocation additionally matches the exact durable `dispatch_claimed` `opId/attempt/dispatchId`. A `WorkerIdentity` binds only an exact `worker_activation` containment matching its Run/epoch/launch; worker identity alone is never death proof. An admin containment matches the active AdminOperation's operation/attempt/principal/method/`requestDigest` as `originalRequestDigest`/target/Supervisor, and a local-service containment matches the exact owner/principal/service launch/spec/Supervisor. Closed decoding rejects every cross-owner Run/epoch/worker/generation/admin/service field.

   Every `containmentPlanRef` resolves to the exact plan above and every actual containment repeats its plan owner/filesystem/parent/nonce plus `sandboxLaunchSpecRef`/digest and backend reservation/locator identity. `SandboxRootImageV1.imageDigest` omits itself; its ref/digest resolves one non-executable signed RuntimeBundle `sandbox_root_profile` entry by exact id/version/digest. Fixed Supervisor code materializes a fresh ephemeral tmpfs root with exactly `/home/cliq`, `/tmp`, and `/work`, owner-only identity, no device/socket/network state, and no persistent bytes. Plan, launch filesystem, and actual containment repeat that same root-image ref/digest. A host directory, mutable image, caller-selected/reused writable root, missing digest, or merely empty-looking path is invalid. Pre-spawn recovery accepts only the exact plan-quiescent evidence union repeating that launch ref/digest; post-spawn retirement/Checkpoint/receipt accepts only the exact all-descendants-dead union repeating it. `PlatformProcessIdentityV1.identityDigest`, `StateRootIdentityV1.identityDigest`, and `StateLockIdentityV1.identityDigest` each omit themselves under JCS. Process identity is a bounded current platform observation with positive safe-integer PID, NFC-ASCII native start token, same-user uid, and executable-image digest equal to the selected signed Supervisor entry. State-root identity is produced only by component-wise no-follow opening of the configured absolute root and `fstat` of the held same-user `0700` directory descriptor; its NFC path has no dot/parent/empty component, device/directory-file ids are unsigned decimal strings, owner equals effective uid, and replacement/rename/owner/mode/descriptor-path disagreement blocks authority. Lock identity comes only from `fstat` of the held no-follow same-user regular `${stateRoot}/runtime/state-owner.lock` descriptor; its state-root ref+digest equal that held parent descriptor and it binds the literal relative path, unsigned-decimal device/file ids, uid, literal `0600`, and link count one. Caller paths, PID without start token, a root reopened by path after validation, or a reopened/replaced lock are invalid.

   `state_owners` stores only exact `StateOwnerRecordV1`: epochs are positive, unique, contiguous, strictly increasing, and row digests recompute. Every identity/acquisition ref+digest closed-decodes exactly. `genesis` is epoch one for an empty owner table and one exact as-yet-unowned `KernelGenerationIdentityV1`: `fresh_empty` validates the fixed empty database/CAS closure; `migrated_candidate` validates the matching durable Kernel authority marker plus exact candidate/database-image/CAS/migration closure and is legal only as the first Kernel repository transaction after cutover. Clean acquisition requires the latest graceful terminal row/evidence; death takeover atomically terminalizes the active predecessor and appends the evidence-matched successor.

   The universal state-owner gate has exactly three narrow acquisition entrypoints while holding/revalidating decoded root/lock descriptors. `bootstrapStateOwner` registers only staged identity/acquisition metadata plus active epoch one for the exact selected fresh or migrated generation under the rules above. `acquireStateOwnerAfterGracefulRelease` registers only new process/acquisition metadata plus `n+1`; `takeoverStateOwner` registers transition/new-process/acquisition metadata and atomically terminalizes+appends. These transactions cannot mutate Run/Session/Journal/broker state or release capability; every other repository write needs an active owner. Staged bytes remain unrooted until commit.

   Every terminal transition references exact `StateOwnerTransitionEvidenceV1`, with its omission digest and prior epoch/instance/process/lock equal to the active row. While holding the same OS lock, `superseded_after_owner_death` requires bounded inspection of the decoded prior PID/start-token identity as absent or mismatched; its successor epoch/instance/bundle/process/nonce equal the acquisition evidence and active row appended in the same transaction under the same root/lock. Graceful evidence repeats the owner's own process identity, terminalizes only itself, appends no successor, then releases that exact descriptor lock; a later clean startup uses only `acquire_after_graceful_release`. Terminal reason and evidence kind match. At most one active row exists; only its decoded process while holding its decoded root/lock may write authority or release broker capability. Lock loss or row mismatch gates every write immediately. Epochs are never reset/reused; acquisition/transition/rows and all referenced identity/bundle artifacts remain GC roots.

   Every `inspectorIdentityRef` decodes only as the exact `SupervisorInspectorIdentityV1`, with `identityDigest=SHA-256(JCS(identity with identityDigest omitted))`, and each evidence artifact repeats that digest. Its referenced signed RuntimeBundle manifest must rehash to the named ref/digest and contain exactly the named executable entry with role `supervisor` and matching entry version/executable digest. `supervisorInstanceId`, current `stateOwnerEpoch`, RuntimeBundle/entry, exact process identity, exact lock identity, and instance nonce must equal the sole active `StateOwnerRecordV1` held continuously through evidence inspection and commit. The Supervisor publishes this identity only after that active row commits while its exact process holds its exact descriptor lock; an ownership change makes it historical and unable to justify any later observation. Evidence digests omit themselves under JCS, `inspectorSupervisorInstanceId` equals both the current state-owning Supervisor and the decoded identity, and observation freshness is bounded to default/max five seconds. The original spawner remains checked independently through the immutable plan owner/worker/admin/local-service launch/nonces. Linux requires absent/empty cgroup plus never-created-or-dead/reaped namespace and zero nonce-matching processes, or for actual death exact cgroup populated zero plus namespace-init/subreaper descendant closure. macOS requires the exact reservation/VM/process/guest identities and never-created or stopped/reaped/retired state. A PID exit, timeout, stale inspector identity, mismatched signed bundle/state owner, or receipt for another plan/spec, activation, invocation, admin operation, or local service is never proof.

7. **Keep preactivation powerless.** This package first artifact-publishes the fresh `WorkspaceGenerationIdentityV1`, inserts its durable `workspace_generations.phase='materializing'` row, materializes and verifies the read-only generation, publishes exact snapshot evidence, and CASes it to `preactivated_readonly` with the deterministic containment plan. Work package 4 then persists the sole `worker_launches` row in `reserved` before any process/VM exists; only afterward may this package create the containment, move the row to `preactivated`, and expose a one-purpose blocked activation channel. Before the authoritative `queued -> running` activation transaction commits both launch and generation rows, the worker/guest has no broker credential, no writable generation capability, no network, no provider/MCP handle, and no path to request a sandbox or child launch. The Supervisor records the inspected identity and `ProcessContainmentRef` on that exact row, then sends a single-use activation capability bound to the committed Run revision, lease epoch, `launchId`, worker identity digest, `supervisorInstanceId`, containment, generation, and expiry. Losing or rejecting the activation handshake terminates/proves the full descendant closure dead and quarantines the generation with the exact reason-matched artifact before another launch/generation may be reserved. A successor Supervisor can never complete or adopt that old handshake, even if its lease would otherwise remain live.

   MCP registration/refresh preactivation is a separate admin path. Work package 1 persists `AdminOperation.phase='prepared'`; this package materializes only an isolated empty-root `admin_probe` containment, and the Supervisor records the exact inspected containment by the row-version-CAS `prepared -> active` transition with `probeDispatch={state:'blocked'}` before releasing any probe capability. It never creates a `worker_launches` row, Run lease, generation, Journal attempt, Run reservation, or frontier. Before `active/blocked`, both stdio and HTTP probes have zero executable/network/broker/credential authority. A stdio probe remains secretless and networkless; an HTTP probe receives only the later canonical admin broker capability, never credential bytes. Failed preactivation requires positive no-spawn/empty-planned-containment evidence, and no successor adopts an old admin containment.

   Managed local inference is a fourth, non-Run preactivation path. Work package 1 first persists exact `LocalInferenceServiceLaunchV1.phase='reserved'` with its immutable `LocalInferenceServiceSpecV1`, `activationCycleId`, `activationAttempt: 1|2`, containment plan, and `SandboxLaunchSpecV1.local_inference_service`; the exact owning `LocalInferenceActivationCycleV1` must currently name that launch/attempt/service/spec. This package validates that equality but never creates/joins a participant, chooses an ordinal, advances retry time, fans out a cycle, or invents attempt 3. It creates only the named isolated-empty-root strong containment, signed RuntimeBundle `local_inference` executable, signed model mount, loopback endpoint, fixed recipe, bounded resources, and secretless/external-networkless environment, then records `preactivated` while model traffic remains blocked. Only the Supervisor's exact health/capability inspection plus `LocalInferenceBoundaryEvidenceV1` may CAS the same row to `active` and expose loopback traffic. Heartbeat changes only its narrow row lease. Retirement is the canonical XOR: a never-spawned `reserved` row becomes `retired/retirementKind='no_spawn'` only with matching exact `ProcessContainmentNoSpawnEvidenceV1` and no process/boundary/quiesce fields; a created containment becomes `retired/retirementKind='death'` only with its quiesce id and exact `ProcessContainmentDeathEvidenceV1`, with boundary evidence if and only if it reached active. A successor never adopts it: it fences traffic, kills/proves/retire-closes the exact plan/spec/containment, and only then may start the one next cycle-authorized launch. Replacement preserves the exact `LocalZeroCostProvenanceV1.stableServiceIdentityDigest` projection while minting fresh launch/containment/plan/SandboxLaunch/inspector/observation identities; it never copies old dynamic ids or falls back to an ambient loopback daemon. It cannot create a Run, Journal grant, admin operation, credential channel, model download, or general local-model manager.

8. **Give every mutable generation one immutable identity and one durable authority row.** Work package 1 exports and this package consumes these exact canonical contracts without widening:

    ```ts
    type WorkspaceGenerationIdentityV1 = {
      schemaVersion: 1
      format: 'cliq-workspace-generation-identity-v1'
      generationId: string
      runId: string
      workspaceIdentityDigest: string
      sourceCheckpointId: string
      sourceWorkspaceStateRef: ArtifactRef
      sourceWorkspaceStateDigest: string
      sourceTreeDigest: string
      creationNonceDigest: string
      locator:
        | {
            kind: 'linux_directory'
            stateRootIdentityRef: ArtifactRef
            stateRootIdentityDigest: string
            canonicalRootRelativePath: string
            deviceId: string
            directoryFileId: string
            ownerUid: number
            mode: 448
            linkCount: 1
          }
        | {
            kind: 'macos_vm_volume'
            stateRootIdentityRef: ArtifactRef
            stateRootIdentityDigest: string
            backingStoreCanonicalRootRelativePath: string
            backingStoreDeviceId: string
            backingStoreFileId: string
            backingStoreOwnerUid: number
            backingStoreMode: 384
            backingStoreLinkCount: 1
            vmVolumeReservationId: string
            guestVolumeId: string
          }
      createdAt: string
      identityDigest: string
    }

    type WorkspaceGenerationSnapshotEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-workspace-generation-snapshot-evidence-v1'
      purpose: 'materialized_from_checkpoint' | 'sealed_to_checkpoint'
      runId: string
      generationRef: ArtifactRef
      generationIdentityDigest: string
      checkpointId: string
      workspaceStateRef: ArtifactRef
      workspaceStateDigest: string
      entriesRef: ArtifactRef
      treeDigest: string
      privateGitStateRef?: ArtifactRef
      descriptorRewalkComplete: true
      fileFsyncComplete: true
      directoryFsyncComplete: true
      observedAt: string
      evidenceDigest: string
    }

    type WorkspaceGenerationFailureDetailV1 = {
      schemaVersion: 1
      format: 'cliq-workspace-generation-failure-detail-v1'
      runId: string
      generationRef: ArtifactRef
      generationIdentityDigest: string
      sourceCheckpointId: string
      phase: 'materializing' | 'preactivated_readonly'
      failureCode:
        | 'descriptor_io_failed'
        | 'artifact_missing_or_corrupt'
        | 'path_or_entry_invalid'
        | 'tree_or_state_digest_mismatch'
        | 'git_closure_invalid'
        | 'fsync_failed'
        | 'runtime_incompatible'
      failingCanonicalRootRelativePath?: string
      observedAt: string
      detailDigest: string
    }

    type WorkspaceGenerationQuarantineEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-workspace-generation-quarantine-evidence-v1'
      runId: string
      generationRef: ArtifactRef
      generationIdentityDigest: string
      sourceRowVersion: number
      observedState:
        | { kind: 'complete_tree'; treeDigest: string }
        | {
            kind: 'unreadable_partial'
            failureCode: 'descriptor_io_failed' | 'artifact_missing_or_corrupt' | 'path_or_entry_invalid' | 'git_closure_invalid'
          }
      inspectorIdentityRef: ArtifactRef
      inspectorIdentityDigest: string
      quarantineCanonicalRootRelativePath: string
      quarantineDeviceId: string
      quarantineFileId: string
      originalLocatorAbsent: true
      renameNoReplace: true
      directoryFsyncComplete: true
      observedAt: string
      evidenceDigest: string
    } & (
      | {
          reason: 'materialization_failed'
          fromPhase: 'materializing'
          failureDetailRef: ArtifactRef
          failureDetailDigest: string
          workerRecoveryEvidenceRef?: never
          workerRecoveryEvidenceDigest?: never
          workerLaunchId?: never
          quiesceId?: never
          containmentDeathEvidenceRef?: never
          containmentDeathEvidenceDigest?: never
        }
      | {
          reason: 'preactivation_failed'
          fromPhase: 'preactivated_readonly'
          failureDetailRef: ArtifactRef
          failureDetailDigest: string
          workerRecoveryEvidenceRef?: never
          workerRecoveryEvidenceDigest?: never
          workerLaunchId?: never
          quiesceId?: never
          containmentNoSpawnEvidenceRef?: never
          containmentNoSpawnEvidenceDigest?: never
          containmentDeathEvidenceRef?: never
          containmentDeathEvidenceDigest?: never
        }
      | {
          reason: 'launch_aborted'
          fromPhase: 'preactivated_readonly'
          workerLaunchId: string
          containmentNoSpawnEvidenceRef: ArtifactRef
          containmentNoSpawnEvidenceDigest: string
          failureDetailRef?: never
          failureDetailDigest?: never
          workerRecoveryEvidenceRef?: never
          workerRecoveryEvidenceDigest?: never
          quiesceId?: never
          containmentDeathEvidenceRef?: never
          containmentDeathEvidenceDigest?: never
        }
      | {
          reason: 'launch_died_before_activation'
          fromPhase: 'preactivated_readonly'
          workerLaunchId: string
          containmentDeathEvidenceRef: ArtifactRef
          containmentDeathEvidenceDigest: string
          failureDetailRef?: never
          failureDetailDigest?: never
          workerRecoveryEvidenceRef?: never
          workerRecoveryEvidenceDigest?: never
          quiesceId?: never
          containmentNoSpawnEvidenceRef?: never
          containmentNoSpawnEvidenceDigest?: never
        }
      | {
          reason: 'worker_recovery'
          fromPhase: 'fenced_reconciling'
          workerRecoveryEvidenceRef: ArtifactRef
          workerRecoveryEvidenceDigest: string
          failureDetailRef?: never
          failureDetailDigest?: never
          workerLaunchId?: never
          quiesceId?: never
          containmentNoSpawnEvidenceRef?: never
          containmentNoSpawnEvidenceDigest?: never
          containmentDeathEvidenceRef?: never
          containmentDeathEvidenceDigest?: never
        }
      | {
          reason: 'checkpoint_failed'
          fromPhase: 'revoking' | 'checkpointing'
          workerLaunchId: string
          quiesceId: string
          containmentDeathEvidenceRef: ArtifactRef
          containmentDeathEvidenceDigest: string
          failureDetailRef?: never
          failureDetailDigest?: never
          workerRecoveryEvidenceRef?: never
          workerRecoveryEvidenceDigest?: never
          containmentNoSpawnEvidenceRef?: never
          containmentNoSpawnEvidenceDigest?: never
        }
    )

    type WorkspaceGenerationRetirementEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-workspace-generation-retirement-evidence-v1'
      runId: string
      generationRef: ArtifactRef
      generationIdentityDigest: string
      inspectorIdentityRef: ArtifactRef
      inspectorIdentityDigest: string
      observedAt: string
      evidenceDigest: string
    } & (
      | {
          fromPhase: 'sealed'
          snapshotEvidenceRef: ArtifactRef
          snapshotEvidenceDigest: string
          workerLaunchId: string
          containmentDeathEvidenceRef: ArtifactRef
          containmentDeathEvidenceDigest: string
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
        }
      | {
          fromPhase: 'quarantined'
          quarantineEvidenceRef: ArtifactRef
          quarantineEvidenceDigest: string
          sourceQuarantinedRowVersion: number
          activeRunPointerCount: 0
          nonretiredWorkerLaunchCount: 0
          liveContainmentCount: 0
          activeMountCount: 0
          releasableBrokerClaimCount: 0
          snapshotEvidenceRef?: never
          snapshotEvidenceDigest?: never
          workerLaunchId?: never
          containmentDeathEvidenceRef?: never
          containmentDeathEvidenceDigest?: never
        }
    )

    type WorkspaceGenerationStateBaseV1 = {
      schemaVersion: 1
      generationId: string
      runId: string
      generationRef: ArtifactRef
      generationIdentityDigest: string
      rowVersion: number
      sourceCheckpointId: string
      sourceWorkspaceStateRef: ArtifactRef
      sourceWorkspaceStateDigest: string
      lastVerifiedTreeDigest: string
      updatedAt: string
    }

    type WorkspaceGenerationStateV1 = WorkspaceGenerationStateBaseV1 & (
      | {
          phase: 'materializing'
          snapshotEvidenceRef?: never
          snapshotEvidenceDigest?: never
          activeWorkerLaunchId?: never
          leaseEpoch?: never
          quiesceId?: never
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        }
      | {
          phase: 'preactivated_readonly'
          snapshotEvidenceRef: ArtifactRef
          snapshotEvidenceDigest: string
          activeWorkerLaunchId?: never
          leaseEpoch?: never
          quiesceId?: never
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        }
      | {
          phase: 'active'
          snapshotEvidenceRef: ArtifactRef
          snapshotEvidenceDigest: string
          activeWorkerLaunchId: string
          leaseEpoch: number
          quiesceId?: never
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        }
      | {
          phase: 'revoking' | 'checkpointing'
          snapshotEvidenceRef: ArtifactRef
          snapshotEvidenceDigest: string
          activeWorkerLaunchId: string
          leaseEpoch: number
          quiesceId: string
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        }
      | ({
          phase: 'fenced_reconciling'
          snapshotEvidenceRef: ArtifactRef
          snapshotEvidenceDigest: string
          activeWorkerLaunchId: string
          leaseEpoch: number
          waitingSubjectRef: ArtifactRef
          waitingSubjectDigest: string
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        } & (
          | { fencedFromPhase: 'active'; quiesceId?: never }
          | { fencedFromPhase: 'revoking' | 'checkpointing'; quiesceId: string }
        ))
      | {
          phase: 'sealed'
          snapshotEvidenceRef: ArtifactRef
          snapshotEvidenceDigest: string
          activeWorkerLaunchId?: never
          leaseEpoch?: never
          quiesceId?: never
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        }
      | {
          phase: 'quarantined'
          snapshotEvidenceRef?: never
          snapshotEvidenceDigest?: never
          activeWorkerLaunchId?: never
          leaseEpoch?: never
          quiesceId?: never
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef: ArtifactRef
          quarantineEvidenceDigest: string
          observedState: WorkspaceGenerationQuarantineEvidenceV1['observedState']
          retirementEvidenceRef?: never
          retirementEvidenceDigest?: never
        }
      | {
          phase: 'retired'
          snapshotEvidenceRef?: never
          snapshotEvidenceDigest?: never
          activeWorkerLaunchId?: never
          leaseEpoch?: never
          quiesceId?: never
          waitingSubjectRef?: never
          waitingSubjectDigest?: never
          fencedFromPhase?: never
          quarantineEvidenceRef?: never
          quarantineEvidenceDigest?: never
          observedState?: never
          retirementEvidenceRef: ArtifactRef
          retirementEvidenceDigest: string
        }
    )
    ```

   Every `workspaceGenerationRef|generationRef` decodes only exact `WorkspaceGenerationIdentityV1`; the ref rehashes the bytes, the omission digest verifies, the same-Run source Checkpoint/state/tree match, and `generationId=H(runId,sourceCheckpointId,sourceWorkspaceStateRef,creationNonceDigest)`. Linux materializes exactly the descriptor-relative StateRoot path and immutable directory tuple in the locator. macOS materializes the analogous private backing image plus uniquely reserved guest volume; no path, mutable handle, directory, VM id, or worker assertion can substitute for the retained identity.

   `workspace_generations`, not the launch row or directory name, is the sole mutable generation authority. Its positive `rowVersion` advances by one. The success spine is exactly `materializing -> preactivated_readonly -> active -> revoking -> checkpointing -> sealed -> retired`. Materialization/preactivation/launch/checkpoint failures use only their closed quarantine edges; every worker loss from `active|revoking|checkpointing` first atomically enters `fenced_reconciling`, and only that phase may enter `quarantined` through `worker_recovery`. Only sealed/quarantined retires. The state XOR is storage-enforced. Every materialization/seal snapshot rewalks the exact identity/Checkpoint/state/entries/private Git, requires all three fsync literals, and rehashes its omission digest. Active/revoking/checkpointing launch/epoch equals the sole Run pointer and WorkerLaunch. A fenced row instead requires that pointer absent, the exact `worker_death` wait ref/digest, its prior phase and phase-valid quiesce id, and the sole WorkerLaunch projected as `reconciling/fenced_reconciling`; it is read-only and cannot dispatch, checkpoint, seal, or be selected. Only `lastVerifiedTreeDigest` is authoritative while writes remain possible.

   Every quarantine derives its sole target before filesystem mutation: `sourceRowVersion` equals the current row and `quarantineCanonicalRootRelativePath='quarantine/workspace-generations/'+H(generationId,base-10 sourceRowVersion)`. It artifact-first publishes exact `WorkspaceGenerationQuarantineEvidenceV1`, proves current inspector, no-replace rename to that descriptor, original-locator absence, parent fsync, and exact `observedState=complete_tree|unreadable_partial`. The reason/from-phase matrix is closed: materialization failure with exact failure detail; preactivation failure with exact failure detail; launch abort with exact no-spawn evidence; launch death before activation with exact death evidence; worker recovery only from the installed `fenced_reconciling` wait with exact `WorkerRecoveryEvidenceV1`; or checkpoint failure from `revoking|checkpointing` with exact launch/quiesce/death evidence. Crash recovery may retry or reconstruct only this same target/evidence; both-present, both-absent, identity drift, or any other target blocks. No quarantined generation may be selected again. Every retirement artifact-first publishes exact `WorkspaceGenerationRetirementEvidenceV1`: sealed requires its snapshot plus last-launch death; quarantined requires its exact quarantine evidence and current literal zero counts for active Run pointers, nonretired launches, live containments, active mounts, and releasable broker claims. WorkerLaunch `generationWriteState` is only a same-transaction denormalized projection of the generation row. Heartbeat cannot change or reopen it.

   Restore always creates a distinct empty immutable identity from the named ready Checkpoint, inserts `materializing`, materializes independent files and `.git`, fsyncs, rewalks and recomputes state/index/object closure, publishes snapshot evidence, and CASes to `preactivated_readonly` before a blocked worker launch can select it. Worker recovery `restored_from_checkpoint` must name this distinct replacement ref; `quarantined` forbids it. An old/quarantined/retired identity is never rewound, rebound to a new epoch, or reopened.

9. **Make `quiesceGeneration` the checkpoint barrier.** Every ready Checkpoint that captures a mutable generation, including every `commitWorkspaceEffect`, follows this closed sequence:

   1. the trusted controller durably compare-and-swaps the exact Run-pointed `workspace_generations` row from `active` to `revoking(quiesceId)` and copies the same state into the pointed WorkerLaunch in one transaction, which makes `releaseClaimedDispatch` fail and blocks every new broker/sandbox dispatch; the Run remains `running` only for this bounded quiesce transaction and heartbeat cannot reactivate the write gate;
   2. the worker reaches the authenticated blocked barrier and returns its exact Run revision/frontier/Journal cursor; the acknowledgement is coordination, not safety proof;
   3. the controller terminates the complete `ProcessContainmentRef`, then proves every descendant is dead and reaped (`cgroup.events populated=0` plus namespace-init death on Linux; stopped VM plus matching VM/guest identity retirement on macOS);
   4. only after that proof, the controller CASes the authoritative generation row plus denormalized launch projection to exclusive `checkpointing(quiesceId)`, revalidates immutable generation identity, independent `.git`, projection inputs, file types/links, and the complete post-effect manifest, then publishes exact `WorkspaceGenerationSnapshotEvidenceV1(purpose='sealed_to_checkpoint')` after a second descriptor rewalk and all fsyncs;
   5. CAS objects are fsynced first; the state service atomically appends any pending invocation terminal fact/result item and settlement, context manifest, ready Checkpoint with `workspaceStateRef`, Run revision/frontier/event, CASes the generation to `sealed` and launch projection to sealed/retired, clears `Run.activeWorkerLaunchId`, and returns the Run to lease-free `queued` or its typed wait/terminal reducer; `commitWorkspaceEffect` always includes its matching Journal terminal fact and result item in this transaction;
   6. exact `WorkspaceGenerationRetirementEvidenceV1` later retires the sealed generation after last-launch death; any failed materialization/preactivation/launch/checkpoint branch first publishes exact reason-matched quarantine evidence and can retire only through its quarantine branch. Every worker loss instead first binds the old row and sole launch to exact `fenced_reconciling`; after death proof, both `WorkerRecoveryEvidenceV1` dispositions publish the exact `worker_recovery` quarantine artifact for that old row, and only `restored_from_checkpoint` additionally selects a distinct fresh `preactivated_readonly` identity from the committed Checkpoint. Neither old phase is activated again. If death is unproven, no Checkpoint/result is published and no replacement starts: the exact worker-death wait plus fenced row remains authoritative until later proof/quarantine.

   A barrier timeout, descendant-death uncertainty, manifest drift, snapshot failure, lease/controller loss, or crash before the SQLite commit publishes no Checkpoint and no Run-visible workspace result. Quiesce ownership is never transferred after lease loss: the dirty generation reaches quarantine only through the exact reason/from-phase artifact and no-replace move; the prior ready Checkpoint remains authoritative, and recovery never opens that generation for a replacement worker.

10. **Keep two manifests and one frozen projection.** `workspaceStateRef` includes the private workspace state required for deterministic recovery, including generated/ignored cache state created inside that generation except declared ephemeral paths and broker-managed credential inputs. `resultSourceRef` is computed only by `sourceProjectionRef`: hard exclusions (`.git`, Cliq state, mounts, known credential roots, ephemeral paths, outside-root and special files) cannot be overridden; exact-v1 excludes beat authorized includes; ignored in-root includes require exact durable read-scope authorization and every outside-root selector is rejected; the default includes admitted source paths plus newly created ordinary non-ignored files/safe in-root symlinks under the frozen admission-time ignore rules. Modification, deletion, binary bytes, executable-bit changes, and safe symlink-target changes are preserved; rename is delete plus add. Unsafe/colliding/over-limit results fail instead of being omitted. A cache, verifier output, dependency tree, or build directory cannot enter the deliverable merely because it exists in recovery state; arbitrary external inputs are never admitted at all.

11. **Reject ambient and external inputs.** Every source/read selector from CLI, API, or trusted config is root-relative and is resolved against the descriptor-held admitted root; any outside-root path, config include, symlink escape, external filesystem input, or requested host mount is unsupported and rejected before target bytes are read. Ignored in-root files remain excluded unless an exact user-level policy or durable admission grant authorizes the frozen root-relative selector; repository config cannot self-authorize it. Authorized in-root bytes are copied into immutable admission inputs and may reach the model/result only under the frozen source-projection rules, never through a mutable host mount. Broker-managed secrets and provider/tool credentials remain opaque references and never enter the general worker. Unknown secrets inside user-authorized in-root bytes cannot be inferred reliably, so consent describes that risk without claiming heuristic detection. External/raw-secret inputs or mounts require a future RFC and cannot be smuggled through config, policy, or `SandboxLaunchSpecV1`.

12. **Sanitize the worker environment.** Build it from a fixed allowlist: controlled `PATH`, locale fields, private `HOME`, private `TMPDIR`, and non-secret Run identity fields. Do not spread `process.env`. Explicit ordinary values must be schema-validated and frozen in the sandbox profile; secret values are handles resolved only by the trusted broker. The preactivated environment contains no usable broker handle. Redact broker errors before they reach artifacts or events.

13. **Broker all privileged network/effect operations.** Broker and sandbox entrypoints accept principal/channel identity only as Supervisor-injected exact `LocalPrincipalIdentityV1`/`LocalControlChannelIdentityV1`; a UDS channel must transitively decode exact held-descriptor `LocalSocketPeerObservationV1`, and in-process identity must bind the signed current process. A worker, environment, operation request, model output, or caller cannot supply or override either field. Every time/deadline/expiry comparison uses exact canonical UTC milliseconds plus checked arithmetic and the current healthy `CanonicalTimeFenceV1`; `clock_regressed` makes both release gates fail closed, revokes broker tokens, blocks renewal/redemption/retry/expiry extension, and begins containment quiescence until the current owner observes the retained high-water. Use a versioned request envelope:

    ```ts
    type BrokerRequest = {
      schemaVersion: 1
      requestId: string
      requestDigest: string
      runId: string
      opId: string
      attempt: number
      dispatchId: string
      supervisorInstanceId: string
      runRevision: number
      leaseEpoch: number
      workerLaunchId: string
      workerIdentityDigest: string
      containmentRef: ProcessContainmentRef
      generationRef: ArtifactRef
      grantRef: ArtifactRef
      target: string
      expiresAt: string
      kind: 'model' | 'remote-mcp' | 'dependency' | 'publish'
      payloadRef: ArtifactRef
    }

    type AdminOperationBase = {
      schemaVersion: 1
      adminOperationId: string
      principalId: string
      method: 'mcp.register' | 'mcp.refresh'
      requestId: string
      requestDigest: string
      attempt: number
      maxAttempts: 3
      deadlineAt: string
      targetRef: ArtifactRef
      targetDigest: string
      probePayloadCoreRef: ArtifactRef
      probePayloadCoreDigest: string
      supervisorInstanceId: string
      plannedContainmentRef: ArtifactRef
      plannedContainmentDigest: string
      sandboxLaunchSpecRef: ArtifactRef
      sandboxLaunchSpecDigest: string
      rowVersion: number
      createdAt: string
    }

    type AdminProbePayloadCoreV1 = {
      schemaVersion: 1
      format: 'cliq-admin-probe-payload-core-v1'
      probeKind: 'mcp_stdio' | 'mcp_streamable_http'
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      adapterExecutableId: string
      adapterVersion: string
      adapterExecutableDigest: string
      protocolRecipe: 'mcp-initialize-capabilities-tools-list-v1'
      maximumResponseBytes: number
      payloadCoreDigest: string
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
      assertStatelessPerCall: true
      requestedToolRecovery: Array<{ toolName: string; recovery: RequestedMcpRecoveryV1 }>
      lifecycle: {
        launchTimeoutMs: number
        callTimeoutMs: number
        maxLaunchesPerCall: number
      }
      requestCoreDigest: string
      targetDigest: string
      createdAt: string
    }

    type McpAdminProbeResultV1 = {
      schemaVersion: 1
      format: 'cliq-mcp-admin-probe-result-v1'
      adminOperationId: string
      attempt: number
      dispatchId: string
      probeRequestDigest: string
      targetRef: ArtifactRef
      targetDigest: string
      probePayloadCoreRef: ArtifactRef
      probePayloadCoreDigest: string
      processContainmentRef: ArtifactRef
      initializeResponseRef: ArtifactRef
      initializeResponseDigest: string
      capabilityResponseRef: ArtifactRef
      capabilityResponseDigest: string
      toolsListResponseRef: ArtifactRef
      toolsListResponseDigest: string
      initializeDigest: string
      capabilityDigest: string
      normalizedTools: McpProbedToolInterfaceV1[]
      probedToolsListDigest: string
      completedAt: string
      resultDigest: string
    }

    type AdminProbeClosureEvidenceV1 = {
      schemaVersion: 1
      format: 'cliq-admin-probe-closure-evidence-v1'
      adminOperationId: string
      attempt: number
      targetRef: ArtifactRef
      targetDigest: string
      plannedContainmentRef: ArtifactRef
      plannedContainmentDigest: string
      sandboxLaunchSpecRef: ArtifactRef
      sandboxLaunchSpecDigest: string
      inspectorIdentityRef: ArtifactRef
      inspectorIdentityDigest: string
      observedAt: string
      evidenceDigest: string
    } & (
      | {
          closureKind: 'no_spawn'
          noSpawnEvidenceRef: ArtifactRef
          noSpawnEvidenceDigest: string
          processContainmentRef?: never
          dispatchId?: never
          probeRequestDigest?: never
          deathEvidenceRef?: never
          deathEvidenceDigest?: never
        }
      | {
          closureKind: 'containment_dead'
          processContainmentRef: ArtifactRef
          dispatchId?: string
          probeRequestDigest?: string
          deathEvidenceRef: ArtifactRef
          deathEvidenceDigest: string
          noSpawnEvidenceRef?: never
          noSpawnEvidenceDigest?: never
        }
    )

    type AdminProbeErrorV1 = {
      schemaVersion: 1
      format: 'cliq-admin-probe-error-v1'
      adminOperationId: string
      attempt: number
      targetRef: ArtifactRef
      targetDigest: string
      closureEvidenceRef: ArtifactRef
      closureEvidenceDigest: string
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
      createdAt: string
      errorDigest: string
    } & (
      | {
          code: 'target_rejected' | 'schema_invalid' | 'capability_mismatch'
          deterministicRejection: true
        }
      | {
          code:
            | 'preactivation_no_spawn'
            | 'transport_failed_no_effect'
            | 'timeout_after_containment_death'
          deterministicRejection: false
        }
    )

    type AdminProbeDispatchState =
      | { state: 'blocked' }
      | {
          state: 'claimed'
          probeRequestDigest: string
          dispatchId: string
          claimedAt: string
        }
      | {
          state: 'released'
          probeRequestDigest: string
          dispatchId: string
          claimedAt: string
          releasedAt: string
        }

    type AdminOperation = AdminOperationBase & (
      | {
          phase: 'prepared'
          processContainmentRef?: never
          leaseExpiresAt?: never
          resultRef?: never
          resultDigest?: never
          evidenceRef?: never
          evidenceDigest?: never
          errorRef?: never
          errorDigest?: never
          controlResponseRef?: never
          controlResponseDigest?: never
          failureDisposition?: never
          retryNotBeforeAt?: never
          probeDispatch?: never
          finishedAt?: never
        }
      | {
          phase: 'active'
          processContainmentRef: ArtifactRef
          leaseExpiresAt: string
          probeDispatch: AdminProbeDispatchState
          resultRef?: never
          resultDigest?: never
          evidenceRef?: never
          evidenceDigest?: never
          errorRef?: never
          errorDigest?: never
          controlResponseRef?: never
          controlResponseDigest?: never
          failureDisposition?: never
          retryNotBeforeAt?: never
          finishedAt?: never
        }
      | {
          phase: 'completed'
          processContainmentRef: ArtifactRef
          probeDispatch: Extract<AdminProbeDispatchState, { state: 'released' }>
          resultRef: ArtifactRef
          resultDigest: string
          evidenceRef: ArtifactRef
          evidenceDigest: string
          controlResponseRef: ArtifactRef
          controlResponseDigest: string
          errorRef?: never
          errorDigest?: never
          failureDisposition?: never
          retryNotBeforeAt?: never
          finishedAt: string
          leaseExpiresAt?: never
        }
      | {
          phase: 'failed'
          failureDisposition: 'retryable_recovery'
          processContainmentRef?: ArtifactRef
          probeDispatch?: AdminProbeDispatchState
          resultRef?: never
          resultDigest?: never
          evidenceRef: ArtifactRef
          evidenceDigest: string
          errorRef: ArtifactRef
          errorDigest: string
          controlResponseRef?: never
          controlResponseDigest?: never
          retryNotBeforeAt: string
          finishedAt: string
          leaseExpiresAt?: never
        }
      | {
          phase: 'failed'
          failureDisposition: 'final_rejection' | 'retry_exhausted'
          processContainmentRef?: ArtifactRef
          probeDispatch?: AdminProbeDispatchState
          resultRef?: never
          resultDigest?: never
          evidenceRef: ArtifactRef
          evidenceDigest: string
          errorRef: ArtifactRef
          errorDigest: string
          controlResponseRef: ArtifactRef
          controlResponseDigest: string
          retryNotBeforeAt?: never
          finishedAt: string
          leaseExpiresAt?: never
        }
    )

    type AdminProbeBrokerRequest = {
      schemaVersion: 1
      kind: 'mcp_registry_probe'
      requestId: string
      adminOperationId: string
      attempt: number
      principalId: string
      method: 'mcp.register' | 'mcp.refresh'
      originalRequestDigest: string
      targetRef: ArtifactRef
      targetDigest: string
      probeRequestDigest: string
      dispatchId: string
      supervisorInstanceId: string
      containmentRef: ArtifactRef
      target:
        | { kind: 'stdio' }
        | {
            kind: 'streamable_http'
            endpointRegistrationRef: ArtifactRef
            endpointIdentityDigest: string
            tlsPolicyDigest: string
            credentialGrantRefs: ArtifactRef[]
          }
      payloadRef: ArtifactRef
      payloadDigest: string
      expiresAt: string
    }
    ```

   For the Run-owned `BrokerRequest`, `requestDigest` is the JCS/SHA-256 digest of the immutable invocation request, including `kind`, `target`, `payloadRef`, `grantRef`, and operation deadline. `requestId` is deterministic from `(runId, opId, attempt, requestDigest)` and cannot be chosen to alias different bytes. `grantRef` must decode as the RFC-exact `OperationGrantV1`: schema/format/digest, Run/principal/policy/frontier/op/request/target, subject/provenance, attempt/launch bounds, and expiry all byte-match the current invocation. The broker rejects `AuthorizationGrantV1`, `RunPolicySnapshotV1`, approval decision, verifier/dependency template, or any opaque artifact in that field. `workerLaunchId` must equal `Run.activeWorkerLaunchId`; its row supplies the live lease, immutable identity digest, containment, and generation in the same database view. `supervisorInstanceId` must equal both current state ownership and the launch row: a successor never adopts an old channel/request, regardless of lease expiry. Heartbeat-only `leaseVersion` is intentionally not client-selected authority and is not frozen into this envelope. The broker resolves provider/integration secrets only after `releaseClaimedDispatch` succeeds; workers receive redacted result/error artifacts, never credentials or unreleased request bytes.

   The canonical admin claim lives inside `AdminOperation.phase='active'` as `probeDispatch: AdminProbeDispatchState`; no sidecar or RunJournal row exists. The row's target/core/plan/spec refs each carry and rehash their mandatory digest; the closure repeats plan/spec digests, and the broker request repeats target/payload digests. `deadlineAt = createdAt + target.lifecycle.launchTimeoutMs`; normalization is default `30000` or accepted `1000..300000`, refresh copies it, and no separate timeout exists. Active row-version CAS permits only `blocked -> claimed -> released`; permanent dispatch id is never cleared/reused. `claimAdminProbe` validates exact row/attempt/request/target/core/principal/Supervisor/admin containment/lease/deadline and target binding, computes the request digest, and changes only blocked to claimed. The deterministic broker request cannot alias changed bytes; duplicates join.

   Immediately before executable, network, payload, endpoint, or credential release, `releaseAdminProbe` re-reads the same active AdminOperation and repeats the exact request/target/principal/Supervisor/containment/grant/endpoint/lease/deadline predicates for its retained digest/`dispatchId`, then CASes only `claimed -> released`. A failed second check reaches no target and cannot mint another claim for that attempt. `completed` requires the retained released state; a failed active row retains its last dispatch state. The request carries no Run id, Run revision, lease epoch, worker launch, generation, Run frontier, or Run budget, and both gates read `admin_operations`, not `runs` or `worker_launches`.

   The `target` union is closed. A stdio target carries `executionIdentityGrantId` plus the exact `AuthorizationConsumptionReceiptV1` ref/digest that proves this registration consumed that named grant for the same principal/target; its resolved guest-toolchain or role-`mcp_server` RuntimeBundle executable and non-secret argv equal that authority. BrokerRequest `stdio` is exactly `{kind:'stdio'}` and carries no opaque/duplicate executable ref: the broker decodes exact `McpAdminProbeTargetV1` from `targetRef`, revalidates that receipt, requires its stdio transport/executable/argv to equal the admin `SandboxLaunchSpecV1` and launched process identity, and releases only that frozen signed probe capability into the secretless/networkless `admin_probe` containment. `streamable_http` may redeem only the exact principal/purpose/endpoint-bound credential refs frozen into `targetRef`; endpoint identity and TLS digests must match the registered endpoint, its redirect policy is literal `reject_all`, and `expiresAt` cannot exceed the active admin lease/deadline or any grant expiry. The broker disables redirect handling, treats every `300..399` as the response of the frozen target, and never resolves `Location` or resends credentials/body. `probePayloadCoreRef` decodes only as exact `AdminProbePayloadCoreV1`: signed RuntimeBundle adapter identity, fixed `mcp-initialize-capabilities-tools-list-v1` recipe, bounded maximum response, and recomputed digest; it contains no endpoint request, caller argv, containment, lease, credential, claim, or dispatch field. It is published with the prepared admin row and launch spec. Only after active containment and `claimAdminProbe` exist does the canonical BrokerRequest use this same ref as `payloadRef`. HTTP endpoint and credential services are reachable only by the trusted broker; containment/IPC/payload/log/receipt/error/registry artifacts contain handles and redacted evidence, never resolved URLs with credentials, bearer tokens, cookies, client-certificate keys, provider secrets, or secret headers.

   Probe terminal artifacts are closed. `McpAdminProbeResultV1.resultDigest`, `AdminProbeClosureEvidenceV1.evidenceDigest`, and `AdminProbeErrorV1.errorDigest` each omit only themselves under JCS; every other ref/digest pair rehashes its exact artifact. A result is legal only for the released dispatch and repeats operation/attempt/request/target/payload/containment. Its three bounded secret-free response artifacts are the exact fixed-recipe bytes; initialize/capability digests are normalized projections. `normalizedTools` contains only unique byte-sorted raw `McpProbedToolInterfaceV1` rows, each `interfaceDigest=SHA-256(JCS(interface with interfaceDigest omitted))`, and `probedToolsListDigest=SHA-256(JCS(normalizedTools))`. It contains no requested recovery intent, profile, template, predicate, final `McpRecoveryContract`, tool-contract, final `toolsListDigest`, registry-core, or registry-manifest field. The completed row's result pair names that artifact exactly; final contract construction is a later trusted reducer and cannot alter or reinterpret the retained probe bytes.

   Every terminal attempt names one exact closure. `AdminProbeClosureEvidenceV1(no_spawn)` is legal only before release, forbids process/dispatch/request fields, and wraps the exact plan/spec/owner/nonce `ProcessContainmentNoSpawnEvidenceV1`. `containment_dead` wraps exact `ProcessContainmentDeathEvidenceV1`, repeats the actual containment, and requires dispatch/request iff claimed or released; its current inspector and all row/target/plan/spec identities match. `AdminProbeErrorV1` repeats that closure and a bounded redacted diagnostic that never chooses disposition. `target_rejected|schema_invalid|capability_mismatch` require `deterministicRejection=true`; preactivation/transport/timeout recovery errors require false and positive no-spawn/death closure. `final_rejection` accepts only true; `retryable_recovery|retry_exhausted` only false. Every terminal row's result/evidence/error/control-response ref+digest pair is exact, and those fields are forbidden outside the canonical phase branch.

   `completed`, or `failed` after active, therefore requires owner-matched closure proving the complete admin containment dead and reaped **and** the broker/launcher has no probe request, credential redemption, stream, or process still live. A released successful probe additionally binds its exact result to the retained request digest/dispatch id before registry publication. `prepared -> failed` may instead use the exact no-spawn closure. Timeout, lease/deadline expiry, Supervisor loss, root PID exit, or inaccessible containment is not death/no-I/O proof. A successor Supervisor never adopts, renews, re-releases, or reconnects to an active admin attempt, and no later attempt begins until the prior containment and I/O are positively quiescent and its canonical error/closure/backoff transaction is durable.

   Managed local inference never borrows Run-worker or admin-probe authority. Before releasing a model request to a `local_zero_cost` endpoint, the trusted broker reads the sole exact `LocalInferenceServiceLaunchV1.phase='active'`, verifies its owner/service spec, unexpired narrow lease, `LocalInferenceBoundaryEvidenceV1`, `SandboxLaunchSpecV1.local_inference_service`, containment ref/spec digest, signed `local_inference` executable and model manifest, loopback endpoint, capability digest, and external-egress denial against the Run assembly's exact `LocalZeroCostProvenanceV1.stableServiceIdentityDigest`. No Run id, worker epoch, `OperationGrantV1`, or admin dispatch can make a missing/stale service row valid. A mismatch reaches no local provider; replacement requires revocation, whole-containment death proof, immutable retirement, a fresh launch under the identical stable service projection, and fresh dynamic launch/containment/plan/SandboxLaunch/inspector/observation identities.

   Run-context compaction uses this same broker boundary, never an implicit provider truncation path. It is an ordinary Journaled `model` invocation bound to the immutable `RunContextCompactionPlan`, exact `phase='context_compaction'` frontier, tools-disabled provider request, ordinary token/cost reservation, frozen retry policy, and `ReplayClass='retry'`; both dispatch gates still apply. The broker accepts only a positively complete UTF-8 Markdown summary capped at 256 KiB. Tool calls, truncated/filter/cancel/unknown stops, oversize bytes, or schema drift are evidence-backed protocol failures—not executable actions. The summary is content, compaction control/evidence never enters model-visible text, raw Run items are never deleted, and successful publication reuses the unchanged `workspaceStateRef` in work packages 1/2's atomic item/context/Checkpoint transition.

14. **Separate productive authority from evidence authority.** `activateWorkerLease` is the only worker-activation authority and validates work package 4's durable launch-row/blocked-handshake contract; it authorizes no invocation. Run-owned productive I/O has two mandatory gates shared by broker, sandbox launcher, model, Run MCP, verifier, and publish adapters. A process-spawning `prepared` Journal row has no `sandboxLaunchSpecRef`. Trusted `claimDispatch` chooses the unguessable `dispatchId`, constructs and artifact-first publishes the exact `SandboxLaunchSpecV1.run_invocation`, then in one SQLite view requires the current Supervisor/admission owner, `status='running'`, exact Run revision/epoch/`activeWorkerLaunchId`, the pointed row in `phase='activated'` with `generationWriteState='active'` and exact worker identity digest/`ProcessContainmentRef`/generation, a currently unexpired row lease and absolute deadline, no `stopIntentRef` or cancel flag, the highest current `prepared` attempt with no claim, matching typed frontier/op/target/request digest, an exact live unexpired `OperationGrantV1` whose full subject/provenance/use closure matches that invocation, matching budget reservation, and exact spec owner/plan/process/runtime/environment/filesystem equality. It atomically appends the unique `dispatch_claimed` fact plus that spec ref and returns the same `dispatchId`; a lost race leaves only an unreachable CAS object. A non-spawning operation forbids the ref throughout. MCP admin probes use only note 13's `claimAdminProbe`/`releaseAdminProbe` path and never this Run gate.

   Immediately before releasing a target capability, secret, executable start, or request bytes, the adapter calls `releaseClaimedDispatch`. It re-reads the Run and exact pointed launch row, repeats the live launch/stop/cancel/deadline/frontier/reservation predicates, re-decodes the same exact `OperationGrantV1`, and requires the claim's exact `sandboxLaunchSpecRef`, owner, process mapping, plan, active parent, request/target, resource, and expiry closure for the just-created `dispatchId` rather than the now-false no-claim predicate. Any invocation-scoped process containment must decode as `run_invocation`, carry this exact `opId/attempt/dispatchId`, repeat that launch ref/digest, and have a parent chain ending at the pointed `worker_activation`; another owner/spec cannot be substituted. A heartbeat may advance only row `leaseVersion`/`leaseExpiresAt`; that does not itself invalidate the same active identity, while revocation, pointer change, expiry, grant mismatch/exhaustion, spec drift, or any failed predicate refuses I/O and closes/reconciles the permanent claim. No broker secret or payload crosses the boundary before this second check.

   The only new post-stop mutation claim is the publication broker's `claimRecoveryMaintenance`/`releaseRecoveryMaintenance`; it is not a fallback into `claimDispatch`. It requires the winning StopIntent, immutable approved DeliveryPlan and historical decision/grant binding for that exact plan (the productive grant may now be expired), no live semantic publication claim, and one frozen `abortOperations` entry whose mkdir receipt proves this delivery created the target directory. It prepares/claims the sole zero-reservation `opKind='publish', ReplayClass='reconcile'` maintenance attempt using the Run's current monotonic `leaseEpoch`, current `supervisorInstanceId`, and no worker-launch authority. The second gate permits only descriptor-relative `rmdir` of that exact proven-empty directory plus fsync/evidence; any desired-path create/replace/delete, file write, unexpected/nonempty directory, target drift, or new semantic envelope is rejected. Completion/cleanup inside an already-claimed leaf uses that leaf's existing claim and an equally bounded continuation; it never creates a maintenance claim or second productive claim. Work package 5 defines the publication receipt/abort-operation semantics.

   `assertEvidenceAuthority` cannot authorize I/O. From one SQLite snapshot it reads the Run, immutable claim/request, and retained original `worker_launches` row, then authenticates evidence against `requestRef`/digest, `dispatchId`, original epoch/launch/worker/containment/generation, target, and trusted adapter, broker, query, or containment receipt. It does not require that old row to remain active or live. The result is `current` or `superseded`: `current` proves the invocation is still the highest attempt and is named by the exact current typed frontier or reconciliation subject with no newer visible result; the original lease may already be expired or cleared. The operation-specific state reducer may then atomically commit its terminal fact, item/receipt, budget settlement, and frontier/subject transition even when cancel/deadline/grant elapsed after dispatch; settlement is ordinary while the attempt is open and zero when resolving an already charged `unknown`. `superseded` means a newer attempt/frontier/result already won and is audit/billing-only. Neither disposition can create a claim, retry, grant, or fresh productive I/O; superseded evidence cannot add a Run-visible item, change a wait, advance the frontier, or replace a newer result. An old or late worker assertion is never sufficient provenance, even if every schema field matches.

15. **Keep `dispatch_claimed` singleflight for the whole invocation.** The trusted arbiter appends the unique durable `dispatch_claimed` Journal fact before any external I/O, invocation-scoped sandbox/guest process start, target capability release, or billable call. For a process-spawning operation that claim carries the one exact `SandboxLaunchSpecV1` ref and every `completed|failed|unknown|abandoned` row repeats it; substitution or omission is invalid. Non-spawning operations forbid it on every phase. The claim is permanent for `(runId, opId, attempt)` from dispatch start through its initial `completed|failed|unknown` outcome and any later `unknown -> completed|failed` evidence resolution; it is never released, stolen, or recreated on disconnect, timeout, worker death, lease expiry, or Supervisor restart. Duplicate frames join the same live outcome or read its durable facts. Recovery treats a claim without an outcome fact as possibly dispatched, uses `assertEvidenceAuthority` and the frozen `ReplayClass`, and never dispatches that attempt number again. A `prepared` attempt with no claim becomes positive no-dispatch evidence only after its original authority is fenced.

   Reconciliation is a separate Supervisor-only broker method, not a worker dispatch exception. It accepts the exact immutable invocation/claim identity plus the current typed reconciliation subject, may perform only the target adapter's declared status/idempotency query, and returns evidence to the subject-specific work package 4 reducer. It cannot originate an opaque effect, reuse a worker grant for a different target, or bypass Journal transition rules.

16. **Define grant expiry at both dispatch gates.** A one-shot capability grant authorizes starting only while `now < grant.expiresAt <= Run.deadlineAt`; `prepared` alone does not consume that authority. Expiry after `prepared` but before `claimDispatch` closes with positive no-dispatch evidence and releases its reservation before a fresh approval/grant may prepare a new attempt. Expiry after the claim but before successful `releaseClaimedDispatch` refuses all target bytes/capability and closes that permanent claim with trusted positive no-target evidence; any replacement still requires the frozen same-op retry policy and fresh authority, never an implicit retry. Only after `releaseClaimedDispatch` succeeds is the attempt already started, so later grant expiry does not relabel or erase it; its operation timeout and Run deadline still bound execution. Every stdio MCP lifecycle launch and its one owning tool call applies this rule independently; there is no long-lived process authority.

   Stdio MCP has no long-lived process grant. Its user-scoped registration freezes a secret-free executable/tool manifest, while each owning batch/call receives a call-scoped lifecycle grant bound to `runId`, `batchItemId`, `callIndex`, `callId`, `registryManifestDigest`, expiry, and `maxLaunches`. `lifecycleSeq` starts at zero and stable launch `opId = H(runId, batchItemId, callIndex, callId, registryManifestDigest, lifecycleSeq)`. Each launch is a fresh `mcp-server` prepared/claim/release sequence and a registered nested `ProcessContainmentRef` with `filesystemBinding.kind='isolated-empty-root'`, never the Run generation. It becomes completed only after spawn, MCP initialize, capability validation, exact `probedToolsListDigest` match, and instance identity registration. The one `mcp` call then uses its own live grant/claim. After result or stop, teardown proves that exact containment empty and appends the stopped lifecycle evidence; no later call can address it. Replacement increments `lifecycleSeq` after a completed launch dies before call dispatch, while an ambiguous launch may retry the same opId only after whole-containment death proof. Expiry/exhaustion creates the exact batch/index-bound `mcp_server_launch` approval subject rather than reusing an instance. Streamable HTTP likewise uses a fresh broker request/client with no cookie jar, client-held session id, ambient header, or cross-call state; credential handles resolve only inside the broker.

17. **Do not confuse permission with containment.** The canonical `RunPolicySnapshotV1` mode table plus `decisionRules` compiled in `cliq-permission-grammar-v0` decides whether a requested tool/effect receives an exact `OperationGrantV1`; mutable policy/config is never reevaluated during recovery. The snapshot engine points to the sole signed **non-executable** RuntimeBundle `policy_engine` data entry and exact `PolicyEngineProfileV1`. The entry id/version match the snapshot; its signed complete-file `entry.digest` equals `engine.profileRef`; decoding those exact bytes and independently recomputing the profile's self-omitting semantic digest yields `engine.profileDigest`. The complete-byte ref and semantic digest are distinct hash domains and are never required to equal. Fixed signed Supervisor code alone interprets the profile's literal evaluator/grammar/Bash-parser ids. It is never spawned or loaded as native/in-process plugin code and needs no SandboxLaunch branch. Before approval, grant, denial item, Journal prepare, or target I/O, that fixed interpreter plus retained profile publishes exact `PolicyChannelEvidenceV1`, and storage reruns the same profile over the immutable request/target to compare complete JCS output. Principal/Run/policy/frontier/op/request/target/action/time rehash exactly. The closed channel union records all-and-only nonempty unique byte-sorted canonical root-relative filesystem paths, exact MCP registration/tool, normalized plan identity, schema-normalized Bash argv/shell text plus fixed parser outer head/lexical nested builtin-deny heads/`unsafeForAllow`, or exact `named-action` identity. Named verifier, dependency-install-script, delivery, MCP-server-launch, and child fields equal the prospective subject/grant/request/target; their literal identity keys are respectively `verifier/<verifierId>`, `dependency_install_scripts/<lockfileDigest>`, `delivery/<operationSetDigest>`, `mcp_server_launch/<registryManifestDigest>/<base-10 lifecycleSeq>`, and `child/<read_only|mutating>` with no escaping. Unsupported/dynamic/ambiguous Bash yields no trusted outer head and `unsafeForAllow=true`; it never becomes an implementation guess. `decisionRules` is the closed bounded ordered grammar from the RFC—canonical channels including `named-action`, exact `*`/literal/suffix-` *`/suffix-`/*` matching, no glob meaning for `**`, and deterministic builtin-deny/deny/allow/ask/mode precedence—not an opaque callback or reduced local dialect. Rule evidence names exactly the winning rule; mode fallthrough has an empty list. `allow` embeds the pair in policy-grant provenance, `ask` embeds it in `ApprovalSubject` and any later user grant, and `deny` embeds it in `PolicyDecisionItem`; storage reruns the classifier/matcher and cross-checks every pair. Host-shell reparse, mutable parser/profile, executable helper, worker/caller boolean, policy text, coarse mode, or cross-frontier/request/target evidence cannot mint authority. The sandbox still applies after `allow` and after `yolo`. Direct shell egress remains disabled, and Kernel Cut has no generic integration/network tool: only the typed model, dependency-registry, and streamable-HTTP MCP broker targets may use network.

   Tool-call policy evidence and authority additionally preserve the exact `policySubjectKind='ordinary_tool'` XOR `child_delegate` plus required `childMode`; verifier, dependency, delivery, MCP-server, and child named-action fields byte-match the complete prospective `ApprovalSubject` and `OperationGrantV1`, not merely their target string.

18. **Wire tools through one execution context.** Detached `read`/`edit`/`bash`/verifier operations receive only immutable inputs, generation identity, sandbox launch service, opaque broker client capability, grant reference, exact lease/worker/containment identity, and absolute deadline. They cannot select host `cwd` or environment from model input. Existing path normalization remains defense in depth; the OS boundary is final enforcement.

19. **Preserve honest result semantics.** A worker can produce workspace and source artifacts, but only work package 5 may create a verified `RunResult`, set `succeeded`, or materialize to the real workspace. This package must not add an implicit copy-back path.

Reuse existing code:

- Preserve `src/session/trust.ts` decision semantics and fail-closed non-interactive behavior, but replace any canonical-realpath hash as authority with the exact descriptor-derived `WorkspaceIdentityV1` contract.
- Preserve policy modes and approval-subject concepts by freezing them into canonical `RunPolicySnapshotV1.decisions` plus exact ordered `decisionRules` under `cliq-permission-grammar-v0`; replace their `ModelAction` coupling through work package 2 rather than creating a second or recovery-time permission system.
- Reuse tool JSON Schemas and path checks as input validation.
- Reuse reflink/copy experiments and symlink-escape tests from `src/workspace/transactions/staged-view.ts`, but not bind paths or its security claims.
- Reuse diff, validator, apply-recovery, path-lock, and ghost-checkpoint lessons where their invariants still apply.
- Reuse current provider adapters behind the broker boundary; do not duplicate provider protocol clients.

Preserve / do not touch:

- Workspace Trust remains independent from Tool Permission and Sandbox.
- Trust is decided before `.cliq/config`, validator suggestions, instructions, or skills are loaded; legacy hook/extension entries are inspected only for diagnostics after trust and are never executed.
- The user's real workspace is read during admission and explicit delivery only; a detached agent worker never mutates it.
- Historical checkpoint/transaction artifacts remain readable until work package 6 completes migration/cutover.
- Do not weaken legacy attached behavior before the Kernel Cut, but never count it toward the detach guarantee; work package 6 removes that owner at cutover and native Windows then fails execution admission explicitly.
- Do not add a `Task`, `EffectPlan`, workflow graph, in-process repository plugin, or weak worktree execution mode.

### Acceptance Criteria

- [ ] Workspace Trust is decided before any repository config, validator suggestion, instruction, skill, legacy hook/extension diagnostic, permission config, or runtime assembly is loaded; deny-path tests prove no repository-controlled file is read or executed, and allow-path tests prove legacy hooks/extensions are diagnosed but not launched.
- [ ] Capture, authorization, admission, apply, and publication require exact immutable `WorkspaceIdentityV1.kind='live'` and descriptor-reopen its root no-follow. Principal/platform/NFC absolute path/owner/device/file must match; device/file are canonical unsigned decimal strings never converted through JS number and owner uid is safe integer. Git additionally requires exact `RepositoryIdentityV1` ref+digest and held literal in-root `.git` identity/object format; non-Git forbids them. Every artifact workspace/repository digest is identical. `run.submit.workspacePath` must resolve to it; `run.apply` has no path and derives the live source Session. Root/`.git` replacement returns `ARTIFACT_MISMATCH`; `legacy_unavailable` Sessions/forks create no Run/effect.
- [ ] `WorkspaceEntryManifest`, `SourceManifest`, `GitIndexSnapshotV1`, `GitObjectPackV1`, `GitObjectClosureV1`, `SanitizedGitConfigV1`, `PrivateGitStateManifest`, and `WorkspaceStateManifest` use only canonical non-self-referential count/byte/tree/index/pack/closure/config/manifest/state equations. The index normalizer accepts only the bounded supported source grammar and emits exact extension-free v2 with `skipWorktree:false`; pack validation proves exact bytes/counts/trailer/object hashes/deltas/index; the closure's byte-sorted pack union equals every-and-only reachable object. Blob/target bytes, source tree, live workspace/repository Git XOR, base/projection, private Git iff Git, exact Head/index/byte-sorted refs/object closure/config, invalidated paths, and Checkpoint Run/base identities all revalidate. The config accepts only the displayed non-executable allowlist and rejects every hook/remote/credential/include/helper/alias/pager/filter/attribute/diff/merge/fsmonitor/sshCommand/worktree/system/global/environment key; no adapter-local/cyclic digest or opaque pack list is accepted.
- [ ] A real backend/worker/pinned-executable self-test is required before every Run admission; an unavailable or failing requirement rejects `run.submit|run.apply` before Run creation with exact `UNSUPPORTED_PLATFORM` or `UNSUPPORTED_EXECUTION_IDENTITY`. Read-only intent, text-only mode, no tools, or no required verifier never bypasses it.
- [ ] `RunAssemblyV1.sandboxBackend` is exactly `macos_vm|linux_namespace`. macOS Runs use only the bundled signed `Virtualization.framework` microVM with a pinned signed guest; Seatbelt-only macOS never admits any Run. Linux Runs require bubblewrap/user/mount/network isolation, a PID namespace, cgroup v2 kill/freeze/enumeration, and a trusted namespace init/subreaper. Missing any prerequisite fails admission.
- [ ] `sandboxProfileRef` decodes exact `SandboxProfileV1`: one strong backend, nonempty unique byte-sorted owner set, fixed typed-launch/no-host-filesystem/no-state-root/no-host-environment/no-network-at-spawn/broker-only-after-release policies, exact `SandboxResourceSpec`, and omission-rule digest. RunSpec/assembly/plan/launch/backend/resources equal it; admin/local profiles use exact owner sets. RFC defaults/ranges/fixed IPC limits are enforced by both strong backends, infeasible admission fails without silent increase, and PID/OOM/disk/output/IPC trips return typed `RESOURCE_EXHAUSTED` but cannot become positive no-effect evidence until full containment death and generation quiescence are proven.
- [ ] Every worker, Run invocation, admin probe, and managed local-inference service launch validates one exact `SandboxLaunchSpecV1`, recomputes every nested/spec digest, and byte-matches runtime/executable/`SandboxProcessInvocationV1`/profile/resources/environment/mounts plus `containmentPlanRef`/owner. Worker activation fixes the signed worker recipe, empty argv, generation-root cwd, blocked activation channel, and exact preactivated-read-only generation with no invocation/admin/service fields. Run invocation has the exact parent activation, claim, `OperationGrantV1`, request/target, purpose recipe, argv/cwd/stdio derivation, and purpose-specific filesystem. Admin probe has the exact AdminOperation owner/target/static preactivation `probePayloadCoreRef`/stdio-or-HTTP recipe and isolated empty root with no Run/lease/worker/frontier/Journal/grant/generation field; the later `AdminProbeBrokerRequest.payloadRef` must equal that core, and no post-containment request/dispatch identity may enter the pre-spawn spec. Local inference has the exact owner/principal/service launch/spec, signed `local_inference` entry/model manifest, isolated root, fixed entrypoint, loopback-only/no-egress envelope, and no Run/admin/grant/credential field. The launcher accepts no out-of-band process parameter or file descriptor. Cross-owner fields, raw host mounts/env, secrets, writable runtime/CAS, verifier RuntimeBundle, non-`mcp_server` RuntimeBundle MCP identity, non-`local_inference` service identity, backend/profile drift, process mapping drift, or any digest mismatch fails before containment creation/I/O.
- [ ] Every `isolated_empty_root` filesystem resolves exact `SandboxRootImageV1`, recomputes its omission digest, and matches one signed RuntimeBundle `sandbox_root_profile` entry by ref/manifest/id/version/digest. Only fixed Supervisor code may materialize the exact fresh tmpfs/directories/uid/no-network/nonpersistent profile; plan, launch filesystem, and actual containment repeat one identical root-image ref+digest. Missing digest, host/mutable/caller-selected/reused roots, extra device/socket/network state, or persistent bytes are rejected.
- [ ] macOS `assemblyRef` includes an exact `GuestToolchainManifest` whose omission-rule `manifestDigest` and `signatureRef` verify through the bundled Cliq release key. Its `guestImageRef` retains the complete immutable `raw-ext4-v1` bytes, `guestImageDigest` equals their SHA-256/ArtifactRef, and `guestImageByteCount` is the exact positive safe-integer size. Boot and launch verify image/ABI plus every executable path/digest/version; containment plan, runtime binding, actual containment, launch evidence, assembly GC, and reboot recovery repeat and rehash the identical image ref/digest. Digest-only/current-installed-image lookup, missing bytes, host-only or incompatible identities fail before admission with `UNSUPPORTED_EXECUTION_IDENTITY`, and the guest receives no ambient dependency/network fallback.
- [ ] Exact `AuthorizationGrantV1` target validation permits verifier execution identity only from signed guest toolchain or root-relative workspace script and rejects every RuntimeBundle verifier target. Every workspace script requires exact `InterpreterIdentityV1` ref+digest matching the retained signed guest toolchain entry, version/path/executable digest, consumed grant, SandboxExecutable, and literal first-argument protocol; optional interpreter, shebang/PATH/ambient shell, host interpreter, or mismatch fails before launch. Stdio MCP requires its exact named consumed grant id and matching `AuthorizationConsumptionReceiptV1` ref/digest, and permits only the receipt-authorized signed guest-toolchain identity or a retained signed RuntimeBundle entry whose role is exactly `mcp_server`; all other bundle roles, workspace scripts, mutable host paths, opaque executable refs, missing receipts, or cross-registration consumption fail before launch.
- [ ] `RunSpec` freezes the exact Node `DependencyPolicy`, while each FinalCandidate derives a fresh immutable `DependencyAcquisitionPlan` from its own exact root `package.json` and exactly one literal root lockfile and binds it into `VerifierPlan`; an admission-time plan is never reused. The plan has the literal format, one manifest ref/digest, adapter-to-lockfile-path union, pinned guest toolchain, byte-sorted endpoint/grant projection, limits, and recomputed omission digest. Workspaces, nested manifests/lockfiles, multiple supported root lockfiles, missing integrity, and adapter/path ambiguity fail before package-manager execution. Script authorization atomically consumes the exact dependency-script `AuthorizationGrantV1` into exact `DependencyInstallScriptsAuthorizationTemplateV1`, and every script-bearing candidate uses an exact template-provenance `OperationGrantV1` with one unused generation ordinal. Lockfile/registry/toolchain/adapter/policy/ordinal drift cannot reuse either authority. The broker fetches bounded content-addressed artifacts without exposing credentials; install is networkless, and the candidate source projection stays read-only while only disjoint declared dependency/cache/temp roots are writable. Before success, Cliq recomputes `resultSourceRef` under the frozen projection and requires equality with the frontier's pre-acquisition value. Any attempted write/drift publishes exact dependency `KernelIntegrityEvidenceV1`: audited-blocked branch repeats exact request/containment/SandboxLaunch/path/access and equal before/after source; drift branch rehashes unequal manifests and a unique nonempty byte-sorted changed-entry set, with exact source XOR—trusted out-of-containment rehash forbids both containment/spec while claimed-process rehash requires both and matches the claim. Its Run/projection/generation/inspector/plan/op/attempt and omission digest match, and the `kernel_integrity/runtime_failed` StopIntent repeats the same ref+digest. The generation is death-proven/quarantined and no readiness/completion is published; generic/asserted/unaudited evidence is rejected. Only an unchanged candidate uses one atomic ready transaction whose exact `DependencyReadyItem` plan/op/attempt/cache fields match the completed acquisition, whose `readyCheckpointId` names the same-transaction post-effect Checkpoint, and whose `installedTreeDigest` equals decoded `Checkpoint.workspaceStateRef -> WorkspaceStateManifest.entriesRef -> WorkspaceEntryManifest.treeDigest`; that transaction also commits settlement and verifier-frontier advance.
- [ ] Native Windows and unenforced macOS/Linux hosts reject Run admission; there is no workerless restricted-read, weak worktree, Seatbelt-only, unsandboxed attached, or text-only fallback Run.
- [ ] Non-Git workspaces are admitted only through the same strong backend, private generation, worker activation, Journal/claim, and Checkpoint contract. Their recovery manifest forbids `privateGitStateRef`, they receive no synthetic `.git`/repository identity, and Git absence cannot weaken filesystem, mount, network, permission, or containment rules.
- [ ] A detached worker can write only its activated private generation but cannot read provider credentials or write the real workspace, source `.git`, another generation, Supervisor/CAS/SQLite state, undeclared home paths, or undeclared external roots. macOS exposes no writable host share to the guest.
- [ ] The worker environment contains no provider key and no unapproved inherited environment variable; `HOME` and `TMPDIR` resolve inside private per-Run roots.
- [ ] Direct network from detached Bash is denied. There is no generic integration/network tool or child endpoint capability; only exact-grant model, dependency-registry, and streamable-HTTP MCP broker requests reach their frozen target and produce Journal evidence.
- [ ] Every broker/sandbox authority path accepts only Supervisor-injected exact local principal/channel artifacts; UDS channels transitively validate exact `LocalSocketPeerObservationV1`, while in-process channels bind the signed process. Caller/worker/environment-supplied identity is rejected. All grant/deadline/lease/release comparisons use canonical UTC-millisecond checked math and a healthy `CanonicalTimeFenceV1`; clock regression makes both dispatch gates and all broker/admin release gates fail closed, revokes tokens, and quiesces active containment without extending authority.
- [ ] `RunPolicySnapshotV1.engine` resolves exact `PolicyEngineProfileV1` from the sole signed non-executable RuntimeBundle `policy_engine` data entry: entry id/version match, the signed complete-file `entry.digest` equals `engine.profileRef`, and decoding those exact bytes independently yields the self-omitting `profileDigest===engine.profileDigest`. The complete-byte ref and semantic digest are distinct hash domains and are never equated. Fixed Supervisor code alone interprets the profile and no helper process/plugin/SandboxLaunch is legal. `decisionRules` is interpreted only as exact bounded `cliq-permission-grammar-v0`. Every evaluation artifact-first publishes exact `PolicyChannelEvidenceV1`; storage reruns the fixed interpreter/profile and validates principal/Run/policy/frontier/op/request/target/action/time, omission digest, exact filesystem/MCP/plan/Bash/named-action projection, deterministic Bash parse, exact verifier/dependency/delivery/MCP-server/child identity key, matching-rule/mode precedence, and effective disposition. Policy allow, approval ask/allow/deny, `PolicyDecisionItem`, and policy/user `OperationGrantV1` provenance preserve the same ref/digest pair. Recovery reuses that immutable policy/profile/evidence; no renamed rule field, reduced approximation, mutable hook/parser/profile, executable helper, host-shell reparse, caller boolean, policy text, coarse mode-only proof, or local matcher dialect can mint authority.
- [ ] Every stdio MCP tool call starts one fresh strong-sandbox process/containment with fresh empty private `HOME`/`TMPDIR`, read-only registered executable/toolchain, no workspace/Cliq-state/persistent writable mount/network/secret access, and exact Run/batch/call-index/call/server/lifecycle identity. It has its own launch and call grants/Journal claims, is torn down with whole-containment death proof after the call, and is never reused by another call.
- [ ] Every containment validates the exact canonical `ProcessContainmentOwner` union. `worker_activation` is top-level/run-generation; `run_invocation` has exact `opId/attempt/dispatchId`, a mandatory same-activation parent chain, and its frozen invocation filesystem binding; `admin_probe` and `local_inference_service` are top-level/isolated-empty-root with their exact admin or owner/service/spec/Supervisor identity. Every invalid owner↔parent/filesystem cross-product fails closed.
- [ ] `PlatformProcessIdentityV1` accepts only a positive safe PID, NFC-ASCII native start token, same-user uid, signed-Supervisor executable-image digest, bounded observation, and omission digest. `StateRootIdentityV1` accepts only the component-wise no-follow held same-user `0700` root descriptor with normalized absolute path, unsigned-decimal device/directory-file ids, layout 1, and omission digest; replacement/rename/owner/mode/path disagreement blocks authority. `StateLockIdentityV1` accepts only the held no-follow same-user regular state-owner lock descriptor whose exact root ref+digest equals that descriptor parent, plus literal path, unsigned-decimal device/file ids, uid, mode `0600`, link count one, and omission digest. PID-only, caller path, root reopen, replaced descriptor, or ref/digest mismatch is invalid.
- [ ] `state_owners` accepts only exact record/acquisition/transition types, contiguous epochs, one active row, and exact phase XOR. Genesis epoch one names an as-yet-unowned exact `KernelGenerationIdentityV1`: fresh-empty validates empty database/CAS; migrated-candidate requires matching durable Kernel authority marker/candidate/image/CAS closure and is first post-cutover repository transaction. Clean acquisition and death takeover retain their exact predecessor/successor proofs. Only three named APIs bypass active ownership and write named metadata/rows under held root/lock; lock loss/mismatch gates every other write/release and history is never reset or collected.
- [ ] Every actual `ProcessContainment`, `ProcessContainmentNoSpawnEvidenceV1`, and `ProcessContainmentDeathEvidenceV1` repeats the exact owning `sandboxLaunchSpecRef` and recomputed digest. Every no-spawn/death artifact also repeats the exact `SupervisorInspectorIdentityV1.identityDigest`; its signed RuntimeBundle `supervisor` entry, executable version/digest, sole active `StateOwnerRecordV1` epoch/process-ref+digest/lock-ref+digest/nonce/Supervisor identity, and at-most-five-second observation are revalidated inside the evidence transaction. A plan/spec/owner/nonce/backend/inspector/bundle/state-owner mismatch cannot spawn, retire, checkpoint, publish, expose local model traffic, or enable replacement.
- [ ] Every worker identity resolves only to its exact `worker_activation` containment; every invocation containment resolves to the exact durable Run claim; every admin containment resolves to its exact AdminOperation attempt/principal/method/`originalRequestDigest`/target/Supervisor; every local-service containment resolves to its exact owner/principal/service launch/spec/Supervisor. Cross-owner Run/epoch/worker/generation/admin/service fields are rejected. Fork, double-fork, daemon, re-parent, and PID-reuse fixtures remain inside the applicable boundary, and termination proof covers every descendant rather than only the root PID.
- [ ] Managed local-service tests enforce exact launch-to-`LocalInferenceActivationCycleV1` service/spec/id/attempt/current-launch equality and the exact `LocalInferenceServiceLaunchV1` phase/forbidden-field matrix, including `reserved -> retired(no_spawn)` and `preactivated -> retired(death)` crash closure. `retirementKind='no_spawn'` is legal only from `reserved`, has no process/boundary/quiesce fields, and validates exact no-spawn evidence; `retirementKind='death'` from preactivated or revoking requires the exact created containment/quiesce/death evidence and includes boundary evidence if and only if the launch was active. No model byte crosses before active boundary evidence, no cross-cycle/stale/attempt-3 launch reaches the backend, and no successor exists before one terminal proof plus cycle authorization.
- [ ] `LocalZeroCostProvenanceV1.stableServiceIdentityDigest` covers the canonical owner/service/spec/runtime/model/backend/no-egress projection. A death-proven replacement reproduces that stable projection but must use fresh launch/containment/plan/SandboxLaunch/inspector/observation identity; an ambient or merely loopback-compatible daemon and a copied old dynamic identity both fail before broker traffic.
- [ ] A preactivated worker/guest starts blocked with no broker credential, generation write capability, network, provider handle, or sandbox-launch authority. Only a successful authoritative lease CAS followed by a matching single-use activation capability can make it productive; every failed/abandoned intent is destroyed and proven empty before replacement.
- [ ] Activation/broker capabilities bind the exact `supervisorInstanceId`. A successor Supervisor accepts no old handshake, channel, heartbeat, or broker request even when the persisted lease is unexpired; it must kill/prove/quarantine before any fresh generation/launch can receive authority.
- [ ] Admission captures tracked, dirty tracked, ordinary non-ignored untracked, symlink target, executable-bit, and explicit-include state without changing the source index or working tree.
- [ ] Admission publishes exact `SanitizedGitConfigV1` and exact `PrivateGitStateManifest` or rejects the repository. It never interprets/copies a non-allowlisted config key; `include`/`includeIf`, helpers, aliases, pagers, filters/drivers, fsmonitor, sshCommand, system/global/environment config, external `core.excludesFile`/`core.attributesFile`, and every other key fail before any external target is opened. No Workspace Trust decision, policy, or grant turns external Git config into readable input.
- [ ] `sourceProjectionRef` is frozen after trust from CLI/API or trusted config, uses hard-exclude > explicit-exclude > explicit-include > default precedence, and cannot be changed by the model or a later `.gitignore` edit.
- [ ] Every submodule/Gitlink, LFS-filtered path, nested repository, special file, unsafe symlink, case collision, and unstable capture fails with a precise path/reason rather than a partial manifest; non-source metadata is explicitly not promised.
- [ ] Every mutating lease gets a new generation with an independent `.git`; `git rev-parse --git-common-dir`, alternates, inode/hardlink, symlink, and ref-mutation tests prove it shares no mutable Git state with the source.
- [ ] Running `edit`, Bash, builds, tests, and verifiers changes at most the generation/declared verifier-ephemeral roots; verifier source writes are denied, completed digest changes and auditable source-write violations are fatal, and no claim is made that a verifier-caught read-only error is observable. Concurrent user edits in the real workspace remain byte-for-byte untouched.
- [ ] `workspaceStateRef` restores generated recovery state while `resultSourceRef` excludes ignored caches, dependency trees, verifier outputs, ephemeral paths, and every secret-bearing input; only ordinary files explicitly admitted to source/result scope may enter the result.
- [ ] New ordinary non-ignored source files, tracked deletions, binary changes, executable modes, and safe in-root symlinks appear deterministically in `resultSourceRef`; unsafe, colliding, special, or over-limit paths fail result construction with an exact reason.
- [ ] `cliq-exact-path-v1` rejects glob/regex/`..`/separator/normalization ambiguity, matches entry/subtree component boundaries byte-exactly without following symlinks, and applies exclude precedence deterministically.
- [ ] Repository-requested ignored in-root selectors remain inert without exact user policy/durable grants; Workspace Trust alone cannot copy them into CAS, worker, model context, or `resultSourceRef`. Every selector is root-relative, and all outside-root selectors, external filesystem inputs, config includes, symlink escapes, and arbitrary mounts are rejected rather than authorized.
- [ ] Every generation ref decodes exact `WorkspaceGenerationIdentityV1`; source Checkpoint/state/tree and platform locator revalidate, and `generationId` follows the canonical Run/Checkpoint/state/nonce formula. `workspace_generations` alone stores exact `WorkspaceGenerationStateV1`; CASes enforce the full success spine, worker-loss `fenced_reconciling` wait binding, every closed failure/quarantine edge, branch XOR, positive row version, launch/epoch equality, and same-transaction WorkerLaunch projection. Snapshot evidence proves descriptor rewalk plus all fsyncs. Quarantine binds current `sourceRowVersion`, the deterministic sole target, exact complete-tree-or-unreadable observed state, and the full materialization/preactivation/launch-abort/launch-death/worker-recovery/checkpoint-failure matrix. Both worker-recovery dispositions quarantine the old fenced row; restore additionally requires a distinct `preactivated_readonly` generation from a ready Checkpoint. Retirement is exact sealed+death XOR quarantined+current literal zero authority counts. No branch reopens the old identity.
- [ ] `quiesceGeneration` blocks new dispatch, reaches the authenticated barrier, terminates and reaps every contained descendant, acquires the exclusive checkpoint write token, revalidates and double-checks the complete manifest, then publishes context/Checkpoint/Run/event plus any pending Journal result/item/budget settlement in one state transaction. Every Run-visible workspace effect includes its mandatory Journal/result/settlement in that transaction; no ready Checkpoint or workspace result exists without the sequence.
- [ ] Crashes or failures at every materialization/preactivation/quiesce/death-proof/snapshot/fsync/SQLite boundary leave the prior ready Checkpoint authoritative, publish no Run-visible result, and allow the dirty generation to enter quarantine only through exact `WorkspaceGenerationQuarantineEvidenceV1`. No replacement worker uses it; retirement requires exact `WorkspaceGenerationRetirementEvidenceV1`, and incomplete evidence remains recoverable rather than being inferred from a path or timeout.
- [ ] Every Run Broker/Journal `grantRef` decodes as exact `OperationGrantV1`; policy decisions, approval payloads, `AuthorizationGrantV1`, verifier/install-script templates, and opaque refs are rejected. `claimDispatch` atomically reads the Run, exact `activeWorkerLaunchId` row, and matching authoritative workspace-generation row and validates current status/revision/epoch, launch `phase='activated'`, both denormalized and authoritative generation phase `active`, identity/containment/generation/live lease/stop/cancel/deadline plus the complete grant subject/provenance/use/expiry/target/request/frontier/attempt/reservation/`prepared` closure before appending one `dispatch_claimed` fact. `releaseClaimedDispatch` repeats every live predicate, the same generation row, and the same exact grant closure for that `dispatchId` immediately before any capability, secret, executable start, or request byte is released; failure reaches no target.
- [ ] After a StopIntent, `claimRecoveryMaintenance`/`releaseRecoveryMaintenance` is the sole new mutation claim and permits only receipt-proven abort removal of one exact delivery-created empty directory, with current Supervisor/epoch, zero reservation, no worker launch, and historical exact-plan authorization even if the productive grant expired. Exact cleanup inside an already-claimed leaf remains on that original claim. Neither path can create/replace/delete a desired path, write a file, widen a target, consume productive budget, or become a generic retry.
- [ ] `assertEvidenceAuthority` accepts only claim-bound authenticated evidence from the original invocation identity and never authorizes productive I/O. Evidence for the still-highest attempt/exact frontier or reconciliation subject may enter its typed terminal reducer despite lease clearing or post-dispatch cancel/deadline/grant expiry; superseded evidence is audit-only and cannot replace a newer result or advance the frontier.
- [ ] Broker and sandbox launch require the unique durable `dispatch_claimed` fact; concurrent duplicate frames reach the target once. The claim remains singleflight until the invocation's terminal/unknown fact, and restart/timeout/lease loss never redispatches the same attempt.
- [ ] Admin preactivation records the inspected `admin_probe` containment only as `AdminOperation.phase='active', probeDispatch.state='blocked'`; it creates no Run, `worker_launches`, Journal, Checkpoint, budget, frontier, or generation authority and releases no capability before that commit.
- [ ] `AdminProbeDispatchState` is embedded in the exact AdminOperation row and row-version CAS permits only permanent `blocked -> claimed -> released`. `claimAdminProbe` and `releaseAdminProbe` validate the same attempt/request/target/principal/Supervisor/containment/grant/endpoint/live-lease/deadline facts; duplicate frames join one dispatch and a failed second check reaches neither executable nor network target.
- [ ] `AdminProbeBrokerRequest` matches the canonical target union, deterministic request id, exact target/payload ref+digest pairs, and no Run authority field. Those pairs equal the row/target/static core/spec/plan closure. Stdio releases only the frozen secretless/networkless executable; HTTP redeems only exact endpoint-bound credentials inside the broker; no secret enters containment or retained output.
- [ ] Exact result is released-dispatch-only and repeats operation/attempt/request/target/core/containment with every digest. The target accepts only exact `RequestedMcpRecoveryV1` intent, and the result accepts only exact raw `McpProbedToolInterfaceV1[]` plus `probedToolsListDigest`; final recovery/profile/template/predicate/tool-contract/list/registry fields are rejected before I/O or completion. Every terminal closure repeats target plus planned-containment and SandboxLaunch ref+digests; no-spawn/death XOR, dispatch/request conditionality, inspector and underlying evidence validate. Exact error repeats closure; deterministic versus recovery codes alone select disposition. All terminal pairs and forbidden fields are enforced.
- [ ] An active admin probe cannot complete or fail until that exact closure proves the whole containment dead/reaped and no broker/launcher I/O or process remains; preactivation failure instead requires exact no-spawn closure. Timeout, expiry, Supervisor loss, root PID exit, or inaccessible containment is not proof, no successor adopts/re-releases it, and no later attempt begins before durable error/closure/backoff.
- [ ] Run-context compaction crosses the broker only as an exact tools-disabled, plan/frontier-bound, Journaled model invocation with ordinary budget/dispatch fencing and a 256 KiB complete-Markdown result cap. Tool calls or non-complete/oversize results cannot become actions; raw items remain durable and the success Checkpoint reuses unchanged workspace state.
- [ ] Grant expiry is checked by both dispatch gates. Pre-claim expiry commits only the exact Journal pre-dispatch failure: the same transaction proves no claim, forbids claim/spec/evidence fields, consumes zero, and releases the reservation. Post-claim/pre-release expiry produces trusted positive no-target closure for that permanent claim; expiry only after successful release cannot rewrite the started outcome. Stdio MCP launch capacity is call-scoped: expiry or `maxLaunches` exhaustion creates the exact batch/index-bound approval subject and never leaves a reusable server process.
- [ ] Supervisor-only reconciliation can query only the exact declared reconcilable operation and cannot dispatch an opaque effect or bypass positive-evidence Journal resolution.
- [ ] `worker_launches` is the sole generation-write/lease authority. Row heartbeat renewal never changes Run revision/event or reactivates a write gate; activation/retirement atomically changes the Run pointer/revision. A stale worker cannot commit state, pass either dispatch gate, write a new generation, or reach the real workspace.
- [ ] Timeout, worker death, or broker disconnect does not fabricate `failed`; ambiguous effects are Journaled `unknown` and follow ReplayClass. Settled/fenced `retry` may retry/abandon, workspace effects need rollback proof, and only unresolved `reconcile|manual` waits; opaque effects are never blindly replayed.
- [ ] No path copies a result back to the real workspace or marks a Run `succeeded`; only the delivery and verification package may do so.
- [ ] Sandbox escape and stale-worker fault tests run on both supported OS families in release CI.

### Validation

Automated:

- `npm run build`
- `npm test`
- `npm run test:sandbox` (added by this package; runs backend probes, exact `SandboxLaunchSpecV1` digest/four-owner/forbidden-field/runtime/process-recipe/argv-cwd-stdio/env/filesystem/mount/profile negative matrix, `SandboxRootImageV1` signed-role/fresh-tmpfs/ref-digest/no-persistence matrix, exact mandatory `InterpreterIdentityV1`/workspace-script/grant/command binding, out-of-band process-parameter/fd rejection, exact resource-limit trips, guest-manifest/image/executable identity checks, exact `PlatformProcessIdentityV1`/`StateRootIdentityV1`/`StateLockIdentityV1` ref-digest/no-follow/root-and-lock-replacement matrix, `StateOwnerAcquisitionEvidenceV1` genesis/clean-acquire/takeover and three-entrypoint matrix, `StateOwnerTransitionEvidenceV1` graceful/takeover/lock/successor matrix, `StateOwnerRecordV1` epoch/OS-lock/old-process transition, and `SupervisorInspectorIdentityV1` signed-bundle/executable/active-owner/digest/freshness validation, verifier-versus-MCP authorization-target/RuntimeBundle-role rejection, `cliq-permission-grammar-v0` golden decisions, exact `OperationGrantV1` broker rejection, locked dependency fetch/install/template/ordinal authorization, call-scoped stdio MCP process isolation/teardown, four-branch containment-owner/XOR validation, local-service phase/retirement/stable-projection/replacement fencing, exact admin terminal result/closure/error isolation and credential-broker tests, escape cases, secret-environment checks, generation isolation, broker fencing, and supported-platform integration tests)
- `npm run test:fault` scenarios for kill-before/after broker dispatch, lease takeover, workspace snapshot publication, and generation quarantine
- On macOS CI, verify helper/guest signatures and execute the real `Virtualization.framework` microVM integration suite against temporary dirty Git and non-Git workspaces; separately prove a Seatbelt-only host cannot admit even read-only/text-only/workerless Runs and that Seatbelt inspection helpers create no Kernel truth.
- On Linux CI, execute the bubblewrap + PID namespace + cgroup v2 + subreaper integration suite against a real temporary Git repository; a missing control is a failed strong-mode job, not a skipped pass.
- Fault tests cover worker, admin, and managed local-service preactivation; local no-spawn/death retirement XOR, traffic-before-boundary denial, row-only lease, Supervisor no-adoption, and fresh dynamic replacement; every embedded admin `blocked -> claimed -> released` CAS boundary; duplicate admin frames; stale row/request/target/grant/endpoint/containment/Supervisor/lease/deadline at both admin gates; credential redemption only after release; admin containment/I/O death proof; launch-row activation; duplicate Run dispatch frames; pointer/row revocation between `claimDispatch` and `releaseClaimedDispatch`; every `claimRecoveryMaintenance`/`releaseRecoveryMaintenance` deny predicate; grant expiry before claim/between claim-release/after release; row-only heartbeat races; descendant double-fork escape attempts; all-descendant termination; and every `quiesceGeneration` publication boundary.
- Broker contract tests prove compaction is tools-disabled and plan/frontier-bound, rejects tool/truncated/filter/cancel/unknown/oversize results without action interpretation, preserves raw items, and cannot change `workspaceStateRef`.
- Admission tests configure external `core.excludesFile`, `core.attributesFile`, `include`, and `includeIf` targets instrumented to detect opens; every case fails closed without reading target bytes, including when a matching generic read grant exists. Root-relative selectors and descriptor-validated in-root ignore sources continue to work.
- Workspace-identity tests cover live/legacy-unavailable forbidden fields and execution rejection; maximum-width root/`.git` device/file decimal strings; sign/leading-zero/unsafe-owner rejection; literal `.git` directory/ref/digest/object-format equality and file/link/outside/linked rejection; symlink and same-path root/`.git` replacement races; Git/non-Git capture; `run.submit` path equality; pathless `run.apply` live source-Session derivation; and cross-artifact workspace/repository-digest mismatch. No test helper may substitute `realpath` text or JS-number inode/device values.
- Dependency fault tests make an install script attempt a candidate-source write, simulate an audited denied write, mutate the candidate digest at every pre-commit boundary, and crash after dependency/cache writes. Every case proves descendant death, quarantines the generation, records kernel-integrity evidence, publishes no `DependencyReadyItem`/ready Checkpoint/frontier advance, and never lets a stale digest reach a verifier.

Manual:

- Start a dirty Git repository Run with `cliq run --detach`, close the terminal, edit the real workspace, reattach, and confirm the real workspace was not changed by the worker.
- Inspect the worker's effective environment without printing values and confirm known provider variable names are absent.
- Attempt writes to the real workspace, source `.git`, `$CLIQ_HOME`, another generation, home, and `/tmp` outside the assigned private temp root; each must fail at the OS boundary.
- Attempt direct DNS/TCP access from Bash, then perform an allowed brokered provider/tool call; only the brokered call succeeds.
- Invoke the same registered stdio MCP tool twice from distinct batch/call identities; confirm different process/containment identities and empty `HOME`/`TMPDIR`, no cross-call file/session state, no network/secrets/workspace access, and complete death proof after each result.
- Kill a worker during a broker call, leave a double-forked descendant alive, and confirm no replacement worker starts until the whole cgroup/VM boundary is proven empty and the claimed invocation is reconciled.
- Pause/fail preactivation before and after activation CAS; confirm the blocked worker performs zero writes/broker calls and recovery destroys the launch containment before any replacement.
- Pause after `claimDispatch`, then revoke the active launch row, install a StopIntent, expire the grant, and independently advance only its heartbeat. Confirm the first three cases make `releaseClaimedDispatch` refuse target I/O, while a still-live heartbeat-only renewal preserves the same active launch identity and does not revise the Run.
- Register one stdio and one streamable-HTTP MCP target, pause each admin attempt before claim and between claim/release, then independently drift row version, target, grant, endpoint, containment owner, Supervisor, lease, and deadline. Verify failed gates release nothing, duplicates never dispatch twice, HTTP secrets exist only in the trusted broker, and completion/retry waits for full containment plus no-live-I/O proof.
- Reserve a managed local-inference service and crash once before spawn and once after activation. Verify the first row retires only as `no_spawn`, the second only as `death`, no old process is adopted, no traffic crosses a stale boundary, and the replacement retains the stable service identity while using fresh dynamic launch/containment identities.
- Trigger a mutating tool, crash at each `quiesceGeneration` step, and confirm recovery selects either the prior Checkpoint or the single complete post-effect Checkpoint, never torn workspace/context state.

### Risks And Dependencies

- The signed macOS helper/guest image creates a release, notarization, update, and CVE-response obligation. Signature/digest verification and a tested guest update path are release gates; Seatbelt is not an emergency mutation fallback.
- Linux strong mode depends on bubblewrap, user/PID namespaces, delegated cgroup v2 control, and the trusted subreaper. Distribution or systemd policy may make the complete backend unavailable; runtime probes and fail-closed admission are release requirements.
- Large repositories and byte-copy fallback can make admission and Checkpoint creation expensive. CAS deduplication, reflink/clonefile, incremental manifests, and retention limits may optimize cost without weakening semantics.
- Git submodules, LFS, nested repositories, unusual file modes, path normalization, and concurrent source changes are correctness hazards; the initial contract explicitly rejects Gitlinks/LFS/nested/special paths and never silently approximates them.
- Linux namespaces/cgroups constrain host processes but are not a hypervisor boundary; macOS strong mode is a local VM boundary. The different threat assumptions and probe evidence must be documented honestly without claiming equivalence.
- Secret redaction is defense in depth, not the primary boundary. Secret-bearing inputs and provider/integration credentials remain opaque broker references and never enter the general agent worker, workspace snapshots, prompt artifacts, or event payloads. Because a writable process could copy a raw mounted secret, this Kernel Cut deliberately provides no raw secret mount to the general worker.
- MCP registration probes share strong containment and the trusted broker without sharing Run authority. A containment-owner decoding bug, stale embedded admin dispatch state, or pre/post-release TOCTOU could leak endpoint credentials or duplicate a probe; exact canonical types, row-version CAS, endpoint/grant revalidation, broker singleflight, and whole-containment/no-live-I/O fault tests are release gates.
- Locked dependency acquisition expands the trusted broker/guest-adapter supply chain and install scripts remain arbitrary package code. Integrity-complete lock resolution, endpoint/credential registration, explicit script authorization, a read-only candidate source projection with disjoint dependency/cache/temp write roots, pre-completion result-digest equality, integrity quarantine, strong containment, byte/package ceilings, and atomic rollback/Checkpoint fault tests are release gates; unlocked fallback is forbidden.
- Fresh stdio MCP containment and durable model compaction add startup/model latency. Process pooling, hidden server sessions, implicit provider truncation, or raw-item deletion are not permitted optimizations; cache only immutable toolchain/CAS bytes and optimize launch/summarization without weakening call isolation or recovery evidence.

Required sequence:

1. Work package 1 must provide authoritative Run plus `worker_launches` snapshot reads, row-only heartbeat CAS, pointer/launch activation and retirement transactions, ready Checkpoints, append-only Journal transactions, `claimDispatch`/`releaseClaimedDispatch`, zero-additional-settlement superseded-evidence commits, and the exact embedded `AdminProbeDispatchState` row-version APIs `claimAdminProbe`/`releaseAdminProbe` before either Run or admin broker dispatch can be considered safe.
2. Work package 2 must provide typed tool invocations/replay classes plus the immutable `RunContextCompactionPlan` and exact compaction frontier reducer before detached tools or brokered compaction are enabled.
3. This package may implement capture, materialization, sandbox backends, and broker interfaces in parallel, but integration must preserve the mandatory security order.
4. Work package 4 supplies the durable `worker_launches` lifecycle, blocked activation/pointer CAS, narrow heartbeat, admin-operation preactivation/recovery orchestration, whole-containment/no-live-I/O death proof, typed worker-death reconciliation, waiting/cancellation, and recovery scheduling against this package's generation/broker interfaces.
5. Work package 5 consumes `workspaceStateRef`, produces `resultSourceRef`/delivery behavior, and supplies the immutable DeliveryPlan/receipt/abort-operation validators used by the narrow recovery-maintenance gate; it must not collapse the workspace/result references or widen that gate.
6. Work package 6 supplies generated dependency/authorization/MCP request schemas, durable user registry semantics, and exact execution/read/install-script grant validation before those inputs reach this package; it may switch the default only after cross-platform sandbox/fault gates pass. There is no intermediate release marketed as safe detach.

Rollback (only for hard-to-reverse changes):

- Before the Kernel Cut, disable admission into the new detached mutation path and retain private generations/CAS artifacts for diagnosis; never fall back to real-workspace Bash under a detached label.
- After cutover, rollback uses the RFC's explicit runtime rollback procedure. It preserves the new SQLite/CAS state and terminal results and may restore the old attached runtime, but it cannot reinterpret strong Run artifacts through the legacy runner.
- Generation cleanup is recoverable until retention expiry. A failed migration or sandbox rollout must quarantine rather than delete a generation referenced by a Run, Checkpoint, Journal entry, or result.

### Open Questions

- None. Platform support, mandatory strong backend for every Git/non-Git Run, signed guest identity, locked dependency acquisition, call-scoped stdio MCP, tools-disabled durable compaction brokering, canonical four-owner containment, non-adoptable worker/admin/local-service preactivation, local no-spawn/death retirement and stable replacement identity, Run and embedded-admin dual authority gates, admin HTTP secret placement, all-descendant/no-live-I/O proof, quiescent Checkpoint publication, workspace/result separation, durable dispatch singleflight, grant expiry, and fail-closed behavior are closed by this Kernel Cut. Changing one requires a new RFC.

### GitHub Issue Body

**Title:** `feat: add trusted execution and private Run workspaces`

Implement work package 3 from `docs/backlog/durable-verified-run-kernel/03-trusted-execution-and-workspaces.md` and the canonical Durable Verified Run Kernel RFC.

Deliver mandatory signed macOS `Virtualization.framework` microVM and Linux bubblewrap/PID-namespace/cgroup-v2/subreaper execution for every Run, with no Seatbelt/read-only/text-only/workerless fallback; frozen `GuestToolchainManifest`/`SandboxResourceSpec`; exact four-owner `SandboxLaunchSpecV1` with closed `SandboxProcessInvocationV1` source/recipe/argv/cwd/stdio derivation; source-read-only locked Node dependency acquisition with exact authorization-template/operation-grant ordinals and integrity quarantine; fresh call-scoped stdio MCP isolation; tools-disabled durable compaction brokering; powerless non-adoptable worker/admin/local-service preactivation; canonical field-for-field four-owner whole-descendant `ProcessContainmentRef`; signed RuntimeBundle/state-owner-bound `SupervisorInspectorIdentityV1` on every no-spawn/death proof; exact local no-spawn/death retirement and stable-service replacement identity; quiescent atomic workspace Checkpoints; strong Git generations with independent `.git` and equally strong non-Git generations without synthetic Git state; distinct recovery/deliverable manifests; root-relative-only source inputs with fail-closed external Git/config/input/mount rejection; sanitized workers; exact-`OperationGrantV1` Run `claimDispatch`/`releaseClaimedDispatch`; exact embedded-`AdminOperation` `claimAdminProbe`/`releaseAdminProbe`; HTTP credentials confined to the trusted broker; and separate evidence authority. Enforce exact `RunPolicySnapshotV1.decisionRules` under `cliq-permission-grammar-v0`; reject RuntimeBundle verifier identity and permit RuntimeBundle stdio MCP only for signed role `mcp_server`. Absorb `#63`; integrate—not collapse—the permission work from `#62`.

Every source operation must require the Session's exact live no-follow descriptor-derived `WorkspaceIdentityV1` plus exact `RepositoryIdentityV1` iff Git; keep root/`.git` device/file ids as unsigned decimal strings, require every workspace/repository ref/digest match, make `run.submit` path equal that identity, derive pathless `run.apply` from the live source Session, reject `legacy_unavailable`, and fail same-path root/`.git` replacement as `ARTIFACT_MISMATCH`.

Done means every acceptance criterion and automated/manual validation item in the local spec passes. Do not admit any Run when its strong backend/worker/executable probes fail, do not expose provider secrets to workers, and do not add a result copy-back path.
