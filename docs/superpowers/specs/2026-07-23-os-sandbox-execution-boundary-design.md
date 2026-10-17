# Optional OS Sandbox and Execution Boundary for Agent Tools — Design Spec

**Status:** proposed; design and research only
**Date:** 2026-07-23
**Issue:** [#63 — Explore OS-level sandbox and execution boundary for agent tools](https://github.com/cogine-ai/cliq-agent/issues/63)
**Decision type:** security architecture
**Audience:** runtime, tool, policy, and platform maintainers
**Implementation status:** no production sandbox is implemented or authorized by this document

## 1. Decision summary

Cliq should add an optional **execution boundary** after Workspace Trust and Tool
Permission. The boundary will eventually constrain designated child processes
with OS- or container-enforced filesystem, network, environment, process-tree,
and resource limits.

The proposed architecture is a central process-launch contract with
platform-specific providers:

1. Workspace Trust decides whether workspace-controlled configuration and code
   may load.
2. Tool Permission decides whether the requested action may proceed.
3. The execution boundary resolves requested capabilities to an effective
   platform plan and launches the process tree.

The first production integration should target model-requested `bash` and its
descendants. Command hooks and shell validators require separate scope
decisions. In-process tools and workspace extensions cannot be contained by a
child-process wrapper and must not be described as sandboxed.

All restrictive behavior remains explicitly opt-in. `off` is the default and
must preserve current behavior. A strict `required` mode must fail closed when
the selected provider cannot enforce every requested restriction. Degraded
execution is permitted only under an explicit `best-effort` mode and must be
reported before launch.

This document does **not** select a production backend. Linux, macOS, Windows,
and network-allowlist research spikes must complete first.

## 2. Why this is a design spec

Issue #63 asks for exploration before implementation. The platform primitives
do not expose one equivalent portable sandbox:

- Linux has strong unprivileged building blocks, but their availability and
  coverage vary by kernel and distribution.
- macOS has App Sandbox for signed applications, while the dynamic
  `sandbox-exec` command available to local CLIs is deprecated.
- Windows has AppContainer, restricted tokens, job objects, and new
  experimental process-sandbox APIs, but their guarantees and minimum OS
  requirements differ.
- Hostname allowlisting is not a direct kernel primitive on all three
  platforms.

The safe outcome of this run is therefore an architecture, threat model,
capability contract, research backlog, and verification plan. It is not a
production sandbox.

## 3. Current Cliq architecture

### 3.1 Existing safety layers

The repository already defines the intended three-layer model in
`AGENTS.md`:

| Layer | Current owner | Question answered |
|---|---|---|
| Workspace Trust | `src/session/trust.ts`, CLI/headless entry points | May this workspace load repo-controlled state and enter the runtime? |
| Tool Permission | `src/policy/*`, command hooks, approval UI | May this requested action proceed? |
| Sandbox / Boundary | Not implemented | What can the process physically access if it runs? |

The public compatibility baseline is explicit in `README.md`: Cliq runs tools
on the local machine and “is not a sandbox.” The same section states that
trusting a workspace does not approve edits or shell commands.

### 3.2 Trust-before-load invariant

Workspace Trust canonicalizes the workspace path and keys the persisted
decision to that real path:

- `createWorkspaceTrustContext` and
  `evaluateWorkspaceTrustForNonInteractive` in `src/session/trust.ts`
- `ensureInteractiveWorkspaceTrustedForRuntime` in `src/cli.ts`
- the trust check before `createRuntimeAssembly` in `src/headless/run.ts`

After trust succeeds, `createRuntimeAssembly` in
`src/runtime/assembly.ts` loads `.cliq/config`, skills, extensions,
instructions, and command hooks. The execution-boundary configuration must
preserve this order:

- CLI/API/user-owned boundary configuration may be read before workspace
  trust.
- Workspace configuration must never enable or weaken a boundary before trust.
- If workspace configuration is allowed to request tighter constraints later,
  it may only intersect with the operator-selected policy after trust.

### 3.3 Permission-before-execution invariant

The current runner already provides the correct policy seam:

1. `buildToolApprovalSubject` in `src/policy/subjects.ts` classifies the action.
2. `createPolicyEngine` in `src/policy/engine.ts` applies policy presets and the
   permission table.
3. `composeRuntimePermissionTable` in `src/policy/compose-runtime.ts` composes
   built-in, workspace, persisted, CLI, and session rules after trust.
4. `src/policy/decision-table.ts` makes deny rules sticky across layers.
5. `createRunner` in `src/runtime/runner.ts` runs approval hooks and policy
   decisions before calling `ToolDefinition.execute`.

An approval means only “attempt this action.” It must not turn into a sandbox
capability grant, disable a sandbox denial, or permit a degraded backend.

### 3.4 Current execution surfaces

The following launch paths exist today:

| Process family | Current entry point | Current exposure | Initial boundary disposition |
|---|---|---|---|
| Model-requested shell | `src/tools/bash.ts` | `bash -lc`, workspace `cwd`, full `process.env`, detached POSIX process group | First production target |
| Repo-configured command hook | `src/hooks/runner.ts` | platform shell, workspace `cwd`, implicit parent environment | Separate scope decision |
| Repo-configured shell validator | `src/validators/shell.ts` | platform shell, staged-view `cwd`, full parent environment plus TX paths | Separate scope decision |
| Workspace JavaScript extension | `src/extensions/loader.ts` and `src/runtime/hooks.ts` | dynamically imported and executed inside the main Cliq process | Not containable by child wrapper |
| Structured read/edit tools | `src/tools/path.ts`, `src/runtime/workspace-writer.ts` | in-process Node filesystem calls | Existing path controls; not OS-sandboxed |
| Trusted internal Git/copy helpers | session, checkpoint, validator, and staged-view modules | mixed environment filtering and process behavior | Exclude initially; inventory separately |

`ToolContext` in `src/tools/types.ts` currently carries the workspace, session,
abort signal, writer, and transaction facade, but no process-execution
abstraction. The future boundary should be injected here (or through a
closely-scoped runtime service), rather than letting tools call
`node:child_process` directly.

### 3.5 Existing controls are not an OS boundary

Structured tools reject absolute paths, traversal, and realpath escapes in
`src/tools/path.ts`. Transaction overlays add further lexical and symlink
checks in `src/workspace/transactions/overlay.ts`. These checks are useful,
but they do not constrain a shell command, a package lifecycle script, or a
grandchild process.

Transactions are also not a sandbox. `bash` still runs against the live
workspace, and `src/runtime/bash-policy.ts` records observed path changes
rather than preventing access outside an allowlist. Staged views may include
configured symlinks back to live workspace paths in
`src/workspace/transactions/staged-view.ts`.

The `network` access channel in `src/policy/types.ts` and
`src/policy/network-placeholder.ts` is intent-only. No model-issued network
tool exists, and a shell command's egress cannot currently be derived reliably
from its text.

Model-provider HTTP in `src/model/http.ts` is host control-plane traffic. It
must remain outside a child-tool boundary unless a future whole-process design
explicitly brokers it.

## 4. Goals

1. Bound the blast radius of malicious, prompt-injected, compromised, or
   mistaken agent-tool subprocesses.
2. Keep Workspace Trust, Tool Permission, and OS enforcement independent and
   composable.
3. Preserve current behavior unless the operator explicitly opts in.
4. Expose requested, effective, degraded, and unavailable capabilities before
   a process starts.
5. Apply restrictions to the full descendant tree, not only the first shell.
6. Separate tool egress from model-provider and Cliq control-plane networking.
7. Define a portable capability vocabulary without claiming identical
   enforcement on every OS.
8. Make platform limitations testable through capability negotiation and
   negative probes.
9. Provide a staged path from research spikes to small production stories.

## 5. Non-goals

This proposal does not:

- implement or enable a sandbox;
- change any runtime default;
- mutate user, system, firewall, entitlement, installer, or service policy;
- install a privileged helper, kernel extension, driver, system extension, or
  network filter;
- claim protection from a compromised OS kernel, administrator, root user, or
  Cliq parent process;
- make `yolo` safe or equivalent to least privilege;
- replace Workspace Trust, approval prompts, permission hooks, path
  validation, transactions, or validators;
- guarantee portable hostname-based network allowlisting;
- contain workspace extensions that execute in the main Cliq process;
- prevent the selected model provider from receiving content that Cliq
  intentionally sends to it;
- provide a general multi-tenant isolation boundary.

## 6. Threat model

### 6.1 Protected assets

The boundary should protect:

- files outside explicitly readable or writable roots;
- provider credentials in environment variables and
  `${CLIQ_HOME}/auth.json` (`src/model/auth-store.ts`);
- session, trust, permission, transaction, and handoff state under
  `${CLIQ_HOME}` (`src/session/store.ts`);
- SSH, GPG, cloud, package-registry, browser, keychain, and credential-manager
  material;
- local service sockets such as SSH agents, Docker/container sockets, database
  sockets, and desktop IPC;
- host processes, clipboard/UI surfaces, devices, registry state, and kernel
  attack surface where the provider supports restrictions;
- local loopback services, private networks, link-local services, cloud
  metadata endpoints, and the public Internet;
- workspace integrity outside explicitly writable paths;
- availability within practical CPU, memory, process-count, output, and time
  limits.

### 6.2 Trusted enforcement inputs

For this threat model, the following are trusted:

- the shipped Cliq core and its boundary-plan resolver;
- the chosen, verified platform provider or helper;
- the OS kernel and mandatory access-control implementation;
- an operator-owned CLI/API request and any future user-local boundary config;
- the exact executable and profile artifacts selected by the resolver.

“Trusted workspace” is an authorization decision, not proof that every file in
the repository is benign. Repo code, dependencies, hooks, validators, and
commands remain potentially hostile inputs to the execution boundary.

### 6.3 Untrusted or mistake-prone inputs

Treat the following as untrusted:

- model output and tool arguments;
- user prompts containing mistaken or adversarial instructions;
- repository files, instructions, build scripts, package scripts, and
  dependencies;
- shell expansion, startup files, `PATH` resolution, and executable
  substitution;
- repo-configured command hooks and validators;
- tool output later reintroduced into the model context;
- symlinks, hard links, mount points, junctions, reparse points, and filesystem
  changes racing policy resolution;
- DNS answers, redirects, proxy responses, and resolved IP addresses;
- descendants spawned by an allowed command.

### 6.4 Attacker and mistake paths

The design must account for:

1. Prompt injection persuades the model to run an exfiltration command.
2. A user approves a plausible command whose package script performs an
   unexpected mutation.
3. A command reads provider keys from the inherited environment.
4. A tool reads `${CLIQ_HOME}`, `~/.ssh`, browser profiles, or cloud
   credentials.
5. A command writes through a symlink, hard link, bind mount, junction, or
   reparse point into a protected location.
6. A permitted parent forks, daemonizes, changes session/process group, or
   delegates work to a grandchild to outlive timeout handling.
7. A command connects through loopback, a Unix socket, a local-network
   address, an IPv6 literal, or a cloud metadata address despite “Internet
   denied.”
8. DNS rebinding or redirect handling changes an allowed hostname to a denied
   address.
9. An inherited file descriptor already references a protected file, socket,
   TTY, or control channel.
10. A fork bomb or high-output process exhausts local resources.
11. A workspace extension bypasses the child-process boundary by executing
    inside the main process.

### 6.5 Assumptions

- The Cliq parent is not already compromised.
- The boundary is applied before the child executes untrusted instructions.
- Dangerous inherited file descriptors are closed or explicitly enumerated.
- No provider grants setuid/setgid execution, new privileges, host namespace
  administration, or sandbox escape capabilities.
- Descendants inherit the boundary and cannot opt out.
- Platform detection is based on a runtime probe, not only the OS name.
- Profiles are constructed from canonical paths and validated again at launch.

### 6.6 Out-of-scope threats

- kernel, hypervisor, firmware, or hardware compromise;
- administrator/root deliberately changing the boundary;
- attacks by unrelated same-user processes that never enter the boundary;
- denial of service that exceeds available platform resource controls;
- side channels not addressed by the selected OS primitive;
- malicious code already running inside the main Cliq process;
- remote model-provider compromise or retention policy;
- physical access to the host.

### 6.7 Failure posture

| Situation | `off` | `audit` | `best-effort` | `required` |
|---|---|---|---|---|
| Provider unavailable | Launch unchanged | Launch unchanged and report unavailable | Launch only after visible degradation report | Refuse before launch |
| Requested feature unsupported | Launch unchanged | Report unresolved feature | Apply supported subset and report exact gap | Refuse before launch |
| Invalid profile | No profile is resolved when omitted; reject a malformed explicitly supplied request | Refuse plan creation | Refuse plan creation | Refuse plan creation |
| Enforcement setup fails | Not applicable | Record setup simulation failure | Refuse rather than launch unexpectedly unbounded | Refuse |
| Runtime denial | Not applicable | No enforcement | Return structured denial/error | Return structured denial/error |

No mode may silently change from `required` to `best-effort`, `audit`, or `off`.

## 7. Layer composition and ordering

```text
workspace path
    |
    v
[1. Workspace Trust]
    | deny -> no workspace config/runtime
    v
load trusted-workspace assembly
    |
model proposes action
    v
[2. Tool Permission + approval hooks]
    | deny -> tool result: denied
    v
resolve operator boundary request
    |
    v
[3. Execution Boundary]
    | unavailable/unsupported in required mode -> no launch
    | OS denial -> structured tool error
    v
sandboxed child process + descendants
```

Composition rules:

1. A denial at an earlier layer stops the flow.
2. Trust does not imply tool approval or boundary relaxation.
3. Tool approval does not imply OS access.
4. Boundary rules are an upper bound. A hook, workspace rule, session allow,
   or `yolo` mode cannot expand them.
5. The effective boundary is the intersection of all applicable
   operator-owned restrictions plus any workspace-requested tightening.
6. Workspace configuration must never select `off`, `audit`, or
   `best-effort` when the operator requested `required`.
7. A boundary denial is not a new permission request. The runtime may explain
   how to rerun with a different operator-owned profile, but must not ask a
   workspace hook to override the OS boundary.

## 8. Proposed configuration and API

The following shapes are proposals, not implemented interfaces.

### 8.1 Configuration sources and authority

Initial production scope should accept boundary configuration only from:

1. an explicit CLI flag/profile selection; or
2. a headless/SDK/RPC request field supplied by the host.

A future user-local config under `${CLIQ_HOME}` may provide defaults. A
workspace `.cliq/config` field should be deferred. If later added, it may only
tighten the operator-owned request after Workspace Trust succeeds.

Proposed precedence:

```text
hard built-in denials
    intersect operator CLI/API request
    intersect user-local defaults
    intersect optional workspace tightening
```

Unlike ordinary “last value wins” settings, capability sets compose by
intersection. A later source cannot recover a path, environment variable, or
network class denied by an earlier source.

### 8.2 Mode semantics

```ts
type ExecutionBoundaryMode =
  | 'off'
  | 'audit'
  | 'best-effort'
  | 'required';
```

| Mode | Semantics | Compatibility claim |
|---|---|---|
| `off` | Current process launch path; no OS-boundary claim | Default and byte-for-behavior compatible |
| `audit` | Resolve and emit the plan, but launch through the current path | Diagnostic only; never described as sandboxed |
| `best-effort` | Apply the supported subset and emit every degradation before launch | Explicitly weaker than requested |
| `required` | Launch only if every requested non-inherited restriction is enforced | Fail closed |

### 8.3 Capability request

```ts
type ExecutionBoundaryRequest = {
  schemaVersion: 1;
  mode: ExecutionBoundaryMode;
  profile: 'workspace' | 'custom';
  applyTo: Array<'model-tool' | 'command-hook' | 'validator'>;
  filesystem: {
    readRoots: string[];
    writeRoots: string[];
    denyPaths: string[];
  };
  network:
    | { mode: 'inherit' }
    | { mode: 'deny' }
    | {
        mode: 'allowlist';
        hosts: string[];
        allowLoopback: boolean;
        allowLocalNetwork: boolean;
      };
  environment: {
    inherit: string[];
    set?: Record<string, string>;
  };
  temp: {
    private: boolean;
  };
  resources?: {
    timeoutMs?: number;
    maxProcesses?: number;
    memoryBytes?: number;
    cpuTimeMs?: number;
    outputBytes?: number;
  };
};
```

The baseline `workspace` profile should mean:

- read the canonical workspace, a private temp directory, and the minimum
  runtime/toolchain roots required to start the command;
- write only the canonical workspace and private temp directory;
- deny `${CLIQ_HOME}`, credential locations, control sockets, devices, and
  other sensitive roots even when an overly broad read root overlaps;
- deny child-process network by default;
- inherit only a minimal environment allowlist;
- apply to the complete descendant tree.

This profile will break commands that depend on home-directory caches,
credential helpers, local daemons, or unrestricted package downloads. That is
expected in opt-in enforcement and must be diagnosed precisely, not “fixed” by
silently broadening access.

### 8.4 Internal process-launch contract

```ts
type BoundaryProcessPurpose =
  | 'model-tool'
  | 'command-hook'
  | 'validator'
  | 'trusted-internal';

type BoundaryLaunchRequest = {
  purpose: BoundaryProcessPurpose;
  argv: string[];
  cwd: string;
  env: Record<string, string>;
  stdio: 'pipe';
  signal?: AbortSignal;
  boundary: ExecutionBoundaryRequest;
};

type BoundaryCapabilityReport = {
  provider: string;
  providerVersion?: string;
  requestedMode: ExecutionBoundaryMode;
  effectiveMode: 'off' | 'audit' | 'degraded' | 'enforced' | 'unavailable';
  enforced: string[];
  unsupported: string[];
  warnings: string[];
};

interface ExecutionBoundaryProvider {
  probe(request: ExecutionBoundaryRequest): Promise<BoundaryCapabilityReport>;
  spawn(
    request: BoundaryLaunchRequest,
    report: BoundaryCapabilityReport
  ): Promise<BoundaryChild>;
}
```

`probe` must be side-effect free. `spawn` must verify that the probe result
still applies, create the private temp area, close unintended descriptors,
apply the OS policy, and launch the process without an unsandboxed gap.

The runner should inject a boundary-aware executor into `ToolContext` before
`ToolDefinition.execute`. `bashTool` then uses that executor instead of
calling `spawn` directly. The approval subject should be retained for audit
correlation, but the sandbox must use the resolved capability profile rather
than infer permissions from shell text.

### 8.5 Compatibility posture

- No boundary option means `mode: off`.
- Existing `--policy` values retain their current meaning.
- Existing headless and RPC callers that omit the new field retain current
  behavior.
- `audit` does not change command semantics.
- No workspace-owned setting may turn the feature on for an operator.
- The first release should mark the API experimental and require an explicit
  schema version.
- Stable mode names must not be reused for weaker behavior on a platform that
  lacks a provider.

### 8.6 Versioning and migration

1. Additive request fields should preserve headless schema compatibility.
2. A breaking capability-schema change requires a new
   `ExecutionBoundaryRequest.schemaVersion`.
3. RPC must validate the shape rather than blindly cast params to
   `HeadlessRunRequest`.
4. Persisted sessions may record the effective report, but must not treat an
   old report as authorization for a later run.
5. Provider versions and OS capability probes belong in each run record.
6. Unknown modes, fields that alter security semantics, and unsupported
   versions fail closed when explicitly supplied.
7. Rollback is `mode: off`; no migration may force users to edit system policy
   or delete platform sandbox state.

## 9. Filesystem and writable-path design

### 9.1 Allowlist first

A sensitive-path denylist is not sufficient because credential and control
paths vary across machines. Providers should start with no ambient filesystem
view and expose only necessary read-only and read-write roots where their
primitive supports it.

The resolver must:

- canonicalize workspace and configured roots;
- reject relative roots, empty roots, volume roots, and roots that collapse to
  a broader path than requested;
- record both lexical and canonical forms;
- make deny paths override read/write roots;
- distinguish read, write, create, delete, execute, metadata, device, and
  socket access where the provider can;
- avoid mounting or granting the entire home directory merely to expose one
  cache;
- provide executable and shared-library roots read-only;
- prevent mount operations and new privilege acquisition inside the boundary.

### 9.2 Sensitive paths

At minimum, profiles should treat these classes as sensitive:

- `${CLIQ_HOME}`, especially `auth.json`, trust, and permissions;
- SSH/GPG keys and agent sockets;
- cloud and package-manager credential files;
- browser profiles, cookies, keychains, and credential stores;
- Docker, Podman, containerd, Kubernetes, database, and desktop-control
  sockets;
- `/proc` or platform equivalents that expose other processes, descriptors,
  memory, environment, namespaces, or tokens;
- raw devices and host control APIs;
- system startup, service, scheduled-task, shell-profile, and executable
  search-path locations.

An explicit high-risk override may be designed later, but it must be
operator-owned, separately named, and visible in the effective report.

### 9.3 Symlinks, hard links, mounts, and races

Path-string validation alone cannot enforce the boundary:

- symlinks or junctions can redirect a path after validation;
- hard links can expose the same inode through allowed and protected trees;
- bind mounts and reparse points can splice external trees into the workspace;
- `/proc/self/fd`-style paths can re-open inherited descriptors;
- network filesystems and automounters can change topology;
- a concurrent process can race check-then-open logic.

Providers should prefer kernel-enforced mount/path rules and descriptor-relative
operations with no-follow semantics. Tests must cover topology changes before
and during launch. If a platform primitive cannot close a required escape
class, `required` mode must report that capability as unsupported.

### 9.4 Private temporary directories

Each bounded launch should receive a new, non-shared temporary directory:

- created by the trusted parent outside workspace control;
- owner-only permissions where the platform supports them;
- not a symlink, junction, or mount controlled by the workspace;
- the only value supplied through `TMPDIR`, `TMP`, and `TEMP`;
- writable by the child but not reused across unrelated runs;
- cleaned after the process tree exits, with a recoverable orphan-cleanup
  path after crashes;
- excluded from logs except for a redacted run-relative identifier.

The system temp root may be required to create the private directory, but the
child should not receive ambient write access to the shared root.

## 10. Environment, descriptors, and subprocess inheritance

The current `bash` and shell-validator paths expose the full parent
environment; hooks inherit it implicitly. Boundary integration must switch to
an allowlist.

The default child environment should include only values required for command
execution, such as a controlled `PATH`, locale, terminal mode where necessary,
workspace path, and private temp variables. Provider API keys, tokens,
credential-helper variables, socket paths, tracing exporters, and arbitrary
`CLIQ_*` values should not be inherited.

Further requirements:

- environment values are never emitted in telemetry;
- executable resolution occurs against the controlled environment;
- shell startup files must not reintroduce host state unexpectedly;
- only enumerated standard streams and protocol descriptors cross the
  boundary;
- stdin must not expose a powerful controlling TTY unless required and tested;
- descendants inherit all filesystem, network, token, namespace, resource,
  and descriptor restrictions;
- timeout and cancellation terminate the entire contained tree;
- backgrounding, double-forking, `setsid`, job-object nesting, and process
  breakaway are negative-test cases;
- an allowed child must not broker an unrestricted sibling through a host
  socket or service.

## 11. Network design

### 11.1 Separate control-plane and tool traffic

The Cliq parent needs network access for configured model providers and local
providers such as Ollama. A child-tool boundary should therefore leave
`src/model/http.ts` outside the restricted process and apply network rules only
to designated child families.

Provider traffic must not be routed through or attributed to the tool's
network allowance. Conversely, an approved shell command must not inherit the
parent's provider sockets, proxy credentials, or HTTP agent descriptors.

### 11.2 Network modes

`inherit` explicitly accepts current host networking and makes no isolation
claim.

`deny` should block:

- IPv4 and IPv6 egress;
- DNS, multicast DNS, and other name-service traffic;
- loopback and local-network traffic unless separately enabled;
- listening sockets;
- abstract and pathname local sockets where the platform can scope them.

`allowlist` is more difficult than a list of host strings. A portable design
should use a trusted broker/proxy for supported protocols:

1. The child has no direct route to the host network.
2. The broker receives an intended hostname and port.
3. The broker resolves DNS and validates every address against local,
   loopback, link-local, private, multicast, metadata, and configured deny
   ranges.
4. The broker revalidates redirects and connection retries.
5. DNS TTLs and CNAME chains do not silently expand authorization.
6. IP literals and alternate numeric forms are normalized and checked.
7. The broker logs the allowed target without request bodies, credentials, or
   response content.

This can realistically cover proxied HTTP/HTTPS. It does not automatically
support arbitrary TCP, UDP, QUIC, SSH, package-manager custom transports, or
peer-to-peer protocols.

### 11.3 Loopback and local networks

Loopback is not harmless: local model servers, databases, browser debug ports,
desktop-control endpoints, and cloud credential proxies may listen there.
`allowLoopback` must therefore be separate from public Internet access.

`allowLocalNetwork` must separately cover RFC1918, IPv6 unique-local and
link-local ranges, multicast, host bridges, container networks, and platform
network classifications. Cloud metadata addresses remain denied unless an
explicit future capability names them.

Unix-domain and named-pipe access is primarily a filesystem/IPC capability,
not evidence that “network is denied.”

## 12. Platform capability matrix

The entries below are candidates to validate, not implementation commitments.

| Capability | Linux | macOS | Windows | Portable promise |
|---|---|---|---|---|
| Unprivileged filesystem view | `bubblewrap` mount namespace when installed and unprivileged user namespaces are enabled; Landlock is a native-helper alternative | App Sandbox provides strong packaged-app controls; dynamic CLI use is not equivalent | AppContainer/LPAC with explicit path grants; newer Bound File System APIs require validation | Capability probe only; no universal backend |
| Read-only/read-write roots | `bwrap --ro-bind/--bind`; Landlock hierarchy rules with ABI-dependent rights | Static entitlements and user-selected access do not map cleanly to arbitrary per-command roots | AppContainer DACL/capability grants; experimental sandbox API exposes `fs_read_only`/`fs_read_write` | Requested/effective root report |
| Network default-deny | New network namespace can expose only isolated loopback; Landlock restricts ports, not hostnames | App Sandbox can deny outgoing network absent entitlement; applying it to arbitrary CLI children is the unresolved problem | AppContainer denies network without a network capability | `required` launches only when probed and tested |
| Hostname allowlist | Requires broker/proxy or network setup beyond a bare namespace; Landlock is port-oriented | Requires broker/proxy or privileged Network Extension class solution | AppContainer capabilities are Internet/intranet classes; host filters need proxy or WFP-class solution | Not promised portably |
| Descendant inheritance | Namespaces, Landlock, and seccomp inherit when correctly installed before exec | App Sandbox child inheritance requires entitlement/signing rules; deprecated profiles need separate validation | AppContainer token plus non-breakaway job object can cover descendants | Full-tree inheritance is mandatory for `required` |
| Process lifetime | PID namespace/cgroup/process group options | Process groups are lifecycle tools, not containment; XPC/job design may be needed | Job objects support tree accounting and kill-on-close, subject to nesting/breakaway rules | Cancellation must kill the bounded tree |
| Syscall/kernel-surface reduction | seccomp can reduce syscall surface but is not a sandbox by itself | App Sandbox/seatbelt policy is not a portable syscall filter API | mitigation policies and restricted tokens reduce selected surfaces | Optional provider capability |
| Resource limits | cgroups where delegated; rlimits as weaker fallback | rlimits/process controls with limited tree accounting | job-object CPU/memory/process limits | Report exact supported limits |
| Availability risk | `bubblewrap` may be absent; user namespaces may be disabled; Landlock ABI varies | `sandbox-exec(1)` is deprecated; App Sandbox implies packaging, signing, and architecture changes | stable AppContainer APIs are complex; `Experimental_CreateProcessInSandbox` is explicitly experimental | Never infer enforcement from OS name |
| Viable degraded mode | Landlock-only filesystem rules, or audit-only, if explicitly selected | external container/VM provider or audit-only; deprecated `sandbox-exec` is spike-only | restricted token + job object without full path/network enforcement, if explicitly selected | Degradation must be named before launch |

### 12.1 Linux notes

The Linux kernel documents Landlock as unprivileged, stackable restriction of
ambient filesystem and network rights inherited by future children. Its ABI
must be detected: filesystem rights have arrived over multiple ABI versions,
network rules are port-based, and some operations remain outside its coverage.

Bubblewrap creates a new mount namespace and can use user, PID, IPC, and
network namespaces plus seccomp. Its own documentation warns that the
arguments determine the strength of the sandbox and that exposed sockets or
mounts can become escape channels. Current bubblewrap no longer provides its
historical setuid mode, so systems with disabled unprivileged user namespaces
need another backend or a visible unavailable state.

Seccomp reduces kernel syscall surface but the kernel documentation explicitly
states that seccomp filtering is not a sandbox by itself.

Primary references:

- [Linux Landlock userspace API](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
- [Linux seccomp filter documentation](https://www.kernel.org/doc/html/v5.9/userspace-api/seccomp_filter.html)
- [bubblewrap project documentation](https://github.com/containers/bubblewrap)

### 12.2 macOS notes

Apple App Sandbox is a strong production mechanism for applications designed,
signed, and entitled for it. Apple documents static entitlement-based network
and file access, child inheritance constraints, and XPC as the preferred
privilege-separation mechanism. Those constraints do not map directly to an
npm-installed CLI launching arbitrary toolchains with per-command roots.

The current macOS `sandbox-exec(1)` manual labels that command deprecated and
directs developers to App Sandbox. It may be useful for a disposable research
prototype, but this design does not accept it as a stable production contract.

Potential outcomes of the macOS spike are:

- a packaged/signed helper or XPC architecture with an acceptable distribution
  story;
- an explicitly external container/VM provider;
- filesystem-only or audit-only support;
- `required` reported as unavailable until a supportable provider exists.

Primary references:

- [Apple App Sandbox entitlements and inheritance](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html)
- [Apple outgoing network entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.client)

### 12.3 Windows notes

AppContainer and LPAC provide process, filesystem, credential, registry, and
network isolation based on package/capability SIDs and DACLs. Job objects
manage descendant processes, accounting, limits, and kill-on-close, but they
do not provide filesystem or network isolation alone. Breakaway settings and
nested jobs affect the process-tree guarantee.

Microsoft now documents composable
`Experimental_CreateProcessInSandbox` APIs with AppContainer, filesystem
grants, network proxy configuration, integrity, and UI restrictions. The page
explicitly marks them experimental and subject to change, so the Windows spike
may evaluate them but a stable release must not depend on them without an
explicit minimum-OS and API-stability decision.

Windows Filtering Platform can express deeper traffic policy, but adding
filters is administrator-controlled and may require a service or callout. That
is outside the initial unprivileged design.

The current tool launcher invokes `bash` by name. The Windows spike must also
state which shell environment is supported and how its command semantics map
to a native Windows provider; OS-level primitives alone do not establish
end-to-end Windows tool support.

Primary references:

- [Microsoft AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Microsoft AppContainer launch guidance](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Microsoft experimental Create Process in Sandbox APIs](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox)
- [Microsoft Windows Filtering Platform overview](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform)

### 12.4 What Cliq cannot promise portably

Cliq cannot honestly promise:

- the same kernel primitive or strength on all three OSes;
- hostname-based network allowlists without a broker;
- arbitrary-protocol network allowlists;
- complete filesystem mediation from path strings alone;
- resource limits with identical semantics;
- containment of code already executing inside the main process;
- `required` availability on every supported machine;
- that a third-party container runtime is installed and correctly configured;
- that `best-effort` means anything stronger than the emitted effective report.

The portable contract is instead:

1. explicit mode and capability request;
2. runtime provider probe;
3. exact effective/degraded report;
4. no silent fallback;
5. full descendant inheritance for any claimed enforced restriction;
6. standardized error and audit semantics;
7. negative tests for every advertised capability.

## 13. Observability and error reporting

### 13.1 Structured states

Every bounded launch should emit or record:

- boundary request schema version;
- requested and effective mode;
- provider name/version and OS capability identifiers;
- process purpose and tool name;
- canonical workspace identity, not an unnecessarily exposed absolute path;
- enforced capabilities;
- unsupported/degraded capabilities;
- start/end timestamps, duration, exit code, signal, timeout, and
  process-tree cleanup status;
- denial or setup-failure category.

### 13.2 Error taxonomy

Proposed additive runtime errors:

- `sandbox-config-invalid`
- `sandbox-provider-unavailable`
- `sandbox-capability-unsupported`
- `sandbox-degraded`
- `sandbox-setup-failed`
- `sandbox-denied`
- `sandbox-launch-failed`
- `sandbox-cleanup-failed`

The protocol must distinguish:

- policy denial before boundary resolution;
- boundary refusal before process creation;
- OS access denial during execution;
- ordinary command failure inside a correctly enforced boundary.

Headless, JSONL, RPC, TUI, and classic CLI surfaces must preserve the same
categories. Human output should include one remediation hint, such as choosing
an installed provider, adding an operator-owned root, or selecting `off`;
machine output should use stable fields.

### 13.3 Redaction

Never record:

- environment values or secret names not needed for diagnosis;
- command output solely because an OS denial occurred;
- auth, cookie, token, or request-body content;
- full sensitive absolute paths when a category or workspace-relative path is
  sufficient;
- proxy credentials or DNS response payloads.

Local aggregate telemetry may count provider selection, capability gaps,
denial classes, setup latency, and cleanup failures. Remote telemetry remains
off unless Cliq establishes a separate consent and privacy design.

## 14. Alternatives considered

### 14.1 Workspace Trust and Tool Permission only

Rejected. They govern authorization and user intent but cannot stop an allowed
or compromised process from exceeding the intended scope.

### 14.2 Sandbox the entire Cliq process

Deferred. It could cover in-process tools and extensions, but it also encloses
model-provider HTTP, auth/session stores, UI integration, updater behavior,
and runtime assembly. It would require brokers for many normal host
operations and has a much larger compatibility surface.

### 14.3 Require containers for all bounded execution

Rejected as the only backend. Containers can provide a strong, inspectable
boundary but add installation, image, mount, UID mapping, performance, and
network-proxy requirements. They remain a possible explicit provider.

### 14.4 Treat `sandbox-exec` as the macOS production backend

Rejected. The installed manual marks it deprecated, and its profile language
is not a stable public application-sandbox contract.

### 14.5 Sensitive-path denylist only

Rejected. It cannot enumerate all credentials, sockets, mounts, and
machine-specific paths. An allowlist view with overriding denials is safer.

### 14.6 Default-on enforcement

Rejected for the initial design. It would break existing toolchains and violate
the issue's explicit compatibility requirement. Default-on behavior would need
a later decision backed by platform parity and migration evidence.

## 15. Phased follow-up work

Research spikes are intentionally separate from production stories. Each spike
must produce a checked-in report or fixture and must not quietly become the
shipping backend.

### Research R1 — Capability contract and probe fixture

**Scope:** finalize capability vocabulary, provider report, mode semantics,
and a platform-neutral escape-probe manifest.

**Acceptance criteria:**

- every requested capability has a defined enforced, degraded, unsupported,
  and error state;
- `required` fail-closed behavior is unambiguous;
- process families are enumerated;
- no workspace-controlled input can weaken the request;
- redaction rules and example events are reviewed.

**Validation:** schema examples, contract tests against a fake provider, and
security review of precedence/intersection behavior.

### Research R2 — Linux provider spike

**Scope:** compare bubblewrap and a minimal Landlock-based helper on supported
CI/host kernels. Evaluate filesystem roots, no-network, descendants,
descriptors, temp, and cleanup.

**Acceptance criteria:**

- capability probe detects missing `bwrap`, disabled user namespaces, and
  Landlock ABI;
- spike blocks protected-file reads, outside writes, direct egress, and
  descendant escape in its supported profile;
- limitations and dependency/distribution costs are documented;
- no privileged installation is required.

**Validation:** Linux version matrix plus the negative probes in Section 16.

### Research R3 — macOS provider spike

**Scope:** compare App Sandbox helper/XPC feasibility, external container
provider, and a research-only `sandbox-exec` prototype.

**Acceptance criteria:**

- documents signing, entitlement, npm distribution, child-exec, filesystem,
  and network constraints;
- proves or disproves arbitrary toolchain execution for each candidate;
- explicitly recommends a provider, a narrower capability, or unavailable
  status;
- does not install privileged components or mutate system policy.

**Validation:** Intel/Apple Silicon where available, current and oldest
supported macOS, descendant and filesystem/network negative probes.

### Research R4 — Windows provider spike

**Scope:** evaluate stable AppContainer/LPAC APIs, restricted tokens plus job
objects, Bound File System behavior, and the experimental sandbox API.

**Acceptance criteria:**

- records minimum Windows build and API availability;
- demonstrates non-breakaway descendant management;
- verifies read/write roots, environment filtering, temp routing, and
  no-network behavior;
- distinguishes stable from experimental dependencies;
- documents junction, reparse-point, named-pipe, registry, and job-nesting
  behavior.

**Validation:** supported Windows CI versions and negative probes.

### Research R5 — Network allowlist broker

**Scope:** determine whether an HTTP/HTTPS-only broker is useful and safe
enough for a first allowlist release.

**Acceptance criteria:**

- threat model covers DNS rebinding, CNAMEs, redirects, proxies, IPv4/IPv6,
  IP literals, loopback, local networks, metadata, and CONNECT;
- unsupported protocols fail explicitly;
- direct child egress remains blocked;
- provider networking remains independent.

**Validation:** controlled DNS/redirect test service, address-class matrix,
and packet-level proof that bypass traffic fails.

### Research R6 — Process-family and in-process isolation decision

**Scope:** decide whether command hooks and validators use the same provider,
and whether extensions/in-process tools require an isolated worker.

**Acceptance criteria:**

- each current process family has an owner, trust level, profile, and rollout
  phase;
- extension dynamic import is not described as contained;
- TX staged-view bind paths and shell-validator needs are addressed;
- trusted internal helpers are separated from untrusted execution.

**Validation:** architecture review against every direct
`node:child_process` import and every workspace-code execution path.

### Production P1 — Boundary types, resolver, fake provider, and audit mode

**Depends on:** R1.

**Acceptance criteria:**

- default remains `off`;
- omitted fields preserve existing CLI/headless/RPC behavior;
- `audit` emits requested/effective plans without changing spawn behavior;
- workspace config cannot enable or weaken the feature;
- all surfaces render structured errors consistently.

**Validation:** unit/contract tests and compatibility snapshots.

### Production P2 — Inject boundary executor into model `bash`

**Depends on:** P1 and one accepted platform provider.

**Acceptance criteria:**

- `bashTool` no longer directly owns bounded process creation;
- permission is resolved before boundary launch;
- environment and descriptors are allowlisted;
- cancellation covers descendants;
- `off` preserves current results and timeout behavior.

**Validation:** runner/tool integration tests and platform escape probes.

### Production P3 — First stable platform provider

**Depends on:** the corresponding platform spike.

**Acceptance criteria:**

- advertises only capabilities proven in CI;
- `required` refuses all unsupported requests;
- no privileged installation or system-policy mutation;
- private temp and cleanup work across crash/timeout paths;
- provider version and effective report are observable.

**Validation:** platform CI, manual matrix, and rollback exercise.

### Production P4 — Hooks and validators

**Depends on:** R6 and P3.

**Acceptance criteria:**

- categories are independently configurable;
- workspace trust still runs before hook/validator config loads;
- validator access to staged views and TX artifacts is explicit;
- a hook cannot relax the operator boundary;
- failures remain distinguishable from policy denials.

**Validation:** hook/validator contract tests plus protected-path and egress
probes.

### Production P5 — Additional platform providers

**Depends on:** R2/R3/R4 as applicable.

**Acceptance criteria:** same contract, redaction, strict failure, descendant,
and negative-test requirements as P3; platform gaps remain visible rather than
normalized away.

### Production P6 — Network allowlist

**Depends on:** R5.

**Acceptance criteria:**

- ships only for explicitly supported protocols/providers;
- direct egress and DNS bypass are blocked;
- redirect and resolved-address checks are enforced;
- local/loopback access is separately authorized;
- no claim of arbitrary-protocol portability.

### Production P7 — Stable configuration and migration

**Depends on:** at least two mature providers and rollout evidence.

**Acceptance criteria:**

- stable schema and deprecation policy;
- user-local defaults, if added, have documented authority;
- workspace config can only tighten and only after trust;
- rollback to `off` is immediate and requires no system cleanup;
- default-on remains a separate future decision.

## 16. Verification plan

### 16.1 Unit tests

- mode resolution and no-silent-fallback rules;
- capability intersection and deny precedence;
- canonical path and duplicate/overlapping root handling;
- environment allowlisting and secret redaction;
- network address classification;
- provider report serialization and schema versioning;
- stable mapping to runtime/headless errors;
- cleanup state machine and idempotency.

### 16.2 Contract tests

Every provider runs the same contract suite:

- `probe` is side-effect free and deterministic for stable host state;
- unsupported capabilities are reported, not ignored;
- `required` never invokes an unbounded spawn;
- `best-effort` emits degradation before spawn;
- descendants inherit restrictions;
- cancellation terminates the contained tree;
- audit records contain no secret values;
- `off` matches the existing launcher.

### 16.3 Integration and negative escape probes

Use disposable fixtures with sentinel files/services:

- read `${CLIQ_HOME}/auth.json` and fake SSH/cloud/browser secrets;
- read provider keys from inherited environment;
- write, create, rename, delete, chmod, and link outside write roots;
- escape through `..`, absolute paths, symlinks, hard links, mount points,
  junctions, reparse points, and `/proc/self/fd`;
- race a symlink or mount change during launch/open;
- access raw devices, credential stores, registries, named pipes, Unix sockets,
  Docker sockets, and other host-control channels;
- connect by hostname, IPv4, IPv6, alternate IP literal, redirect, DNS rebind,
  loopback, private range, link-local range, multicast, and metadata address;
- spawn a grandchild, background process, new session, double-forked daemon,
  nested job, and breakaway attempt;
- retain an inherited descriptor after its path is denied;
- exceed timeout, output, process-count, memory, and CPU limits;
- crash the parent/provider and verify orphan cleanup;
- run from a workspace containing staged-view bind paths.

A probe passes only when the OS denies the operation or the resolver refuses
launch. A log message without enforcement is not a pass.

### 16.4 Platform CI

Minimum matrix:

| Platform lane | Required coverage |
|---|---|
| Linux oldest supported kernel/distro | unavailable and degraded probes; filesystem/no-network if supported |
| Linux current kernel | full advertised provider contract |
| macOS oldest supported version | provider probe and exact availability |
| macOS current Intel, if supported | provider contract |
| macOS current Apple Silicon | provider contract |
| Windows oldest supported build | stable API/provider behavior |
| Windows current build | stable plus experimental-spike comparison where applicable |

Security claims must be gated on real hosted/self-hosted OS runs. Mock-only
coverage is insufficient.

### 16.5 Manual test matrix

For each platform/provider:

- modes: `off`, `audit`, `best-effort`, `required`;
- surfaces: TUI, classic CLI, one-shot, JSONL, RPC;
- policy modes: `default`, `accept-edits`, `plan`, `yolo`;
- trust states: new, trusted, denied, non-interactive explicit trust;
- process purposes: model `bash`, hook, validator;
- network: inherit, deny, supported allowlist;
- paths: workspace read/write, read-only dependency cache, private temp,
  protected home/CLIQ paths;
- lifecycle: success, command error, OS denial, timeout, cancel, parent crash.

### 16.6 Telemetry and rollout

Before enforcement rollout, `audit` should measure locally:

- provider availability;
- requested versus enforceable capabilities;
- commands that need extra read/write roots;
- setup and launch latency;
- denial and cleanup failure categories.

No command text, file content, environment value, or network payload is
required for these metrics. Any remote collection requires separate consent.

Rollout sequence:

1. `off` default with hidden developer probe;
2. explicit `audit`;
3. explicit `best-effort`;
4. explicit `required` on one platform/provider;
5. additional providers;
6. separate decision on whether any profile can become a recommended or
   default posture.

### 16.7 Rollback

- `mode: off` selects the existing launch path.
- Provider-specific kill switches may mark a backend unavailable without
  changing policy modes.
- No production phase should require persistent firewall rules, privileged
  services, or irreversible system state.
- Per-run temp/profile state is disposable and recoverable by an idempotent
  cleanup command.
- A provider regression rolls back that provider, not Workspace Trust or Tool
  Permission behavior.

## 17. Decisions still required

The following are explicit blockers to production implementation:

1. **Boundary granularity:** child-process launcher only, isolated tool worker,
   or a later whole-process broker architecture?
2. **Process-family scope:** are command hooks and validators bounded in the
   first release, and under which profiles?
3. **In-process code:** should workspace extensions remain trust-only, or move
   to a separate process before Cliq makes a broader sandbox claim?
4. **Linux backend:** bubblewrap dependency, native Landlock helper, external
   container, or a layered combination?
5. **macOS backend:** packaged helper/XPC, external container, a narrower
   supported capability set, or no `required` mode initially?
6. **Windows backend:** stable AppContainer implementation and minimum OS;
   when, if ever, may an experimental API be used?
7. **Network contract:** is HTTP/HTTPS brokered allowlisting enough, or should
   v1 support only `inherit` and `deny`?
8. **Readable roots:** how are compilers, interpreters, shared libraries,
   package caches, and SDKs discovered without exposing the home directory?
9. **Writable workspace semantics:** should an edit transaction make the live
   workspace read-only for shell commands, and how are declared build outputs
   represented?
10. **Configuration authority:** CLI/API only for v1, or user-local config as
    well? Workspace configuration cannot weaken the result.
11. **Resource guarantees:** which CPU, memory, PID, output, and wall-time
    limits belong in the portable required profile?
12. **Observability versioning:** additive runtime fields or new sandbox event
    variants, and does headless schema require a version bump?
13. **Distribution:** may Cliq depend on an external binary, ship a native
    helper, or require a separately installed provider?
14. **Support language:** what exact claim appears in `README.md` for each mode
    and provider?

## 18. Acceptance criteria for this design

This design is ready to move to research spikes when maintainers agree that:

- the three layers remain independent and ordered;
- default behavior remains unchanged;
- `required` fails closed and degraded execution is explicit;
- model-provider traffic is separated from tool egress;
- child descendants, temp directories, environment, descriptors, sensitive
  paths, links/mounts, and local-network cases are in scope;
- platform capabilities are reported honestly rather than normalized into a
  false portable promise;
- in-process extensions and tools are not mislabeled as contained;
- research spikes precede production providers;
- the open questions above have owners or explicit deferral decisions.

Until then, Cliq remains accurately described by the current README:
Workspace Trust and Tool Permission exist; an OS execution sandbox does not.
