# M0 platform qualification

M0 is a hidden Kernel foundation, not a change to Cliq's product surface.
Cliq remains an npm-installed command-line tool with an interactive TUI. The
default CLI/runtime does not call this code yet, and no end user needs an Apple
Developer certificate.

The M0 contract is fail-closed: `qualifyExecutionBackend` returns an opaque,
process-lifetime capability only after a real strong backend passes identity,
deny/allow, descendant-containment, and death-evidence checks. Calling it
without a frozen installation returns `UNSUPPORTED_EXECUTION_IDENTITY` and
cannot create Run authority.

## What “fixed digest” means

Each built backend has a frozen installation identity. Linux uses a closed
manifest containing raw lowercase SHA-256 digests for every executable used by
the probe. macOS uses the canonical manifest digest plus the final,
post-signing helper digest because Mach-O signing changes the executable bytes.
A Supervisor must already know those identity values; it may not accept them
merely because the installation says so.

The identity is version-specific, not permanent. An intentional helper,
kernel, initramfs, BusyBox, or bubblewrap change produces a new frozen digest
and therefore requires a new qualification. No large guest image or private
key is committed to this repository.

## macOS

The only qualifying macOS path is the bundled Virtualization.framework helper.
It boots a pinned Alpine aarch64 Linux kernel and a custom, pinned initramfs.
The VM has:

- one disposable VM-owned block device for the generation write test;
- no shared workspace, StateRoot, HOME, or host directory;
- no network device; and
- a serial challenge/receipt channel bound to that VM instance.

The helper rejects any VM configuration containing a directory share or network
device. The guest independently attempts the forbidden host-path and direct
network operations, publishes those observed results, and verifies one exact
detached PID, its PPID 1 adoption, and its BusyBox executable digest immediately
before the receipt. The host then destructively stops the VM and verifies both
the stopped boundary and the bytes written to the disposable disk. The
TypeScript qualifier independently verifies the helper's Developer ID
Team/identifier, virtualization entitlement, Gatekeeper notarization, signed
resource seal, caller-frozen post-signing helper digest, manifest digest, asset
digests, challenge, receipt, and disk marker.

Build on an Apple Silicon Mac. Replace the examples with a Developer ID
Application identity and `notarytool` Keychain profile installed on that
controlled runner:

```bash
export CLIQ_CODESIGN_IDENTITY='Developer ID Application: YOUR NAME (TEAMID)'
scripts/kernel/build-macos-execution-probe.sh /absolute/output/directory
```

Secure timestamping is enabled by default. `CLIQ_CODESIGN_TIMESTAMP=0` is only
for local diagnostics; such a bundle is not eligible for the notarization gate.

Notarization is a distinct external publication to Apple and must be explicitly
authorized:

```bash
export CLIQ_NOTARY_KEYCHAIN_PROFILE='YOUR-NOTARYTOOL-PROFILE'
scripts/kernel/notarize-macos-execution-probe.sh \
  /absolute/output/directory/CliqKernelProbe.app
```

After stapling, run the production qualification seam with both build-reported
identity digests and an existing owner-only scratch directory:

```bash
CLIQ_MACOS_PROBE_BUNDLE=/absolute/output/directory/CliqKernelProbe.app \
CLIQ_MACOS_PROBE_MANIFEST_DIGEST=<64-lowercase-hex> \
CLIQ_MACOS_PROBE_HELPER_DIGEST=<64-lowercase-hex> \
CLIQ_MACOS_PROBE_SCRATCH_ROOT=/absolute/0700/scratch \
npm run test:sandbox-probe:macos
```

GitHub-hosted macOS runners cannot run this nested Virtualization.framework
gate. The project's controlled Mac is the authoritative macOS qualification
runner; ordinary GitHub macOS jobs still compile and run unit tests.

## Linux

The Linux manifest pins a statically linked native launcher and the exact host
`bubblewrap` bytes. Before `exec`, the launcher places the child into a
Supervisor-delegated cgroup v2 subtree. The sandbox then proves:

- private user, mount, network, PID, IPC, UTS, and cgroup namespaces;
- `no_new_privs`, an empty tmpfs root, and only the generation bind;
- real workspace, StateRoot, HOME, and direct-network denial;
- generation file and directory durability;
- subreaper adoption of a detached grandchild;
- full cgroup descendant enumeration; and
- working `cgroup.freeze`, thaw, `cgroup.kill`, and `populated 0` evidence.

The launcher hashes `/proc/self/exe` and opens/hashes bubblewrap before using
`fexecve`, so a path replacement after TypeScript validation does not change
the executable that runs. The sandbox receives the already-running launcher's
`/proc/<pid>/exe` as a read-only file.

The `Kernel foundation` GitHub workflow builds this helper on the fixed
`ubuntu-22.04` hosted image, delegates exactly one disposable cgroup subtree,
and runs the real probe as the unprivileged runner user. Missing user
namespaces, cgroup controllers, or bubblewrap behavior fails the job; it is
never converted to a skip. `ubuntu-24.04` remains in the ordinary build/test
matrix, but its default AppArmor user-namespace policy blocks bubblewrap's
network-namespace setup. It must not be called qualified unless a separately
frozen AppArmor policy or a suitable self-hosted runner passes the same real
probe; the workflow does not disable that host security policy globally.

For M0, the repository-supported reproducible Linux qualification entry is the
`linux-strong-probe` job in `.github/workflows/kernel-foundation.yml`, triggered
by a push to `cliq/**` or a pull request targeting `main`. Directly running
`npm run test:sandbox-probe:linux` is intentionally not presented as a local
gate: it requires a root-created cgroup v2 parent with `cpu`, `memory`, and
`pids` delegated to the invoking uid, a sibling Supervisor cgroup containing
the qualifier process, a pinned installation and manifest digest, and private
scratch/StateRoot paths. The workflow is the canonical executable setup for
all required `CLIQ_LINUX_PROBE_*` variables and performs depth-first cleanup of
the complete disposable cgroup subtree.

## M0 gates

Before M0 is considered qualified for a platform:

1. `npm run build`, `npm test`, `npm run test:state`, and
   `npm run test:sandbox-probe` pass with no skips.
2. The platform's real qualification command returns `authorityReady: true`.
3. Negative fixtures reject unsigned/unpinned helpers, incomplete receipts,
   traversal, digest drift, and false observations.
4. The default CLI/TUI remains disconnected from Kernel authority until the
   later Supervisor/cutover work explicitly consumes the opaque capability.
