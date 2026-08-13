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

Each built backend contains a closed manifest with raw lowercase SHA-256
digests for every executable or guest asset used by the probe. The manifest
has its own canonical digest. A Supervisor must already know that manifest
digest; it may not accept the value merely because the installation says so.

The digest is version-specific, not permanent. An intentional helper, kernel,
initramfs, BusyBox, or bubblewrap change produces a new manifest digest and
therefore requires a new qualification. No large guest image or private key is
committed to this repository.

## macOS

The only qualifying macOS path is the bundled Virtualization.framework helper.
It boots a pinned Alpine aarch64 Linux kernel and a custom, pinned initramfs.
The VM has:

- one disposable VM-owned block device for the generation write test;
- no shared workspace, StateRoot, HOME, or host directory;
- no network device; and
- a serial challenge/receipt channel bound to that VM instance.

The guest performs real deny/allow and double-fork checks. The host then stops
the VM and verifies both the stopped boundary and the bytes written to the
disposable disk. The TypeScript qualifier independently verifies the helper's
Developer ID Team/identifier, virtualization entitlement, Gatekeeper
notarization, signed resource seal, manifest digest, asset digests, challenge,
receipt, and disk marker.

Build on an Apple silicon Mac with the signing identity in Keychain:

```bash
export CLIQ_CODESIGN_IDENTITY='Developer ID Application: Chuan Liu (LMWH2NK82S)'
export CLIQ_CODESIGN_TIMESTAMP=1
scripts/kernel/build-macos-execution-probe.sh /absolute/output/directory
```

Notarization is a distinct external publication to Apple and must be explicitly
authorized:

```bash
export CLIQ_NOTARY_KEYCHAIN_PROFILE='coginework local'
scripts/kernel/notarize-macos-execution-probe.sh \
  /absolute/output/directory/CliqKernelProbe.app
```

After stapling, run the production qualification seam with the build-reported
manifest digest and an existing owner-only scratch directory:

```bash
CLIQ_MACOS_PROBE_BUNDLE=/absolute/output/directory/CliqKernelProbe.app \
CLIQ_MACOS_PROBE_MANIFEST_DIGEST=<64-lowercase-hex> \
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

The `Kernel foundation` GitHub workflow builds this helper on `ubuntu-24.04`,
delegates exactly one disposable cgroup subtree, and runs the real probe as the
unprivileged runner user. Missing user namespaces, cgroup controllers, or
bubblewrap behavior fails the job; it is never converted to a skip.

## M0 gates

Before M0 is considered qualified for a platform:

1. `npm run build`, `npm test`, `npm run test:state`, and
   `npm run test:sandbox-probe` pass with no skips.
2. The platform's real qualification command returns `authorityReady: true`.
3. Negative fixtures reject unsigned/unpinned helpers, incomplete receipts,
   traversal, digest drift, and false observations.
4. The default CLI/TUI remains disconnected from Kernel authority until the
   later Supervisor/cutover work explicitly consumes the opaque capability.
