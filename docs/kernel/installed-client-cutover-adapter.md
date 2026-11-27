# Installed CLI and embedded SDK composition

This implements one client composition, not the I4 default Kernel Cut. The
source baseline is the complete 1246-file feature-v2 candidate (`f87aef2c…`).
The existing default `src/index.ts` still starts the legacy CLI; changing that
default requires all WP01–06/I4 gates, migration and supported installed proof.

## Evidence and selected scope

The design review defines I2 as a real qualified model, required verification
and explicit delivery; I3 adds complete ordinary behavior and recovery. The
common application already consumes the canonical schema3 protocol, but the
published package has no SDK entry and real installed CLI applications still
depend on a testing driver to compose a selected runtime, authenticate and own
stdio. That is the nearest client integration gap that can be closed without
inventing a provider, MCP backend, trust root or another Run owner.

The implementation exposes the existing deep application through a stable
embedded SDK entry and one genuine installed host. The host borrows one actual
`HeldInstalledRuntime`, opens only the existing authenticated schema3 control
session, and owns its client/application lifetime. It cannot install/start a
Supervisor, create a StateOwner, execute a tool, access a secret, accept a socket
callback or choose release keys. Closing detaches, joins all owned client work
and preserves every original resource-retirement failure. The embedding host
keeps its selected runtime held until client close completes.

The SDK uses the same `createClientApplication` state machine as CLI/Ink:
bounded immutable requests, one original pending mutation, explicit reconnect,
explicit replay of exactly the original bytes, no automatic redispatch, full
artifact hashes/lengths and unchanged read/output backpressure. SDK output is a
borrowed callback, not a Run lifetime or a server authority. Client cancellation
or disconnect cannot silently turn into `run.cancel`.

The installed SEA adds only a client branch after the original fixed embedded
`release-trust-roots.json` and `createInstalledRuntime` composition. Its
StateRoot argument is an untrusted locator, never a signer, identity, socket,
CAS authority or public-key override. `openSelected` still verifies the actual
installation. This branch does not enter Supervisor/keeper/credential roles,
call `executeSelected`, acquire Store authority or bypass signed7→8 refusal.
The existing legacy default remains unchanged until the release gate passes.

CLI/JSONL/RPC/Ink qualification consumers call this shared production host.
Testing code retains only its exact controlled-release fixture discovery and
bounded diagnostic/framing observations; it does not independently recreate
the application's session/stdio assembly. No original case, POST, download,
scanner stream or acceptance assertion is removed to obtain a green report.
The public SDK is a genuine fifth consumer of the same original admitted Run,
not an alternate control server or a new workload. Its fixed read-only campaign
flag has no general command language and all output still passes through the
existing scanned, bounded schema3 consumer.

## Ownership and failure contract

- Selected installation descriptors are borrowed by the client. The original
  installer/SEA/embedding host alone closes them after client join.
- The client owns only its authenticated control session and application tasks.
  Caller callbacks/streams are not secret stores or permission providers.
- Inherited pipe duplicates remain genuinely client-owned; borrowed SDK IO is
  not closed by a normal detach. An aborted pending write must still join its
  actual callback or preserve retirement uncertainty, never a fake timeout.
  The inherited pipe duplicates are owned; the CLI's explicit abort retains
  its existing destroy-and-join contract for a supplied pending output stream.
  The embedded SDK accepts only a borrowed callback, owns no caller stream,
  and waits for that callback to settle even during close.
- Validation or authentication failure creates no Run. A lost mutation response
  retains the original bounded request identity. A different mutation is fenced
  until original replay/inspection. Reconnect sends no request automatically.
- All protocol/JSON/output bounds, Stop2/READY5/request30/terminal90 and the one
  4096-stream/512MiB/60s corpus remain unchanged.

## Verification and remaining qualification

Use the public package entry and the same shared application for component
regressions: no import-time CLI/config/legacy runner side effects; complete
pending/replay/conflict/refusal behavior; borrow/close/abort ownership; genuine
structural-installation refusal; exact package declarations; and original
CLI/Ink/schema3/FD-join regressions. Pure protocol data cannot mint a real
installation, authenticated peer, native death, permission or Linux proof.

Extend the original installed campaign to consume the production composition
without reducing its existing coverage or resetting the secret corpus. Actual
SEA/keeper/peer/frontends and real Linux execution remain pending until the
combined source is built and run by the root qualification lane. Official
release/discovery deployment, signed upgrades/migration, unsupported MCP and
dependency backends, all providers and final default cutover retain their own
explicit incomplete release gates.

`npm run build` builds all ordinary sources and then emits only the public
declaration dependency graph. It rejects private state/sandbox/runtime
declarations; it does not erase private brands to make them public. Run
`node scripts/check-sdk-package.mjs` under the supported Node binary after the
build to pack the actual package, extract it outside the repository, copy only
already installed locked production dependencies and verify ESM exports plus
strict external TypeScript with `skipLibCheck: false`. It performs no network
installation and uses neither `src` nor `tsx` as the package runtime. Compiler
and Node typings are verification tools kept outside that runtime. This check
passed on the actual minimum Node 22.13.0, but remains component evidence.
