# MCP recovery inspection and signed profile identity

This companion specifies the two accepted refinements needed to implement the
RFC's closed MCP retry/reconcile profiles. It does not make an unimplemented
profile available or qualify any platform.

Server launch and ordinary tool effect remain distinct actions. Each productive
server launch is separately permitted and, once claimed, costs one tool call;
the ordinary effect has its own claim and charge. Stdio's signed executable can
run and modify its fresh private scratch before RPC, but its fixed empty root
has no M/Checkpoint, host filesystem, secret or network access. Old domain death
and complete output/descriptor join precede any relaunch. A never-claimed
ordinary effect remains never claimed; server failure never proves an external
effect outcome. Complete original birth without a retained setup result may
close only as `setup_outcome_unavailable`, not a manufactured initialized or
not-initialized assertion.

## Nonproductive status inspection

The exact signed read-only status query is a fixed recovery inspection owned by
the existing `ReconciliationProbeDispatchV1`, with a closed
`reconciliation_probe` SandboxLaunch owner and `cliq-mcp-readonly-status-v1`
recipe. It has a separate opaque broker/input/scope purpose. It is not an Admin
probe or productive server/effect invocation, introduces no new ledger and
consumes no productive Run tool budget. Its real process/scratch creation is
limited recovery work, not a claim that startup has no side effects.

It binds original Run, effect op/attempt/claim/server instance, immutable registry,
signed adapter/profile, registration status template, current persisted wait,
dispatch, subject, ordinal, nonce and token. Only the distinct signed status
operation can be written, with the template's static arguments and original
stable idempotency key. It cannot use HTTP, call the effect operation, alter the
target, inherit M/credentials, renew the original effect deadline or borrow an
old native instance. Native READY5/Stop2, complete process/pipe/task/FD joins,
NoEcho and the original probe-start-plus-30-second deadline remain mandatory.

Broker request and target use the previous pending/exhausted wait and stable
subject/nonce, then the dispatch hashes those identities, then the in-flight
wait hashes that dispatch. The native birth may bind the resulting current
wait only after its transaction commits; the current wait ref is not fed back
into its own broker-request digest.

Automatic/user counts, eight-probe exhaustion, original backoff, late audit,
nonce closure and user `probe_now` replay keep the RFC's one durable wait
lifecycle. A transport close is not timeout or business evidence. A timeout
requires the exact original token irreversibly revoked and actual matching
release count zero under the native fence, plus complete scope join. A missing
source or unsafe event remains unresolved/recovery-required.

## Acyclic profile signing identity

The original full server execution identity remains:

`SHA-256(JCS({ executable: resolvedTransport.executable, argv: resolvedTransport.argv }))`

It retains `runtimeBundleRef`. The original registration, Admin target, server
instance and per-registration status template continue to bind that complete
original bundle identity.

A signed adapter profile uses a deliberately different
`profileSigningIdentityDigest`: its executable projection excludes only the
outer `runtimeBundleRef` selector and retains `kind`, role `mcp_server`, exact
entry id, execution path, complete executable digest and exact normalized argv.
The outer signed RuntimeBundle independently and uniquely binds both that
server entry and the adapter structured artifact/executable. Profile matching
always begins from this actual verified outer bundle; the selector-free digest
alone cannot grant authority, load an artifact or adopt another bundle.

This separation is necessary: including the complete outer bundle hash inside
a profile whose signed bytes are themselves rooted by that same bundle would
require a hash fixed point. The adapter has no explicit or indirect outer
bundle hash in its signed profile identity. After the bundle exists, the
Supervisor publishes the registration-specific template containing **both**
the profile signing digest and full original server execution identity, plus
the exact original Admin target/result. Final recovery/tool/registry digests
then follow in the existing one-way publication order. There is no external
catalog, additional ledger or compatibility fallback.

Profile signatures, release trust, unique profile tuple selection, exact raw
interfaces, status input/output schemas, static arguments and closed depth/node
bounded predicates remain mandatory. Server annotations supply no replay or
status authority. Neither/both predicates matching, malformed results, drift,
unknown keys or unsigned/substituted metadata cannot resolve an invocation.

The outer adapter structured root has the closed fields `artifactId`,
`rootEntryId`, `artifactRef`, `semanticDigest`, `memberRefs`, `kind` and
`executableEntryId`. Its root entry is non-executable `mcp_recovery_profile`
data; `executableEntryId` identifies the distinct `mcp_recovery_adapter`
executable. Both entries keep the manifest's exact version, complete bytes and
digest. `memberRefs` is exactly the unique byte-sorted union of every profile's
static-arguments and completed/failed-predicate refs. Installation reads every
member as its original signed `bundle_object`, verifies both release signatures
with the immutable trust store, and decodes every predicate. Merely admitting
this data graph does not enable the unqualified third native purpose.

Stable-key injection happens in the original resolved `ToolCallInput`, before
its input digest and any ToolRequest/target/grant or permission display are
formed. The model's original observed arguments remain unchanged in their
separate existing artifact. The batch identity is computable from the original
Run/model-op/attempt before resolved arguments, so the stable key introduces no
hash cycle. Historical model-turn validation repeats the same normalization.
The actual HTTP/stdio recipe and its retained audit only verify the frozen
complete arguments; they never replace arguments after authorization.

Normalization copies the original arguments and replaces only the leaf
authorized by the original exact RFC-6901 pointer. Parent containers must exist;
array indices are canonical existing indices, with no append, implicit parent
creation or inherited-property traversal. The arguments root remains an object.
The exact resulting wire arguments are checked with the frozen input schema
before release. Missing parents, an invalid root target or a schema rejection
do not authorize an I/O attempt, refund a previous unknown attempt, extend its
deadline or manufacture an external failure result.
