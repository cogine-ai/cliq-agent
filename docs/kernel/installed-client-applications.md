# Installed thin client applications

The CLI, Ink view, JSONL adapter and local RPC adapter use the same authenticated
`InstalledControlSession`. `src/client/application.ts` owns the connection,
bounded command/read queue and disposable view lifetime. It never owns a Run,
WorkerLaunch, lease, Checkpoint or permission decision. Closing observer/stdio
input, pressing Esc/Ctrl+C, an output failure or a lost connection detaches;
only an explicit revisioned `run.cancel` requests cancellation. Natural finite
`run` and `apply` commands wait for their terminal result even with redirected
or already-closed stdin. `--detach` explicitly returns after durable admission.

The launcher calls `runInstalledClient` with a genuine held installation selected
under fixed shipped release roots. This module accepts no key, ledger or trust-root
override. Public release-root/discovery composition remains an I4 dependency.
`src/index.ts` and the default legacy CLI/TUI are unchanged until the Kernel Cut.
The commands below describe the implemented installed composition, not a claim
that the universal npm entry has switched or that a public release is qualified.

## One client flow

Natural CLI commands and Ink actions call the same `executeClientAction` and
closed generated protocol. `run` captures a Session when needed and admits a
new Run. `resume` reads the current context revision and submits a new Run with
its own request/admission identity. It cannot restart old Session execution.
Session inspection shows whole projection segment boundaries for explicit fork
and compaction; raw/legacy/control bodies are not introduced as model content.
Handoff remains the deterministic server JSON/Markdown artifact query.

A new user mutation receives one UUIDv7 identity and one canonical digest.
A failed transport preserves those identities for inspection and explicit replay.
An explicit reconnect authenticates a new connection and sends no mutation.
The installed composition also persists the exact bounded canonical request
before its first wire send. The private files bind the actual StateRoot directory
identity and canonical locator; a bundle digest is a provenance hint, not a second
authority or an upgrade prohibition. A strict authenticated response is durably
recorded before the request becomes known. These records survive client exit and
lost output and are shared by CLI, Ink, JSONL, RPC and the installed SDK. They
contain no credential bytes and never stand in for a fresh authenticated peer.

In Ink, `:reconnect` followed by an explicit `:replay` sends the same closed
request, including its original digest and admission identity. Read-only
inspection remains available while an unresolved original fences a different new
mutation. Across processes, `requests`, `requests show <id>` and
`requests replay <id>` inspect or explicitly replay that original. Replay binds
the exact bytes loaded for presentation; it cannot displace a different current
unresolved request. Text/JSONL/RPC acknowledge only this host's strictly known
sends after a successful return, complete output/stdio joins and no cancellation.
Ink and SDK clients retain known responses until explicit
`requests acknowledge <id>` or `client.requests.acknowledge(id)`; cancelled or
failed output retains them too. Older retained responses require explicit
acknowledgement. `requests show` and SDK `load` return historical client data,
not a newly authenticated peer observation.
An unknown response cannot be acknowledged. Incomplete or changed files remain
failures requiring inspection, never a reason to submit a replacement.

Every pending-data operation uses the same private-directory OS file lock.
The current unresolved set is checked atomically with original request
publication, including across already-open clients and independent processes.
The lock is released before sending on the control channel. Contention is a
local busy refusal, with no automatic polling, wire retry or unhealthy-peer
substitution. Explicit replay requires an existing exact original and can
reconcile multiple historical unknowns one at a time. The lock file is a live
mutex only: it has no owner epoch, recovery evidence, expiry or unlink protocol.
Model-alias read/merge/write also uses this same short metadata lock.

Files use the actual Linux account's private directory, descriptor-relative
no-follow operations, single-link files, fixed permissions, complete bounded
reads, identity checks, fsync and real close/join. Create/adopt paths persist
the actual owned parent-directory edges even when another process created the
directory first; a child fsync alone cannot persist that birth. The request retains the
unchanged 1 MiB, depth-32 and 10,000-node wire limits. Protocol-only fixtures
without an installed file owner retain in-memory data only. A disk record never
permits an automatic retry, a replacement admission, a hidden cancellation or a
permission grant.

## Normal commands in the signed Linux image

The same signed image now includes a normal daily-client entry in addition to
its original fixed service roles. It selects the actual system account's
`~/.cliq/kernel-v1`, with no root, key, socket, transport, loader or environment
override. `setup` uses the original signed installer and service installation;
an existing directory is validated rather than adopted. The npm `cliq` entry
still uses its existing composition until the Kernel Cut is qualified.

`models add <alias>` selects a bounded public setup profile embedded in that
image. The endpoint tuple must match a unique currently valid signed catalog
and price pair. The existing endpoint registration, native credential producer,
Secret Service round-trip, Supervisor time fence and credential finalizer remain
mandatory. Setup retains the original secret-free operation identities before
writing, so an explicit retry reads history before requesting secret input.
Terminal input uses Node readline with hidden input and bounded real stream
retirement; `--api-key-stdin` selects the original non-TTY input path. A key is
never an argument, model preference, request record or CAS object.

The terminal reader owns signal handling until its actual stream joins and
terminal restoration finish. Outside that prompt, normal model setup retains
real OS termination instead of intercepting a signal with an AbortSignal that
its native credential action cannot consume. An interrupted operation is
resolved through its retained original setup/credential history on an explicit
retry, not declared rolled back or gracefully joined. This does not change the
Supervisor's separate two-second Stop contract. Strict preference validation and
the alias limit are checked before starting credential setup; a concurrent or
later storage failure still requires original-request recovery.

Model aliases retain only model/endpoint/credential identifiers. Preferences
grant neither Workspace Trust nor a tool permission. A new workspace requires
its retained Trust decision, an interactive decision or an explicit
`--trust-workspace`; a retained denial is not overridden. The canonical trusted
workspace is passed to Session capture. The fixed `--check-node <relative.mjs>`
preset requires explicit `--policy yolo`, obtains a real verifier identity-read
grant, and uses the original read-only guest Node recipe. It does not run npm,
arbitrary shell code or a check discovered in repository configuration.

`--budget-usd` converts exact decimal USD to integer micros; `--budget-tokens`
selects the existing bounded token allowance. Neither changes unmentioned
limits, conservative reservations or the kernel's default budget. In particular,
a provider's large per-request ceiling may require an explicit larger token
budget to allow multiple turns. `result <id> --wait` follows authoritative state
and then displays the original result review; a waiting/refused Run is not
automatically approved or retried. `apply <id> --result <ref>` retains the
distinct exact-result Delivery action.

These are implemented source paths, not installed qualification evidence. The
combined daily command campaign, real provider call, interruption/upgrade
qualification and public release/default switch remain separate gates. Real
Linux file lifecycle tests and terminal PTY components do not replace them.

The normal daily campaign and the original installed application's normal
campaign include their actual private client partition in the same cumulative
credential scan, after all client/service writers join. The fixed locator is
derived from the real StateRoot device/inode/owner/path tuple. It covers existing
preferences, model setup requests, original requests/responses, acknowledgement
residues and the zero-byte mutex. A read-only client may legitimately have only
the request directory; optional files are fully scanned when present. Unknown
entries, aliases, unsafe modes, incomplete original groups and replaced
directories refuse qualification. The original byte, stream, entry, file and
time bounds remain unchanged. Successful byte scanning conveys no execution,
replay, credential or process-death authority.

The Ink view attaches to authoritative snapshots and finite event cuts. It
renders committed model/tool items through the original bounded artifact reader;
progress events never become model text or authority. A cold viewport starts
with the most recent 100 committed items and retains 200 display lines; inspection
and artifact reads retain the original bytes. Terminal controls and bidi controls
are escaped. Long display lines are marked as clipped rather than changing an
artifact. CLI transcript output preserves full text.

Input and approval actions retain the exact original wait reference and revision.
Input presentation resolves the original InputRequest, prompt, model text and
response-schema links. Empty text is a valid reply when the original text prompt
allows it. A non-input empty Enter cannot admit a new Run. A pending display read
uses the same serial wire queue but cannot occupy the one explicit command slot,
so cancel remains available. Reattaching explicitly may retry a refused read of
that same captured wait; it cannot replay a mutation. A requested Stop is displayed
as pending until the authoritative terminal state arrives.

On an expired attach cursor the original refusal and inline snapshot are shown.
The client does not invent a replacement cursor; a user may explicitly attach at
the retained boundary. Non-TTY CLI refusals and failed/cancelled terminal Runs
return a nonzero exit code. Esc detach remains a normal TUI exit.

`inspect` accepts independent item, Journal and Checkpoint cursors; `session show`
accepts the original raw-item cursor and limit. Metadata pages expose their exact
next/high-water values. These are explicit reads, not a hidden mutable-history
reconstruction. `diff` and `result` download their selected immutable artifacts
and reuse the original pure result/closure decoders. A result review keeps its
committed summary, required/advisory check outcomes and code changes together in
one view, including in Ink. The exact base/result source pair must match the
selected diff. Unified text changes use pinned jsdiff over original authenticated
blob reads, without opening the user workspace or invoking Git. File mode, type
and symlink changes remain visible. Binary/invalid-UTF-8 files, files above
128 KiB, and exhausted one-MiB review budgets are explicitly marked incomplete
with original artifact references. Each asynchronous text comparison has a fixed
work/time bound and is joined before cancellation returns. Raw artifact export
retains its original byte limits. No rendered diff is applied directly.

The review shows `apply <runId> --result <ref>` to bind a later explicit application
to that exact immutable result. A mismatching current result sends no mutation.
Application still creates one distinct authorized Delivery Run through the existing
protocol, then follows its real status by default. Admission is not displayed as
completed publication; a failed/cancelled terminal Delivery returns nonzero in
the finite CLI. `apply --detach` returns only the acknowledged Delivery id. Lost
mutation responses retain their exact original request identity without an
automatic replacement or execution retry.

Handoff downloads its exact JSON and Markdown refs
at the captured Session revision. `artifact <ref> > file` exports every verified
original byte with no header; a terminal gets escaped text or a binary-export
hint. No export bypasses registered-artifact membership or the 64-MiB buffered
consumer ceiling. Larger artifacts fail explicitly. An interrupted export or
finite action returns nonzero; ordinary observation detach remains a normal exit.

An Ink inspection retains only a bounded text preview and the original ref.
`:back` returns to the original wait. Approval/input shortcuts are disabled while
their subject is hidden by an inspection. This view cannot approve, apply or import
an artifact. Ctrl+K remains the distinct explicit cancellation action.

Output backpressure remains real. Explicit client abort destroys its owned output
streams and waits for the actual pending write callbacks and stream close; merely
rejecting a display promise cannot retire a blocked pipe. A real owned-child/OS-pipe
component verifies this path, plus unchanged connection close and zero mutations.
It does not qualify an installed Supervisor or replace the signed Linux campaign.
Known refusals and a local view abort remain read failures; a transport failure
fences an already queued command until a user explicitly reconnects.

## Lists and wire limits

`run.list` and `authorization.list` extend the existing Session materialized-cut
implementation. They preserve the sole owner/time fence, 15-minute TTL, canonical
HMAC cursor, issued-page boundary, complete source/cut equality, real query close
and Store join. There are no new tables, ledgers, clocks or execution permissions.
Each new page freezes at most 100,000 summaries and 64 MiB; subsequent pages use
that immutable cut, including after a genuine Store restart. A fresh request may
observe later admissions or grant transitions. Run operation filtering validates
all candidate original RunSpec references before choosing the complete source set.
Authorization summaries contain only the public metadata of the original rows.

The public page limit remains default 50, maximum 100. Boundary fixtures retain
all fields of 100 maximally escaped Run snapshots and grant summaries and pass
the unchanged 1 MiB frame, 10,000-node and depth-32 decoder. They are not a reason
to raise a limit or discard fields. The list implementation keeps the existing
single Store-owned preparation permit and bounded TEMP scratch, with complete
abort/close cleanup. The original SQLite cut is frozen atomically in that
connection-private scratch without an entire JS array. Every field is bounded
before sorting or retention. Fixed batches retain original BLOB bytes, require
fatal UTF-8 with BOM preservation and exact re-encoding, and perform every original
canonical decoder, byte count and final source/cut equality. No SQL scope or
statement iterator survives a yield. The original capacity component refuses
100001 rows before data reads and refuses 100000 Run rows when their complete
payload exceeds 64 MiB; its exact-byte cases retain 50000 Run rows and 100000
authorization summaries at exactly 64 MiB.

Authorization capture orders the original `json_extract(row_json,'$.createdAt')`
and grant id with binary collation inside the same capture transaction. The
single fixed schema8 index starts with owner principal and these exact ordering
expressions. This avoids a synchronous sort of all bounded projected payloads;
Run capture and its `parent_cancellation_ref` projection remain unchanged.
The original count-first 100001 refusal, all field lengths, complete 64-MiB
materialization, fatal UTF-8/BOM-preserving decoding and all-and-only source
comparison remain mandatory. Malformed or overlong times cannot be accepted
merely because their raw index order differs from the bounded projection.
The index changes only the unpublished fixed8 recipe; it does not rewrite
signed schema7 or authorize an unsigned upgrade. Timing or query-plan component
measurements alone are not the original real SIGTERM/Stop2 qualification.

The unchanged component's real capture/prepare/final SIGTERM cuts passed on
macOS with Node 24.21.0 and the minimum Node 22.13.0, including original owner
terminal state, zero active owners, full cut cardinality/bytes and actual
process/pipe join. Authorization signal-to-join measurements were respectively
639.4/46.3/519.5 ms and 677.6/46.0/575.7 ms, under the unchanged strict 2000 ms
bound. All three original Run-list cuts passed too. These are actual local
component observations, not signed installed-Supervisor or Linux qualification;
the combined installed campaigns remain necessary.

Session capture likewise assigns contiguous ordinals through the fresh private
table's `INTEGER PRIMARY KEY`, in the original explicit binary source order.
It removes a redundant full-row window pass; the atomic complete capture,
bounded projections, row/byte limits and final all-and-only comparison remain.
Source-change retries must restart ordinals at one and publish only a complete
cut. An earlier full local run exceeded the unchanged 2-second capture-stop
deadline and remains failed evidence. After removing the extra pass, the ten
original Session regressions passed on both Node 22.13.0 and 24.21.0. Their real
capture/prepare/final SIGTERM joins were 1781.3/52.4/345.1 ms and
296.7/53.1/353.3 ms respectively. These uncontrolled-host component observations
do not qualify the installed Supervisor; full local and Linux validation remain
required.

## Installed validation and evidence boundary

### Explicit real-provider experiment

The fixed Linux provider journey uses the same disposable UID, root-owned ledger,
owned filesystem, actual systemd user manager, Secret Service, signed SEA/native
package builder, installer and resource finalizers as the original Node journey.
Its separate `provider` branch calls the public model → private edit → required
Node check → result review → explicit exact-result Delivery workflow. It does not
run an owned HTTPS model responder or reuse that responder's POST-count evidence.
The package and client both select headless schema 3; the original fixture modes
retain their original schema and every original case/assertion.

The root-owned experiment launcher selects this mode explicitly:

```text
sudo bash scripts/kernel/qualify-systemd-user.sh \
  --run-provider-journey /absolute/root-owned-public-config.json \
  /absolute/supported-node /absolute/new-output-directory
```

The configuration is secret-free canonical JSON containing only `definition`
and `budgets`. It must be a root-owned, single-link, no-follow file of at most
64 KiB, mode 0400 or 0444, with no aliased locator. The selected definition uses
`openai-compatible`, `deepseek-flash`, `https://api.deepseek.com/`, explicit
currently authenticated SPKI pins, nonzero prices, full per-request token
ceilings, capability declarations and a finite validity interval. The public CA
bytes enter the same signed package; no new runtime CA/root override is accepted.
The publisher's signature does not independently qualify these declarations.

The caller sends **no credential bytes during shell setup**. It waits for the
exact original driver's `CLIQ_PROVIDER_SECRET_STDIN_READY_V1` line, then writes
the key once through its private stdin pipe and closes that pipe. The driver
consumes actual EOF before spawning any build or installation child, requires
1–4096 bytes within thirty seconds, erases consumed chunks, and clears its owned
copy in `finally`. The key is enrolled through the existing bootstrap credential
stdin path. It is never placed in arguments, environment, public configuration,
reports, source files or CAS. This mode is not invoked by free repository CI.

The first authorized experiment has an explicit USD 5 source-Run ceiling and
a conservative CNY 35 scheduling reservation within the owner's cumulative
CNY 200 authorization. The recorded USD/CNY upper conversion is 7; this is a
conservative scheduling allowance, not a currency conversion built into the
kernel. No second experiment is started without checking cumulative spend and
unresolved reservations. The selected highest documented non-discount rates
and whole-request bounds must be checked again before execution; returned usage
and input estimates never reduce the original reservation. Current references:
[prices](https://api-docs.deepseek.com/quick_start/pricing/) and
[request/token bounds](https://api-docs.deepseek.com/api/create-chat-completion/).

The report is `cliq-installed-provider-journey-v1`, with its own profile. Public
workflow completion, complete actual resource joins, unchanged Stop2 checks and
the original cumulative 512-MiB/4096-stream secret scan are independently
required. External HTTPS is owned by the installed native broker; no fixture
`httpsJoined` observation is invented. `actualProviderQualified`,
`actualProviderBillingQualified`, `officialReleaseQualified` and complete I1/I2
remain false. Protocol/data regressions and a successful package build are not
evidence that this real installed experiment has executed.

The installed journey composes the real natural CLI, JSONL and RPC applications
and a util-linux PTY running the actual Ink component, through the existing held
installation and test-owned signed fixture. It preserves all original normal
journey assertions before adding the client campaign. The additional campaign:

- Reads the original Run and Session, then explicitly replays the exact original
  admission through natural CLI; it cannot create a new Run.
- Opens the public embedded SDK with the same genuine installation, reads that
  original Run exactly, and joins its client, process and pipes before continuing.
- Reads materialized Run and authorization lists through JSONL and replays the
  exact frozen next page over a fresh authenticated RPC connection.
- Waits for the actual authenticated Run to be visibly rendered by Ink, sends Esc
  as terminal input, and joins the owned application process and both pipes.
- Rechecks the original complete Run/Journal/Checkpoint/Session bytes and the
  original five provider requests; the additional provider request count is zero.

The resulting `clientApplications` report is evidence only for those actual
read/replay/detach operations. `newExecutionQualified` and `completeI3Qualified`
are explicitly false. Local pure protocol/stdio, actual SQLite/CAS, compiled Ink
and bundle tests cannot stand in for the signed Linux campaign or a native proof.
The PTY campaign and the combined tool approval/input/new-admission journey still
require actual Linux execution after source integration. Public release roots,
macOS qualification, all provider/MCP rows, migration/retention and default Kernel
Cut remain separate incomplete gates.

The new fixed `fixtureProfile: cli_sdk_shared_host_v1` additionally requires
`embeddedSdkReadAndDetach: true`. Both fields are published only after that
actual SDK response and close, all original four application assertions and
the unchanged five POSTs/full snapshot comparisons have passed. The historical
report without these fields remains a distinct older contract. A strict
consumer must select the new complete shape by this profile and source binding;
an optional true field cannot upgrade the old evidence. The existing next-page
cursor must really exist and replay exactly; no new Run or grant is created to
obtain one. Whole-stage failure remains false and has no success report.

CI484's final application assertion retained no application-local frame. The
source-owned diagnostic allowlist now also contains only the two exact files
`installed-client-applications.ts` and `installed-ink-consumer.ts`, under the
original eight-error/eight-frame bounds. This preserves an actual failing line
without serializing messages, arbitrary source paths or request data; it does
not infer the cause of that historical run or change its failed qualification.

The fixed installed test-client bundle includes normal Ink 7.0.2 code and compiles
only its three pinned optional DevTools conditions to false in memory. Package and
both source hashes, exact sizes/condition counts, no-follow/full reads, stable
identity, actual descriptor close, Node-only externals and the 16-MiB output guard
are retained. No dependency file is modified or missing package externalized.
