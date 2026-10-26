# Installed thin client applications

The CLI, Ink view, JSONL adapter and local RPC adapter use the same authenticated
`InstalledControlSession`. `src/client/application.ts` owns the connection,
bounded command/read queue and disposable view lifetime. It never owns a Run,
WorkerLaunch, lease, Checkpoint or permission decision. Closing input, pressing
Esc/Ctrl+C, an output failure or a lost connection detaches; only an explicit
revisioned `run.cancel` requests cancellation.

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
The application retains one bounded original unresolved request in memory.
In Ink, `:reconnect` followed by an explicit `:replay` sends that same closed
request, including its original digest and admission identity. Read-only
inspection remains available, while a different new mutation waits for the
original response. Closing the client discards this local memory; JSONL/RPC
callers retain their own original request, and `request <json>` accepts an
explicit original request without rebuilding its context revision.
The client never retries an uncertain Invocation, creates a replacement
admission, hides cancellation or grants itself permission. A one-shot natural
CLI command reports the uncertain original identities and read-only recovery
guidance; it does not persist or print its full request body. Retaining that
body across separate CLI processes remains an explicit gap.

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
reconstruction. `diff` and `result` download their selected immutable artifacts,
reuse the original pure result/closure decoders and show the committed summary
and verification provenance. Handoff downloads its exact JSON and Markdown refs
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

## Installed validation and evidence boundary

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
