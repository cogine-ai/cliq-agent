# Paged retained Session context

New complete Session publications use `cliq-session-context-v2`: schema version
2, Session id, positive context revision, through-item sequence, nullable
`rootPageRef`, height in 0..7, and the omit-self `projectionDigest`. An empty
prefix has no root. Existing v1 projection bytes keep their original historical
profile; paging never reinterprets an old admitted cursor or grants authority.

A `cliq-session-context-page-v1` is a strict canonical JSON leaf or branch,
including schema version 1, kind, height and its exact inclusive source range.
A leaf contains at most 64 contiguous whole segments and 256 raw source items;
a branch contains at most 128 contiguous child ref/range tuples. Every page is
at most 262144 bytes. Children decrease height by one. Pages preserve existing
raw, summary and excluded-control semantics, and complete SQL lineage/item and
compaction justification checks remain mandatory. Normal append replaces only
the original right path; bulk conversion retains fixed fanout buffers.

Pages are internal immutable CAS children. Publishing and fully joining pages
changes no SQL row and creates no public catalog membership. Only the complete
head is registered in the caller's original single Session/Run transaction,
with its original owner, time fence, Session cut, request, result, Checkpoint
and once-only checks. Rejection leaves the entire SQL state, including the
`artifacts` table, unchanged; fully published unreferenced CAS bytes may remain.
No page metadata vector, spool, secondary ledger or transaction spanning async
publication is required, including conversion of a large historical v1 head.

The CAS reader verifies exact complete bytes, digest, identity and actual close
before strict page/range decoding. It does not require a catalog row or infer a
typed use from `schema_kind`. A preexisting declaration of identical bytes
retains its original fields; internal use still independently validates them.
`artifact.get` continues to expose only registered membership: an uncatalogued
internal page is not made a public root by being reachable. Read-only display
uses the closed `session.get.contextPage` branch: its request contains only the
captured projection ref, expected revision and at most seven child ordinals.
The server derives the root from the authenticated principal's actual current
SQL Session and checks that exact id/revision/ref before and after complete
ancestry reads. Every selected page has full hash/canonical bytes, range and
height checks. It returns an empty item page plus one bounded full context page;
ordinary item pagination cannot include this unsolicited branch. The client
binds the response to the original request and independently rehashes the target
page. A caller-selected ref, arbitrary registered JSON wrapper or schema label
cannot authorize an orphan. Head drift is an explicit revision conflict; no
automatic retry, frozen-head replacement or partial completion occurs. Head
bytes still use ordinary registered `artifact.get`; the fixed DFS retains only
its bounded ancestry path. Old metadata-only responses reject the new query
rather than being accepted as a context page. The hello `session.get` feature
still gates dispatch, and client/server use the same installed method contract.

Retention must enumerate the actual CAS namespace, then retain every page ref
reached from each retained head using the complete typed page walk. All raw,
summary, excluded-control and previous-compaction edges must be independently
validated with their original parent/index context. The catalog is neither the
CAS object inventory nor a reachability allowlist. A missing page, unknown
parent/purpose, incomplete walk or unsupported authority store makes the whole
sweep delete zero. No production sweep is enabled by this publication change.
Original archive capture likewise copies the complete physical CAS namespace,
including uncatalogued internal pages and published orphans.

Finite fixture collectors in `src/state/testing/session-context.ts` consume the
real page/source readers to EOF for integration assertions. They are never
production readers or a v2-to-v1 compatibility path. The large-scale migration,
physical rollback and Stop qualification remain independently required.
