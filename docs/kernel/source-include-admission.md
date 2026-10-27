# Explicit source inclusion

Status: the integration candidate connects explicit includes through the
original installed admission path. Real Linux qualification remains pending.
Data regressions do not authorize capture or consume a grant.

The complete path uses the existing SourceInspectionTarget, native capture,
retirement, Run admission transaction and immutable SourceProjection. There is
no new runner, SQL writer, authority ledger or mutable-path recovery fallback.

## Permission and one original admission

Before capture, the genuine verified target resolves each supplied read grant
against its original authenticated creation, principal, live Session/workspace,
exact path/scope, current active row and expiry. An ignored untracked entry
requires that read grant. A tracked or nonignored entry can use only its actual
descriptor-captured classification. A needless or mismatched grant refuses;
neither Workspace Trust nor historical source data supplies a missing grant.
Hard exclusions and no-follow/device/ownership rules always apply.

An optional `expectedDigest` constrains the complete bytes of one regular file,
whose captured blob ref must match exactly. A constrained subtree has no defined
content-hash meaning and refuses before consumption. A constrained entry that is
a directory, symlink or absent also refuses. Matching cannot be inferred from a
path, stat, partial stream or another manifest.

The original unpublished rule required read-grant consumption only in Run
admission, while requiring the complete immutable source and its authorization
closure before that transaction. That would require a future consumption
receipt or rewriting the captured source after an owner change. This package
revises that timing explicitly; it does not claim the original timing passed.

Reuse the existing SourceInspection first transaction. It alone consumes the
still-active matching read grant and registers the original receipt, exact
consumed-grant snapshot and verified capture target before any source read.
`sourceReadGrantRefs` holds those complete snapshots; the receipt's consumer is
the exact `source_inspection`, not an invented Run admission. Publication alone
creates no permission. Prepared time and the fresh transaction time retain
their existing owner/frame/fence/expiry checks. The source owner then captures,
fully joins and retires through its original lifecycle. A failed or cancelled
capture does not restore a consumed one-use grant.

The Run id remains the existing deterministic id derived from principal, method
and admission key, without becoming authority before a Run exists. The original
Run admission transaction binds that same authentic retired capture, complete
source/receipt closure and original intent while creating the Run, initial
Checkpoint and first response atomically. It never consumes the grant again.
A lost response replays those exact bytes. Another request or workspace cannot
adopt the captured source or receipt. Missing original capture/consumption
evidence requires recovery rather than a mutable reread or a new receipt.

## Classification and immutable reconstruction

Each builtin authorization binds the original capture's full entries, exact
frozen ignore rules and optional original Git classification index. Its
descriptor observations must come from that same capture. Exact selector
coverage is nonempty, byte-sorted and complete, with every entry's full
WorkspaceEntry digest. Tracked classification requires the exact frozen index;
nonignored classification is reproduced using the frozen matcher.
The classification root retains the complete original entries ref and tree
digest. Every consumer rereads that original immutable manifest and checks exact
coverage and full entry digests. A child fork or fresh Delivery A can have a new
base-role manifest; that role never reinterprets its current entries as the
original capture. Original admission separately binds the evidence to its own
captured entries and retirement.

Both authorization branches bind that original `capturedEntriesRef` and tree
digest. The user branch additionally retains `consumedGrantSnapshotRef`, exactly
the original Target's complete consumed-grant snapshot, including its constraint
and receipt. Retained readers validate the whole snapshot/receipt and original
file bytes. They apply the constraint to the original capture, never a child or
later private result. The complete original entries use the existing full typed
WorkspaceEntryManifest reader plus canonical ref and tree checks. The smaller
authorization, classification-root and page artifacts retain their original
1 MiB/10,000-node/depth-32 limits; the entries contract is not narrowed to those
inline artifact bounds.

The implementation must preserve the original JSON/depth/byte bounds at large
source cardinalities. A fixed bounded page representation can carry the
classification sequence without a giant JSON array; all page bytes, counts,
order and incremental digest must verify before it can be registered. It must
not replace the existing full source/descriptor checks or become a second
authority record.

Result and Checkpoint capture use the original frozen selection. A user-read
selector may include its authorized ignored subtree; a builtin nonignored
selector never turns newly ignored bytes into authorized source. Recovery
reproduces the immutable authorization/receipt and original owning admission;
it never rereads mutable ignore files to reinterpret the old selection.

Delivery preserves the original B projection for merge and verification. A new
capture of current A requires new live read permission for ignored includes;
the old consumed grant cannot be reused. Fresh capture consent belongs to the
existing delivery SourceInspectionTarget and its original capture transaction, without
retargeting or rewriting B's projection. Child private-source inheritance is
data inheritance through the actual parent allocation/fork, not new permission
to capture the user's mutable root.

The pathless `run.apply.sourceReadGrantIds` contains at most 128 unique fresh
grant locators in the original projection's user-include order. The Supervisor
derives every path/scope from B's fully verified authorizations; builtin
selectors take no grant. Missing, extra, duplicated, old-consumed or
ignore-rule-overlapping grants refuse. Current A can have deleted the selected
entry: that is a captured absence under the same frozen selection, never a
reason to retarget the grant or rewrite B's authorization. Fresh receipts stay
in the original Delivery capture target, while A reuses B's exact projection.
Fresh constrained consent is checked against A's actual complete captured file
even though A reuses B's authorization refs. A missing entry remains legal only
for an unconstrained selector; it cannot satisfy an expected file digest. Replay
checks the same fresh snapshot and A bytes from immutable CAS.

## Required whole-path checks

Exercise actual held roots and SQLite/CAS: tracked/nonignored/ignored selection,
overlap and excludes, hidden ancestors, exact file/subtree scopes, needless and
mismatched grants, credential hard exclusions, symlinks and identity drift,
grant expiry/revoke/competing consumption, CAS/SQL failure, lost first response,
Supervisor restart, result/Checkpoint reconstruction, fresh Delivery consent
and child inheritance. Classification pages need missing/extra/reordered/page
substitution and byte-plus-one regressions. Genuine installed source capture,
retirement, timing and secret-corpus coverage remain separate required evidence.
