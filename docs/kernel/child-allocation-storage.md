# Child allocation storage

Schema 8 extends the existing allocation table and Journal; it adds no table,
second scheduler or execution authority. The authority-table inventory remains
21. A child has exactly one incoming parent. Within a parent, admission key,
delegate operation and each batch call identity are unique.

An allocation starts reserved and advances only through child_terminal to
settled. Its original base is immutable; the first terminal result, timestamp
and inclusive use are immutable; settled rows cannot change or be deleted.
The existing strict decoder and child lifecycle independently check complete
authority, inclusive budgets and exact unused settlement. SQL constraints do
not establish those permissions or physical evidence.

The two grant-bearing local Journal kinds are child_admission and child_merge. They
retain original sequencing, append-only, claim and terminal checks. Each has
exact prepared/dispatch_claimed/completed records, attempt and leaseEpoch zero,
the same original request/grant and P/C cut, one call charged, and no native or
broker dispatch fields. The complete triplet, allocation and business effect
must commit in one genuine current-owner transaction. Half a triplet is a
recovery failure, never a local operation to dispatch again.

The separate child_await control-registration kind has its own exact
14/17/19-field no-grant triplet and one-call accounting. It registers an
explicit original provider await, not execution or child completion; wake,
settlement and Stop cleanup never charge that registration again. The old
physical and two local grant guards remain independently closed.

The existing Run row also gains parent_cancellation_ref. It is absent at birth,
can first be set only for the same existing nonterminal child in its revision
and cancellation-fence transaction, and is then immutable. Its original
parent relation, cancel index and winning Stop cannot be cleared. The data
reader proves the complete observed revocation even when a higher real Stop
wins; a loser never claims supersedes or parent quiescence. This is one Run
aggregate field, not another authority table or cancellation ledger.

Schema migration validates all retained allocation JSON and indexed identity
before adding these guards. Invalid or conflicting retained rows abort the
entire transaction; no old row is normalized, discarded or reconstructed.
Exact schema 6 and 7 birth recipes remain unchanged. Their schema-only owner
history can advance to 8 without rewriting the original birth. A new signed
schema-8 installation has its own original authority. Upgrading an existing
signed schema-7 birth still requires its original signed-schema authority;
a current DDL recipe or compatibility range cannot supply that missing source.

SQLite, real Store/history and decoder regressions are component evidence.
They do not qualify child execution, native retirement, successor wake, serial
merge, installed Linux timing, existing signed upgrades or complete I4.
