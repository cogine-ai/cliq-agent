# Linux guest ELF dependency strings

The owner-approved ELF A contract changes the accepted image set: a dynamic
string table is no longer rejected merely because its declared size exceeds
1 MiB. The complete table must lie in one unique file-backed `PT_LOAD` of the
same completely hashed ELF, within the full signed image's measured file
extent. A second load overlapping even part of its virtual-memory or file
extent is rejected, including a file alias at another virtual address. The
extractor never reads or allocates the complete table.

This is needed by the unchanged official Node v24.21.0 Linux x64 executable:
its `DT_STRSZ` is 2,082,484 bytes, with one `DT_STRTAB`, one `DT_STRSZ`, and seven
`DT_NEEDED` entries. Its archive SHA-256 is
`fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6`;
the 126,595,440-byte executable's SHA-256 is
`7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c`.
No stripping, alternate Node, host-loader fallback, or executable substitution
is part of this change.

## Bounds and authority

Each requested dependency-name window is still at most 256 bytes, including
its required NUL terminator. Before reading it, the original native extraction
job reserves the entire window against a fixed cumulative 262,144-byte limit:
32 mapped files × 32 `DT_NEEDED` entries per ELF × 256 bytes. This counts actual
requested name windows across the complete job, not declared table sizes or
an estimate of successful names. Cancellation or failure cannot refund the
counter or restart another owner. Empty, unterminated, slash-containing, or
otherwise noncanonical library names remain forbidden.

All original complete-image and per-file hashes, source identity observations,
read-only descriptors, immutable memfd seals, image path/inode checks, fixed
library roots, 256 MiB image bound, 32-file worklist, 128 program-header bound,
4,096 dynamic-entry bound, and 32-needed-entry bound remain. ELF class,
architecture, header/segment/offset arithmetic, exact interpreter,
single dynamic segment, unique string tags, nonzero size, terminating `DT_NULL`,
and forbidden dynamic lookup overrides remain checked. Signature selection,
installed ownership, WorkerLaunch, lease, claim, and execution authorization
are unchanged; this parser does not create any of those authorities.

## Validation boundary

The adjacent byte-plan tests verify independent, bounded mutations without
executing them. The existing real Linux extraction campaign puts each mutant
Node into an owned complete ext4 copy, independently hashes the resulting
Node and full image, and asks the actual signed test extractor to reject it at
the expected native guard. Each refusal is followed by the actual original
native close/join, still subject to the existing two-second bound. Original
descriptors must remain unchanged. The malformed inputs are never executed,
signed as releases, admitted as Runs, or used as recovery evidence.

The campaign requires the unchanged official Node to pass with its measured
large string table. Its closed report explicitly lists each malformed case's
guard, refusal, and completed join; raw ELF bytes, library names, debugfs output,
and arbitrary error messages are not evidence fields. Cases cover missing,
duplicate, zero or unterminated dynamic metadata; address and full-extent
bounds; duplicate/partial virtual mapping and file aliases; invalid needed
offsets; unterminated, path-containing and empty names; and the 33rd needed
entry. Existing digest, ext4-open, source identity, descriptor reuse and
cancellation cases remain.

Local pure-data or TypeScript success is not native Linux qualification. The
complete new campaign and installed verifier must pass on genuine Linux before
this acceptance change is called qualified. Installation, CLI delivery and
other unexecuted cuts retain their independent validation requirements.
