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

## Publisher image layout

The shared Linux image builder defaults to a deterministic compact layout.
It retains the complete, measured executable/library inventory and the original
16 MiB metadata reserve, then rounds their sum up to the next 16 MiB multiple.
The result must remain at most 256 MiB. The closed publisher input records
`imageLayout` with profile `cliq-guest-image-layout-v1`, kind `compact`, the
complete inventory's `contentBytes`, fixed `reserveBytes` and `alignmentBytes`,
and the resulting `imageByteCount`. The signing packager independently sums
the same closed inventory and requires this exact layout and actual file size;
it does not accept an arbitrary smaller image. `mke2fs` must actually fit the
complete tree: a capacity failure refuses the build, without dropping files,
growing the image, or retrying a different recipe.

This changes only unused padding in the publisher's output. The complete raw
image remains independently read and hashed at every existing revalidation,
including both installed and CAS copies. All source identity, EOF, signature,
ABI, extractor and file-size bounds remain. No hash result, descriptor,
validation or authority is cached, and the original authentication, restart,
probe and stop deadlines are unchanged.

The fixed builder argument `--qualification-max` selects the separate
`qualification_max` construction profile, still with the identical complete
inventory and reserve, but an exact 256 MiB image. It is selected only by the
existing native guest campaign and installed verifier qualifier. This keeps
their maximum-image tests, four distinct signed 256 MiB image copies (1 GiB
total), enrollment and complete secret-writer corpus separate from the
default compact installed Delivery campaign. The corpus still scans its one
CAS image plus all original database/artifact streams within the original
512 MiB, 4,096-stream and 60-second limits; it never claimed to scan all four
images within that byte budget. Compact success cannot qualify this maximum
workload or replace an earlier failure.

Installed compact reports add `bundle.guestImageLayout` with the same closed
layout; the unchanged maximum-profile report shape still requires exactly
256 MiB and 1 GiB over four copies. A compact report's copy total must instead
equal four times its exact recomputed image size. No runtime option,
environment override, execution permission or new native acceptance rule is
introduced. New image bytes and digests require genuine Linux qualification;
local arithmetic, file/hash/signature and source-wiring regressions do not
prove ext4 capacity, native execution or either profile's five-second
authentication performance. Those checks remain unverified until executed.

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
