# Frozen skills in installed Runs

This package implements the RFC SkillSourceIdentity/SkillManifest closure. It
does not qualify the installed Linux path or switch the default CLI.

The selected request's `skillIds` are authoritative and retain their order.
Discovery examines only the trusted workspace's `.cliq/skills` and
`.agents/skills`, the actual platform user's `.cliq/skills` and `.agents/skills`,
and the selected RuntimeBundle's signed skill closures. The same unqualified
id appearing more than once is an admission error. There is no rank-based
shadowing, automatic activation, repository code import, environment override
or legacy runtime composition.

`kernel/skill.ts` owns the closed data types, omission digests and bounded
decoders. `state/skill-source.ts` owns descriptor-relative capture using the
genuine HeldWorkspaceRoot/cursor API. Its fixed `openSkillSnapshot` recipe
skips Git metadata, including a cloned skill's `.git`, without reading it;
it cannot read symlink targets. The ordinary source and AGENTS-only recipes
retain their original guards. Every selected file is a
same-owner regular file, one link, one of the RFC modes, on the held root's
device; complete reads, EOF, before/after metadata and final directory/source
rechecks precede returning a capture. The trusted workspace and actual
principal bind workspace and user roots respectively. Captures have only
read authority. All cursors, readers and directory handles really close;
uncertain close is ResourceRetirementError.

The raw `SKILL.md` is canonical nonempty NFC/LF UTF-8. Its pure markdown parser
produces one exact nonempty ModelText instruction. The explicit reference
closure is frozen as resources, in byte-sorted path order, with at most
128 resources and 16 MiB of resource bytes. Executable files are explicitly
`executable-disabled` data. Nothing imports or executes resource bytes.

The reference grammar follows the [AgentSkills specification](https://agentskills.io/specification):
there is no required or interpreted `resources` frontmatter field. Metadata is
a string map. Standard inline/image links, single-line reference definitions
with full/collapsed/shortcut uses, and explicit relative code or line tokens
such as `scripts/extract.py`, `references/guide.md:12` and
`assets/template.txt#L3-L7` identify files. Markdown paths are relative to the
skill root. Explicit fenced commands can name data dependencies; they never
authorize execution. Plain prose paths have a relative path component and
an ordinary file suffix or a literal scripts/references/assets/templates
prefix. Bare names need a link, inline code or their own standalone line;
ambiguous natural-language names such as Node.js are not file declarations.
Other names can use an explicit `./` path. This grammar does not infer unspecified files from natural-language
phrases or execute scripts to discover imports. The optional license string
can likewise name a literal bundled file.

External URLs and same-file anchors remain inert text. Local HTML file
attributes, escaped/multiline Markdown destinations, globs, variable-based
paths, absolute paths and root escapes are unsupported and refuse capture.
Percent-encoded link paths are decoded before containment validation. JSON
resources are limited to the original 1 MiB/10k/depth32 decoding bound; a
literal local `$ref` resolves relative to that JSON file, while URI rebasing,
remote/dynamic/recursive schema references refuse. Dependencies recurse with
depth32 and cycle checks. The complete retained CAS graph is independently
recomputed: missing references, unreferenced extra files and altered raw bytes
all refuse. Unselected neighboring files are never opened as resources.

Bundled sources use an acyclic signed non-executable `skill_bundle` entry
whose complete-byte ref is the BundledSkillClosure ref. Its semantic omission
digest is independently checked. All raw members are signed non-executable
bundle objects. Installation imports the complete closure; recovery never
opens an installed package path or mutable user/workspace path.
The existing aggregate RuntimeBundle bound of 65 structured roots and its
1 MiB/10k/depth32 manifest bounds remain in force, together with the original
non-skill member bounds. A skill's per-closure maximum does not promise that
all maxima can be combined in one signed bundle.

`state/skill-data.ts` is the common complete CAS reader for admission material,
model instruction projection, resource reads, recovery and reachability. It
validates every original source identity, descriptor projection, bundled
signature member, raw byte count/hash, instruction derivation and manifest.
Assembly retains only ordered skill ids and exact manifest refs/digests;
ContextManifest retains the assembly ref. Child assembly derivation keeps
the parent's exact skill closure. Skill capture adds nothing to the separate
SourceProjection; an independently selected workspace file may remain ordinary
source. Explicit source selectors govern that separate choice. Skills cannot
modify tool, credential, MCP, network or sandbox permissions.

## Fixed resource operation

The fixed signed Supervisor `skill_resource` recipe is CAS-only and read-only,
with the explicit `supervisor_operation` execution variant. Its current
implementation uses the same local reducer, strict history and installed
campaign contract described below. Actual Linux qualification remains pending.
Its exact input is `{skillId,canonicalRelativePath,offset,length}`: a selected
skill id, one canonical resource file path, a byte offset and 1..65536 bytes.
Clients/models cannot supply an ArtifactRef or an absolute/host path. Every
call rereads and validates the original complete selected closure and full
resource bytes before selecting its range. Its bounded output contains the
skill/path/kind, total byte count, exact offset, canonical base64 bytes,
nextOffset and eof. Empty resources return a genuine empty EOF result; no
implicit truncation or skipped read is allowed. Base64 makes binary and
executable-disabled data representable without interpreting it. The original
1 MiB model JSON limit and token/compaction checks still apply.

This is an ordinary named read action under the frozen Run policy, with an
explicit `skill_resource` policy channel and target. Workspace Trust alone
never grants it. It uses the existing exact ToolRequest/OperationGrant and
authenticated approval/replay contract. An implementation-specific closed
Supervisor-local Journal branch records prepared/claim/completed and one
normal tool-call charge in the sole Checkpoint/effect transaction. It carries
no native operation, broker fence, process/death assertion or fabricated
worker lease. No await follows the final current owner/time/Stop/ancestry,
grant, input, assembly and original Checkpoint checks. SQL rollback leaves
only orphan publications; retrying the same local operation does not invent
UNKNOWN or dispatch it twice. Claimed/UNKNOWN physical operations remain on
their original recovery path. A committed result is reconstructed from its
original sources, never by reopening a skill directory.

The handler changes context only: it preserves the exact WorkspaceState and
existing worker's generation/lease, when one is active; a queued Run needs no
worker to read its immutable resource. Its result has ordinary provider
tool-call ownership and never creates a synthetic provider call. Denial,
expiry, cancellation, resource failure, output bounds and recovery use the
existing once-accounting and Stop rules.

## Validation boundary

Required coverage includes hostile data without getters/proxies; all three
real source scopes; id conflicts and request order; replaced/symlink/hardlink,
wrong owner/mode/device, invalid text, count/byte limits and cancellation;
durability/reader-close failure join; full bundled/member substitution; CAS
mutation and mutable-path deletion after admission; original model prompt
order, bounded resource ranges and repeated/reopened history; approval,
Stop and exactly-once budget/Journal behavior. Pure data and local Store
components do not establish Linux installation or sandbox qualification.
