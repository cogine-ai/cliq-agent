# Signed runtime and schema upgrade

This implementation adds one explicit transition: a fully retired signed
schema 7 installation to the fixed schema 8 recipe. It does not enable the
default Kernel Cut, a general SQL migration engine, an unsigned runtime,
cross-platform execution, or arbitrary service control.

## Signed source

A new schema 8 bundle contains the existing `role: schema` entry
`kernel_schema`, version `8`, at `schema/kernel-v8.json`. Its complete canonical
bytes bind the six-field schema manifest, complete DDL, complete SQLite catalog
and both semantic digests. Fresh signed genesis publishes and registers that
exact profile in the original first StateOwner transaction. A compatibility
range, today's schema, a matching label or a CAS-provided key cannot replace
these signed bytes.

An upgrade bundle also contains `schema_conversion`, version `7-to-8`, at
`schema/convert-v7-to-v8.json`. This fixed profile names the original signed
bundle, Supervisor entry and executable, original generated schema manifest,
and exact known schema 7 catalog. It explicitly recognizes that legacy source;
it does not claim the old publisher signed a schema entry which never existed.
The target profile names the exact schema 8 profile and fixed compiled 7-to-8
statements. Package-supplied SQL is never executed.

The generic `schema` role also carries the model's tool-input JSON schemas.
Only the reserved `kernel_schema` and `schema_conversion` entry IDs select
database schema purposes. Both still require the exact role, non-executable
flag, version, path, signed digest, byte count and complete fixed recipe.
Tool-input schemas remain in their original verified package/consumer closure;
they do not enter credential-history SQL provenance or authorize DDL. An
original schema 7 model package may contain these ordinary JSON schemas, but
must contain neither reserved database-schema entry.

Both bundle signatures must verify under the same actual trusted Ed25519
public key. The key ID is insufficient. The ArtifactCatalog retains an
immutable snapshot of the Store's existing trusted release configuration for
historical signature reads. Missing trusted context refuses; CAS, requests,
old artifacts and mutable external arrays cannot add or merge trust roots.
This context does not create a StateOwner or execution authority.

The schema 8 recipe includes the exact derived authorization-list index
`authorization_grants_list_order_v1` over the original principal, canonical
`createdAt` expression and grant ID. Schema 7 remains unchanged. No unsigned
migration adds the index to an existing signed installation.

## One administrative command

Run the genuine signed **target** Supervisor image with:

```text
<target-package>/supervisor --upgrade-runtime <canonical-StateRoot> <signed-target-package>
```

Trust roots come from that SEA image's original compiled asset. Arguments do
not accept a key, arbitrary unit, PID, transport, SQL, death observation or
runtime override. The SDK client facade does not expose these administrative
constructors. The command performs the whole sequence and joins its owners;
operators do not manually order low-level stage, Stop and selector operations.

1. Open the genuine old selection and authenticate its live keeper anchor.
   Capture the original keeper PID/start, boot/locator bytes and ready-file
   inode before closing the anchor. Verify the whole old and target signed
   closures. Create target files only in the held private runtime stage.
2. Persist target package, bootstrap, CAS roots and streams. Roots use the same
   fixed groups of at most four with every original file sync, four publication
   stages, complete rereads and all failure joins. The stage precreates the
   selection file; the final receipt binds its actual inode before filling its
   receipt-dependent bytes. Publication requires one filesystem for runtime
   objects and bundles; an independent CAS filesystem retains its existing
   contract.
3. Refuse a nonterminal Run before requesting service Stop. Observe the exact
   original two fixed service profiles. The signed target manager helper may
   administratively stop only the derived Supervisor and keeper units. Their
   actual MainPID, process start and InvocationID must match the captured
   originals before the request. StopUnit addresses a unit name and is not an
   atomic Invocation selector: a restart in that gap can stop the same unit's
   successor. The later complete owner comparison must then reject conversion;
   it cannot use that successor as the original producer or death evidence.
   Its optional
   interface does not become a requirement for ordinary old helper loading.
4. A StopUnit job or inactive unit is not a death proof. Independently observe
   actual original Supervisor and keeper PID/start death, preserve the original
   two-second Stop bound and join the original native inspection, timer and
   cancellation owners. No arbitrary kill, pause or inferred namespace proof
   is added.
5. Hold the same StateRoot flock. Require the exact schema 7 catalog and actual
   graceful old StateOwner release. Fully read each terminal Run's ordinary
   recovery closure, all retired launches/generations and source retirements.
   Outstanding reservations, UNKNOWN/unsettled attempts, missing provenance
   and unsupported producer families refuse. Actual connection change counters
   and the complete old owner history bind this audited SQL cut.
6. Publish and completely reread the original row evidence through the fixed
   four-family reference graph before sampling the final death/time cut.
   Each canonical page contains at most 512 row refs; each family contains at
   most 100,000 refs (196 pages), and the total is at most 400,000 refs. Each
   index binds original owner epoch/row digest, family, exact row/page counts,
   ordered page refs and an unambiguous incremental sequence digest over a
   fixed domain/owner/family/count header and every verified 64-hex row ref.
   No large array is JSON-serialized for that total hash. Every page/index
   keeps the original 1 MiB, 10,000-entry and depth-32 limits. Missing, duplicate,
   reordered, changed, aliased or wrong-owner pages/rows refuse; all original
   rows are fully decoded and compared with the real SQL cut. Family capacity
   is checked before row publication, and no row is truncated. This is one
   final unpublished witness representation, not a legacy dual reader.
   Only after all page/index persistence, full reads and joins does preparation
   sample the actual process/death observation. Publish the fixed current
   process, receipt and acquisition evidence and join every CAS operation.
   The sole conversion
   transaction rechecks current filesystem/lock/process/source facts, samples
   fresh commit time, applies only fixed DDL, transfers the existing time fence
   and registers the next StateOwner with that exact receipt. Preparation time
   does not advance the time fence. A real regression commits the same original
   sticky `clock_regressed` fence before refusal outside its transaction; it
   creates no upgrade owner or DDL decision.
7. Retain the flock through the registered target directory, bootstrap and
   selection renames and actual directory fsyncs. Gracefully release the actual
   upgrade owner, then close the credential/native scope and original FDs.
   Start the existing services and require a real authenticated HELLO naming
   the exact target bundle. Owned stdout is joined through the same native
   fixed-stdio factory as the installed clients.

Success emits one canonical JSON line with the target bundle and registered
receipt ref, plus
`providerBindingPolicy: "explicit_new_runtime_authorization_required"`.
Selected schema 8 with actual READY and usable provider authorization are
separate facts. Original endpoint TLS material remains bound to its original
runtime bundle. Old records remain readable/revocable, and first response
bytes stay retained; a new binding must use the existing public endpoint and
credential enrollment flows. Qualification may explicitly authorize its own
new test binding, but cannot call this automatic credential migration.

Historical endpoint and credential metadata revalidates its original retained
signed bundle, complete original HTTPS trust-store bytes and exact original
channel/root/principal/operation chain. A different runtime is accepted only
through the current held installation's exact signed 7-to-8 conversion and full
schema bytes under the same trusted publisher key. Trust configuration comes
only from that genuine installation. Old source images are never replaced by
today's process identity. An explicit non-expanding revoke may instead name the
real current producer, but its original signed bundle bytes must already be
retained by that operation; today's package cannot fill missing history.
New registration, enrollment, rotation and model material release still require
the current runtime's exact TLS binding. Historical readability and revocation
do not authorize a new model request or copy a secret into another binding.

Opening an upgraded installation still fully audits its registered SQL/CAS
receipt, original retirement and signed conversion. Its original source package
then receives a separate fresh descriptor scope: every original byte and exact
namespace is checked, and all old executable descriptors actually close before
the current selection is returned. Subsequent current authentication reads keep
the original complete target package/CAS/active/bootstrap checks and all sixteen
R boundaries. They also retain and fully rehash the small signed source manifest
and check its original directory and complete namespace, but do not borrow old
executable files. A later historical package read opens and verifies everything
again; it cannot reuse the earlier hash result. Receipt recovery and retained
SQL/CAS history keep their own complete source checks. This scope distinction
does not claim to fix the schema-7 installation's independent five-second
timeout; actual schema-8 authentication and upgrade qualification remain required.

## Failure and recovery

Before the conversion transaction commits, the old schema, owner and active
selection remain authoritative. A private stage or CAS orphan is not an
upgrade decision. A recorded real clock regression is deliberately sticky.
If a precommit attempt stopped the old services, the same command first starts
only the genuine old selection's fixed units and requires its real authenticated
HELLO before taking another stage. Schema 8 takes only registered-receipt
recovery and cannot reach that old-start branch. The unit-restart race itself
remains unverified until an actual lifecycle execution hits that boundary.

After commit, schema 7 must never write again. Repeating the same formal command
finds the registered acquisition and exact receipt; it neither reruns the DDL
nor allocates a second upgrade decision. Recovery requires the complete
original signed source, registered stage/runtime/file inode identities,
original bytes and actual original holder death before resuming any incomplete
publication. Missing, half-written, replaced or duplicate births refuse. An
already complete publication is a strict read-only idempotent result.
Recovery never adopts same-content replacements, claims to hold old FDs,
creates a substitute unlink proof, or treats a missing keeper locator as death.
The registered old bundle and empty original stage remain retained roots.

Source capture failures written by old schema 7 can contain the historical
43-character INTERNAL correlation value, which the later public UUID guard
does not accept. Upgrade never rewrites it, applies today's producer formula
to old bytes, or promotes an unretired source. Such replay can remain explicitly
unsupported; missing original retirement evidence blocks the transition.
This historical gap must be reported by qualification rather than hidden by
a compatible-looking current response.

## Evidence and release boundary

Real focused Store/SQLite/CAS tests cover signed fresh genesis, same actual
publisher verification, wrong-key/same-ID rejection, missing trust context,
fixed DDL rollback, immutable source evidence, read-only DB opening and foreign
opaque object rejection. A separately pinned, genuinely compiled schema 7
Store process creates the old genesis; a current process converts it, repeats
the same receipt, reopens schema 8, and confirms the old binary refuses without
changing database bytes. Negative damaged-fence data is restored exactly before
the independent positive. These are mechanism tests, not installed qualification.

The installed campaign must build the actual frozen schema 7 product and target
product under one in-memory controlled publisher session, execute real old Run
retirement, use the formal command, preserve old results/requests, explicitly
enroll a new runtime-bound provider credential and complete a real target Run.
Supported Node/Linux systemd Stop, all crash boundaries, delayed storage,
cross-platform execution and final release acceptance remain unverified until
those exact executions pass. No focused pass substitutes for them.

The 100,000-reference representation boundary is tested against real SQLite
ordering and complete bounded CAS publication/reads. Those are reference data,
not 100,000 genuinely admitted and physically retired Runs. Actual large-state
installed upgrade latency, shutdown and recovery qualification remain separate.

The unsigned release inputs are the exact target source inventory, signed
schema bytes/catalog digest, fixed conversion recipe, actual compiled SEA and
native/helper/guest bytes, complete source bundle and full dependency closure.
An unsigned candidate is never selectable. Qualification's ephemeral key is
not a project release root. Maintainers must provide the official compiled trust
configuration and sign the real complete package; publishing, signed installed
upgrade qualification and the default client cut remain gated separately.
