# I1 release trust and npm-first installation decision

**Status:** proposed npm-first distribution; production key custody and a clean
installed-path qualification remain open. This does not qualify a Kernel installation.

## Evidence in this repository

- `verifyRuntimeBundle` accepts release public keys supplied by trusted
  composition. No production Cliq Ed25519 public key, private-key custody,
  rotation policy, or signing job is configured. Existing test keys are
  generated in process and cannot authorize an installed runtime.
- `npm-publish.yml` builds on Ubuntu and publishes the universal npm package.
  `package.json` includes `dist/**/*.js` but no `dist/native/**`; the required
  StateOwner and local-control helpers are therefore absent from the tarball.
  The workflow uses a long-lived `NPM_TOKEN` and does not establish npm trusted
  publishing/provenance. It cannot build, sign, or qualify the macOS runtime.
- A local npm publish token authenticates the publisher to the npm registry.
  It is not an Ed25519 private key and cannot produce the RuntimeBundle
  `signature` verified against Cliq's embedded release public key. Keep these
  two authorities distinct; neither secret belongs in the source repository.
- A macOS Developer ID identity and a notarized **probe** app were qualified
  locally. That identity and probe are separate from an installed RuntimeBundle
  release signature or a shippable Supervisor/worker image.

## Recommended trust chain

1. The stable bootstrap embeds a small, versioned allowlist of Cliq release
   Ed25519 public keys (`keyId`, public key, lifecycle state). It reads no
   public key or private key from the repository, mutable workspace, Run,
   client request, model output, or bundle being verified. Development-only
   ephemeral keys stay behind the existing test fixture boundary.
2. CI builds an unsigned, immutable candidate for each supported OS and
   architecture. It records the compiler/toolchain, exact native helper,
   Supervisor, worker, guest and data-file digests, and runs the platform
   probes plus installed-path tests. Any macOS code signing and notarization
   finishes **before** complete-file digests enter the RuntimeBundle manifest.
   The Supervisor image includes its fixed JavaScript implementation; a signed
   Node interpreter that later reads replaceable JS files is insufficient.
   [Node's SEA contract](https://nodejs.org/download/release/v24.16.0/docs/api/single-executable-applications.html)
   supplies the current Node 24 packaging candidate. Its build uses one bundled
   CommonJS entry, disables snapshot and code cache, and sets
   `execArgvExtension='none'` so `NODE_OPTIONS` cannot extend the signed
   process's execution arguments. Native helpers remain separately signed and
   byte-pinned in the bundle. The macOS release image must be Developer ID
   signed and notarized after SEA injection, before manifest hashing; an
   ad-hoc-signed test SEA is not a releasable payload.
3. A release-only signer, isolated from PR jobs, signs the final canonical
   manifest digest with a Cliq-controlled Ed25519 private key. It never accepts
   a caller-supplied key ID as proof of trust. The release job independently
   verifies the signature and all file bytes, then publishes the immutable
   bundle by complete signed-manifest ref. CI test keys cannot pass this gate.
4. Keep **npm as the one required public distribution channel**. Publish the
   CLI and complete, version-matched OS/architecture runtime payloads to npm;
   they may be separate platform-scoped npm packages or one package if size and
   install behavior permit. A missing platform payload, including an omitted
   optional dependency, fails closed. The runtime must not download executable
   bytes from an unpinned second endpoint during install or first Run.
   An explicit, idempotent setup/first-run path imports the verified payload
   from the installed npm package into an owner-only stable state root and
   registers the user service. Updating/removing the npm client cannot erase a
   bundle pinned by a nonterminal Run. Do not make correctness depend on
   `postinstall`, which npm users may disable with `--ignore-scripts`.
5. npm's registry signatures and [trusted publishing with provenance](https://docs.npmjs.com/trusted-publishers/)
   strengthen the npm release path; use OIDC instead of the current long-lived
   token and verify the published package's attestations. The current
   `npm-publish.yml` has only `contents: read`, accepts an arbitrary dispatch
   ref, and passes `NPM_TOKEN`; it is not an OIDC release job. Before switching,
   configure this package's trusted publisher, restrict the authorized release
   ref/workflow, grant `id-token: write`, and pin a release toolchain with
   Node >=22.14.0 and npm >=11.5.1 as required by the current
   [npm trusted-publishing contract](https://docs.npmjs.com/trusted-publishers/).
   Do not remove the existing publish credential until a separately approved
   release qualification proves the new path. Provenance links a
   package to its source/workflow; it does not prove that the source or
   authorized workflow is benign. Under this npm-first choice, the npm release
   path is the **first-install trust anchor** for the bootstrap and its embedded
   Cliq public keys. The independent Cliq Ed25519 signer protects the runtime
   bundle after that bootstrap is established, but cannot rescue a malicious
   first bootstrap that replaces both verifier and key. Surviving compromise of
   the authorized npm release path requires a separately authenticated bootstrap
   anchor; that is a stronger, optional threat model, not an I1 distribution
   prerequisite.
6. Sign and notarize the macOS executable payload before including its final
   bytes in the RuntimeBundle manifest. [Apple permits direct distribution of
   notarized software](https://developer.apple.com/documentation/technologyoverviews/distribution);
   a separate `.pkg` or `.dmg` channel is not intrinsically required. Qualify
   the actual `npm pack` → clean install → state-root import → Gatekeeper/
   `spctl` → restart path on macOS, including preserved signatures and stapled
   tickets. Linux needs the same clean npm install and executable-identity
   proof. If those installed-path tests expose a platform distribution
   constraint, revisit packaging with that evidence.
7. The installed bootstrap holds the package and destination directories,
   opens every signed component descriptor-relative with no-follow rules,
   checks owner/type/mode/link-count and pre/post metadata, rehashes full
   bytes, decodes every structured root/member, imports their bytes to CAS,
   and fsyncs the immutable bundle directory before `active.json` can select
   it. Startup and update repeat the published identity and compatibility
   checks; an incompatible candidate leaves the current bundle active.
8. Key rotation requires a new bootstrap trusted by the current distribution
   channel and an overlap window for previously installed, pinned bundles.
   Retirement cannot strand a nonterminal Run or invalidate retained audit
   verification. A compromised-key response needs an explicit release policy;
   it cannot silently reinterpret historical signatures.

## Decision required before production I1

The release owner must identify an existing production Cliq Ed25519 trust root
and protected signing workflow, or authorize creation and custody of a new one.
The recommended first-install channel is npm; no additional channel is required
by this design. We must still qualify the actual published npm payload on Linux
and macOS and explicitly accept npm release-path trust for the first bootstrap.
Until then, implementation can use injected **test** public keys to verify
mechanics, but may not label a source build, npm tarball, or locally signed
probe as an installed signed Kernel runtime. Production key provisioning is a
release-qualification gate, not a reason to stop independent implementation.
