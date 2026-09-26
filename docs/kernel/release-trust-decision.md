# I1 release trust and first-install decision

**Status:** proposed; production key custody and first-install channel require
the release owner's decision. This does not qualify a Kernel installation.

## Evidence in this repository

- `verifyRuntimeBundle` accepts release public keys supplied by trusted
  composition. No production Cliq Ed25519 public key, private-key custody,
  rotation policy, or signing job is configured. Existing test keys are
  generated in process and cannot authorize an installed runtime.
- `npm-publish.yml` builds on Ubuntu and publishes the universal npm package.
  `package.json` includes `dist/**/*.js` but no `dist/native/**`; the required
  StateOwner and local-control helpers are therefore absent from the tarball.
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
3. A release-only signer, isolated from PR jobs, signs the final canonical
   manifest digest with a Cliq-controlled Ed25519 private key. It never accepts
   a caller-supplied key ID as proof of trust. The release job independently
   verifies the signature and all file bytes, then publishes the immutable
   bundle by complete signed-manifest ref. CI test keys cannot pass this gate.
4. A first-install channel establishes the bootstrap itself. macOS can use a
   Developer ID signed/notarized installer; Linux needs an explicitly trusted
   package/signature channel and pinned bootstrap bytes. The current generic
   npm tarball can remain a thin client, but by itself does not establish this
   native runtime chain or an owner-only stable state-root bootstrap.
5. The installed bootstrap holds the package and destination directories,
   opens every signed component descriptor-relative with no-follow rules,
   checks owner/type/mode/link-count and pre/post metadata, rehashes full
   bytes, decodes every structured root/member, imports their bytes to CAS,
   and fsyncs the immutable bundle directory before `active.json` can select
   it. Startup and update repeat the published identity and compatibility
   checks; an incompatible candidate leaves the current bundle active.
6. Key rotation requires a new bootstrap trusted by the current distribution
   channel and an overlap window for previously installed, pinned bundles.
   Retirement cannot strand a nonterminal Run or invalidate retained audit
   verification. A compromised-key response needs an explicit release policy;
   it cannot silently reinterpret historical signatures.

## Decision required before production I1

The release owner must identify an existing production Cliq Ed25519 trust
root and protected signing workflow, or authorize creation and custody of a
new one. We also need the supported first-install distribution channel for
Linux and macOS. Until then, implementation can use injected **test** public
keys to verify mechanics, but may not label a source build, npm tarball, or
locally signed probe as an installed signed Kernel runtime.
