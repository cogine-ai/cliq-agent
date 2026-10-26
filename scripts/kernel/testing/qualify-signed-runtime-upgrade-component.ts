// Explicit generic Store/process component, not installed/Linux/release proof.
import { exerciseSignedRuntimeUpgradeSource } from '../../../src/state/testing/runtime-upgrade-fixture.js';
import { assertArtifactRef, normalizeAbsolutePath } from '../../../src/kernel/identity.js';
const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== '--source-root' || args[2] !== '--source-manifest' || args[4] !== '--source-manifest-sha256')
  throw new TypeError('expected exact frozen source-root, source-manifest and manifest SHA256');
const sourceRoot = normalizeAbsolutePath(args[1]!), sourceManifest = normalizeAbsolutePath(args[3]!);
assertArtifactRef(args[5]!);
await exerciseSignedRuntimeUpgradeSource({ sourceRoot, sourceManifest, expectedManifestDigest: args[5]! });
console.log(JSON.stringify({ schemaVersion: 1, kind: 'genuine-frozen7-store-upgrade-component', passed: true,
  sourceManifestSha256: args[5], installedQualified: false, officialReleaseQualified: false }));
