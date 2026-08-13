import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertMacOSExecutionInstallationIdentity,
  computeExecutionProbeManifestDigest,
  parseExecutionProbeManifest
} from './runtime-bundle.js';

const baseManifest = {
  schemaVersion: 1,
  format: 'cliq-execution-probe-manifest-v1',
  backend: 'macos_vm',
  guest: {
    kernelPath: 'Contents/Resources/Image',
    kernelSha256: '1'.repeat(64),
    initramfsPath: 'Contents/Resources/cliq-initramfs-virt',
    initramfsSha256: '2'.repeat(64),
    workerSha256: '3'.repeat(64),
    protocolVersion: 'cliq-guest-probe-v1'
  }
} as const;

test('execution probe manifest has one canonical self-digest', () => {
  const manifestDigest = computeExecutionProbeManifestDigest(baseManifest);
  const parsed = parseExecutionProbeManifest({ ...baseManifest, manifestDigest });

  assert.equal(parsed.manifestDigest, manifestDigest);
  assert.equal(parsed.backend, 'macos_vm');
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.guest), true);
});

test('macOS frozen installation identity rejects different helper bytes', () => {
  const expected = {
    manifestDigest: 'a'.repeat(64),
    helperDigest: 'b'.repeat(64)
  } as const;

  assert.doesNotThrow(() => assertMacOSExecutionInstallationIdentity(expected, expected));
  assert.throws(
    () =>
      assertMacOSExecutionInstallationIdentity(expected, {
        ...expected,
        helperDigest: 'c'.repeat(64)
      }),
    /helper digest/i
  );
});

test('execution probe manifest rejects traversal, unknown fields, and digest drift', () => {
  const manifestDigest = computeExecutionProbeManifestDigest(baseManifest);

  assert.throws(
    () =>
      parseExecutionProbeManifest({
        ...baseManifest,
        guest: { ...baseManifest.guest, kernelPath: '../Image' },
        manifestDigest
      }),
    /relative path/i
  );
  assert.throws(
    () => parseExecutionProbeManifest({ ...baseManifest, manifestDigest, extra: true }),
    /unknown member/i
  );
  assert.throws(
    () => parseExecutionProbeManifest({ ...baseManifest, manifestDigest: '4'.repeat(64) }),
    /digest mismatch/i
  );
});

test('Linux execution probe manifest pins launcher and bubblewrap bytes', () => {
  const core = {
    schemaVersion: 1,
    format: 'cliq-execution-probe-manifest-v1',
    backend: 'linux_namespace',
    launcher: {
      path: 'bin/cliq-linux-probe',
      sha256: '5'.repeat(64),
      protocolVersion: 'cliq-linux-probe-v1'
    },
    bubblewrap: {
      path: '/usr/bin/bwrap',
      sha256: '6'.repeat(64)
    }
  } as const;
  const manifestDigest = computeExecutionProbeManifestDigest(core);
  const parsed = parseExecutionProbeManifest({ ...core, manifestDigest });

  assert.equal(parsed.backend, 'linux_namespace');
  assert.equal(parsed.manifestDigest, manifestDigest);
  if (parsed.backend === 'linux_namespace') {
    assert.equal(parsed.launcher.path, 'bin/cliq-linux-probe');
    assert.equal(parsed.bubblewrap.path, '/usr/bin/bwrap');
  }
});
