import { randomBytes } from 'node:crypto';
import path from 'node:path';

import { assertControlSocketPath } from '../control/socket-path.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { assertArtifactRef, normalizeAbsolutePath } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ReleaseTrustKey, RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from '../state/errors.js';
import {
  openInitialSelectionWriter, openInstalledBundleRoot, openRuntimeSelectionRoot, readHeldActiveSelection,
  verifyHeldInstalledBundle, type NativePackageReader
} from './native-package-reader.js';

export type ActiveRuntimeSelectionV1 = Readonly<{
  schemaVersion: 1;
  format: 'cliq-runtime-active-selection-v1';
  bundleDigest: string;
  manifestDigest: string;
}>;

const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

function decodeSelection(bytes: Buffer): ActiveRuntimeSelectionV1 {
  let value: unknown;
  try { value = JSON.parse(strictUtf8.decode(bytes)); }
  catch { throw new KernelStorageError('ARTIFACT_MISMATCH', 'active runtime selection is not UTF-8 JSON'); }
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      Object.keys(value).length !== 4 ||
      !['schemaVersion', 'format', 'bundleDigest', 'manifestDigest'].every((key) => Object.hasOwn(value, key)) ||
      !canonicalJsonBytes(value).equals(bytes)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'active runtime selection is not canonical');
  }
  const selection = value as ActiveRuntimeSelectionV1;
  if (selection.schemaVersion !== 1 || selection.format !== 'cliq-runtime-active-selection-v1') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'active runtime selection has an unsupported schema');
  }
  assertArtifactRef(selection.bundleDigest);
  assertArtifactRef(selection.manifestDigest);
  return Object.freeze(selection);
}

function readSelection(reader: NativePackageReader, stateRoot: string): {
  selection: ActiveRuntimeSelectionV1; bytes: Buffer;
} {
  const root = openRuntimeSelectionRoot(reader, path.join(stateRoot, 'runtime'));
  try {
    const bytes = readHeldActiveSelection(root);
    return { selection: decodeSelection(bytes), bytes };
  } finally { root.close(); }
}

/** Read-only bootstrap inspection. The caller must separately own service transition and StateOwner compatibility. */
export async function inspectSelectedRuntimeBundle(reader: NativePackageReader, stateRoot: string,
  releaseKeys: readonly ReleaseTrustKey[]): Promise<{
    selection: ActiveRuntimeSelectionV1;
    bundle: RuntimeBundleManifest;
    bundlePath: string;
  }> {
  const trustedKeys = immutableSnapshot(releaseKeys);
  if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('StateRoot path must be canonical');
  assertControlSocketPath(stateRoot);
  const before = readSelection(reader, stateRoot);
  const bundlePath = path.join(stateRoot, 'runtime', 'bundles', before.selection.bundleDigest);
  const root = openInstalledBundleRoot(reader, bundlePath);
  let bundle: RuntimeBundleManifest;
  try {
    const verified = await verifyHeldInstalledBundle(root, trustedKeys, before.selection.bundleDigest);
    if (verified.bundle.manifestDigest !== before.selection.manifestDigest) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'active selection has a different manifest digest');
    }
    bundle = verified.bundle;
  } finally { root.close(); }
  const after = readSelection(reader, stateRoot);
  if (!before.bytes.equals(after.bytes)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'active runtime selection changed during verification');
  }
  return { selection: before.selection, bundle, bundlePath };
}

/** First-install filesystem cut after the initial owner has imported and released the signed bundle.
 * This does not authorize an update or replace an existing selection. */
export async function publishInitialRuntimeSelection(reader: NativePackageReader, stateRoot: string,
  releaseKeys: readonly ReleaseTrustKey[], bundleDigest: string): Promise<ActiveRuntimeSelectionV1> {
  const trustedKeys = immutableSnapshot(releaseKeys);
  if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('StateRoot path must be canonical');
  assertControlSocketPath(stateRoot);
  assertArtifactRef(bundleDigest);
  const bundlePath = path.join(stateRoot, 'runtime', 'bundles', bundleDigest);
  const installed = openInstalledBundleRoot(reader, bundlePath);
  let manifestDigest: string;
  try {
    const verified = await verifyHeldInstalledBundle(installed, trustedKeys, bundleDigest);
    manifestDigest = verified.bundle.manifestDigest;
  } finally { installed.close(); }
  const expected: ActiveRuntimeSelectionV1 = Object.freeze({
    schemaVersion: 1, format: 'cliq-runtime-active-selection-v1', bundleDigest, manifestDigest
  });
  const runtime = openInitialSelectionWriter(reader, path.join(stateRoot, 'runtime'));
  try {
    runtime.publishInitialActive(canonicalJsonBytes(expected), randomBytes(16).toString('hex'));
  } finally { runtime.close(); }
  const observed = await inspectSelectedRuntimeBundle(reader, stateRoot, trustedKeys);
  if (observed.selection.bundleDigest !== expected.bundleDigest ||
      observed.selection.manifestDigest !== expected.manifestDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'initial runtime selection differs from the verified bundle');
  }
  return observed.selection;
}
