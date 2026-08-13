import path from 'node:path';

import { canonicalSha256 } from '../kernel/canonical.js';

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

type MacOSExecutionProbeManifestCore = {
  schemaVersion: 1;
  format: 'cliq-execution-probe-manifest-v1';
  backend: 'macos_vm';
  guest: {
    kernelPath: string;
    kernelSha256: string;
    initramfsPath: string;
    initramfsSha256: string;
    workerSha256: string;
    protocolVersion: 'cliq-guest-probe-v1';
  };
};

type LinuxExecutionProbeManifestCore = {
  schemaVersion: 1;
  format: 'cliq-execution-probe-manifest-v1';
  backend: 'linux_namespace';
  launcher: {
    path: string;
    sha256: string;
    protocolVersion: 'cliq-linux-probe-v1';
  };
  bubblewrap: {
    path: string;
    sha256: string;
  };
};

export type MacOSExecutionProbeManifest = MacOSExecutionProbeManifestCore & {
  manifestDigest: string;
};

export type LinuxExecutionProbeManifest = LinuxExecutionProbeManifestCore & {
  manifestDigest: string;
};

export type ExecutionProbeManifest = MacOSExecutionProbeManifest | LinuxExecutionProbeManifest;
export type ExecutionProbeManifestWithoutDigest =
  | MacOSExecutionProbeManifestCore
  | LinuxExecutionProbeManifestCore;

export type MacOSExecutionInstallationIdentity = Readonly<{
  manifestDigest: string;
  helperDigest: string;
}>;

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }
}

function assertClosedKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string
): void {
  const allowed = new Set(expected);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new TypeError(`${label} contains unknown member ${JSON.stringify(key)}`);
    }
  }
  for (const key of expected) {
    if (!Object.hasOwn(value, key)) {
      throw new TypeError(`${label} is missing required member ${JSON.stringify(key)}`);
    }
  }
}

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a raw lowercase SHA-256 digest`);
  }
}

function assertBundleRelativePath(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new TypeError(`${label} must be a nonempty relative path`);
  }
  if (path.isAbsolute(value) || path.posix.normalize(value) !== value) {
    throw new TypeError(`${label} must be a normalized relative path`);
  }
  const components = value.split('/');
  if (components.some((component) => component.length === 0 || component === '.' || component === '..')) {
    throw new TypeError(`${label} must be a normalized relative path without traversal`);
  }
}

function assertLinuxAbsolutePath(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    path.posix.normalize(value) !== value ||
    value.includes('\0')
  ) {
    throw new TypeError(`${label} must be a normalized absolute Linux path`);
  }
}

function parseManifestCore(input: unknown): ExecutionProbeManifestWithoutDigest {
  assertPlainObject(input, 'execution probe manifest');
  if (input.schemaVersion !== 1) {
    throw new TypeError('execution probe manifest schemaVersion must be 1');
  }
  if (input.format !== 'cliq-execution-probe-manifest-v1') {
    throw new TypeError('execution probe manifest format is unsupported');
  }
  if (input.backend === 'linux_namespace') {
    assertClosedKeys(
      input,
      ['schemaVersion', 'format', 'backend', 'launcher', 'bubblewrap'],
      'execution probe manifest core'
    );
    assertPlainObject(input.launcher, 'execution probe launcher');
    assertClosedKeys(
      input.launcher,
      ['path', 'sha256', 'protocolVersion'],
      'execution probe launcher'
    );
    assertBundleRelativePath(input.launcher.path, 'launcher.path');
    assertSha256(input.launcher.sha256, 'launcher.sha256');
    if (input.launcher.protocolVersion !== 'cliq-linux-probe-v1') {
      throw new TypeError('launcher.protocolVersion is unsupported');
    }
    assertPlainObject(input.bubblewrap, 'execution probe bubblewrap');
    assertClosedKeys(input.bubblewrap, ['path', 'sha256'], 'execution probe bubblewrap');
    assertLinuxAbsolutePath(input.bubblewrap.path, 'bubblewrap.path');
    assertSha256(input.bubblewrap.sha256, 'bubblewrap.sha256');
    return {
      schemaVersion: 1,
      format: 'cliq-execution-probe-manifest-v1',
      backend: 'linux_namespace',
      launcher: {
        path: input.launcher.path,
        sha256: input.launcher.sha256,
        protocolVersion: 'cliq-linux-probe-v1'
      },
      bubblewrap: {
        path: input.bubblewrap.path,
        sha256: input.bubblewrap.sha256
      }
    };
  }
  if (input.backend !== 'macos_vm') {
    throw new TypeError('execution probe manifest backend is unsupported');
  }
  assertClosedKeys(
    input,
    ['schemaVersion', 'format', 'backend', 'guest'],
    'execution probe manifest core'
  );

  assertPlainObject(input.guest, 'execution probe guest');
  assertClosedKeys(
    input.guest,
    [
      'kernelPath',
      'kernelSha256',
      'initramfsPath',
      'initramfsSha256',
      'workerSha256',
      'protocolVersion'
    ],
    'execution probe guest'
  );
  assertBundleRelativePath(input.guest.kernelPath, 'guest.kernelPath');
  assertSha256(input.guest.kernelSha256, 'guest.kernelSha256');
  assertBundleRelativePath(input.guest.initramfsPath, 'guest.initramfsPath');
  assertSha256(input.guest.initramfsSha256, 'guest.initramfsSha256');
  assertSha256(input.guest.workerSha256, 'guest.workerSha256');
  if (input.guest.protocolVersion !== 'cliq-guest-probe-v1') {
    throw new TypeError('guest.protocolVersion is unsupported');
  }

  return {
    schemaVersion: 1,
    format: 'cliq-execution-probe-manifest-v1',
    backend: 'macos_vm',
    guest: {
      kernelPath: input.guest.kernelPath,
      kernelSha256: input.guest.kernelSha256,
      initramfsPath: input.guest.initramfsPath,
      initramfsSha256: input.guest.initramfsSha256,
      workerSha256: input.guest.workerSha256,
      protocolVersion: 'cliq-guest-probe-v1'
    }
  };
}

export function computeExecutionProbeManifestDigest(
  input: ExecutionProbeManifestWithoutDigest | ExecutionProbeManifest
): string {
  assertPlainObject(input, 'execution probe manifest');
  const { manifestDigest: _omitted, ...candidate } = input as ExecutionProbeManifest &
    Record<string, unknown>;
  const core = parseManifestCore(candidate);
  return canonicalSha256(core);
}

function parseMacOSExecutionInstallationIdentity(
  input: unknown,
  label: string
): MacOSExecutionInstallationIdentity {
  assertPlainObject(input, label);
  assertClosedKeys(input, ['manifestDigest', 'helperDigest'], label);
  assertSha256(input.manifestDigest, `${label}.manifestDigest`);
  assertSha256(input.helperDigest, `${label}.helperDigest`);
  return Object.freeze({
    manifestDigest: input.manifestDigest,
    helperDigest: input.helperDigest
  });
}

/**
 * Verifies the post-signing helper bytes and signed manifest against identity
 * values frozen outside the app bundle by the installer/Supervisor.
 */
export function assertMacOSExecutionInstallationIdentity(
  expectedInput: unknown,
  observedInput: unknown
): void {
  const expected = parseMacOSExecutionInstallationIdentity(
    expectedInput,
    'expected macOS execution installation identity'
  );
  const observed = parseMacOSExecutionInstallationIdentity(
    observedInput,
    'observed macOS execution installation identity'
  );
  if (observed.manifestDigest !== expected.manifestDigest) {
    throw new TypeError('macOS execution installation manifest digest mismatch');
  }
  if (observed.helperDigest !== expected.helperDigest) {
    throw new TypeError('macOS execution installation helper digest mismatch');
  }
}

export function parseExecutionProbeManifest(input: unknown): ExecutionProbeManifest {
  assertPlainObject(input, 'execution probe manifest');
  const expectedKeys =
    input.backend === 'linux_namespace'
      ? ['schemaVersion', 'format', 'backend', 'launcher', 'bubblewrap', 'manifestDigest']
      : ['schemaVersion', 'format', 'backend', 'guest', 'manifestDigest'];
  assertClosedKeys(input, expectedKeys, 'execution probe manifest');
  assertSha256(input.manifestDigest, 'manifestDigest');
  const { manifestDigest, ...candidate } = input;
  const core = parseManifestCore(candidate);
  const expectedDigest = canonicalSha256(core);
  if (manifestDigest !== expectedDigest) {
    throw new TypeError('execution probe manifest digest mismatch');
  }

  if (core.backend === 'macos_vm') {
    Object.freeze(core.guest);
    return Object.freeze({ ...core, manifestDigest });
  }
  Object.freeze(core.launcher);
  Object.freeze(core.bubblewrap);
  return Object.freeze({ ...core, manifestDigest });
}
