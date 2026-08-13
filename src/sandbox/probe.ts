import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  statfs
} from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import { parseExecutionProbeReceipt } from './probe-protocol.js';
import {
  assertMacOSExecutionInstallationIdentity,
  parseExecutionProbeManifest
} from './runtime-bundle.js';

const execFileAsync = promisify(execFile);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const MACOS_TEAM_IDENTIFIER = 'LMWH2NK82S';
const MACOS_SIGNING_IDENTIFIER = 'ai.cogine.cliq.kernel-probe';
const MANIFEST_RELATIVE_PATH = path.join(
  'Contents',
  'Resources',
  'execution-probe-manifest.json'
);
const HELPER_RELATIVE_PATH = path.join('Contents', 'MacOS', 'cliq-kernel-probe');
const SCRATCH_DISK_BYTES = 64 * 1024 * 1024;
const capabilityBrand = Symbol('QualifiedExecutionBackend');

export type ExecutionBackendFailureCode =
  | 'UNSUPPORTED_PLATFORM'
  | 'UNSUPPORTED_EXECUTION_IDENTITY';

export type ExecutionBackendQualificationFailure = {
  ok: false;
  authorityReady: false;
  observedPlatform: NodeJS.Platform;
  error: {
    code: ExecutionBackendFailureCode;
    message: string;
  };
};

type QualifiedMacOSExecutionBackend = Readonly<{
  [capabilityBrand]: true;
  backend: 'macos_vm';
  processId: number;
  qualifiedAt: string;
  fingerprint: Readonly<{
    manifestDigest: string;
    helperDigest: string;
    kernelDigest: string;
    initramfsDigest: string;
    workerDigest: string;
    teamIdentifier: typeof MACOS_TEAM_IDENTIFIER;
    signingIdentifier: typeof MACOS_SIGNING_IDENTIFIER;
  }>;
}>;

type QualifiedLinuxExecutionBackend = Readonly<{
  [capabilityBrand]: true;
  backend: 'linux_namespace';
  processId: number;
  qualifiedAt: string;
  fingerprint: Readonly<{
    manifestDigest: string;
    helperDigest: string;
    bubblewrapDigest: string;
  }>;
}>;

export type QualifiedExecutionBackend =
  | QualifiedMacOSExecutionBackend
  | QualifiedLinuxExecutionBackend;

export type ExecutionBackendQualificationSuccess =
  | {
      ok: true;
      authorityReady: true;
      observedPlatform: 'darwin';
      backend: 'macos_vm';
      capability: QualifiedMacOSExecutionBackend;
      observations: Extract<
        ReturnType<typeof parseExecutionProbeReceipt>,
        { backend: 'macos_vm' }
      >['observations'];
    }
  | {
      ok: true;
      authorityReady: true;
      observedPlatform: 'linux';
      backend: 'linux_namespace';
      capability: QualifiedLinuxExecutionBackend;
      observations: Extract<
        ReturnType<typeof parseExecutionProbeReceipt>,
        { backend: 'linux_namespace' }
      >['observations'];
    };

export type ExecutionBackendQualification =
  | ExecutionBackendQualificationSuccess
  | ExecutionBackendQualificationFailure;

export type MacOSExecutionBackendProbeOptions = {
  backend: 'macos_vm';
  /** A signed and notarized CliqKernelProbe.app built by the release pipeline. */
  bundlePath: string;
  /** Frozen by the installed Supervisor/Run assembly, never discovered from the bundle. */
  expectedManifestDigest: string;
  /** Final post-signing helper digest, frozen alongside expectedManifestDigest. */
  expectedHelperDigest: string;
  /** Existing owner-only local directory used only for the disposable probe disk. */
  scratchRoot: string;
};

export type LinuxExecutionBackendProbeOptions = {
  backend: 'linux_namespace';
  installationRoot: string;
  expectedManifestDigest: string;
  cgroupParent: string;
  scratchRoot: string;
  workspacePath: string;
  stateRootPath: string;
  homePath: string;
};

export type QualifyExecutionBackendOptions =
  | MacOSExecutionBackendProbeOptions
  | LinuxExecutionBackendProbeOptions;

function failure(
  code: ExecutionBackendFailureCode,
  message: string
): ExecutionBackendQualificationFailure {
  return {
    ok: false,
    authorityReady: false,
    observedPlatform: process.platform,
    error: { code, message }
  };
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) return error.message;
  return String(error);
}

async function sha256File(filename: string): Promise<string> {
  const handle = await open(filename, 'r');
  try {
    const hash = crypto.createHash('sha256');
    for await (const chunk of handle.readableWebStream()) {
      hash.update(Buffer.from(chunk));
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

async function assertRegularOwnedFile(filename: string, label: string): Promise<void> {
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a non-symlink regular file`);
  }
  if (metadata.nlink !== 1) {
    throw new Error(`${label} must have exactly one hard link`);
  }
  if (typeof process.geteuid !== 'function' || metadata.uid !== process.geteuid()) {
    throw new Error(`${label} owner does not match the effective uid`);
  }
  if ((metadata.mode & 0o022) !== 0) {
    throw new Error(`${label} must not be group- or world-writable`);
  }
}

async function assertTrustedExecutable(
  filename: string,
  label: string,
  allowedOwners: readonly number[]
): Promise<void> {
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a non-symlink regular file`);
  }
  if (!allowedOwners.includes(metadata.uid)) {
    throw new Error(`${label} has an untrusted owner`);
  }
  if ((metadata.mode & 0o022) !== 0 || (metadata.mode & 0o111) === 0) {
    throw new Error(`${label} must be executable and not group- or world-writable`);
  }
}

async function assertOwnedDirectory(
  dirname: string,
  label: string,
  exactMode?: number
): Promise<void> {
  if (!path.isAbsolute(dirname) || path.normalize(dirname) !== dirname) {
    throw new Error(`${label} must be a normalized absolute path`);
  }
  const metadata = await lstat(dirname);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a non-symlink directory`);
  }
  if (typeof process.geteuid !== 'function' || metadata.uid !== process.geteuid()) {
    throw new Error(`${label} owner does not match the effective uid`);
  }
  if (exactMode !== undefined && (metadata.mode & 0o7777) !== exactMode) {
    throw new Error(`${label} mode must be exactly ${exactMode.toString(8).padStart(4, '0')}`);
  }
  if ((metadata.mode & 0o022) !== 0) {
    throw new Error(`${label} must not be group- or world-writable`);
  }
}

async function assertInsideBundle(bundlePath: string, filename: string, label: string): Promise<void> {
  const [bundleRealPath, fileRealPath] = await Promise.all([realpath(bundlePath), realpath(filename)]);
  if (!fileRealPath.startsWith(`${bundleRealPath}${path.sep}`)) {
    throw new Error(`${label} resolves outside the signed bundle`);
  }
}

async function verifyScratchRoot(scratchRoot: string): Promise<void> {
  await assertOwnedDirectory(scratchRoot, 'scratch root', 0o700);
}

async function verifyMacOSCodeIdentity(bundlePath: string): Promise<void> {
  try {
    await execFileAsync('/usr/bin/codesign', [
      '--verify',
      '--deep',
      '--strict',
      '--verbose=2',
      bundlePath
    ]);
  } catch (error) {
    throw new Error(`macOS helper signature verification failed: ${errorMessage(error)}`);
  }

  const display = await execFileAsync('/usr/bin/codesign', ['-d', '--verbose=4', bundlePath]);
  const signingDetails = `${display.stdout}\n${display.stderr}`;
  if (!signingDetails.includes(`Identifier=${MACOS_SIGNING_IDENTIFIER}`)) {
    throw new Error('macOS helper signature has the wrong signing identifier');
  }
  if (!signingDetails.includes(`TeamIdentifier=${MACOS_TEAM_IDENTIFIER}`)) {
    throw new Error('macOS helper signature has the wrong Team identifier');
  }

  const entitlements = await execFileAsync('/usr/bin/codesign', [
    '-d',
    '--entitlements',
    '-',
    '--xml',
    bundlePath
  ]);
  const entitlementBytes = `${entitlements.stdout}\n${entitlements.stderr}`;
  if (
    !/<key>com\.apple\.security\.virtualization<\/key>\s*<true\s*\/>/.test(
      entitlementBytes
    )
  ) {
    throw new Error('macOS helper signature lacks the virtualization entitlement');
  }

  try {
    await execFileAsync('/usr/sbin/spctl', [
      '--assess',
      '--type',
      'execute',
      '--verbose=4',
      bundlePath
    ]);
  } catch (error) {
    throw new Error(`macOS helper notarization assessment failed: ${errorMessage(error)}`);
  }
}

async function createScratchDisk(scratchRoot: string): Promise<{
  directory: string;
  filename: string;
}> {
  const directory = await mkdtemp(path.join(scratchRoot, '.cliq-execution-probe-'));
  await chmod(directory, 0o700);
  const filename = path.join(directory, 'generation.raw');
  const handle = await open(filename, 'wx', 0o600);
  try {
    await handle.truncate(SCRATCH_DISK_BYTES);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const directoryHandle = await open(directory, 'r');
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
  return { directory, filename };
}

async function qualifyMacOSBackend(
  options: MacOSExecutionBackendProbeOptions
): Promise<ExecutionBackendQualification> {
  if (process.platform !== 'darwin') {
    return failure('UNSUPPORTED_PLATFORM', 'The macOS microVM backend requires macOS.');
  }
  if (!path.isAbsolute(options.bundlePath) || path.normalize(options.bundlePath) !== options.bundlePath) {
    return failure(
      'UNSUPPORTED_EXECUTION_IDENTITY',
      'The macOS helper bundle path must be a normalized absolute path.'
    );
  }
  if (!SHA256_PATTERN.test(options.expectedManifestDigest)) {
    return failure(
      'UNSUPPORTED_EXECUTION_IDENTITY',
      'The expected execution manifest digest is invalid.'
    );
  }
  if (!SHA256_PATTERN.test(options.expectedHelperDigest)) {
    return failure(
      'UNSUPPORTED_EXECUTION_IDENTITY',
      'The expected macOS helper digest is invalid.'
    );
  }

  let scratch: { directory: string; filename: string } | undefined;
  try {
    await verifyScratchRoot(options.scratchRoot);
    const bundleMetadata = await lstat(options.bundlePath);
    if (bundleMetadata.isSymbolicLink() || !bundleMetadata.isDirectory()) {
      throw new Error('macOS helper bundle must be a non-symlink directory');
    }
    await verifyMacOSCodeIdentity(options.bundlePath);

    const manifestPath = path.join(options.bundlePath, MANIFEST_RELATIVE_PATH);
    const helperPath = path.join(options.bundlePath, HELPER_RELATIVE_PATH);
    await Promise.all([
      assertRegularOwnedFile(manifestPath, 'execution probe manifest'),
      assertRegularOwnedFile(helperPath, 'macOS probe helper'),
      assertInsideBundle(options.bundlePath, manifestPath, 'execution probe manifest'),
      assertInsideBundle(options.bundlePath, helperPath, 'macOS probe helper')
    ]);

    const manifest = parseExecutionProbeManifest(
      JSON.parse(await readFile(manifestPath, 'utf8')) as unknown
    );
    if (manifest.backend !== 'macos_vm' || manifest.manifestDigest !== options.expectedManifestDigest) {
      throw new Error('execution probe manifest does not match the frozen manifest digest');
    }

    const kernelPath = path.join(options.bundlePath, manifest.guest.kernelPath);
    const initramfsPath = path.join(options.bundlePath, manifest.guest.initramfsPath);
    await Promise.all([
      assertRegularOwnedFile(kernelPath, 'guest kernel'),
      assertRegularOwnedFile(initramfsPath, 'guest initramfs'),
      assertInsideBundle(options.bundlePath, kernelPath, 'guest kernel'),
      assertInsideBundle(options.bundlePath, initramfsPath, 'guest initramfs')
    ]);
    const [helperDigest, kernelDigest, initramfsDigest] = await Promise.all([
      sha256File(helperPath),
      sha256File(kernelPath),
      sha256File(initramfsPath)
    ]);
    assertMacOSExecutionInstallationIdentity(
      {
        manifestDigest: options.expectedManifestDigest,
        helperDigest: options.expectedHelperDigest
      },
      {
        manifestDigest: manifest.manifestDigest,
        helperDigest
      }
    );
    if (kernelDigest !== manifest.guest.kernelSha256) {
      throw new Error('guest kernel digest does not match the signed manifest');
    }
    if (initramfsDigest !== manifest.guest.initramfsSha256) {
      throw new Error('guest initramfs digest does not match the signed manifest');
    }

    scratch = await createScratchDisk(options.scratchRoot);
    const challenge = crypto.randomBytes(32).toString('hex');
    const invocation = await execFileAsync(
      helperPath,
      [
        '--kernel',
        kernelPath,
        '--initramfs',
        initramfsPath,
        '--scratch-disk',
        scratch.filename,
        '--challenge',
        challenge,
        '--kernel-sha256',
        kernelDigest,
        '--initramfs-sha256',
        initramfsDigest,
        '--worker-sha256',
        manifest.guest.workerSha256,
        '--timeout-seconds',
        '45'
      ],
      { timeout: 60_000, maxBuffer: 1024 * 1024 }
    );
    if (invocation.stderr.trim().length > 0) {
      throw new Error('macOS probe helper wrote unexpected stderr output');
    }
    const receipt = parseExecutionProbeReceipt(invocation.stdout.trim());
    if (
      receipt.backend !== 'macos_vm' ||
      receipt.challenge !== challenge ||
      receipt.helperDigest !== helperDigest ||
      receipt.kernelDigest !== kernelDigest ||
      receipt.initramfsDigest !== initramfsDigest ||
      receipt.workerDigest !== manifest.guest.workerSha256
    ) {
      throw new Error('macOS probe receipt identity does not match the signed bundle');
    }

    const marker = Buffer.from(`cliq-m0-generation-${challenge}`, 'utf8');
    const diskHandle = await open(scratch.filename, 'r');
    try {
      const observed = Buffer.alloc(marker.length);
      const { bytesRead } = await diskHandle.read(observed, 0, observed.length, 0);
      if (bytesRead !== marker.length || !crypto.timingSafeEqual(observed, marker)) {
        throw new Error('host could not verify the guest generation write');
      }
    } finally {
      await diskHandle.close();
    }

    const qualifiedAt = new Date().toISOString();
    const fingerprint = Object.freeze({
      manifestDigest: manifest.manifestDigest,
      helperDigest,
      kernelDigest,
      initramfsDigest,
      workerDigest: manifest.guest.workerSha256,
      teamIdentifier: MACOS_TEAM_IDENTIFIER,
      signingIdentifier: MACOS_SIGNING_IDENTIFIER
    });
    const capability: QualifiedMacOSExecutionBackend = Object.freeze({
      [capabilityBrand]: true as const,
      backend: 'macos_vm',
      processId: process.pid,
      qualifiedAt,
      fingerprint
    });
    return {
      ok: true,
      authorityReady: true,
      observedPlatform: 'darwin',
      backend: 'macos_vm',
      capability,
      observations: receipt.observations
    };
  } catch (error) {
    return failure(
      'UNSUPPORTED_EXECUTION_IDENTITY',
      `The signed macOS microVM qualification failed: ${errorMessage(error)}`
    );
  } finally {
    if (scratch !== undefined) {
      await rm(scratch.directory, { recursive: true, force: true });
    }
  }
}

async function assertProbeDenyPath(filename: string, label: string): Promise<void> {
  if (!path.isAbsolute(filename) || path.normalize(filename) !== filename) {
    throw new Error(`${label} must be a normalized absolute path`);
  }
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a real directory`);
  }
}

async function qualifyLinuxBackend(
  options: LinuxExecutionBackendProbeOptions
): Promise<ExecutionBackendQualification> {
  if (process.platform !== 'linux') {
    return failure('UNSUPPORTED_PLATFORM', 'The Linux namespace backend requires Linux.');
  }
  if (!SHA256_PATTERN.test(options.expectedManifestDigest)) {
    return failure(
      'UNSUPPORTED_EXECUTION_IDENTITY',
      'The expected execution manifest digest is invalid.'
    );
  }

  let generationDirectory: string | undefined;
  try {
    await Promise.all([
      assertOwnedDirectory(options.installationRoot, 'Linux probe installation'),
      verifyScratchRoot(options.scratchRoot),
      assertOwnedDirectory(options.cgroupParent, 'delegated cgroup parent', 0o700),
      assertProbeDenyPath(options.workspacePath, 'workspace probe path'),
      assertProbeDenyPath(options.stateRootPath, 'StateRoot probe path'),
      assertProbeDenyPath(options.homePath, 'home probe path')
    ]);
    const cgroupFilesystem = await statfs(options.cgroupParent, { bigint: true });
    if (BigInt.asUintN(32, cgroupFilesystem.type) !== 0x63677270n) {
      throw new Error('delegated cgroup parent is not on a cgroup v2 filesystem');
    }

    const manifestPath = path.join(options.installationRoot, 'execution-probe-manifest.json');
    await assertRegularOwnedFile(manifestPath, 'execution probe manifest');
    await assertInsideBundle(
      options.installationRoot,
      manifestPath,
      'execution probe manifest'
    );
    const manifest = parseExecutionProbeManifest(
      JSON.parse(await readFile(manifestPath, 'utf8')) as unknown
    );
    if (
      manifest.backend !== 'linux_namespace' ||
      manifest.manifestDigest !== options.expectedManifestDigest
    ) {
      throw new Error('execution probe manifest does not match the frozen manifest digest');
    }

    const helperPath = path.join(options.installationRoot, manifest.launcher.path);
    const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : -1;
    await Promise.all([
      assertTrustedExecutable(helperPath, 'Linux probe helper', [effectiveUid]),
      assertInsideBundle(options.installationRoot, helperPath, 'Linux probe helper'),
      assertTrustedExecutable(manifest.bubblewrap.path, 'bubblewrap', [0, effectiveUid])
    ]);
    const [helperDigest, bubblewrapDigest] = await Promise.all([
      sha256File(helperPath),
      sha256File(manifest.bubblewrap.path)
    ]);
    if (helperDigest !== manifest.launcher.sha256) {
      throw new Error('Linux probe helper digest does not match the frozen manifest');
    }
    if (bubblewrapDigest !== manifest.bubblewrap.sha256) {
      throw new Error('bubblewrap digest does not match the frozen manifest');
    }

    generationDirectory = await mkdtemp(path.join(options.scratchRoot, '.cliq-linux-generation-'));
    await chmod(generationDirectory, 0o700);
    const challenge = crypto.randomBytes(32).toString('hex');
    const invocation = await execFileAsync(
      helperPath,
      [
        '--host',
        '--bwrap',
        manifest.bubblewrap.path,
        '--cgroup-parent',
        options.cgroupParent,
        '--generation',
        generationDirectory,
        '--challenge',
        challenge,
        '--helper-sha256',
        helperDigest,
        '--bwrap-sha256',
        bubblewrapDigest,
        '--workspace-path',
        options.workspacePath,
        '--state-root-path',
        options.stateRootPath,
        '--home-path',
        options.homePath
      ],
      { timeout: 60_000, maxBuffer: 1024 * 1024 }
    );
    if (invocation.stderr.trim().length > 0) {
      throw new Error('Linux probe helper wrote unexpected stderr output');
    }
    const receipt = parseExecutionProbeReceipt(invocation.stdout.trim());
    if (
      receipt.backend !== 'linux_namespace' ||
      receipt.challenge !== challenge ||
      receipt.helperDigest !== helperDigest ||
      receipt.bubblewrapDigest !== bubblewrapDigest
    ) {
      throw new Error('Linux probe receipt identity does not match the frozen manifest');
    }

    const expectedMarker = Buffer.from(`cliq-linux-generation-${challenge}`, 'utf8');
    const marker = await readFile(path.join(generationDirectory, 'probe-marker'));
    if (marker.length !== expectedMarker.length || !crypto.timingSafeEqual(marker, expectedMarker)) {
      throw new Error('host could not verify the sandbox generation write');
    }

    const fingerprint = Object.freeze({
      manifestDigest: manifest.manifestDigest,
      helperDigest,
      bubblewrapDigest
    });
    const capability: QualifiedLinuxExecutionBackend = Object.freeze({
      [capabilityBrand]: true as const,
      backend: 'linux_namespace',
      processId: process.pid,
      qualifiedAt: new Date().toISOString(),
      fingerprint
    });
    return {
      ok: true,
      authorityReady: true,
      observedPlatform: 'linux',
      backend: 'linux_namespace',
      capability,
      observations: receipt.observations
    };
  } catch (error) {
    return failure(
      'UNSUPPORTED_EXECUTION_IDENTITY',
      `The Linux namespace qualification failed: ${errorMessage(error)}`
    );
  } finally {
    if (generationDirectory !== undefined) {
      await rm(generationDirectory, { recursive: true, force: true });
    }
  }
}

/**
 * Mints an opaque, process-lifetime execution capability only after the real
 * backend passes its complete identity, deny/allow, descendant-containment,
 * and death-evidence probe. With no installed backend, or on any mismatch,
 * admission remains fail-closed.
 */
export async function qualifyExecutionBackend(
  options?: QualifyExecutionBackendOptions
): Promise<ExecutionBackendQualification> {
  if (options?.backend === 'macos_vm') return qualifyMacOSBackend(options);
  if (options?.backend === 'linux_namespace') return qualifyLinuxBackend(options);

  const observedPlatform = process.platform;
  if (observedPlatform !== 'darwin' && observedPlatform !== 'linux') {
    return failure(
      'UNSUPPORTED_PLATFORM',
      `Cliq Kernel Run execution is unsupported on ${observedPlatform}.`
    );
  }

  const backend =
    observedPlatform === 'darwin'
      ? 'signed and notarized macOS microVM'
      : 'Linux namespace, cgroup v2, and trusted subreaper';
  return failure(
    'UNSUPPORTED_EXECUTION_IDENTITY',
    `No installed ${backend} qualification bundle was supplied; Run authority remains disabled.`
  );
}
