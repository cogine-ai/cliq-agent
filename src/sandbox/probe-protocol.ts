const SHA256_PATTERN = /^[0-9a-f]{64}$/;

const COMMON_OBSERVATION_KEYS = [
  'generationWrite',
  'workspaceReadDenied',
  'workspaceWriteDenied',
  'stateReadDenied',
  'stateWriteDenied',
  'homeReadDenied',
  'directNetworkDenied',
  'daemonContained',
  'descendantsEnumerated',
  'forcedTerminationEmpty',
  'helperIdentityObserved',
  'workerIdentityVerified'
] as const;

const MACOS_OBSERVATION_KEYS = [
  ...COMMON_OBSERVATION_KEYS,
  'guestImageDigestVerified',
  'authenticatedGuestBoot',
  'noWritableHostShare',
  'vmStopped'
] as const;

const LINUX_OBSERVATION_KEYS = [
  ...COMMON_OBSERVATION_KEYS,
  'userNamespace',
  'mountNamespace',
  'networkNamespace',
  'pidNamespace',
  'cgroupV2',
  'cgroupOwned',
  'cgroupFreeze',
  'cgroupKill',
  'cgroupEmpty',
  'resourceLimits',
  'subreaper',
  'noNewPrivileges'
] as const;

export type MacOSExecutionProbeReceipt = {
  schemaVersion: 1;
  protocolVersion: 'cliq-execution-backend-probe-v1';
  backend: 'macos_vm';
  challenge: string;
  helperDigest: string;
  kernelDigest: string;
  initramfsDigest: string;
  workerDigest: string;
  observations: Record<(typeof MACOS_OBSERVATION_KEYS)[number], true>;
};

export type LinuxExecutionProbeReceipt = {
  schemaVersion: 1;
  protocolVersion: 'cliq-execution-backend-probe-v1';
  backend: 'linux_namespace';
  challenge: string;
  helperDigest: string;
  bubblewrapDigest: string;
  observations: Record<(typeof LINUX_OBSERVATION_KEYS)[number], true>;
};

export type ExecutionProbeReceipt = MacOSExecutionProbeReceipt | LinuxExecutionProbeReceipt;

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

export function parseExecutionProbeReceipt(input: string): ExecutionProbeReceipt {
  let decoded: unknown;
  try {
    decoded = JSON.parse(input);
  } catch {
    throw new TypeError('execution probe receipt must be valid JSON');
  }
  assertPlainObject(decoded, 'execution probe receipt');
  const expectedKeys =
    decoded.backend === 'linux_namespace'
      ? [
          'schemaVersion',
          'protocolVersion',
          'backend',
          'challenge',
          'helperDigest',
          'bubblewrapDigest',
          'observations'
        ]
      : [
          'schemaVersion',
          'protocolVersion',
          'backend',
          'challenge',
          'helperDigest',
          'kernelDigest',
          'initramfsDigest',
          'workerDigest',
          'observations'
        ];
  assertClosedKeys(decoded, expectedKeys, 'execution probe receipt');
  if (decoded.schemaVersion !== 1) {
    throw new TypeError('execution probe receipt schemaVersion must be 1');
  }
  if (decoded.protocolVersion !== 'cliq-execution-backend-probe-v1') {
    throw new TypeError('execution probe receipt protocolVersion is unsupported');
  }
  assertSha256(decoded.challenge, 'receipt.challenge');
  assertSha256(decoded.helperDigest, 'receipt.helperDigest');
  if (decoded.backend === 'linux_namespace') {
    assertSha256(decoded.bubblewrapDigest, 'receipt.bubblewrapDigest');
    assertPlainObject(decoded.observations, 'execution probe observations');
    assertClosedKeys(decoded.observations, LINUX_OBSERVATION_KEYS, 'execution probe observations');
    const observations = {} as Record<(typeof LINUX_OBSERVATION_KEYS)[number], true>;
    for (const key of LINUX_OBSERVATION_KEYS) {
      if (decoded.observations[key] !== true) {
        throw new TypeError(`execution probe observation ${key} must be true`);
      }
      observations[key] = true;
    }
    Object.freeze(observations);
    return Object.freeze({
      schemaVersion: 1,
      protocolVersion: 'cliq-execution-backend-probe-v1',
      backend: 'linux_namespace',
      challenge: decoded.challenge,
      helperDigest: decoded.helperDigest,
      bubblewrapDigest: decoded.bubblewrapDigest,
      observations
    });
  }
  if (decoded.backend !== 'macos_vm') {
    throw new TypeError('execution probe receipt backend is unsupported');
  }
  assertSha256(decoded.kernelDigest, 'receipt.kernelDigest');
  assertSha256(decoded.initramfsDigest, 'receipt.initramfsDigest');
  assertSha256(decoded.workerDigest, 'receipt.workerDigest');
  assertPlainObject(decoded.observations, 'execution probe observations');
  assertClosedKeys(decoded.observations, MACOS_OBSERVATION_KEYS, 'execution probe observations');

  const observations = {} as Record<(typeof MACOS_OBSERVATION_KEYS)[number], true>;
  for (const key of MACOS_OBSERVATION_KEYS) {
    if (decoded.observations[key] !== true) {
      throw new TypeError(`execution probe observation ${key} must be true`);
    }
    observations[key] = true;
  }
  Object.freeze(observations);

  return Object.freeze({
    schemaVersion: 1,
    protocolVersion: 'cliq-execution-backend-probe-v1',
    backend: 'macos_vm',
    challenge: decoded.challenge,
    helperDigest: decoded.helperDigest,
    kernelDigest: decoded.kernelDigest,
    initramfsDigest: decoded.initramfsDigest,
    workerDigest: decoded.workerDigest,
    observations
  });
}
