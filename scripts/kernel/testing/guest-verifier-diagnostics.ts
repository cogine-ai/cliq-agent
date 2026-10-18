import type { VerificationReceipt } from '../../../src/kernel/verifier.js';

const stages = ['runtime_identity', 'source_read', 'environment', 'ambient_paths', 'source_readonly',
  'descriptor_surface', 'workspace_noexec', 'tmp_noexec', 'loader_noexec', 'network_denied',
  'child_node', 'child_domain', 'complete'] as const;
type BoundaryFailure = Readonly<{ stage: typeof stages[number]; outcome: VerificationReceipt['outcome'] }>;
const failures = new WeakMap<Error, BoundaryFailure>();
const prefix = 'CLIQ_GUEST_BOUNDARY_V1:';
const errorCodes = ['ERR_MODULE_NOT_FOUND', 'ERR_TEST_FAILURE', 'ERR_WORKER_INIT_FAILED', 'ERR_CHILD_PROCESS_IPC_REQUIRED',
  'EACCES', 'EPERM', 'ENOMEM', 'EMFILE', 'ENFILE', 'ENOENT', 'ETIMEDOUT'] as const;
type MarkerStatus = 'absent' | 'ordered' | 'invalid_sequence' | 'invalid_utf8';
type OutputFailure = Readonly<{ outcome: VerificationReceipt['outcome']; stdoutBytes: number; stderrBytes: number;
  markerStatus: MarkerStatus; reportedErrorCodes: readonly typeof errorCodes[number][] }>;
const outputFailures = new WeakMap<Error, OutputFailure>();

function markers(text: string): { status: Exclude<MarkerStatus, 'invalid_utf8'>; stage?: typeof stages[number] } {
  let next = 0;
  // Node's test runner may prefix child stdout with '# '. Unknown, duplicate,
  // reordered or partial lines never become a valid observation prefix.
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!, marker = line.startsWith('# ') ? line.slice(2) : line;
    if (!marker.startsWith(prefix)) continue;
    if (index === lines.length - 1 || next >= stages.length || marker !== prefix + stages[next]) return { status: 'invalid_sequence' };
    next++;
  }
  return next ? { status: 'ordered', stage: stages[next - 1]! } : { status: 'absent' };
}

/** Only projects already fully read/verified receipt stdout into fixed data.
 * This does not authenticate bytes, mint evidence or change the original error. */
export function recordGuestVerifierBoundaryFailure(error: unknown, outcome: VerificationReceipt['outcome'], stdout: Uint8Array,
  stderr?: Uint8Array): void {
  if (!(error instanceof Error) || stdout.byteLength > 65_536
      || stderr && stdout.byteLength + stderr.byteLength > 65_536
      || !['passed', 'assertion_failed', 'infra_failed', 'source_mutation'].includes(outcome)) return;
  let text: string | undefined, errorText: string | undefined;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(stdout); } catch { /* finite invalid-UTF-8 status only */ }
  if (stderr) {
    try { errorText = new TextDecoder('utf-8', { fatal: true }).decode(stderr); } catch { /* no arbitrary replacement text */ }
  }
  const observed: { status: MarkerStatus; stage?: typeof stages[number] } =
    text === undefined ? { status: 'invalid_utf8' } : markers(text);
  if (observed.stage) failures.set(error, Object.freeze({ stage: observed.stage, outcome }));
  if (stderr) {
    // Literal allowlist projection over the original full-hash receipt bytes.
    // These are reported tokens, not authenticated causes or execution proof.
    // Paths, test names, stack text and unlisted codes are never retained.
    const reportedErrorCodes = errorCodes.filter(code => [text, errorText].some(value =>
      value !== undefined && new RegExp(`\\b${code}\\b`, 'u').test(value)));
    outputFailures.set(error, Object.freeze({ outcome, stdoutBytes: stdout.byteLength, stderrBytes: stderr.byteLength,
      markerStatus: observed.status, reportedErrorCodes: Object.freeze(reportedErrorCodes) }));
  }
}

export function readGuestVerifierBoundaryFailure(error: unknown): BoundaryFailure | undefined {
  return error instanceof Error ? failures.get(error) : undefined;
}

export function readGuestVerifierOutputFailure(error: unknown): OutputFailure | undefined {
  return error instanceof Error ? outputFailures.get(error) : undefined;
}
