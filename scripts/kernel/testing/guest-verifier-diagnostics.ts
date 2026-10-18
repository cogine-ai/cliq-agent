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
type SpawnFailure = Readonly<{ spawnSyscall: 'spawn' | 'other_or_absent';
  spawnTarget: 'canonical_node' | 'deleted_canonical_node' | 'deleted_bindfile' | 'other_or_absent' }>;
type OutputFailure = Readonly<{ outcome: VerificationReceipt['outcome']; stdoutBytes: number; stderrBytes: number;
  markerStatus: MarkerStatus; reportedErrorCodes: readonly typeof errorCodes[number][] } & SpawnFailure>;
const outputFailures = new WeakMap<Error, OutputFailure>();

function reportedSpawn(stdout: string | undefined, stderr: string | undefined): SpawnFailure {
  const absent: SpawnFailure = { spawnSyscall: 'other_or_absent', spawnTarget: 'other_or_absent' };
  if (stdout === undefined || stderr === undefined) return absent;
  const observations: SpawnFailure[] = [];
  for (const text of [stdout, stderr]) {
    let block: { indent: string; error?: string; code?: string; invalid: boolean } | undefined;
    const lines = text.split('\n');
    // Only a complete Node TAP diagnostic block can identify a reported
    // spawn. Test names, comments, partial lines and arbitrary path strings
    // never become a target. This remains a diagnostic, not a native cause.
    for (const line of lines.slice(0, -1).map(value => value.endsWith('\r') ? value.slice(0, -1) : value)) {
      const start = /^( {2,16})---$/u.exec(line);
      if (start) { block = { indent: start[1]!, invalid: block !== undefined }; continue; }
      if (!block) continue;
      if (line === block.indent + '...') {
        if (block.invalid) observations.push(absent);
        else if (block.error?.startsWith("'spawn ")) {
          const match = /^'spawn (\/[^'\r\n]{1,256}) ENOENT'$/u.exec(block.error);
          const target = match?.[1];
          const spawnTarget = target === '/usr/bin/node' ? 'canonical_node' :
            target === '/usr/bin/node (deleted)' ? 'deleted_canonical_node' :
              target !== undefined && /^\/bindfile[A-Za-z0-9]{6} \(deleted\)$/u.test(target) ? 'deleted_bindfile' : undefined;
          observations.push(spawnTarget && block.code === "'ENOENT'" ? { spawnSyscall: 'spawn', spawnTarget } : absent);
        }
        block = undefined; continue;
      }
      for (const key of ['error', 'code'] as const) {
        const prefix = block.indent + key + ': ';
        if (!line.startsWith(prefix)) continue;
        if (block[key] !== undefined) block.invalid = true;
        block[key] = line.slice(prefix.length);
      }
    }
    if (block) observations.push(absent);
  }
  return observations.length === 1 ? observations[0]! : absent;
}

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
      markerStatus: observed.status, reportedErrorCodes: Object.freeze(reportedErrorCodes), ...reportedSpawn(text, errorText) }));
  }
}

export function readGuestVerifierBoundaryFailure(error: unknown): BoundaryFailure | undefined {
  return error instanceof Error ? failures.get(error) : undefined;
}

export function readGuestVerifierOutputFailure(error: unknown): OutputFailure | undefined {
  return error instanceof Error ? outputFailures.get(error) : undefined;
}
