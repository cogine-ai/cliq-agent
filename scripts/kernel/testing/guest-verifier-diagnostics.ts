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
  spawnTarget: 'canonical_node' | 'deleted_canonical_node' | 'deleted_bindfile' | 'other_or_absent';
  diagnosticFormat: 'tap' | 'spec' | 'other_or_absent';
  reportedOperation: 'spawn' | 'spawnSync' | 'open' | 'stat' | 'lstat' | 'access' | 'readlink' | 'scandir' | 'other_or_absent' }>;
type OutputFailure = Readonly<{ outcome: VerificationReceipt['outcome']; stdoutBytes: number; stderrBytes: number;
  markerStatus: MarkerStatus; reportedErrorCodes: readonly typeof errorCodes[number][] } & SpawnFailure>;
const outputFailures = new WeakMap<Error, OutputFailure>();

type ReportedError = { format: 'tap' | 'spec'; message: string; code: string; syscall?: string; path?: string };
const absent: SpawnFailure = { spawnSyscall: 'other_or_absent', spawnTarget: 'other_or_absent',
  diagnosticFormat: 'other_or_absent', reportedOperation: 'other_or_absent' };

// Node's TAP reporter uses util.inspect strings, not arbitrary YAML. Decode
// only their bounded delimiters/quote escapes; never evaluate/interpolate or
// turn escaped control/path text into one of the fixed known target names.
function scalar(value: string): string | undefined {
  const quote = value[0];
  if (value.length < 2 || value.length > 1024 || !["'", '"', '`'].includes(quote!) || value.at(-1) !== quote) return;
  let result = '';
  for (let i = 1; i < value.length - 1; i++) {
    const at = value[i]!;
    if (at === quote || at === '\r' || at === '\n' || at === '\0' || quote === '`' && at === '$' && value[i + 1] === '{') return;
    if (at === '\\') {
      const next = value[++i]; if (!next || i >= value.length - 1) return;
      if (next === quote || next === '\\') result += next;
      else if (/^[bfnrtv0xu]$/u.test(next)) result += '\\' + next;
      else return;
    } else result += at;
  }
  return result;
}

function tapErrors(lines: readonly string[]): Array<ReportedError | undefined> {
  const observations: Array<ReportedError | undefined> = [];
  let block: { indent: string; error?: string; code?: string; invalid: boolean; literal?: string[] } | undefined;
  for (const line of lines) {
    if (block?.literal && line.startsWith(block.indent + '  ')) { block.literal.push(line.slice(block.indent.length + 2)); continue; }
    if (block?.literal) { block.error = block.literal.join('\n'); block.literal = undefined; }
    const start = /^( {2,16})---$/u.exec(line);
    if (start) { if (block) observations.push(undefined); block = { indent: start[1]!, invalid: block !== undefined }; continue; }
    if (!block) continue;
    if (line === block.indent + '...') {
      if (block.invalid || block.error !== undefined && (block.code === undefined || block.error.length > 1024)) observations.push(undefined);
      else if (block.error !== undefined) observations.push({ format: 'tap', message: block.error, code: block.code! });
      block = undefined; continue;
    }
    for (const key of ['error', 'code'] as const) {
      const prefix = block.indent + key + ': '; if (!line.startsWith(prefix)) continue;
      if (block[key] !== undefined) block.invalid = true;
      const raw = line.slice(prefix.length);
      if (key === 'error' && raw === '|-') { block.literal = []; block.error = ''; }
      else { block[key] = scalar(raw); if (block[key] === undefined) block.invalid = true; }
    }
  }
  if (block) observations.push(undefined);
  return observations;
}

function specErrors(lines: readonly string[]): Array<ReportedError | undefined> {
  const sections = lines.flatMap((line, index) => line === '✖ failing tests:' ? [index] : []);
  if (!sections.length) return [];
  if (sections.length !== 1) return [undefined];
  const observations: Array<ReportedError | undefined> = [];
  let location = false, failure = false;
  let block: { indent: string; message: string; code?: string; syscall?: string; path?: string; opened: boolean; invalid: boolean } | undefined;
  for (const line of lines.slice(sections[0]! + 1)) {
    if (!block) {
      if (/^test at [^\r\n]{1,4096}:[1-9][0-9]*:[1-9][0-9]*$/u.test(line)) { location = true; failure = false; continue; }
      if (location && /^✖ [^\r\n]{1,4096}$/u.test(line)) { failure = true; continue; }
      const start = /^( {2,16})Error: ([^\r\n]{1,1024})$/u.exec(line);
      if (failure && start) {
        const opened = start[2]!.endsWith(' {');
        block = { indent: start[1]!, message: opened ? start[2]!.slice(0, -2) : start[2]!, opened, invalid: false };
        location = false; failure = false;
      }
      continue;
    }
    if (line === block.indent + '}') {
      observations.push(block.opened && !block.invalid && block.code !== undefined
        ? { format: 'spec', message: block.message, code: block.code, ...(block.syscall === undefined ? {} : { syscall: block.syscall }),
          ...(block.path === undefined ? {} : { path: block.path }) } : undefined);
      block = undefined; continue;
    }
    if (line.startsWith(block.indent + '    at ') && line.endsWith(' {')) block.opened = true;
    for (const key of ['code', 'syscall', 'path'] as const) {
      const prefix = block.indent + '  ' + key + ': '; if (!line.startsWith(prefix)) continue;
      if (block[key] !== undefined) block.invalid = true;
      const raw = line.slice(prefix.length); block[key] = scalar(raw.endsWith(',') ? raw.slice(0, -1) : raw);
      if (block[key] === undefined) block.invalid = true;
    }
    if (line.length <= block.indent.length && line !== '') { observations.push(undefined); block = undefined; }
  }
  if (block || location || failure) observations.push(undefined);
  return observations;
}

function reportedSpawn(stdout: string | undefined, stderr: string | undefined): SpawnFailure {
  if (stdout === undefined || stderr === undefined) return absent;
  const observations: Array<ReportedError | undefined> = [];
  for (const text of [stdout, stderr]) {
    const lines = text.split('\n').slice(0, -1).map(value => value.endsWith('\r') ? value.slice(0, -1) : value);
    observations.push(...tapErrors(lines), ...specErrors(lines));
  }
  if (observations.length !== 1 || !observations[0]) return absent;
  const value = observations[0], base = { ...absent, diagnosticFormat: value.format };
  if (value.code !== 'ENOENT') return base;
  const spawn = /^(spawn|spawnSync) (\/[^\r\n]{1,256}) ENOENT$/u.exec(value.message);
  const file = /^ENOENT: no such file or directory, (open|stat|lstat|access|readlink|scandir) '([^\r\n]{1,256})'$/u.exec(value.message);
  const match = spawn ?? file; if (!match) return base;
  const operation = match[1] as Exclude<SpawnFailure['reportedOperation'], 'other_or_absent'>, target = match[2]!;
  if (value.format === 'spec' && (value.syscall !== (spawn ? operation + ' ' + target : operation) || value.path !== target)) return base;
  if (operation !== 'spawn') return { ...base, reportedOperation: operation };
  const spawnTarget = target === '/usr/bin/node' ? 'canonical_node' : target === '/usr/bin/node (deleted)' ? 'deleted_canonical_node' :
    /^\/bindfile[A-Za-z0-9]{6} \(deleted\)$/u.test(target) ? 'deleted_bindfile' : 'other_or_absent';
  return { ...base, reportedOperation: 'spawn', spawnSyscall: 'spawn', spawnTarget };
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
