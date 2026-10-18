import type { VerificationReceipt } from '../../../src/kernel/verifier.js';

const stages = ['runtime_identity', 'source_read', 'environment', 'ambient_paths', 'source_readonly',
  'descriptor_surface', 'workspace_noexec', 'tmp_noexec', 'loader_noexec', 'network_denied',
  'child_node', 'child_domain', 'complete'] as const;
type BoundaryFailure = Readonly<{ stage: typeof stages[number]; outcome: VerificationReceipt['outcome'] }>;
const failures = new WeakMap<Error, BoundaryFailure>();
const prefix = 'CLIQ_GUEST_BOUNDARY_V1:';

/** Only projects already fully read/verified receipt stdout into fixed data.
 * This does not authenticate bytes, mint evidence or change the original error. */
export function recordGuestVerifierBoundaryFailure(error: unknown, outcome: VerificationReceipt['outcome'], stdout: Uint8Array): void {
  if (!(error instanceof Error) || stdout.byteLength > 65_536
      || !['passed', 'assertion_failed', 'infra_failed', 'source_mutation'].includes(outcome)) return;
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(stdout); } catch { return; }
  let next = 0;
  // Node's test runner prefixes child stdout with '# '. Nothing else from TAP
  // (including assertion messages) is retained or interpreted.
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    const marker = line.startsWith('# ') ? line.slice(2) : line;
    if (!marker.startsWith(prefix)) continue;
    if (index === lines.length - 1 || next >= stages.length || marker !== prefix + stages[next]) return;
    next++;
  }
  if (next) failures.set(error, Object.freeze({ stage: stages[next - 1]!, outcome }));
}

export function readGuestVerifierBoundaryFailure(error: unknown): BoundaryFailure | undefined {
  return error instanceof Error ? failures.get(error) : undefined;
}
