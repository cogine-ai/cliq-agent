import { parseCanonicalTime } from '../kernel/identity.js';

/** Data ordering only. The original transaction still samples C, advances its
 * real clock fence, and independently reobserves the actual physical owner.
 * An unrelated fence advance during CAS does not move logical projection P. */
export function manualStopTimeOrderIsValid(input: Readonly<{
  projectionAt: string;
  sourceRunUpdatedAt: string;
  sourceCheckpointCreatedAt: string;
  sourceSessionUpdatedAt?: string;
  committedAt: string;
  lastAcceptedAt: string;
}>): boolean {
  const projection = parseCanonicalTime(input.projectionAt), committed = parseCanonicalTime(input.committedAt);
  return projection >= parseCanonicalTime(input.sourceRunUpdatedAt) &&
    projection >= parseCanonicalTime(input.sourceCheckpointCreatedAt) &&
    (input.sourceSessionUpdatedAt === undefined || projection >= parseCanonicalTime(input.sourceSessionUpdatedAt)) &&
    committed >= projection && committed >= parseCanonicalTime(input.lastAcceptedAt);
}
