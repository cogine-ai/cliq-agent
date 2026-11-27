import type { BigIntStats } from 'node:fs';

/** Negative scheduling hint only. Replacement neither authenticates a peer
 * nor proves that its service, StateOwner or application channel is ready. */
export function isReplacementControlSocketHint(previous: BigIntStats, current: BigIntStats): boolean {
  return previous.isSocket() && current.isSocket() && previous.uid === current.uid && previous.dev === current.dev &&
    (previous.ino !== current.ino || previous.ctimeNs !== current.ctimeNs);
}
