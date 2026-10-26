// Closed projection data only. Original lineage/index/source authority remains
// in the StateOwner's Session context reader; this decoder grants none.
import { immutableSnapshot } from '../model/immutable.js';
import { assertArtifactRef, digestOmitting } from './identity.js';
import { controlWireInteger, controlWireRecord, controlWireText } from './control-wire-data.js';
import type { SessionContextProjection } from './types.js';
function corrupt(): never { throw new TypeError('Session context projection is not a closed contiguous graph'); }

export function decodeSessionContextData(value: unknown): SessionContextProjection {
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'sessionId', 'contextRevision', 'throughItemSeq', 'segments', 'projectionDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-session-context-v1' || !Array.isArray(data.segments)) return corrupt();
  controlWireText(data.sessionId); controlWireInteger(data.contextRevision, 1); controlWireInteger(data.throughItemSeq);
  assertArtifactRef(data.projectionDigest as string);
  if (digestOmitting(data, 'projectionDigest') !== data.projectionDigest) return corrupt();
  let next = 1;
  for (const raw of data.segments) {
    const base = raw as Record<string, unknown>, kind = base?.kind;
    const segment = controlWireRecord(raw, kind === 'raw' ? ['kind', 'fromItemSeq', 'throughItemSeq', 'items'] :
      kind === 'summary' ? ['kind', 'fromItemSeq', 'throughItemSeq', 'compactionItemId', 'summaryRef', 'summaryDigest', 'sourceItemsDigest', 'retainedItemIds'] :
        ['kind', 'fromItemSeq', 'throughItemSeq', 'sourceItemsDigest']);
    if (!['raw', 'summary', 'excluded_control'].includes(kind as string) || segment.fromItemSeq !== next) return corrupt();
    controlWireInteger(segment.throughItemSeq, next, data.throughItemSeq as number); next = (segment.throughItemSeq as number) + 1;
    if (kind === 'raw') {
      if (!Array.isArray(segment.items) || segment.items.length !== (segment.throughItemSeq as number) - (segment.fromItemSeq as number) + 1) return corrupt();
      for (const [index, rawItem] of segment.items.entries()) {
        const source = controlWireRecord(rawItem, ['sourceSessionId', 'itemSeq', 'itemId', 'kind', 'payloadRef']);
        controlWireText(source.sourceSessionId); controlWireText(source.itemId); assertArtifactRef(source.payloadRef as string);
        if (source.itemSeq !== (segment.fromItemSeq as number) + index || source.kind !== 'run_terminal') return corrupt();
      }
    } else {
      assertArtifactRef(segment.sourceItemsDigest as string);
      if (kind === 'summary') {
        controlWireText(segment.compactionItemId); assertArtifactRef(segment.summaryRef as string); assertArtifactRef(segment.summaryDigest as string);
        if (!Array.isArray(segment.retainedItemIds) || segment.retainedItemIds.length > 256 || new Set(segment.retainedItemIds).size !== segment.retainedItemIds.length) return corrupt();
        segment.retainedItemIds.forEach(id => controlWireText(id));
      }
    }
  }
  if (next - 1 !== data.throughItemSeq) return corrupt();
  return immutableSnapshot(data) as SessionContextProjection;
}
