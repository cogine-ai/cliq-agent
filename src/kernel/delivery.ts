import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Immutable delivery facts. They carry no model invocation, dispatch or
 * publication authority; owning readers validate their complete retained graph. */
export type DeliveryMergeItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'delivery_merge';
  sourceRunResultRef: string; sourceBaseRef: string; sourceDesiredRef: string; capturedWorkspaceRef: string;
  resultSourceRef: string; diffRef: string; summaryRef: string; deliveryPlanRef: string; createdAt: string;
};
export type DeliveryMergeConflictItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'delivery_merge_conflict';
  sourceRunResultRef: string; sourceBaseRef: string; sourceDesiredRef: string; capturedWorkspaceRef: string;
  mergeAlgorithm: 'cliq-diff3-v1'; conflictRef: string; createdAt: string;
};
export type DeliveryDecisionItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'delivery_decision'; deliveryPlanRef: string;
  approvalOpId: string; decision: 'allow' | 'deny'; decisionRef: string; grantRef?: string; createdAt: string;
};

export function decodeDeliveryMergeItem(value: unknown): Readonly<DeliveryMergeItem> {
  const fields = ['schemaVersion', 'itemId', 'runId', 'kind', 'sourceRunResultRef', 'sourceBaseRef', 'sourceDesiredRef',
    'capturedWorkspaceRef', 'resultSourceRef', 'diffRef', 'summaryRef', 'deliveryPlanRef', 'createdAt'];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('delivery merge must be plain data');
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).length !== fields.length || fields.some(field => !Object.hasOwn(properties, field)) ||
      Object.values(properties).some(property => !property.enumerable || !Object.hasOwn(property, 'value')))
    throw new TypeError('delivery merge has unknown, missing or non-data fields');
  const item = value as DeliveryMergeItem;
  if (item.schemaVersion !== 1 || item.kind !== 'delivery_merge') throw new TypeError('invalid delivery merge schema');
  for (const id of [item.itemId, item.runId])
    if (typeof id !== 'string' || normalizeBoundedText(id, 1, 128) !== id) throw new TypeError('invalid delivery merge identity');
  for (const ref of [item.sourceRunResultRef, item.sourceBaseRef, item.sourceDesiredRef, item.capturedWorkspaceRef,
    item.resultSourceRef, item.diffRef, item.summaryRef, item.deliveryPlanRef]) assertArtifactRef(ref);
  parseCanonicalTime(item.createdAt);
  return immutableSnapshot(item);
}
