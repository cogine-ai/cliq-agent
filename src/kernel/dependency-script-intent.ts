// One immutable pre-admission source graph. This is intent and original data,
// never an execution grant, current endpoint observation or capture capability.
import { types } from 'node:util';
import { assertArtifactRef, assertRequestId, digestOmitting, normalizeBoundedText } from './identity.js';
import { decodeDependencyScriptConditions, type DependencyScriptConditionsV1 } from './dependency.js';
import { immutableSnapshot } from '../model/immutable.js';

export type DependencyScriptIntentV1 = {
  schemaVersion: 1; format: 'cliq-dependency-script-intent-v1';
  inspectionId: string; principalId: string; targetRef: string;
  originalRequestId: string; originalRequestDigest: string; admissionIntentDigest: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string;
  sourceManifestRef: string; sourceManifestDigest: string;
  conditions: DependencyScriptConditionsV1;
  scriptlessPolicyRef: string; scriptlessPlanRef: string;
  registrySourceRefs: string[]; intentDigest: string;
};
function invalid(): never { throw new TypeError('dependency script intent is not its complete closed original graph'); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const props = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(props).length !== keys.length || keys.some(key => !Object.hasOwn(props, key) ||
      !('value' in props[key]!) || !props[key]!.enumerable)) invalid();
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 128) !== value) invalid(); return value;
}
export function decodeDependencyScriptIntent(value: unknown): DependencyScriptIntentV1 {
  const data = record(value, ['schemaVersion', 'format', 'inspectionId', 'principalId', 'targetRef', 'originalRequestId',
    'originalRequestDigest', 'admissionIntentDigest', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'sourceManifestRef',
    'sourceManifestDigest', 'conditions', 'scriptlessPolicyRef', 'scriptlessPlanRef', 'registrySourceRefs', 'intentDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-script-intent-v1' || !/^[A-Za-z0-9_-]{43}$/u.test(text(data.inspectionId))) invalid();
  text(data.principalId); assertRequestId(text(data.originalRequestId));
  for (const field of ['targetRef', 'originalRequestDigest', 'admissionIntentDigest', 'workspaceIdentityRef', 'workspaceIdentityDigest',
    'sourceManifestRef', 'sourceManifestDigest', 'scriptlessPolicyRef', 'scriptlessPlanRef', 'intentDigest']) assertArtifactRef(text(data[field]));
  const refs = data.registrySourceRefs;
  if (!Array.isArray(refs) || types.isProxy(refs) || refs.length < 1 || refs.length > 128 ||
      Reflect.ownKeys(refs).length !== refs.length + 1) invalid();
  let previous = '';
  for (let index = 0; index < refs.length; index++) {
    const property = Object.getOwnPropertyDescriptor(refs, String(index));
    if (!property || !property.enumerable || !('value' in property)) invalid();
    const ref = text(property.value); assertArtifactRef(ref); if (ref <= previous) invalid(); previous = ref;
  }
  const conditions = decodeDependencyScriptConditions(data.conditions);
  if (conditions.source.sourceRole !== 'base' || conditions.source.sourceManifestRef !== data.sourceManifestRef ||
      conditions.source.sourceManifestDigest !== data.sourceManifestDigest || conditions.source.workspaceEntriesRef !== conditions.source.projectedEntriesRef ||
      conditions.source.workspaceTreeDigest !== conditions.source.projectedTreeDigest || digestOmitting(data, 'intentDigest') !== data.intentDigest) invalid();
  return immutableSnapshot(data) as DependencyScriptIntentV1;
}

export type DependencyRegistrySourceV1 = {
  schemaVersion: 1; format: 'cliq-dependency-registry-source-v1';
  record: import('./credential-authority.js').EndpointAuthorityRecordV1;
  originalRecord: import('./credential-authority.js').EndpointAuthorityRecordV1;
  operation: import('./credential-authority.js').EndpointAuthorityOperationV1;
  objectRefs: string[]; sourceDigest: string;
};
