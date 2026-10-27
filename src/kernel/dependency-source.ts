import { types } from 'node:util';
import { InvalidRunSubmitRequestError, type NormalizedRunSubmitRequest, type SourceSelectorRequest } from './control-submit.js';

type Exclude = Omit<SourceSelectorRequest, 'readGrantId'>;
export const MANAGED_NODE_DEPENDENCIES = 'node_modules';
export function isManagedNodeDependencyPath(path: string): boolean {
  return path === MANAGED_NODE_DEPENDENCIES || path.startsWith(`${MANAGED_NODE_DEPENDENCIES}/`);
}
function fail(): never { throw new InvalidRunSubmitRequestError('source selection conflicts with the fixed managed Node dependency root'); }
function own(value: unknown, field: string): unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value)) fail();
  const property = Object.getOwnPropertyDescriptor(value, field);
  if (!property || !('value' in property) || !property.enumerable) fail(); return property.value;
}
function selectors(value: unknown, include: boolean): SourceSelectorRequest[] {
  if (!Array.isArray(value) || types.isProxy(value) || value.length > 128) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== value.length + 1) fail();
  return Array.from({ length: value.length }, (_, index) => {
    const property = descriptors[index]; if (!property || !('value' in property) || !property.enumerable) fail();
    const item = property.value, path = own(item, 'path'), scope = own(item, 'scope');
    if (!item || Array.isArray(item) || ![Object.prototype, null].includes(Object.getPrototypeOf(item)) ||
        Reflect.ownKeys(item).some(field => !['path', 'scope', ...(include ? ['readGrantId'] : [])].includes(field as string)) ||
        typeof path !== 'string' || !path || path !== path.normalize('NFC') || Buffer.byteLength(path) > 4096 || path.includes('\\') ||
        path.split('/').some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || part.includes('\0') || Buffer.byteLength(part) > 255) ||
        scope !== 'entry' && scope !== 'subtree') fail();
    if (Object.hasOwn(item, 'readGrantId')) {
      const grant = own(item, 'readGrantId'); if (typeof grant !== 'string' || !grant) fail();
      return { path, scope, readGrantId: grant };
    }
    return { path, scope };
  });
}
/** Fixed data derivation from the original normalized public request. Capture
 * and history both use it. This neither rewrites the wire/request digest nor
 * adds a classifier, read grant, native fact or general managed-root facility. */
export function effectiveSourceExcludes(request: Pick<NormalizedRunSubmitRequest, 'dependency' | 'sourceIncludes' | 'sourceExcludes'>): readonly Exclude[] {
  const mode = own(own(request, 'dependency'), 'mode'); if (mode !== 'none' && mode !== 'locked') fail();
  const includes = selectors(own(request, 'sourceIncludes'), true), excludes = selectors(own(request, 'sourceExcludes'), false);
  const seen = new Set<string>();
  for (const item of excludes) { const key = `${item.path}\0${item.scope}`; if (seen.has(key)) fail(); seen.add(key); }
  if (mode === 'locked') {
    // Both an exact entry and a subtree include address the managed object;
    // no explicit read consent can turn install output into source input.
    if (includes.some(item => isManagedNodeDependencyPath(item.path))) fail();
    if (!seen.has(`${MANAGED_NODE_DEPENDENCIES}\0subtree`)) {
      if (excludes.length === 128) fail(); excludes.push({ path: MANAGED_NODE_DEPENDENCIES, scope: 'subtree' });
    }
  }
  return Object.freeze(excludes.map(item => Object.freeze({ path: item.path, scope: item.scope })));
}
