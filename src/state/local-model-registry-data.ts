// Complete immutable registry transitions. These functions only verify data;
// the actual model-store pointer transaction requires its original native lock.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeLocalModelRegistryHead, decodeLocalModelRegistration,
  type LocalModelRegistryHeadV1, type LocalModelRegistrationV1 } from '../kernel/local-inference.js';
import { requireEqual } from '../policy/runtime-authority.js';

type Active = LocalModelRegistrationV1 & { state: 'active' };
type Retired = LocalModelRegistrationV1 & { state: 'retired' };
type Head = LocalModelRegistryHeadV1;
export type LocalModelRegistryStep = Readonly<{
  head: Head; active?: Active; retired?: Retired;
  predecessor?: Readonly<{ head: Head; active?: Active; retired?: Retired }>;
}>;
function invalid(): never { throw new TypeError('local model head differs from its complete immutable original registry history'); }
function pair(value: LocalModelRegistrationV1 | undefined, reference: string, semantic: string): void {
  if (!value || canonicalSha256(value) !== reference || value.registrationDigest !== semantic) invalid();
}
function sameIdentity(head: Head, value: LocalModelRegistrationV1): void {
  if (head.ownerPrincipalId !== value.ownerPrincipalId || head.provider !== value.provider || head.model !== value.model ||
      value.createdAt > head.committedAt) invalid();
}
export function assertLocalModelRetiredCopy(original: Active, retired: Retired, at: string): void {
  const { state: _oldState, registrationDigest: _oldDigest, ...base } = original;
  const { state: _newState, retiredAt, registrationDigest: _newDigest, ...copy } = retired;
  requireEqual(base, copy, 'local model retired copy retains every original base field');
  if (retiredAt !== at) invalid();
}
/** One decoded step requires all and only its original immutable head and
 * registration data. This function cannot follow a current mutable pointer,
 * accept a same-model replacement, or infer authority from a content hash. */
export function validateLocalModelRegistryStep(input: LocalModelRegistryStep): void {
  const head = decodeLocalModelRegistryHead(input.head);
  const active = input.active && decodeLocalModelRegistration(input.active), retired = input.retired && decodeLocalModelRegistration(input.retired);
  if (active && active.state !== 'active' || retired && retired.state !== 'retired') invalid();
  if ('activeRegistrationRef' in head) {
    pair(active, head.activeRegistrationRef, head.activeRegistrationDigest); if (!active) invalid(); sameIdentity(head, active);
  } else if (active) invalid();
  if ('retiredRegistrationRef' in head) {
    pair(retired, head.retiredRegistrationRef, head.retiredRegistrationDigest); if (!retired) invalid(); sameIdentity(head, retired);
  } else if (retired) invalid();
  if (head.transition === 'initial') {
    if (input.predecessor !== undefined || !active || active.registryRevision !== 1 || head.headRevision !== 1) invalid();
    return;
  }
  const prior = input.predecessor;
  if (!prior) invalid();
  const previous = decodeLocalModelRegistryHead(prior.head);
  if (canonicalSha256(previous) !== head.predecessorHeadRef || previous.headDigest !== head.predecessorHeadDigest ||
      head.ownerPrincipalId !== previous.ownerPrincipalId || head.provider !== previous.provider || head.model !== previous.model ||
      !Number.isSafeInteger(previous.headRevision + 1) || head.headRevision !== previous.headRevision + 1 || head.committedAt < previous.committedAt) invalid();
  const priorActive = prior.active && decodeLocalModelRegistration(prior.active), priorRetired = prior.retired && decodeLocalModelRegistration(prior.retired);
  if (previous.state === 'active') {
    if (!priorActive || priorActive.state !== 'active' || priorRetired !== undefined && previous.transition !== 'replace') invalid();
    pair(priorActive, previous.activeRegistrationRef, previous.activeRegistrationDigest); sameIdentity(previous, priorActive);
    if (previous.transition === 'replace') {
      pair(priorRetired, previous.retiredRegistrationRef, previous.retiredRegistrationDigest);
      if (!priorRetired || priorRetired.state !== 'retired') invalid(); sameIdentity(previous, priorRetired);
    }
    if (head.transition !== 'replace' && head.transition !== 'retire' || !retired || retired.state !== 'retired') invalid();
    assertLocalModelRetiredCopy(priorActive as Active, retired, head.committedAt);
    if (head.transition === 'replace' && (!active || active.registryRevision !== priorActive.registryRevision + 1 ||
        active.serviceSpec.serviceSpecCoreDigest === priorActive.serviceSpec.serviceSpecCoreDigest)) invalid();
  } else {
    if (priorActive || !priorRetired || priorRetired.state !== 'retired' || previous.transition !== 'retire') invalid();
    pair(priorRetired, previous.retiredRegistrationRef, previous.retiredRegistrationDigest); sameIdentity(previous, priorRetired);
    if (head.transition !== 'reenroll' || !active || active.registryRevision !== priorRetired.registryRevision + 1) invalid();
  }
}

/** Registry port allocation is data-only and performed under the original
 * model-store lock by the importer. It scans all retained registrations,
 * including retired ones, and never reuses their service's port. */
export function nextLocalModelPort(registrations: readonly LocalModelRegistrationV1[]): number {
  const used = new Set<number>();
  for (const value of registrations) used.add(decodeLocalModelRegistration(value).serviceSpec.endpoint.port);
  for (let port = 49152; port <= 65535; port++) if (!used.has(port)) return port;
  throw new TypeError('local model retained service ports are exhausted');
}
