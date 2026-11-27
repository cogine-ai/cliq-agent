import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration } from '../kernel/identity.js';
import { decodeLocalModelRegistryHead, decodeLocalModelRegistration, type LocalModelRegistrationV1,
  type LocalModelRegistryHeadV1 } from '../kernel/local-inference.js';
import { validateLocalModelRegistryStep, nextLocalModelPort } from './local-model-registry-data.js';
import { LOCAL_AT, localRegistrationFixture } from './testing/local-inference-data.js';

type Active = LocalModelRegistrationV1 & { state: 'active' };
type Retired = LocalModelRegistrationV1 & { state: 'retired' };
function retire(active: Active, at: string): Retired {
  const { registrationDigest: _digest, state: _state, ...base } = active;
  const core = { ...base, state: 'retired' as const, retiredAt: at };
  return decodeLocalModelRegistration({ ...core, registrationDigest: canonicalSha256(core) }) as Retired;
}
const head = (value: Record<string, unknown>) => decodeLocalModelRegistryHead({ schemaVersion: 1, format: 'cliq-local-model-registry-head-v1',
  ownerPrincipalId: 'literal-principal', provider: 'ollama', model: 'literal-local-model', ...value,
  headDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-local-model-registry-head-v1', ownerPrincipalId: 'literal-principal',
    provider: 'ollama', model: 'literal-local-model', ...value }) });
const activePair = (value: Active) => ({ activeRegistrationRef: canonicalSha256(value), activeRegistrationDigest: value.registrationDigest });
const retiredPair = (value: Retired) => ({ retiredRegistrationRef: canonicalSha256(value), retiredRegistrationDigest: value.registrationDigest });
const predecessor = (value: LocalModelRegistryHeadV1) => ({ predecessorHeadRef: canonicalSha256(value), predecessorHeadDigest: value.headDigest });

test('model registry validates exact initial, replace, retire and reenroll history without mutating retained registration bytes', () => {
  const first = localRegistrationFixture(), initial = head({ transition: 'initial', state: 'active', headRevision: 1, committedAt: LOCAL_AT, ...activePair(first) });
  validateLocalModelRegistryStep({ head: initial, active: first });
  const second = localRegistrationFixture(49153, 2), retiredFirst = retire(first, addCanonicalDuration(LOCAL_AT, 1000));
  const replaced = head({ transition: 'replace', state: 'active', headRevision: 2, committedAt: retiredFirst.retiredAt,
    ...predecessor(initial), ...activePair(second), ...retiredPair(retiredFirst) });
  validateLocalModelRegistryStep({ head: replaced, active: second, retired: retiredFirst, predecessor: { head: initial, active: first } });
  const retiredSecond = retire(second, addCanonicalDuration(LOCAL_AT, 2000)), stopped = head({ transition: 'retire', state: 'retired',
    headRevision: 3, committedAt: retiredSecond.retiredAt, ...predecessor(replaced), ...retiredPair(retiredSecond) });
  validateLocalModelRegistryStep({ head: stopped, retired: retiredSecond, predecessor: { head: replaced, active: second, retired: retiredFirst } });
  const third = localRegistrationFixture(49154, 3), reenrolled = head({ transition: 'reenroll', state: 'active', headRevision: 4,
    committedAt: addCanonicalDuration(LOCAL_AT, 3000), ...predecessor(stopped), ...activePair(third) });
  validateLocalModelRegistryStep({ head: reenrolled, active: third, predecessor: { head: stopped, retired: retiredSecond } });
  assert.equal(first.state, 'active'); assert.equal(first.registryRevision, 1);
  assert.equal(nextLocalModelPort([first, retiredFirst, second, retiredSecond, third]), 49155, 'retired ports remain occupied');
});

test('model registry refuses a borrowed original head, skipped revisions, changed retired copy and duplicate semantic registration', () => {
  const first = localRegistrationFixture(), initial = head({ transition: 'initial', state: 'active', headRevision: 1, committedAt: LOCAL_AT, ...activePair(first) });
  const second = localRegistrationFixture(49153, 2), retired = retire(first, addCanonicalDuration(LOCAL_AT, 1000));
  const next = head({ transition: 'replace', state: 'active', headRevision: 2, committedAt: retired.retiredAt,
    ...predecessor(initial), ...activePair(second), ...retiredPair(retired) });
  assert.throws(() => validateLocalModelRegistryStep({ head: next, active: second, retired }));
  const skipped = head({ transition: 'replace', state: 'active', headRevision: 3, committedAt: retired.retiredAt,
    ...predecessor(initial), ...activePair(second), ...retiredPair(retired) });
  assert.throws(() => validateLocalModelRegistryStep({ head: skipped, active: second, retired, predecessor: { head: initial, active: first } }));
  const equalCore = localRegistrationFixture(49152, 2), redundant = head({ transition: 'replace', state: 'active', headRevision: 2,
    committedAt: retired.retiredAt, ...predecessor(initial), ...activePair(equalCore), ...retiredPair(retired) });
  assert.throws(() => validateLocalModelRegistryStep({ head: redundant, active: equalCore, retired, predecessor: { head: initial, active: first } }));
  const changed = retire({ ...first, createdAt: addCanonicalDuration(LOCAL_AT, 1) }, retired.retiredAt), replaced = head({ transition: 'replace',
    state: 'active', headRevision: 2, committedAt: retired.retiredAt, ...predecessor(initial), ...activePair(second), ...retiredPair(changed) });
  assert.throws(() => validateLocalModelRegistryStep({ head: replaced, active: second, retired: changed, predecessor: { head: initial, active: first } }));
});
