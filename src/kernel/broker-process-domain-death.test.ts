import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeBrokerProcessDomainDeath, decodeBrokerProcessDomainDeathDispatchClosure,
  type BrokerProcessDomainDeathEvidenceV1, type BrokerProcessDomainDeathDispatchClosureV1 } from './broker-process-domain-death.js';
import { digestOmitting } from './identity.js';

// Offline data examples only: no StateOwner, broker, process observation,
// installation, release token or physical retirement is constructed here.
function deathWire(): BrokerProcessDomainDeathEvidenceV1 {
  const value: BrokerProcessDomainDeathEvidenceV1 = {
    schemaVersion: 1, format: 'cliq-broker-process-domain-death-evidence-v1',
    runId: 'run-1', opId: 'model-1', attempt: 0, dispatchId: 'dispatch-1', dispatchJournalSeq: 2,
    operationRequestRef: '1'.repeat(64), operationTargetDigest: '2'.repeat(64), operationGrantRef: '3'.repeat(64),
    claimingSupervisorInstanceId: 'supervisor-1', claimingStateOwnerEpoch: 1,
    claimingProcessIdentityRef: '4'.repeat(64), claimingProcessIdentityDigest: '5'.repeat(64),
    inspectorIdentityRef: '6'.repeat(64), inspectorIdentityDigest: '7'.repeat(64), inspectorStateOwnerEpoch: 2,
    brokerFenceTokenDigest: '8'.repeat(64), authorityDomain: 'linux_installed_native_creator_process_v1',
    processObservation: 'absent_or_start_token_mismatch', observedAt: '2026-10-16T00:00:00.000Z', evidenceDigest: '',
  };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); return value;
}

function rehash(value: Record<string, unknown>) {
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); return value;
}

function closureWire(): BrokerProcessDomainDeathDispatchClosureV1 {
  const value: BrokerProcessDomainDeathDispatchClosureV1 = {
    schemaVersion: 1, format: 'cliq-invocation-dispatch-closure-evidence-v1',
    runId: 'run-1', opId: 'model-1', attempt: 0, dispatchId: 'dispatch-1', unknownJournalSeq: 3,
    closure: { kind: 'broker_process_domain_dead', brokerProcessDeathEvidenceRef: '9'.repeat(64),
      brokerProcessDeathEvidenceDigest: 'a'.repeat(64) }, observedAt: '2026-10-16T00:00:00.000Z', evidenceDigest: '',
  };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); return value;
}

test('broker process-domain death data accepts initial attempt and a strictly newer inspector without creating authority', () => {
  for (const value of [deathWire(), Object.assign(Object.create(null), deathWire())]) {
    const decoded = decodeBrokerProcessDomainDeath(value);
    assert.equal(decoded.attempt, 0); assert.equal(decoded.dispatchJournalSeq, 2);
    assert.equal(decoded.claimingStateOwnerEpoch, 1); assert.equal(decoded.inspectorStateOwnerEpoch, 2);
    assert.equal(decoded.authorityDomain, 'linux_installed_native_creator_process_v1');
    assert.equal(decoded.processObservation, 'absent_or_start_token_mismatch');
    assert.equal(decoded.observedAt, '2026-10-16T00:00:00.000Z');
  }
});

test('broker process-domain death data refuses mixed lock actions, native booleans, non-newer owners and forged digests', () => {
  for (const fields of [
    { schemaVersion: 2 }, { format: 'cliq-broker-release-fence-evidence-v1' },
    { authorityDomain: 'arbitrary_signed_broker' }, { processObservation: 'socket_closed' },
    { fenceAction: 'token_revoked_and_matching_active_release_count_zero' }, { tokenRevokedAt: '2026-10-16T00:00:00.000Z' },
    { matchingActiveReleaseCount: 0 }, { tokenRevoked: true }, { processDead: true }, { pid: 123 },
    { attempt: -1 }, { attempt: 0.5 }, { attempt: Number.MAX_SAFE_INTEGER + 1 },
    { dispatchJournalSeq: 0 }, { dispatchJournalSeq: 1.5 },
    { claimingStateOwnerEpoch: 0 }, { inspectorStateOwnerEpoch: 1 }, { inspectorStateOwnerEpoch: 0 },
    { inspectorStateOwnerEpoch: 2.5 }, { inspectorStateOwnerEpoch: Number.MAX_SAFE_INTEGER + 1 },
    { observedAt: '2026-10-16T00:00:00Z' }, { observedAt: '2026-02-30T00:00:00.000Z' }, { observedAt: 0 },
  ]) assert.throws(() => decodeBrokerProcessDomainDeath(rehash({ ...deathWire(), ...fields })), TypeError);
  assert.throws(() => decodeBrokerProcessDomainDeath({ ...deathWire(), runId: 'different-run' }), /digest/);
  assert.throws(() => decodeBrokerProcessDomainDeath({ ...deathWire(), evidenceDigest: '0'.repeat(64) }), /digest/);
});

test('broker process-domain death data validates every identity and reference and refuses missing fields or foreign prototypes', () => {
  const identityKeys = ['runId', 'opId', 'dispatchId', 'claimingSupervisorInstanceId'] as const;
  for (const key of identityKeys) for (const invalid of ['', 'x'.repeat(257), 'a\0b', 1, null])
    assert.throws(() => decodeBrokerProcessDomainDeath(rehash({ ...deathWire(), [key]: invalid })), TypeError);
  const referenceKeys = ['operationRequestRef', 'operationTargetDigest', 'operationGrantRef', 'claimingProcessIdentityRef',
    'claimingProcessIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'brokerFenceTokenDigest'] as const;
  for (const key of referenceKeys) for (const invalid of ['', 'a'.repeat(63), 'A'.repeat(64), 1, null])
    assert.throws(() => decodeBrokerProcessDomainDeath(rehash({ ...deathWire(), [key]: invalid })), TypeError);
  for (const key of Object.keys(deathWire())) {
    const value: Record<string, unknown> = { ...deathWire() }; delete value[key];
    assert.throws(() => decodeBrokerProcessDomainDeath(value), TypeError);
  }
  for (const value of [null, [], 1, 'dead', Object.assign(Object.create({ inherited: true }), deathWire())])
    assert.throws(() => decodeBrokerProcessDomainDeath(value), TypeError);
});

test('broker process-domain death dispatch data accepts only its exact implemented closed branch', () => {
  const plain = closureWire();
  const values = [plain, Object.assign(Object.create(null), plain, { closure: Object.assign(Object.create(null), plain.closure) })];
  for (const value of values) {
    const decoded = decodeBrokerProcessDomainDeathDispatchClosure(value);
    assert.equal(decoded.attempt, 0); assert.equal(decoded.unknownJournalSeq, 3);
    assert.equal(decoded.closure.kind, 'broker_process_domain_dead');
    assert.equal(decoded.closure.brokerProcessDeathEvidenceRef, '9'.repeat(64));
    assert.equal(decoded.closure.brokerProcessDeathEvidenceDigest, 'a'.repeat(64));
  }
});

test('broker process-domain death dispatch data refuses mixed branches, invalid sequences and forged digests', () => {
  for (const fields of [
    { schemaVersion: 2 }, { format: 'cliq-broker-process-domain-death-evidence-v1' }, { runId: '' }, { opId: null },
    { dispatchId: 'a\0b' }, { attempt: -1 }, { attempt: Number.MAX_SAFE_INTEGER + 1 },
    { unknownJournalSeq: 0 }, { unknownJournalSeq: 1.5 }, { observedAt: '2026-10-16T00:00:00Z' },
    { closure: { kind: 'broker_release_fenced', brokerFenceEvidenceRef: '1'.repeat(64), brokerFenceEvidenceDigest: '2'.repeat(64) } },
    { closure: { ...closureWire().closure, kind: 'containment_death' } },
    { closure: { ...closureWire().closure, tokenRevoked: true } },
    { closure: { ...closureWire().closure, brokerFenceEvidenceRef: '1'.repeat(64) } },
    { closure: { ...closureWire().closure, processDead: true } },
    { closure: { ...closureWire().closure, brokerProcessDeathEvidenceRef: null } },
    { closure: { ...closureWire().closure, brokerProcessDeathEvidenceDigest: 'A'.repeat(64) } },
    { closure: { ...closureWire().closure, brokerProcessDeathEvidenceDigest: undefined } },
  ]) {
    const value = { ...closureWire(), ...fields };
    // Undefined is not JSON; exercise its shape rejection without attempting to hash it.
    if (fields.closure && Object.values(fields.closure).includes(undefined))
      assert.throws(() => decodeBrokerProcessDomainDeathDispatchClosure(value), TypeError);
    else assert.throws(() => decodeBrokerProcessDomainDeathDispatchClosure(rehash(value)), TypeError);
  }
  assert.throws(() => decodeBrokerProcessDomainDeathDispatchClosure({ ...closureWire(), runId: 'different-run' }), /digest/);
  for (const key of Object.keys(closureWire())) {
    const value: Record<string, unknown> = { ...closureWire() }; delete value[key];
    assert.throws(() => decodeBrokerProcessDomainDeathDispatchClosure(value), TypeError);
  }
  for (const key of Object.keys(closureWire().closure)) {
    const closure: Record<string, unknown> = { ...closureWire().closure }; delete closure[key];
    assert.throws(() => decodeBrokerProcessDomainDeathDispatchClosure(rehash({ ...closureWire(), closure })), TypeError);
  }
});

test('broker process-domain death decoders reject inherited, hidden and accessor fields without calling getters', () => {
  for (const [wire, decode] of [[deathWire(), decodeBrokerProcessDomainDeath], [closureWire(), decodeBrokerProcessDomainDeathDispatchClosure]] as const) {
    for (const value of [null, [], false, Object.assign(Object.create({ inherited: true }), wire),
      Object.defineProperty({ ...wire }, 'hidden', { value: true }), { ...wire, [Symbol('native')]: true }])
      assert.throws(() => decode(value), TypeError);
    let reads = 0;
    const accessor = Object.defineProperty({ ...wire }, 'runId', { enumerable: true, get() { reads++; return 'run-1'; } });
    assert.throws(() => decode(accessor), TypeError); assert.equal(reads, 0);
  }
  assert.throws(() => decodeBrokerProcessDomainDeathDispatchClosure({ ...closureWire(),
    closure: Object.assign(Object.create({ inherited: true }), closureWire().closure) }), TypeError);
});
