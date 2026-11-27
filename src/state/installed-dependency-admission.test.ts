import assert from 'node:assert/strict';
import test from 'node:test';
import { assertInstalledDependencyAdmissionAuthority, readInstalledDependencyAdmission, consumeInstalledDependencyAdmission,
  type InstalledDependencyAdmission } from './installed-dependency-admission.js';

test('installed dependency preparation cannot be reconstructed from public refs, a proxy or borrowed currentness callback', () => {
  let observed = 0;
  const foreign = new Proxy({}, { get() { observed++; throw 0; }, getPrototypeOf() { observed++; throw 0; }, ownKeys() { observed++; throw 0; } });
  for (const value of [{}, foreign]) {
    const token = value as InstalledDependencyAdmission;
    assert.throws(() => readInstalledDependencyAdmission(undefined!, undefined!, token), /original preparation/);
    assert.throws(() => assertInstalledDependencyAdmissionAuthority(undefined!, undefined!, token, foreign as never), /original owner/);
    assert.throws(() => consumeInstalledDependencyAdmission(undefined!, undefined!, undefined!, token, foreign as never, ''), /original owner/);
  }
  assert.equal(observed, 0);
});
