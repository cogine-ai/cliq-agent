import assert from 'node:assert/strict';
import test from 'node:test';
import { installedServiceProfiles, installServices } from './installed-services.js';

test('installed profiles bind the complete root identity and preserve a literal non-shell executable', () => {
  const identity = 'a'.repeat(64), profiles = installedServiceProfiles('/home/cliq/state', identity);
  assert.equal(profiles.keeper.unit, `cliq-${identity}-keeper.service`);
  assert.equal(profiles.supervisor.unit, `cliq-${identity}-supervisor.service`);
  assert.notEqual(profiles.keeper.unit, installedServiceProfiles('/home/cliq/state', `${'a'.repeat(63)}b`).keeper.unit);
  assert(profiles.supervisor.text.includes(`Requires=cliq-${identity}-keeper.service\nAfter=cliq-${identity}-keeper.service\n`));
  assert(profiles.keeper.text.includes('ExecStart=/home/cliq/state/runtime/bootstrap --bootstrap-keeper\n'));
  assert(profiles.keeper.text.includes('Restart=no\n')); assert(profiles.supervisor.text.includes('Restart=on-failure\n'));
  assert(!profiles.keeper.text.includes('PartOf=') && !profiles.keeper.text.includes('BindsTo='));
  const literal = installedServiceProfiles('/home/cliq/state %H $USER\n[Service]', identity).supervisor;
  assert(literal.text.includes('ExecStart=":/home/cliq/state %%H $USER\\x0a[Service]/runtime/bootstrap" --bootstrap-supervisor\n'));
  assert.deepEqual(literal.args, ['/home/cliq/state %H $USER\n[Service]/runtime/bootstrap', '--bootstrap-supervisor']);
  assert.deepEqual(literal.flags, ['no-env-expand']);
  assert.equal(literal.text.split('\n').filter(line => line === '[Service]').length, 1);
});

test('service setup rejects an unverified selection before observing its caller properties', async () => {
  const selected = Object.defineProperty({}, 'bundle', { get() { throw new Error('caller property must not be observed'); } });
  await assert.rejects(installServices(selected as Parameters<typeof installServices>[0]), { code: 'ARTIFACT_MISMATCH' });
});
