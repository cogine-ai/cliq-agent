import assert from 'node:assert/strict';
import test from 'node:test';
import { installedServiceProfiles, installServices, observeInstalledCredentialSupervisor } from './installed-services.js';

test('installed profiles bind the complete root identity and preserve a literal non-shell executable', () => {
  const identity = 'a'.repeat(64), profiles = installedServiceProfiles('/home/cliq/state', identity);
  assert.equal(profiles.keeper.unit, `cliq-${identity}-keeper.service`);
  assert.equal(profiles.supervisor.unit, `cliq-${identity}-supervisor.service`);
  assert.notEqual(profiles.keeper.unit, installedServiceProfiles('/home/cliq/state', `${'a'.repeat(63)}b`).keeper.unit);
  assert(profiles.supervisor.text.includes(`Requires=cliq-${identity}-keeper.service\nAfter=cliq-${identity}-keeper.service\n`));
  assert(profiles.keeper.text.includes('ExecStart=/home/cliq/state/runtime/bootstrap --bootstrap-keeper\n'));
  assert(profiles.keeper.text.includes('Restart=no\n')); assert(profiles.supervisor.text.includes('Restart=on-failure\n'));
  assert(!profiles.keeper.text.includes('PartOf=') && !profiles.keeper.text.includes('BindsTo='));
  const literal = installedServiceProfiles('/home/cliq/state %H $USER [Service]', identity).supervisor;
  assert(literal.text.includes('ExecStart=":/home/cliq/state %%H $USER [Service]/runtime/bootstrap" --bootstrap-supervisor\n'));
  assert.deepEqual(literal.args, ['/home/cliq/state %H $USER [Service]/runtime/bootstrap', '--bootstrap-supervisor']);
  assert.deepEqual(literal.flags, ['no-env-expand']);
  assert.equal(literal.text.split('\n').filter(line => line === '[Service]').length, 1);
});

test('installed profiles reject characters systemd forbids in a decoded executable path', () => {
  // systemd validates the C-unescaped executable, not its quoted unit bytes.
  // Keep this platform-specific restriction out of generic filesystem paths.
  const unsupported = [...Array.from({ length: 32 }, (_, index) => String.fromCharCode(index)), '\x7f', '"', "'"];
  for (const character of unsupported) {
    assert.throws(() => installedServiceProfiles(`/home/cliq/state${character}root`, 'a'.repeat(64)), TypeError,
      `unsupported executable character U+${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
  }
});

test('service setup rejects an unverified selection before observing its caller properties', async () => {
  const selected = Object.defineProperty({}, 'bundle', { get() { throw new Error('caller property must not be observed'); } });
  await assert.rejects(installServices(selected as Parameters<typeof installServices>[0]), { code: 'ARTIFACT_MISMATCH' });
  for (const startIfNeeded of [false, true])
    await assert.rejects(observeInstalledCredentialSupervisor(selected as Parameters<typeof installServices>[0], startIfNeeded), { code: 'ARTIFACT_MISMATCH' });
});

test('installed roles select a fixed working directory instead of an implicit user-manager home', () => {
  const profiles = installedServiceProfiles('/home/cliq/state', 'a'.repeat(64));
  for (const profile of [profiles.keeper, profiles.supervisor]) {
    assert.equal(profile.text.split('\n').filter(line => line.startsWith('WorkingDirectory=')).length, 1);
    assert(profile.text.includes('WorkingDirectory=/\n'));
  }
});
