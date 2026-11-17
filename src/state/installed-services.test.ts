import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Script } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
import { KernelStorageError } from './errors.js';
import { installedServiceProfiles, installServices, loadInstalledSupervisorObserver, observeInstalledCredentialSupervisor } from './installed-services.js';

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
  for (const purpose of ['control', 'credential'] as const)
    await assert.rejects(loadInstalledSupervisorObserver(selected as never, purpose), { code: 'ARTIFACT_MISMATCH' });
});

test('installed roles select a fixed working directory instead of an implicit user-manager home', () => {
  const profiles = installedServiceProfiles('/home/cliq/state', 'a'.repeat(64));
  for (const profile of [profiles.keeper, profiles.supervisor]) {
    assert.equal(profile.text.split('\n').filter(line => line.startsWith('WorkingDirectory=')).length, 1);
    assert(profile.text.includes('WorkingDirectory=/\n'));
  }
});

// Original callback ordering only. The inert objects below never enter a
// selected runtime, native manager, StateOwner or installed qualification.
test('readonly profile observation uses full entry and exit validation while service mutations keep their pre-operation check', async () => {
  const source = await readFile(new URL('./installed-services.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('services.ts', source, ts.ScriptTarget.Latest, true);
  const helper = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'withProfiles');
  assert(helper);
  for (const mode of ['readonly', 'mutating', 'create', 'exit_refusal'] as const) {
    const events: string[] = [], failure = new KernelStorageError('ARTIFACT_MISMATCH', 'inert exit validation refused');
    const readonly = mode !== 'mutating', platform = { currentUser: () => ({ uid: 42, gid: 42, home: '/owned' }),
      ...(readonly ? { inspect() {} } : { userManager() {} }) };
    class ProfileScope {
      async profilesDirectory() { events.push('directory'); return {}; }
      async read() { events.push('profile'); return {}; }
      async assertHeld() { events.push('profiles_held'); }
      async close() { events.push('joined'); }
    }
    const context = { process: { platform: 'linux', geteuid: () => 42, getegid: () => 42 },
      healthy() {}, assertInstalledManagerObservationAvailable() {}, ProfileScope, KernelStorageError,
      decodeCredentialPlatformUser: (value: unknown) => value, normalizeAbsolutePath: (value: string) => value,
      stateRootIdentityFromDescriptor: () => ({ canonicalAbsolutePath: '/owned/state', identityDigest: 'inert' }),
      installedServiceProfiles: () => ({ keeper: {}, supervisor: {} }), path: { join: (...parts: string[]) => parts.join('/') },
      withHeldInstalledRuntime: async (_selected: unknown, operation: (installed: unknown) => Promise<unknown>) => {
        events.push('entry_full');
        return operation({ stateRoot: { ownerUid: 42 }, revalidate: async () => {
          events.push(events.includes('operation') ? 'exit_full' : 'before_operation_full');
          if (mode === 'exit_refusal' && events.includes('operation')) throw failure;
        } });
      },
      invoke: undefined as undefined | ((selected: unknown, create: boolean, platform: unknown, operation: () => Promise<string>) => Promise<string>) };
    new Script(ts.transpileModule(`${helper.getText(parsed)}; globalThis.invoke = withProfiles;`,
      { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText).runInNewContext(context);
    const result = context.invoke!(undefined, mode === 'create', platform, async () => { events.push('operation'); return 'inert'; });
    if (mode === 'exit_refusal') await assert.rejects(result, error => error === failure);
    else assert.equal(await result, 'inert');
    assert.deepEqual(events, ['entry_full', 'directory', 'profile', 'profile',
      ...(mode === 'mutating' || mode === 'create' ? ['before_operation_full'] : []),
      'operation', 'profiles_held', 'exit_full', 'joined']);
  }
});
