// Fixed diagnostic data only; no installation, credential or Run authority.
import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES, noteInstalledCredentialPhase } from './installed-diagnostics.js';

test('installed credential observations publish only the eight fixed primitive phases', () => {
  assert.deepEqual(INSTALLED_CREDENTIAL_PHASES, ['open_selected', 'history', 'first_supervisor', 'secret_input',
    'second_supervisor', 'platform_store', 'finalize', 'retire']);
  assert(Object.isFrozen(INSTALLED_CREDENTIAL_PHASES));
  const observed: unknown[] = [], diagnostic = channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL);
  const subscriber = (phase: unknown) => { observed.push(phase); };
  diagnostic.subscribe(subscriber);
  try {
    for (const phase of INSTALLED_CREDENTIAL_PHASES) noteInstalledCredentialPhase(phase);
    let accessed = false;
    for (const value of [null, undefined, 'untrusted-private-value', Object.defineProperty({}, 'phase', {
      get() { accessed = true; throw new Error('must not inspect caller properties'); },
    })]) noteInstalledCredentialPhase(value as never);
    assert.equal(accessed, false);
    assert.deepEqual(observed, [...INSTALLED_CREDENTIAL_PHASES]);
  } finally { diagnostic.unsubscribe(subscriber); }
});

test('an ordinary production process has no phase subscriber and writes no diagnostic output', () => {
  const moduleUrl = new URL('./installed-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '-e', `
    import { channel } from 'node:diagnostics_channel';
    const { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES, noteInstalledCredentialPhase } = await import(${JSON.stringify(moduleUrl)});
    if (channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL).hasSubscribers) throw new Error('unexpected subscriber');
    for (const phase of INSTALLED_CREDENTIAL_PHASES) noteInstalledCredentialPhase(phase);
  `], { encoding: 'utf8', timeout: 5000, cwd: fileURLToPath(new URL('../..', import.meta.url)) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
