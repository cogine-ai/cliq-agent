// Fixed diagnostic data only; no installation, credential or Run authority.
import assert from 'node:assert/strict';
import { channel } from 'node:diagnostics_channel';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES, noteInstalledCredentialPhase,
  INSTALLED_CLIENT_PHASE_CHANNEL, INSTALLED_CLIENT_PHASES, noteInstalledClientPhase } from './installed-diagnostics.js';

test('the fixed server observation preserves fulfilled values and the original rejection, without sensitive data', async () => {
  const module = await import('./installed-diagnostics.js') as Record<string, any>;
  assert.equal(typeof module.beginInstalledServerAuthentication, 'function');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.server.authentication.v1');
  const subscriber = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(subscriber);
  try {
    const observe = module.beginInstalledServerAuthentication();
    const result = { privateValue: 'not diagnostic content' }, original = new Error('private failure');
    assert.equal(await observe('image_hash', async () => result), result);
    await assert.rejects(observe('process_cas', async () => { throw original; }), (error: unknown) => error === original);
    assert.equal(records.length, 3);
    const rows = records as Array<Record<string, unknown>>;
    assert.deepEqual(rows.map(row => row.phase), ['publish_started', 'image_hash_completed', 'process_cas_failed']);
    assert(rows.every(row => Object.isFrozen(row) && Object.keys(row).sort().join(',') === 'elapsedNs,ordinal,phase'));
    assert(rows.every(row => row.ordinal === rows[0]!.ordinal && Number.isSafeInteger(row.elapsedNs) && Number(row.elapsedNs) >= 0));
    assert.equal(rows[0]!.elapsedNs, 0);
    assert.equal(JSON.stringify(records).includes('private'), false);
  } finally { diagnostic.unsubscribe(subscriber); }
});

test('server spans finish only with their original promise and never inspect an unrecognized phase', async () => {
  const { beginInstalledServerAuthentication } = await import('./installed-diagnostics.js');
  const records: unknown[] = [], diagnostic = channel('cliq.installed.server.authentication.v1');
  const subscriber = (record: unknown) => { try { records.push(record); } catch {} };
  diagnostic.subscribe(subscriber);
  try {
    const observe = beginInstalledServerAuthentication()!;
    let finish!: (value: number) => void;
    const original = new Promise<number>(resolve => { finish = resolve; });
    const measured = observe('image_hash', () => original);
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(records.length, 1); finish(42);
    assert.equal(await measured, 42); assert.equal(records.length, 2);
    let getter = false;
    const phase = Object.defineProperty({}, 'toString', { get() { getter = true; throw 0; } });
    assert.equal(await observe(phase as never, async () => 7), 7);
    assert.equal(getter, false); assert.equal(records.length, 2);
  } finally { diagnostic.unsubscribe(subscriber); }
});

test('concurrent server spans emit each actual promise settlement immediately, even after a sibling fails', async () => {
  const { beginInstalledServerAuthentication } = await import('./installed-diagnostics.js');
  const records: Array<{ ordinal: number; phase: string; elapsedNs: number }> = [];
  const diagnostic = channel('cliq.installed.server.authentication.v1');
  const subscriber = (record: unknown) => { try { records.push(record as typeof records[number]); } catch {} };
  diagnostic.subscribe(subscriber);
  try {
    const observe = beginInstalledServerAuthentication()!;
    assert.equal(await observe('image_hash', async () => 42), 42);
    const resolve: Array<(value: number) => void> = [], reject: Array<(error: Error) => void> = [];
    const phases = ['process_cas', 'principal_cas', 'peer_cas', 'channel_cas'] as const;
    const tasks = phases.map((phase, index) => observe(phase, () => new Promise<number>((yes, no) => {
      resolve[index] = yes; reject[index] = no;
    })));
    const joined = Promise.allSettled(tasks), original = new Error('not diagnostic content');
    resolve[2]!(3); await new Promise<void>(yes => setImmediate(yes));
    assert.deepEqual(records.map(record => record.phase), ['publish_started', 'image_hash_completed', 'peer_cas_completed']);
    reject[0]!(original); await new Promise<void>(yes => setImmediate(yes));
    assert.equal(records.at(-1)!.phase, 'process_cas_failed');
    resolve[3]!(4); await new Promise<void>(yes => setImmediate(yes));
    assert.equal(records.at(-1)!.phase, 'channel_cas_completed');
    resolve[1]!(2);
    assert.deepEqual(await joined, [{ status: 'rejected', reason: original }, { status: 'fulfilled', value: 2 },
      { status: 'fulfilled', value: 3 }, { status: 'fulfilled', value: 4 }]);
    assert.deepEqual(records.map(record => record.phase), ['publish_started', 'image_hash_completed', 'peer_cas_completed',
      'process_cas_failed', 'channel_cas_completed', 'principal_cas_completed']);
    assert(records.every(record => record.ordinal === records[0]!.ordinal && Object.isFrozen(record) &&
      Number.isSafeInteger(record.elapsedNs) && record.elapsedNs >= 0));
    assert.equal(JSON.stringify(records).includes('not diagnostic content'), false);
  } finally { diagnostic.unsubscribe(subscriber); }
});

test('unsubscribed server diagnostics do not sample clocks or consume an ordinal; missing clocks cannot fail an operation', () => {
  const moduleUrl = new URL('./installed-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { channel } from 'node:diagnostics_channel';
    const {beginInstalledServerAuthentication} = await import(${JSON.stringify(moduleUrl)});
    const clock = process.hrtime.bigint;
    let clocks = 0;
    process.hrtime.bigint = () => { clocks++; throw new Error('diagnostic clock unavailable'); };
    assert.equal(beginInstalledServerAuthentication(), undefined); assert.equal(clocks, 0);
    const rows = [], diagnostic = channel('cliq.installed.server.authentication.v1');
    const subscriber = row => { try { rows.push(row); } catch {} };
    diagnostic.subscribe(subscriber);
    try {
      const observe = beginInstalledServerAuthentication();
      assert.equal(rows[0].ordinal, 1);
      assert.equal(await observe('image_hash', async()=>42),42);
      const original = new Error('original failure');
      await assert.rejects(observe('process_cas',async()=>{throw original}),error=>error===original);
      assert.equal(rows.length,1);
    } finally { diagnostic.unsubscribe(subscriber); process.hrtime.bigint = clock; }
  `], { encoding: 'utf8', timeout: 5000, cwd: fileURLToPath(new URL('../..', import.meta.url)) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});

test('installed client authentication publishes only its seven fixed primitive boundaries', () => {
  assert.deepEqual(INSTALLED_CLIENT_PHASES, ['manager_observer_loaded', 'initial_current_observed', 'native_connected',
    'pre_hello_current_verified', 'hello_exchange_started', 'hello_received', 'final_current_verified']);
  assert(Object.isFrozen(INSTALLED_CLIENT_PHASES));
  const observed: unknown[] = [], diagnostic = channel(INSTALLED_CLIENT_PHASE_CHANNEL);
  const subscriber = (phase: unknown) => { try { observed.push(phase); } catch { /* Trusted diagnostic sink only. */ } };
  diagnostic.subscribe(subscriber);
  try {
    for (const phase of INSTALLED_CLIENT_PHASES) noteInstalledClientPhase(phase);
    let accessed = false;
    const untrusted = Object.defineProperty({}, 'phase', { get() { accessed = true; throw 0; } });
    for (const value of [null, undefined, 'hello_sent', untrusted]) noteInstalledClientPhase(value as never);
    assert.equal(accessed, false); assert.deepEqual(observed, [...INSTALLED_CLIENT_PHASES]);
  } finally { diagnostic.unsubscribe(subscriber); }
});

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
    const { INSTALLED_CREDENTIAL_PHASE_CHANNEL, INSTALLED_CREDENTIAL_PHASES, noteInstalledCredentialPhase,
      INSTALLED_CLIENT_PHASE_CHANNEL, INSTALLED_CLIENT_PHASES, noteInstalledClientPhase } = await import(${JSON.stringify(moduleUrl)});
    if (channel(INSTALLED_CREDENTIAL_PHASE_CHANNEL).hasSubscribers) throw new Error('unexpected subscriber');
    for (const phase of INSTALLED_CREDENTIAL_PHASES) noteInstalledCredentialPhase(phase);
    if (channel(INSTALLED_CLIENT_PHASE_CHANNEL).hasSubscribers) throw new Error('unexpected client subscriber');
    for (const phase of INSTALLED_CLIENT_PHASES) noteInstalledClientPhase(phase);
  `], { encoding: 'utf8', timeout: 5000, cwd: fileURLToPath(new URL('../..', import.meta.url)) });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
});
