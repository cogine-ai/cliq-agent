// Pure observations and source wiring only; not installed Linux qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createEnrollPhaseObservation } from './installed-enroll-diagnostic.js';

test('open-input phase observations accept complete fixed split markers without retaining arbitrary output', () => {
  const bytes = Buffer.from('private-unretained-output\nCLIQ_CREDENTIAL_PHASE_V1:history\nCLIQ_CREDENTIAL_PHASE_V1:retire\n');
  for (let split = 0; split <= bytes.length; split++) {
    const phases = createEnrollPhaseObservation();
    phases.write(bytes.subarray(0, split), 7); phases.write(bytes.subarray(split), 8); phases.finish();
    assert.deepEqual(phases.result.map(value => value.phase), ['history', 'retire']);
    assert(phases.result.every(value => value.elapsedMs === 7 || value.elapsedMs === 8));
    assert(!JSON.stringify(phases.result).includes('private-unretained-output'));
  }
});

test('open-input phase observations are bounded data and incomplete or malformed bytes cannot invent a phase', () => {
  const phases = createEnrollPhaseObservation();
  phases.write(Buffer.from('x'.repeat(200) + '\nCLIQ_CREDENTIAL_PHASE_V1:unknown\nCLIQ_CREDENTIAL_PHASE_V1:history\r\n'), 1);
  phases.write(Buffer.from([0xff, 10]), 2);
  phases.write(Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:history\n'), 3);
  for (const elapsed of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 2])
    phases.write(Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:secret_input\n'), elapsed);
  phases.write(Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:retire\n'.repeat(50)), 4);
  phases.write(Buffer.from('CLIQ_CREDENTIAL_PHASE_V1:history'), 5); phases.finish();
  assert.equal(phases.result.length, 32);
  assert.deepEqual(phases.result[0], { elapsedMs: 3, phase: 'history' });
  assert(phases.result.slice(1).every(row => row.phase === 'retire' && row.elapsedMs === 4));
  assert(Object.isFrozen(phases.result) && phases.result.every(Object.isFrozen));
  let accessed = false;
  phases.write(Object.defineProperty({}, 'length', { get() { accessed = true; throw 0; } }) as never, 5);
  assert.equal(accessed, false);
});

test('only the existing completed revoke replay retains a failure observation after the original join', async () => {
  const source = await readFile(new URL('./credential-installed-journey.ts', import.meta.url), 'utf8');
  const recipe = await readFile(new URL('./installed-supervisor-package.ts', import.meta.url), 'utf8');
  assert(recipe.includes('credentialPhaseDiagnostics?: true'));
  assert(recipe.includes('options.credentialPhaseDiagnostics === undefined || options.credentialPhaseDiagnostics === true'));
  assert(recipe.includes("options.guestToolchain === 'node-test-v1' || options.credentialPhaseDiagnostics"));
  assert(source.includes("campaignKind === 'authority_lifecycle' ? { credentialPhaseDiagnostics: true } : {}"));
  assert.equal((source.match(/undefined, 'completed_revoke_replay'/gu) ?? []).length, 1);
  assert.equal((source.match(/report\.offlineCompletedReceiptReplayFailure =/gu) ?? []).length, 1);
  const capture = source.indexOf('const capture = (chunks: Buffer[], bytes: Buffer, index: number)');
  const scan = source.indexOf('outputScans[index]!.scan(bytes)', capture);
  const observe = source.indexOf('phaseObservation.write(bytes, elapsedMs)', capture);
  assert(scan > capture && observe > scan);
  const final = source.indexOf('const failures: unknown[] = []', capture);
  const pipeJoin = source.indexOf('await bounded(streamsClosed, 5000)', final);
  const failureOnly = source.indexOf('if (primary || failures.length)', pipeJoin);
  const publish = source.indexOf('report.offlineCompletedReceiptReplayFailure =', failureOnly);
  assert(pipeJoin > final && failureOnly > pipeJoin && publish > failureOnly);
  assert(source.includes('const deadline = Date.now() + 30000;'));
  assert(source.includes("assert(Date.now() < deadline, 'committed replay waited for open secret input or unavailable services');"));
  assert(source.includes("else assert.equal(child.stdin.writableEnded, false, 'fixture must never end or write the secret-input pipe');"));
  assert(source.includes('processAndPipesJoined: finished && pipesJoined'));
});
