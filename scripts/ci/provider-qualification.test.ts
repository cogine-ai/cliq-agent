import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { providerSelection, runProviderProcess } from './provider-qualification.js';

// Real subprocess/pipe tests with inert bytes. No StateOwner, credential
// enrollment, installed identity, provider request or native proof is created.
const secret = Buffer.from('inert-qualification-transport-fixture');
const digest = createHash('sha256').update(secret).digest('hex');
const ready = 'CLIQ_PROVIDER_SECRET_STDIN_READY_V1';
const environment = { PATH: process.env.PATH };

test('funded selection keeps the exact endpoint, full request ceilings and one finite Run budget', () => {
  const input = providerSelection(new Date('2026-11-13T00:00:00.000Z'));
  assert.equal(input.budgets.costMicros, 3_500_000);
  assert.equal(input.budgets.wallTimeMs, 300_000);
  assert.equal(input.definition.requestTokenCeiling.inputTokens, 1048576);
  assert.equal(input.definition.requestTokenCeiling.outputTokens, 393216);
  assert.equal(input.definition.claims.trustedUsageEvidence, false);
  assert.equal(input.definition.target.hostAscii, 'api.deepseek.com');
  assert.deepEqual(input.definition.tls.spkiSha256Pins, [
    '2ac9550952cd8f9b7f7baeccd3a140e4d4ae76c0a721a4e5231975f652a1a836',
    'a19e7f96489037676b8e0804127357088934c6253f9c9131ffe58a509b259702']);
  assert.equal(input.definition.validFrom, '2026-11-12T23:59:00.000Z');
  assert.equal(input.definition.validThrough, '2026-11-13T04:00:00.000Z');
});

test('private bytes arrive once after the complete marker and EOF, with no inherited credential environment', async () => {
  const phases: string[] = [];
  const code = `const {createHash}=require('node:crypto'); let ready=false; const chunks=[];
    if(process.env.CLIQ_PROVIDER_API_KEY!==undefined) process.exit(10);
    process.stdin.on('data',b=>{if(!ready)process.exit(11);chunks.push(b)});
    process.stdin.on('end',()=>{if(createHash('sha256').update(Buffer.concat(chunks)).digest('hex')!=='${digest}')process.exit(12);
      process.stdout.write('arbitrary private child output\\nInstalled daily journey phase model_setup\\n');});
    process.stdout.write('${ready.slice(0, 12)}');setTimeout(()=>{ready=true;process.stdout.write('${ready.slice(12)}\\n')},20);`;
  const result = await runProviderProcess(process.execPath, ['-e', code], secret, environment, phase => { phases.push(phase); });
  assert.equal(result.passed, true); assert.equal(result.privateInputSent, true); assert.equal(result.processAndPipesJoined, true);
  assert.deepEqual(phases, ['Installed daily journey phase model_setup']);
  assert(!JSON.stringify(result).includes(secret.toString()));
});

test('exit without readiness never supplies private input or qualifies a child', async () => {
  const result = await runProviderProcess(process.execPath, ['-e', 'process.exit(0)'], secret, environment);
  assert.equal(result.exitCode, 0); assert.equal(result.privateInputSent, false);
  assert.equal(result.passed, false); assert.equal(result.processAndPipesJoined, true);
});

test('a repeated marker stops and joins the original process without a second private write', async () => {
  const code = `process.on('SIGTERM',()=>process.exit(17)); setInterval(()=>{},1000);
    process.stdout.write('${ready}\\n${ready}\\n');`;
  const result = await runProviderProcess(process.execPath, ['-e', code], secret, environment);
  assert.equal(result.privateInputSent, true); assert.equal(result.outputRefused, true);
  assert.equal(result.passed, false); assert.equal(result.processAndPipesJoined, true);
});

test('secret fragments on one pipe remain detectable across interleaved output on the other', async () => {
  const code = `const chunks=[];process.stdin.on('data',b=>chunks.push(b));process.stdin.on('end',()=>{
    const b=Buffer.concat(chunks);process.stderr.write(b.subarray(0,9));setTimeout(()=>{
      process.stdout.write('unrelated output\\n');setTimeout(()=>process.stderr.write(b.subarray(9)),10)},10)});
    process.stdout.write('${ready}\\n');`;
  const result = await runProviderProcess(process.execPath, ['-e', code], secret, environment);
  assert.equal(result.exitCode, 0); assert.equal(result.outputRefused, true); assert.equal(result.passed, false);
  assert.equal(result.processAndPipesJoined, true); assert(!JSON.stringify(result).includes(secret.toString()));
});

test('a diagnostic callback failure still stops and joins the original child', async () => {
  const code = `process.on('SIGTERM',()=>process.exit(18));setInterval(()=>{},1000);
    process.stdout.write('Installed daily journey phase setup\\n');`;
  const result = await runProviderProcess(process.execPath, ['-e', code], secret, environment, () => { throw new Error('refused output'); });
  assert.equal(result.passed, false); assert.equal(result.processAndPipesJoined, true);
});

test('an inherited credential variable is rejected before even trying to spawn', async () => {
  await assert.rejects(runProviderProcess('/no-such-program', [], secret, { CLIQ_PROVIDER_API_KEY: 'inert' }),
    { code: 'ERR_ASSERTION' });
});
