import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { providerSelection, runProviderProcess } from './provider-qualification.js';
import { PR532_POLL_INTERVAL_MS } from '../kernel/testing/provider-journey-input.js';
import { buildModelRequestWire, type ModelVisiblePromptV1 } from '../../src/model/request.js';
import { calculateModelCostMicros } from '../../src/model/pricing.js';

// Real subprocess/pipe tests with inert bytes. No StateOwner, credential
// enrollment, installed identity, provider request or native proof is created.
const secret = Buffer.from('inert-qualification-transport-fixture');
const digest = createHash('sha256').update(secret).digest('hex');
const ready = 'CLIQ_PROVIDER_SECRET_STDIN_READY_V1';
const environment = { PATH: process.env.PATH };

test('funded selection keeps the exact endpoint, full request ceilings and one finite Run budget', () => {
  const input = providerSelection(new Date('2026-11-13T00:00:00.000Z'));
  assert.equal(input.budgets.costMicros, 5_000_000);
  assert.equal(input.budgets.wallTimeMs, 300_000);
  assert.equal(input.definition.requestTokenCeiling.inputTokens, 1048576);
  assert.equal(input.definition.requestTokenCeiling.outputTokens, 393216);
  assert.equal(input.definition.claims.trustedUsageEvidence, false);
  assert.equal(input.definition.claims.contextLimitTokens, 1_000_000);
  assert.equal(input.definition.target.hostAscii, 'api.deepseek.com');
  assert.deepEqual(input.definition.tls.spkiSha256Pins, [
    '2ac9550952cd8f9b7f7baeccd3a140e4d4ae76c0a721a4e5231975f652a1a836',
    'a19e7f96489037676b8e0804127357088934c6253f9c9131ffe58a509b259702']);
  assert.equal(input.definition.validFrom, '2026-11-12T23:59:00.000Z');
  assert.equal(input.definition.validThrough, '2026-11-13T04:00:00.000Z');
  const pr532 = providerSelection(new Date('2026-11-13T00:00:00.000Z'), true);
  assert.equal(pr532.budgets.wallTimeMs, 90 * 60_000);
  assert.equal(pr532.budgets.wallTimeMs / PR532_POLL_INTERVAL_MS, 720);
  assert.equal(pr532.budgets.costMicros, 1_660_000);
  assert.equal(pr532.definition.requestTokenCeiling.outputTokens, 8192);
  assert.equal(pr532.budgets.modelTokens, 32_000_000);
});

test('the fixed provider ceiling covers every admitted output cap and the exact serialized request', () => {
  // Pure public selection, wire bytes and price arithmetic. No installed
  // identity, request preparation, native claim or provider call is created.
  const { definition } = providerSelection(new Date('2026-11-13T00:00:00.000Z'), true);
  const { claims, requestTokenCeiling: ceiling } = definition;
  const summaryCap = Math.min(8192, Math.floor(claims.contextLimitTokens / 8));
  assert.equal(ceiling.outputTokens, Math.max(claims.maxOutputTokens, summaryCap));
  const prompt: ModelVisiblePromptV1 = { format: 'cliq-model-visible-prompt-v1',
    messages: [{ role: 'user', contentUtf8: 'inert request data' }], tools: [],
    responseContract: { mode: 'text-only', toolCallsAllowed: false } };
  for (const output of [claims.maxOutputTokens, summaryCap]) {
    const wire = buildModelRequestWire({ provider: definition.provider, model: definition.model,
      streaming: claims.streaming, contextLimitTokens: claims.contextLimitTokens }, prompt, output, 'text-only');
    assert.equal(JSON.parse(wire.bodyBytes.toString('utf8')).max_tokens, ceiling.outputTokens);
  }
  assert.equal(ceiling.inputTokens, 1048576);
  assert.equal(ceiling.cacheReadTokens, 1048576);
  assert.equal(calculateModelCostMicros(ceiling, definition.prices), 330696);
  const { budgets } = providerSelection(new Date('2026-11-13T00:00:00.000Z'), true);
  assert.equal(Math.floor(budgets.costMicros / calculateModelCostMicros(ceiling, definition.prices)), 5);
});

test('the source-bounded CNY-account booking covers the next complete native lifetime within the approved total', () => {
  // External conservative bookkeeping, under the separately authenticated CNY
  // account observation and published peak tariffs. This creates no billing,
  // price-table, native budget or refund authority and uses no usage telemetry.
  const input = providerSelection(new Date('2026-11-19T00:00:00.000Z'), true);
  const ceiling = input.definition.requestTokenCeiling;
  const usdMicros = calculateModelCostMicros(ceiling, input.definition.prices);
  const cnyMicros = calculateModelCostMicros(ceiling,
    { input: 2_000_000, output: 8_000_000, cacheRead: 40_000, cacheWrite: 0 });
  assert.equal(cnyMicros, 2_204_632);
  // Preserve the already-audited original bounds, including the entire fifth
  // lifetime despite its failed Stop and the entire eighth thirteen-call cap.
  const historicalCalls = [15, 4, 10, 4, 15, 12, 12, 13].reduce((sum, count) => sum + count, 0);
  const historical = Number((BigInt(historicalCalls) * BigInt(cnyMicros) + 999_999n) / 1_000_000n);
  const nextCalls = Math.floor(input.budgets.costMicros / usdMicros);
  const next = Number((BigInt(nextCalls) * BigInt(cnyMicros) + 999_999n) / 1_000_000n);
  assert.deepEqual({ historicalCalls, historical, nextCalls, next },
    { historicalCalls: 85, historical: 188, nextCalls: 5, next: 12 });
  assert.equal(historical + next, 200);
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
