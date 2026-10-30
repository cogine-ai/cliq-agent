import assert from 'node:assert/strict';
import { Readable, PassThrough } from 'node:stream';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';
import { decodeProviderJourneyConfiguration, readProviderJourneySecret } from './provider-journey-input.js';

const selection = {
  definition: { provider: 'openai-compatible', model: 'deepseek-flash',
    target: { hostAscii: 'api.deepseek.com', port: 443, basePath: '/' },
    tls: { serverNameAscii: 'api.deepseek.com', spkiSha256Pins: ['a'.repeat(64)] },
    claims: { nativeToolCalling: true, streaming: false, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 8192 },
    prices: { input: 300000, output: 1200000, cacheRead: 6000, cacheWrite: 0 },
    requestTokenCeiling: { inputTokens: 1048576, outputTokens: 393216, cacheReadTokens: 1048576, cacheWriteTokens: 0 },
    validFrom: '2026-10-30T00:00:00.000Z', validThrough: '2026-10-31T00:00:00.000Z' },
  budgets: { wallTimeMs: 300000, modelTokens: 20000000, costMicros: 5000000, toolCalls: 100,
    repairAttempts: 2, childDepth: 0, childConcurrency: 1 }
};

test('explicit provider selection preserves the complete conservative ceiling and rejects secret/config scope drift', () => {
  const selected = decodeProviderJourneyConfiguration(selection);
  assert.deepEqual(selected, selection); assert.equal(Object.isFrozen(selected.definition), true); assert.equal(Object.isFrozen(selected.budgets), true);
  for (const input of [
    { ...selection, secret: 'must not enter public configuration' },
    { ...selection, definition: { ...selection.definition, model: 'different-model' } },
    { ...selection, definition: { ...selection.definition, target: { ...selection.definition.target, hostAscii: 'other.example' } } },
    { ...selection, definition: { ...selection.definition, prices: { ...selection.definition.prices, input: 150000 } } },
    { ...selection, definition: { ...selection.definition, requestTokenCeiling: { ...selection.definition.requestTokenCeiling, outputTokens: 8192 } } },
    { ...selection, definition: { ...selection.definition, claims: { ...selection.definition.claims, trustedUsageEvidence: true } } },
    { ...selection, budgets: { ...selection.budgets, costMicros: 0 } },
    { ...selection, budgets: { ...selection.budgets, costMicros: Infinity } },
    { ...selection, budgets: { ...selection.budgets, extraBudget: 100 } }
  ]) assert.throws(() => decodeProviderJourneyConfiguration(input));
});

test('secret reader waits for actual EOF before returning an owned copy and erases its input chunks', async () => {
  const input = new PassThrough(), first = Buffer.from('inert-'), second = Buffer.from('test-key');
  let returned = false;
  const pending = readProviderJourneySecret(input).then(value => { returned = true; return value; });
  input.write(first); await new Promise(resolve => setImmediate(resolve)); assert.equal(returned, false);
  input.end(second);
  const secret = await pending;
  assert.equal(secret.toString(), 'inert-test-key'); assert.equal(input.readableEnded, true);
  assert(first.every(byte => byte === 0)); assert(second.every(byte => byte === 0));
  secret.fill(0); assert(secret.every(byte => byte === 0));
});

test('secret reader refuses empty, oversized and failed streams without returning partial input', async () => {
  await assert.rejects(readProviderJourneySecret(Readable.from([])), /empty/);
  const oversized = Buffer.alloc(4097, 97), input = Readable.from([oversized]);
  await assert.rejects(readProviderJourneySecret(input), /fixed bound/);
  assert(oversized.every(byte => byte === 0)); assert.equal(input.destroyed, true);
  const failure = new Error('owned stdin failed'), broken = new PassThrough();
  const pending = readProviderJourneySecret(broken); broken.write(Buffer.from('inert')); broken.destroy(failure);
  await assert.rejects(pending, error => error === failure); assert.equal(broken.destroyed, true);
  const maximum = Buffer.alloc(4096, 97), exact = await readProviderJourneySecret(Readable.from([maximum]));
  assert.equal(exact.length, 4096); assert(exact.every(byte => byte === 97)); assert(maximum.every(byte => byte === 0)); exact.fill(0);
});

test('secret stdin requires raw bytes and preserves their complete value without trimming or textual coercion', async () => {
  const encoded = Readable.from(['inert-text-stream']);
  await assert.rejects(readProviderJourneySecret(encoded), /raw stdin bytes/u); assert.equal(encoded.destroyed, true);
  const bytes = Buffer.from('inert raw bytes\n'), secret = await readProviderJourneySecret(Readable.from([bytes]));
  try { assert.equal(secret.toString('utf8'), 'inert raw bytes\n'); assert(bytes.every(byte => byte === 0)); }
  finally { secret.fill(0); }
});

test('provider and normal daily branches select matching schema3 framing while original modes retain schema1', async () => {
  // Inspect the actual fixed caller expression. Do not execute this Linux
  // bootstrap, a child process, credential operation or provider request.
  const source = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const file = ts.createSourceFile('installed-node-journey.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'openInstalledClientConsumer') calls.push(node);
    ts.forEachChild(node, visit);
  };
  visit(file); assert.equal(calls.length, 1);
  const options = calls[0]!.arguments[0]; assert(options && ts.isObjectLiteralExpression(options));
  const branch = (value: ts.Expression, provider: boolean, daily: boolean): ts.Expression => {
    while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)) value = value.expression;
    assert(ts.isConditionalExpression(value)); assert.equal(value.condition.getText(file), 'options.provider || dailyJourney');
    return provider || daily ? value.whenTrue : value.whenFalse;
  };
  const args = options.properties.find((property): property is ts.PropertyAssignment =>
    ts.isPropertyAssignment(property) && property.name.getText(file) === 'args');
  assert(args && ts.isArrayLiteralExpression(args.initializer));
  const conditionalArgs = args.initializer.elements.filter((element): element is ts.SpreadElement =>
    ts.isSpreadElement(element) && element.expression.getText(file).includes('options.provider'));
  assert.equal(conditionalArgs.length, 1);
  const conditionalOptions = options.properties.filter((property): property is ts.SpreadAssignment =>
    ts.isSpreadAssignment(property) && property.expression.getText(file).includes('headlessSchemaVersion'));
  assert.equal(conditionalOptions.length, 1);
  for (const [provider, daily] of [[false, false], [true, false], [false, true]] as const) {
    const values = branch(conditionalArgs[0]!.expression, provider, daily); assert(ts.isArrayLiteralExpression(values));
    const selectedArgs = values.elements.map(value => { assert(ts.isStringLiteral(value)); return value.text; });
    const selected = branch(conditionalOptions[0]!.expression, provider, daily); assert(ts.isObjectLiteralExpression(selected));
    const schema = selected.properties.find((property): property is ts.PropertyAssignment =>
      ts.isPropertyAssignment(property) && property.name.getText(file) === 'headlessSchemaVersion');
    assert.deepEqual(selectedArgs, provider || daily ? ['--schema3'] : []);
    if (provider || daily) {
      assert(schema); let value = schema.initializer;
      while (ts.isAsExpression(value)) value = value.expression;
      assert(ts.isNumericLiteral(value)); assert.equal(value.text, '3');
    } else assert.equal(schema, undefined);
  }
});
