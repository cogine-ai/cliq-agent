import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { McpResolvedTransportV1 } from '../kernel/mcp.js';
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData, mcpToolsCallRequestData } from '../kernel/mcp-wire.js';
import { encodeMcpStdioRecipe, decodeMcpStdioRecipeData, MCP_STDIO_RECIPE_HEADER_BYTES } from './mcp-stdio-recipe.js';
import type { FrozenMcpStdioInput } from './mcp-stdio-broker-native.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
function input(run = false): FrozenMcpStdioInput {
  const frames = [mcpInitializeRequestData(1, '1'), mcpInitializedNotificationData(), mcpToolsListRequestData(2)];
  if (run) frames.push(mcpToolsCallRequestData(3, 'echo', { message: 'value' }));
  return { argv: ['', 'α'], serverDigest: 'a'.repeat(64), serverByteCount: 512, maximumResponseBytes: 1_048_576,
    maximumOutputBytes: 16_777_216, remainingDeadlineMs: 300_000,
    recipe: frames.map(frame => ({ phase: frame.phase, bodyBytes: Buffer.from(frame.json), bodyBytesDigest: frame.digest })) };
}
test('fixed stdio recipe data retains the pinned C layout, exact empty/UTF8 argv and three/four complete frames', () => {
  for (const purpose of ['admin', 'run'] as const) {
    const original = input(purpose === 'run'), encoded = encodeMcpStdioRecipe(original, purpose), bytes = encoded.bytes;
    assert.equal(MCP_STDIO_RECIPE_HEADER_BYTES, 984); assert.equal(bytes.readUInt32LE(0), 0x43535243);
    assert.equal(bytes.readUInt32LE(4), 1); assert.equal(bytes.readUInt32LE(8), purpose === 'admin' ? 1 : 2);
    assert.equal(bytes.readUInt32LE(12), 2); assert.equal(bytes.readUInt32LE(16), 4); assert.equal(bytes.readUInt32LE(20), original.recipe.length);
    assert.equal(bytes.readBigUInt64LE(32), 16_777_216n); assert.equal(bytes.readBigUInt64LE(40), 512n);
    assert.deepEqual(bytes.subarray(113, 116), Buffer.alloc(3)); assert.deepEqual(bytes.subarray(628, 632), Buffer.alloc(4));
    assert.equal(bytes.readUInt32LE(116), 0); assert.equal(bytes.readUInt32LE(120), 1);
    assert.deepEqual(bytes.subarray(984, 988), Buffer.from([0, 0xce, 0xb1, 0]));
    let at = 988;
    original.recipe.forEach((frame, index) => {
      const offset = 632 + index * 88;
      assert.equal(bytes.readBigUInt64LE(offset), BigInt(at)); assert.equal(bytes.readBigUInt64LE(offset + 8), BigInt(frame.bodyBytes.length));
      assert.equal(bytes.subarray(offset + 16, offset + 80).toString(), frame.bodyBytesDigest);
      assert.deepEqual(bytes.subarray(offset + 80, offset + 88), Buffer.alloc(8));
      assert.deepEqual(bytes.subarray(at, at + frame.bodyBytes.length), frame.bodyBytes); at += frame.bodyBytes.length;
    });
    assert.equal(at, bytes.length); assert.equal(encoded.remainingDeadlineMs, original.remainingDeadlineMs);
    const decoded = decodeMcpStdioRecipeData(bytes);
    assert.equal(decoded.purpose, purpose); assert.deepEqual(decoded.argv, original.argv); assert.equal(decoded.recipeDigest, sha256Bytes(bytes));
    assert.equal(decoded.recipe.length, original.recipe.length); assert.equal(decoded.recipe[0]!.bodyJson, original.recipe[0]!.bodyBytes.toString());
    assert.equal(Object.hasOwn(decoded, 'remainingDeadlineMs'), false, 'time samples never enter the retained recipe blob');
    original.recipe[0]!.bodyBytes.fill(0); assert.notEqual(bytes[988], 0, 'data encoding owns its exact original body copy');
  }
});
test('fixed stdio recipe data rejects incomplete phases, altered digests, raw newline framing and side-effectful inputs before traversing them', () => {
  const value = input();
  assert.throws(() => encodeMcpStdioRecipe(value, 'run'));
  assert.throws(() => encodeMcpStdioRecipe({ ...value, recipe: value.recipe.map((frame, index) => index ? frame : { ...frame, bodyBytesDigest: 'b'.repeat(64) }) }, 'admin'));
  const multiline = Buffer.from(value.recipe[0]!.bodyBytes.toString().replace('{', '{\n'));
  assert.throws(() => encodeMcpStdioRecipe({ ...value, recipe: [{ ...value.recipe[0]!, bodyBytes: multiline, bodyBytesDigest: sha256Bytes(multiline) }, ...value.recipe.slice(1)] }, 'admin'));
  let calls = 0;
  const proxy = new Proxy(value, { ownKeys() { calls++; throw 0; }, get() { calls++; throw 0; }, getPrototypeOf() { calls++; throw 0; } });
  assert.throws(() => encodeMcpStdioRecipe(proxy, 'admin')); assert.equal(calls, 0);
  const getter = Object.defineProperty({ ...value }, 'argv', { enumerable: true, get() { calls++; throw 0; } });
  assert.throws(() => encodeMcpStdioRecipe(getter, 'admin')); assert.equal(calls, 0);
  const extra = { ...value, recipe: [...value.recipe] };
  Object.defineProperty(extra.recipe, 'extra', { value: true }); assert.throws(() => encodeMcpStdioRecipe(extra, 'admin'));
  assert.throws(() => encodeMcpStdioRecipe({ ...value, remainingDeadlineMs: NaN }, 'admin'));
  const body = canonicalJsonBytes({ unknown: true });
  assert.throws(() => encodeMcpStdioRecipe({ ...value, recipe: [{ ...value.recipe[0]!, bodyBytes: Buffer.from(' ' + body), bodyBytesDigest: sha256Bytes(Buffer.from(' ' + body)) }, ...value.recipe.slice(1)] }, 'admin'));
});
test('fixed stdio historical recipe decoder rejects padding, offsets, partial bytes and a correctly hashed different RPC recipe', () => {
  const original = input(true), bytes = encodeMcpStdioRecipe(original, 'run').bytes;
  for (const offset of [28, 113, 628, 712]) {
    const changed = Buffer.from(bytes); changed[offset] = 1; assert.throws(() => decodeMcpStdioRecipeData(changed));
  }
  const offset = Buffer.from(bytes); offset.writeBigUInt64LE(1n, 632); assert.throws(() => decodeMcpStdioRecipeData(offset));
  assert.throws(() => decodeMcpStdioRecipeData(bytes.subarray(0, bytes.length - 1)));
  const invalidBody = canonicalJsonBytes({ jsonrpc: '2.0', method: 'other', id: 3, params: { name: 'echo', arguments: {} } });
  const changed = encodeMcpStdioRecipe({ ...original, recipe: [...original.recipe.slice(0, 3), {
    phase: 'tools_call', bodyBytes: invalidBody, bodyBytesDigest: sha256Bytes(invalidBody) }] }, 'run');
  assert.throws(() => decodeMcpStdioRecipeData(changed.bytes));
});
test('fixed recovery recipe has its distinct purpose 3 and cannot omit its exact fourth status frame', () => {
  const original = input(true), recovery = encodeMcpStdioRecipe(original, 'recovery');
  assert.equal(recovery.bytes.readUInt32LE(8), 3);
  const decoded = decodeMcpStdioRecipeData(recovery.bytes);
  assert.equal(decoded.purpose, 'recovery'); assert.equal(decoded.recipe.length, 4);
  assert.equal(decoded.recipe[3]?.bodyBytesDigest, original.recipe[3]?.bodyBytesDigest);
  const productive = encodeMcpStdioRecipe(original, 'run');
  assert.notEqual(sha256Bytes(recovery.bytes), sha256Bytes(productive.bytes));
  assert.equal(recovery.bytes.subarray(12).equals(productive.bytes.subarray(12)), true, 'only the closed purpose differs; no deadline/response/output bound is raised');
  assert.throws(() => encodeMcpStdioRecipe(input(false), 'recovery'));
  const invalid = Buffer.from(recovery.bytes); invalid.writeUInt32LE(4, 8);
  assert.throws(() => decodeMcpStdioRecipeData(invalid));
});
test('the status recipe executes its signed adapter while retaining the registered server identity', () => {
  const originalServer = 'a'.repeat(64), adapter = 'b'.repeat(64), argumentsValue = { key: 'fixed' };
  const transport: Extract<McpResolvedTransportV1, { kind: 'stdio' }> = { kind: 'stdio', executionIdentityGrantId: 'original-grant',
    executionIdentityConsumptionReceiptRef: 'c'.repeat(64), executionIdentityConsumptionReceiptDigest: 'd'.repeat(64),
    executable: { kind: 'runtime_bundle', runtimeBundleRef: 'e'.repeat(64), executableId: 'original-server',
      executableDigest: originalServer, executionPath: '/runtime/mcp-server' }, argv: [{ kind: 'non_secret_literal', value: 'fixed-profile' }] };
  const frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2),
    mcpToolsCallRequestData(3, 'inspect-status', argumentsValue)];
  const material = { argv: ['fixed-profile'], serverDigest: adapter, serverByteCount: 512, maximumResponseBytes: 1_048_576,
    maximumOutputBytes: DEFAULT_SANDBOX_RESOURCES.maxInvocationOutputBytes, remainingDeadlineMs: 30_000,
    recipe: frames.map(frame => ({ phase: frame.phase, bodyBytes: Buffer.from(frame.json), bodyBytesDigest: frame.digest })) };
  const inspect = (value: typeof material) => decodeMcpStdioRecipeData(encodeMcpStdioRecipe(value, 'recovery').bytes);
  const expected = { purpose: 'recovery' as const, transport, adapterExecutableDigest: adapter, serverByteCount: 512,
    resources: DEFAULT_SANDBOX_RESOURCES, effectServerToolName: 'perform-effect', statusOperationName: 'inspect-status', arguments: argumentsValue };
  assert.doesNotThrow(() => assertMcpStdioRecipeData(inspect(material), expected));
  assert.throws(() => assertMcpStdioRecipeData(inspect({ ...material, serverDigest: originalServer }), expected));
  assert.throws(() => assertMcpStdioRecipeData(inspect({ ...material, serverDigest: originalServer }),
    { ...expected, adapterExecutableDigest: originalServer }));
  assert.throws(() => assertMcpStdioRecipeData(inspect(material), { ...expected, statusOperationName: 'perform-effect' }));
});
