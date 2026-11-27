// Fixed private binary data encoder. Native independently repeats the closed
// layout/hash/strict MCP recipe checks; these bytes carry no live authority.
import { types } from 'node:util';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { controlWireInteger, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { parseJsonStrict } from '../kernel/json.js';
import { sha256Bytes } from '../kernel/identity.js';
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData, mcpToolsCallRequestData } from '../kernel/mcp-wire.js';
import { MCP_RESPONSE_BYTES } from '../kernel/mcp.js';
import type { FrozenMcpStdioInput, McpStdioPhase } from './mcp-stdio-broker-native.js';
import { MCP_STDIO_EXECUTABLE_BYTES } from '../sandbox/mcp-stdio-executable.js';
export const MCP_STDIO_RECIPE_HEADER_BYTES = 984;
const phases: readonly McpStdioPhase[] = ['initialize', 'initialized', 'tools_list', 'tools_call'];
const viewPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(viewPrototype, 'byteLength')!.get!;
const byteOffset = Object.getOwnPropertyDescriptor(viewPrototype, 'byteOffset')!.get!;
const backingBuffer = Object.getOwnPropertyDescriptor(viewPrototype, 'buffer')!.get!;
function record(value: unknown, keys: readonly string[]) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value)) throw new TypeError('invalid fixed stdio recipe record');
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key) || !fields[key]!.enumerable ||
      !Object.hasOwn(fields[key]!, 'value'))) throw new TypeError('invalid fixed stdio recipe fields');
  return Object.fromEntries(keys.map(key => [key, fields[key]!.value])) as Record<string, unknown>;
}
function dense(value: unknown, maximum: number): unknown[] {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !Array.isArray(value)) throw new TypeError('invalid fixed stdio recipe array');
  const fields = Object.getOwnPropertyDescriptors(value), length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum || Reflect.ownKeys(fields).length !== length + 1)
    throw new TypeError('invalid fixed stdio recipe array length');
  const result: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const field = fields[String(index)];
    if (!field || !field.enumerable || !Object.hasOwn(field, 'value')) throw new TypeError('invalid fixed stdio recipe array element');
    result.push(field.value);
  }
  return result;
}
function bodyBytes(value: unknown): Buffer {
  return ownedBytes(value, MCP_RESPONSE_BYTES);
}
function ownedBytes(value: unknown, maximum: number): Buffer {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !types.isUint8Array(value)) throw new TypeError('fixed stdio recipe body requires bytes');
  const length = Reflect.apply(byteLength, value, []);
  controlWireInteger(length, 1, maximum);
  return Buffer.from(new Uint8Array(Reflect.apply(backingBuffer, value, []), Reflect.apply(byteOffset, value, []), length));
}
export function encodeMcpStdioRecipe(input: FrozenMcpStdioInput, purpose: 'admin' | 'run' | 'recovery'): Readonly<{ bytes: Buffer; remainingDeadlineMs: number }> {
  if (purpose !== 'admin' && purpose !== 'run' && purpose !== 'recovery') throw new TypeError('invalid fixed stdio recipe purpose');
  const data = record(input, ['argv', 'serverDigest', 'serverByteCount', 'maximumResponseBytes', 'maximumOutputBytes', 'remainingDeadlineMs', 'recipe']);
  const args = dense(data.argv, 128).map(value => Buffer.from(controlWireText(value, 8192, 0) + '\0'));
  const stringBytes = args.reduce((total, value) => total + value.length, 0);
  const source = dense(data.recipe, 4), phaseCount = purpose === 'admin' ? 3 : 4;
  if (source.length !== phaseCount) throw new TypeError('fixed stdio recipe phase count differs');
  const serverDigest = controlWireRef(data.serverDigest), serverByteCount = controlWireInteger(data.serverByteCount, 1, MCP_STDIO_EXECUTABLE_BYTES);
  const maximumResponseBytes = controlWireInteger(data.maximumResponseBytes, 65_536, MCP_RESPONSE_BYTES);
  const maximumOutputBytes = controlWireInteger(data.maximumOutputBytes, 65_536, 67_108_864);
  const remainingDeadlineMs = controlWireInteger(data.remainingDeadlineMs, 1, 0x7fffffff);
  const frames = source.map((value, index) => {
    const frame = record(value, ['phase', 'bodyBytes', 'bodyBytesDigest']), bytes = bodyBytes(frame.bodyBytes);
    if (frame.phase !== phases[index] || controlWireRef(frame.bodyBytesDigest) !== sha256Bytes(bytes) || bytes.includes(10) || bytes.includes(13))
      throw new TypeError('fixed stdio recipe phase, digest or newline framing differs');
    const json = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(json).equals(bytes)) throw new TypeError('fixed stdio recipe body is not its complete canonical JSON');
    return { bytes, digest: frame.bodyBytesDigest as string };
  });
  const size = MCP_STDIO_RECIPE_HEADER_BYTES + stringBytes + frames.reduce((total, frame) => total + frame.bytes.length, 0);
  const bytes = Buffer.alloc(size);
  bytes.writeUInt32LE(0x43535243, 0); bytes.writeUInt32LE(1, 4); bytes.writeUInt32LE(purpose === 'admin' ? 1 : purpose === 'run' ? 2 : 3, 8);
  bytes.writeUInt32LE(args.length, 12); bytes.writeUInt32LE(stringBytes, 16); bytes.writeUInt32LE(phaseCount, 20); bytes.writeUInt32LE(maximumResponseBytes, 24);
  bytes.writeBigUInt64LE(BigInt(maximumOutputBytes), 32); bytes.writeBigUInt64LE(BigInt(serverByteCount), 40); bytes.write(serverDigest, 48, 64, 'ascii');
  let at = MCP_STDIO_RECIPE_HEADER_BYTES;
  args.forEach((argument, index) => { bytes.writeUInt32LE(at - MCP_STDIO_RECIPE_HEADER_BYTES, 116 + index * 4); argument.copy(bytes, at); at += argument.length; });
  frames.forEach((frame, index) => {
    const offset = 632 + index * 88;
    bytes.writeBigUInt64LE(BigInt(at), offset); bytes.writeBigUInt64LE(BigInt(frame.bytes.length), offset + 8); bytes.write(frame.digest, offset + 16, 64, 'ascii');
    frame.bytes.copy(bytes, at); at += frame.bytes.length;
  });
  return Object.freeze({ bytes, remainingDeadlineMs });
}
export type McpStdioRecipeData = Readonly<{
  version: 1; purpose: 'admin' | 'run' | 'recovery'; argv: readonly string[]; serverDigest: string; serverByteCount: number;
  maximumResponseBytes: number; maximumOutputBytes: number; byteCount: number; recipeDigest: string;
  recipe: readonly Readonly<{ phase: McpStdioPhase; bodyJson: string; bodyBytesDigest: string }>[];
}>;
/** Historical data only. No elapsed/remaining time, fd, native recipe tag or
 * execution authority can be reconstructed from this complete bounded blob. */
export function decodeMcpStdioRecipeData(input: Uint8Array): McpStdioRecipeData {
  const bytes = ownedBytes(input, MCP_STDIO_RECIPE_HEADER_BYTES + 128 * 8193 + 4 * MCP_RESPONSE_BYTES);
  if (bytes.length < MCP_STDIO_RECIPE_HEADER_BYTES || bytes.readUInt32LE(0) !== 0x43535243 || bytes.readUInt32LE(4) !== 1 ||
      ![1, 2, 3].includes(bytes.readUInt32LE(8)) || bytes.readUInt32LE(28) || bytes.subarray(113, 116).some(Boolean) || bytes.subarray(628, 632).some(Boolean))
    throw new TypeError('invalid fixed stdio recipe binary header');
  const purpose = bytes.readUInt32LE(8) === 1 ? 'admin' : bytes.readUInt32LE(8) === 2 ? 'run' : 'recovery', count = bytes.readUInt32LE(12), strings = bytes.readUInt32LE(16);
  const phaseCount = bytes.readUInt32LE(20);
  if (count > 128 || strings > 128 * 8193 || strings > bytes.length - MCP_STDIO_RECIPE_HEADER_BYTES || phaseCount !== (purpose === 'admin' ? 3 : 4))
    throw new TypeError('invalid fixed stdio recipe binary counts');
  const maximumResponseBytes = controlWireInteger(bytes.readUInt32LE(24), 65_536, MCP_RESPONSE_BYTES);
  const maximumOutputBytes = controlWireInteger(Number(bytes.readBigUInt64LE(32)), 65_536, 67_108_864);
  const serverByteCount = controlWireInteger(Number(bytes.readBigUInt64LE(40)), 1, MCP_STDIO_EXECUTABLE_BYTES);
  const serverDigest = controlWireRef(bytes.subarray(48, 112).toString('ascii'));
  if (bytes[112] || !/^[0-9a-f]{64}$/u.test(serverDigest)) throw new TypeError('invalid fixed stdio server digest bytes');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }), argv: string[] = [];
  let at = MCP_STDIO_RECIPE_HEADER_BYTES;
  for (let index = 0; index < count; index++) {
    if (bytes.readUInt32LE(116 + index * 4) !== at - MCP_STDIO_RECIPE_HEADER_BYTES) throw new TypeError('fixed stdio argv offset differs');
    const end = bytes.indexOf(0, at);
    if (end < at || end >= MCP_STDIO_RECIPE_HEADER_BYTES + strings || end - at > 8192) throw new TypeError('fixed stdio argv terminator differs');
    argv.push(controlWireText(decoder.decode(bytes.subarray(at, end)), 8192, 0)); at = end + 1;
  }
  if (at !== MCP_STDIO_RECIPE_HEADER_BYTES + strings || bytes.subarray(116 + count * 4, 628).some(Boolean)) throw new TypeError('fixed stdio argv has unassigned bytes');
  const recipe: Array<{ phase: McpStdioPhase; bodyJson: string; bodyBytesDigest: string }> = [];
  for (let index = 0; index < phaseCount; index++) {
    const offset = 632 + index * 88, start = bytes.readBigUInt64LE(offset), size = bytes.readBigUInt64LE(offset + 8);
    const length = controlWireInteger(Number(size), 1, MCP_RESPONSE_BYTES);
    if (start !== BigInt(at) || length > bytes.length - at || bytes.subarray(offset + 80, offset + 88).some(Boolean))
      throw new TypeError('fixed stdio frame offset or padding differs');
    const body = bytes.subarray(at, at + length), bodyBytesDigest = controlWireRef(bytes.subarray(offset + 16, offset + 80).toString('ascii'));
    if (sha256Bytes(body) !== bodyBytesDigest || body.includes(10) || body.includes(13)) throw new TypeError('fixed stdio frame bytes differ');
    const value = parseJsonStrict(decoder.decode(body));
    let expected: string;
    if (index === 0) {
      const root = record(value, ['jsonrpc', 'id', 'method', 'params']), params = record(root.params, ['protocolVersion', 'capabilities', 'clientInfo']);
      const client = record(params.clientInfo, ['name', 'version']);
      expected = mcpInitializeRequestData(1, controlWireText(client.version)).json;
    } else if (index === 1) expected = mcpInitializedNotificationData().json;
    else if (index === 2) expected = mcpToolsListRequestData(2).json;
    else {
      const root = record(value, ['jsonrpc', 'id', 'method', 'params']), params = record(root.params, ['name', 'arguments']);
      expected = mcpToolsCallRequestData(3, controlWireText(params.name, 128), params.arguments).json;
    }
    if (!Buffer.from(expected).equals(body)) throw new TypeError('fixed stdio actual MCP recipe differs');
    recipe.push(Object.freeze({ phase: phases[index]!, bodyJson: body.toString('utf8'), bodyBytesDigest })); at += length;
  }
  if (at !== bytes.length || bytes.subarray(632 + phaseCount * 88, 984).some(Boolean)) throw new TypeError('fixed stdio recipe has trailing unassigned bytes');
  return Object.freeze({ version: 1 as const, purpose, argv: Object.freeze(argv), serverDigest, serverByteCount,
    maximumResponseBytes, maximumOutputBytes, byteCount: bytes.length, recipeDigest: sha256Bytes(bytes), recipe: Object.freeze(recipe) });
}
