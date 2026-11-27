// Pure data for the one signed builtin program. These bytes are not an
// OperationGrant, a native receiver, a permission decision or execution proof.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { immutableSnapshot } from '../model/immutable.js';
import { builtinInputContracts } from '../tools/builtin-inputs.js';

export const BUILTIN_SCRIPT_RECIPE = Object.freeze({ entryId: 'builtin_tools', version: '1',
  invocation: 'cliq-builtin-tools-v1', relativePath: 'adapters/builtin-tools.mjs', scriptBytes: 1_048_576,
  scriptPath: '/runtime/cliq-builtin-tools.mjs', nodePath: '/usr/bin/node', bashPath: '/bin/bash',
  privateGitProtection: 'existing_read_only', inputBytes: 16_777_216, maximumFileBytes: 268_435_456, maximumOutputBytes: 67_108_864,
  modelOutputBytes: 1_048_576, timeoutMs: 60_000 } as const);
export type BuiltinScriptTool = 'read' | 'ls' | 'find' | 'grep' | 'bash';
const environment = (controlledPath: readonly string[], bash = false) => {
  const value = { schemaVersion: 1 as const, format: 'cliq-sanitized-sandbox-environment-v1' as const,
    home: '/home/cliq', tmpdir: '/tmp', controlledPath: [...controlledPath], locale: { lang: 'C', lcAll: 'C' },
    variables: bash ? [{ name: 'GIT_OPTIONAL_LOCKS', value: { kind: 'non_secret_literal' as const, value: '0' } }] : [], networkMode: 'none' as const, inheritedHostEnvironment: false as const,
    secretMaterial: 'none' as const, brokerAccessAtSpawn: 'none' as const };
  return immutableSnapshot({ ...value, environmentDigest: canonicalSha256(value) });
};
export const BUILTIN_SCRIPT_ENVIRONMENTS = Object.freeze({ read: environment(['/usr/bin']), bash: environment(['/usr/bin', '/bin'], true) });
export const BUILTIN_SCRIPT_PRIVATE_MOUNTS = immutableSnapshot([
  { kind: 'private_ephemeral', access: 'read_write', targetPath: '/home/cliq', purpose: 'home' },
  { kind: 'private_ephemeral', access: 'read_write', targetPath: '/tmp', purpose: 'tmp' }
] as const);

export type BuiltinReadTool = Exclude<BuiltinScriptTool, 'bash'>;
export type BuiltinToolInput = Readonly<{ schemaVersion: 1; tool: BuiltinScriptTool; input: Readonly<Record<string, unknown>>;
  limits: Readonly<{ maxSingleFileBytes: number; maxInvocationOutputBytes: number }> }>;
export type BuiltinReadReason = 'entry_limit' | 'match_limit' | 'depth_limit' | 'file_limit' | 'output_limit' |
  'unreadable' | 'symlink' | 'hardlink' | 'special_file' | 'invalid_utf8';
export type BuiltinReadOutput = Readonly<{ schemaVersion: 1; tool: BuiltinReadTool;
  scope: 'private_generation_non_git'; path: string; complete: boolean; reasons: readonly BuiltinReadReason[];
  scannedEntries: number; content: unknown }>;
export class BuiltinToolInputError extends TypeError {
  constructor() { super('invalid fixed builtin input'); this.name = 'BuiltinToolInputError'; }
}
function invalid(): never { throw new BuiltinToolInputError(); }
function closed(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const data = Object.getOwnPropertyDescriptors(value);
  return Reflect.ownKeys(data).length === keys.length && keys.every(key => Object.hasOwn(data, key) &&
    Object.hasOwn(data[key]!, 'value') && data[key]!.enumerable);
}
export function isBuiltinScriptTool(value: unknown): value is BuiltinScriptTool {
  return value === 'read' || value === 'ls' || value === 'find' || value === 'grep' || value === 'bash';
}
function inputData(value: unknown): BuiltinToolInput {
  if (!closed(value, ['schemaVersion', 'tool', 'input', 'limits']) || value.schemaVersion !== 1 || !isBuiltinScriptTool(value.tool) ||
      !closed(value.limits, ['maxSingleFileBytes', 'maxInvocationOutputBytes'])) invalid();
  const limits = value.limits;
  if (!Number.isSafeInteger(limits.maxSingleFileBytes) || (limits.maxSingleFileBytes as number) < 1 ||
      (limits.maxSingleFileBytes as number) > BUILTIN_SCRIPT_RECIPE.maximumFileBytes ||
      !Number.isSafeInteger(limits.maxInvocationOutputBytes) || (limits.maxInvocationOutputBytes as number) < 65_536 ||
      (limits.maxInvocationOutputBytes as number) > BUILTIN_SCRIPT_RECIPE.maximumOutputBytes) invalid();
  const normalized = builtinInputContracts[value.tool].parseInput(value.input);
  if (!normalized || !canonicalJsonBytes(normalized.input).equals(canonicalJsonBytes(value.input))) invalid();
  return immutableSnapshot(value) as BuiltinToolInput;
}
/** Shared pre-claim size validation and actual sealed input construction. */
export function builtinToolInputBytes(tool: BuiltinScriptTool, input: Readonly<Record<string, unknown>>,
  resources: Pick<SandboxResourceSpec, 'maxSingleFileBytes' | 'maxInvocationOutputBytes'>): Buffer {
  const held = immutableSnapshot(resources);
  const capsule = inputData(immutableSnapshot({ schemaVersion: 1, tool, input,
    limits: { maxSingleFileBytes: held.maxSingleFileBytes, maxInvocationOutputBytes: held.maxInvocationOutputBytes } }));
  const bytes = canonicalJsonBytes(capsule);
  if (bytes.length > BUILTIN_SCRIPT_RECIPE.inputBytes) invalid();
  return bytes;
}
export function decodeBuiltinToolInput(bytes: Uint8Array): BuiltinToolInput {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > BUILTIN_SCRIPT_RECIPE.inputBytes) invalid();
  let value: unknown;
  try { value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { return invalid(); }
  if (!canonicalJsonBytes(value).equals(bytes)) invalid();
  return inputData(value);
}
/** UTF-8 byte clipping never introduces a replacement character or splits a
 * surrogate pair. The returned flag is data, never a completeness inference. */
export function clipBuiltinText(text: string, maximum: number): { text: string; truncated: boolean } {
  if (!Number.isSafeInteger(maximum) || maximum < 0) invalid();
  const bytes = Buffer.from(text);
  if (bytes.length <= maximum) return { text, truncated: false };
  let end = maximum;
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return { text: bytes.subarray(0, end).toString('utf8'), truncated: true };
}
/** Keep the actual structured frame valid when a directory/match prefix is
 * larger than its output budget. It never silently upgrades partial results. */
export function builtinReadOutputBytes(value: BuiltinReadOutput, outputLimit: number): Buffer {
  if (!Number.isSafeInteger(outputLimit) || outputLimit < 65_536 || outputLimit > BUILTIN_SCRIPT_RECIPE.maximumOutputBytes) invalid();
  const limit = Math.min(outputLimit, BUILTIN_SCRIPT_RECIPE.modelOutputBytes), full = canonicalJsonBytes(value);
  if (full.length <= limit) return full;
  if (!Array.isArray(value.content)) throw new TypeError('fixed non-list builtin output exceeded its bounded text contract');
  const reasons = [...new Set([...value.reasons, 'output_limit'])];
  let lower = 0, upper = value.content.length;
  while (lower < upper) {
    const count = Math.ceil((lower + upper) / 2);
    const bytes = canonicalJsonBytes({ ...value, complete: false, reasons, content: value.content.slice(0, count) });
    if (bytes.length <= limit) lower = count; else upper = count - 1;
  }
  const bytes = canonicalJsonBytes({ ...value, complete: false, reasons, content: value.content.slice(0, lower) });
  if (bytes.length > limit) throw new TypeError('fixed builtin output metadata exceeds its real output bound');
  return bytes;
}

/** Strict data decoding only. Never mints the genuine native result or a
 * permission/retirement observation. Validate against the original input. */
export function decodeBuiltinReadOutput(bytes: Buffer, capsule: BuiltinToolInput): BuiltinReadOutput {
  capsule = inputData(immutableSnapshot(capsule));
  if (capsule.tool === 'bash' || !Buffer.isBuffer(bytes) || bytes.length < 1 ||
      bytes.length > Math.min(capsule.limits.maxInvocationOutputBytes, BUILTIN_SCRIPT_RECIPE.modelOutputBytes)) invalid();
  let value: unknown;
  try { value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return invalid(); }
  if (!canonicalJsonBytes(value).equals(bytes) || !closed(value,
    ['schemaVersion', 'tool', 'scope', 'path', 'complete', 'reasons', 'scannedEntries', 'content'])) invalid();
  const paths = (path: unknown, leaf = false): path is string => {
    if (typeof path !== 'string' || !path || path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.normalize('NFC') !== path) return false;
    const pieces = path.split('/');
    return pieces.every(part => part && part !== '.' && part !== '..' && part.toLowerCase() !== '.git' && Buffer.byteLength(part) <= 255) && (!leaf || pieces.length === 1);
  };
  const integer = (value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
  const reasons = new Set(['entry_limit', 'match_limit', 'depth_limit', 'file_limit', 'output_limit',
    'unreadable', 'symlink', 'hardlink', 'special_file', 'invalid_utf8']);
  if (value.schemaVersion !== 1 || value.tool !== capsule.tool || value.scope !== 'private_generation_non_git' || value.path !== capsule.input.path ||
      typeof value.complete !== 'boolean' || !Array.isArray(value.reasons) || value.reasons.length > reasons.size ||
      value.reasons.some(reason => !reasons.has(reason)) || new Set(value.reasons).size !== value.reasons.length ||
      value.complete !== (value.reasons.length === 0) || !integer(value.scannedEntries, 0, 100_001)) invalid();
  const scope = (path: unknown): path is string => paths(path) &&
    (capsule.input.path === '.' || path === capsule.input.path || path.startsWith(`${capsule.input.path}/`));
  if (capsule.tool === 'read') {
    const data = value.content;
    if (!closed(data, ['startLine', 'endLine', 'fileByteCount', 'bytesRead', 'text', 'truncated', 'reachedEof']) ||
        !integer(data.startLine) || !integer(data.endLine) || !integer(data.fileByteCount, 0, capsule.limits.maxSingleFileBytes) ||
        !integer(data.bytesRead, 0, data.fileByteCount) || typeof data.text !== 'string' || Buffer.byteLength(data.text) > 8000 ||
        typeof data.truncated !== 'boolean' || typeof data.reachedEof !== 'boolean' || data.startLine > data.endLine ||
        (data.startLine === 0 ? data.endLine !== 0 || data.text !== '' : data.startLine !== (capsule.input.start_line ?? 1)) ||
        data.endLine > (capsule.input.end_line as number | undefined ?? Math.min(Number.MAX_SAFE_INTEGER, (capsule.input.start_line as number | undefined ?? 1) + 199)) ||
        data.truncated && (!value.reasons.includes('output_limit') || value.complete)) invalid();
  } else {
    if (!Array.isArray(value.content) || value.content.length > 200) invalid();
    const seen = new Set<string>();
    for (const item of value.content) {
      if (capsule.tool === 'ls') {
        if (!closed(item, ['name', 'kind']) || !paths(item.name, true) || !['file', 'directory', 'symlink', 'other'].includes(item.kind as string) || seen.has(item.name)) invalid();
        seen.add(item.name);
      } else if (capsule.tool === 'find') {
        if (!scope(item) || !item.split('/').at(-1)!.includes(capsule.input.name as string) || seen.has(item)) invalid(); seen.add(item);
      } else {
        if (!closed(item, ['path', 'line', 'text']) || !scope(item.path) || !integer(item.line, 1, 64_001) ||
            typeof item.text !== 'string' || item.text.includes('\n') || Buffer.byteLength(item.text) > 64_000 ||
            !item.text.includes(capsule.input.pattern as string)) invalid();
        const key = `${item.path}\0${item.line}`; if (seen.has(key)) invalid(); seen.add(key);
      }
    }
  }
  return immutableSnapshot(value) as BuiltinReadOutput;
}
