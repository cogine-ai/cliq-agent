// Closed immutable identity data only. No signature, current process, permission
// or native execution authority is created by decoding a manifest entry.
import { types } from 'node:util';
import type { ToolContractManifestV1 } from '../kernel/continuation.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { GuestToolchainManifest } from '../kernel/execution.js';

export type ToolExecutionIdentity = ToolContractManifestV1['entries'][number]['execution'];
export const BUILTIN_SCRIPT_TOOL_NAMES = Object.freeze(['read', 'ls', 'find', 'grep', 'bash'] as const);
/** Support for the fixed native recipe, after the original manifest decoder.
 * A signed Node discovery root alone does not promise a Bash executable. */
export function assertBuiltinScriptGuest(manifest: GuestToolchainManifest, tools: readonly string[]): void {
  const admitted = manifest.admittedExecutables;
  if (admitted.length > 1 || admitted.some(entry => entry.logicalName !== 'bash' || entry.canonicalGuestPath !== '/bin/bash') ||
      tools.includes('bash') && admitted.length !== 1)
    throw new TypeError('fixed builtin tools require their exact signed Bash discovery root');
}
function invalid(): never { throw new TypeError('invalid closed tool execution identity'); }
export function decodeToolExecutionIdentity(value: unknown): ToolExecutionIdentity {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid();
  const fields = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(fields);
  if (keys.some(key => typeof key !== 'string') || Object.values(fields).some(field => !field.enumerable || !Object.hasOwn(field, 'value'))) return invalid();
  const data = Object.fromEntries(Object.entries(fields).map(([key, field]) => [key, field.value]));
  const exact = (expected: readonly string[]) => {
    if (keys.length !== expected.length || expected.some(key => !Object.hasOwn(data, key))) invalid();
  };
  const text = (key: string) => {
    const item = data[key];
    if (typeof item !== 'string' || !item || Buffer.byteLength(item) > 1024 || item.includes('\0') || item.normalize('NFC') !== item) invalid();
  };
  const refs = (...names: string[]) => { for (const name of names) assertArtifactRef(data[name] as string); };
  if (data.kind === 'builtin') {
    exact(['kind', 'adapterId', 'adapterVersion', 'adapterCodeDigest']);
    text('adapterId'); text('adapterVersion'); refs('adapterCodeDigest');
  } else if (data.kind === 'builtin_script') {
    exact(['kind', 'adapterId', 'adapterVersion', 'adapterCodeDigest', 'guestToolchainManifestRef',
      'guestToolchainManifestDigest', 'toolId', 'executionPath', 'executableDigest']);
    if (data.adapterId !== 'builtin_tools' || data.adapterVersion !== '1' || data.toolId !== 'node' || data.executionPath !== '/usr/bin/node') invalid();
    refs('adapterCodeDigest', 'guestToolchainManifestRef', 'guestToolchainManifestDigest', 'executableDigest');
  } else if (data.kind === 'supervisor_control' || data.kind === 'supervisor_operation') {
    exact(['kind', 'handlerId', 'supervisorEntryId', 'supervisorEntryVersion', 'supervisorExecutableDigest']);
    if (data.kind === 'supervisor_control' ? !['request_input', 'await_children'].includes(data.handlerId)
      : !['delegate', 'child_merge'].includes(data.handlerId)) invalid();
    text('supervisorEntryId'); text('supervisorEntryVersion'); refs('supervisorExecutableDigest');
  } else if (data.kind === 'mcp') {
    exact(['kind', 'registrationId', 'registryRevisionRef', 'registryManifestDigest', 'serverToolName', 'toolContractDigest']);
    text('registrationId'); text('serverToolName'); refs('registryRevisionRef', 'registryManifestDigest', 'toolContractDigest');
  } else return invalid();
  return immutableSnapshot(data) as ToolExecutionIdentity;
}
