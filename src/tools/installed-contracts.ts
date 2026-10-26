// Deterministic compiled contract data. Signing and original byte verification
// remain the installed composition's responsibility.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ToolContractManifestV1 } from '../kernel/types.js';
import type { GuestToolchainManifest } from '../kernel/execution.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { builtinInputContracts } from './builtin-inputs.js';
import { immutableSnapshot } from '../model/immutable.js';
import { assertBuiltinScriptGuest } from './execution-identity.js';

type Entry = RuntimeBundleManifest['entries'][number];
export const INSTALLED_TOOL_NAMES = Object.freeze(['await_children', 'bash', 'delegate', 'edit', 'find', 'grep', 'ls', 'read', 'request_input'] as const);
const descriptions = {
  await_children: 'Register one wait for the supplied owned child Run handles. Return ordered actual child results and serialized patch merge outcomes. Each explicit registration costs one tool call; internal wake and settlement do not add another charge.',
  bash: 'Execute an authorized Bash command in the private Run workspace.',
  delegate: 'Admit one ordinary child Run under an explicit unchanged budget ceiling and an intersection of the parent capabilities. The parent retains a bounded continuation budget floor; insufficient room returns not_admitted. Read-only children cannot publish patches. Mutating child patches require separate parent fs-write permission and are merged serially after settlement. Children are scheduled within the existing single-worker installation slot.',
  edit: 'Edit an authorized file in the private Run workspace.',
  find: 'Find private workspace entries whose names contain a literal substring.',
  grep: 'Search private workspace file contents for a literal substring.',
  ls: 'List a directory in the private Run workspace.',
  read: 'Read a file in the private Run workspace.',
  request_input: 'Ask the user for a bounded text or schema-bound JSON answer.'
};
export function buildInstalledToolContracts(input: { edit: Entry;
  scripts?: { entry: Entry; supervisor: Entry; guest: { manifestRef: string; manifest: GuestToolchainManifest } } }) {
  const { edit, scripts } = input;
  if (edit.entryId !== 'edit' || edit.role !== 'tool_adapter' || !edit.executable || edit.version !== '1')
    throw new TypeError('installed edit requires its original fixed executable entry');
  if (scripts && (scripts.entry.entryId !== 'builtin_tools' || scripts.entry.role !== 'tool_adapter' || scripts.entry.executable ||
      scripts.entry.version !== '1' || scripts.supervisor.role !== 'supervisor' || !scripts.supervisor.executable ||
      scripts.guest.manifest.node.logicalName !== 'node' || scripts.guest.manifest.node.canonicalGuestPath !== '/usr/bin/node'))
    throw new TypeError('installed tools require their signed script, Supervisor and guest Node identities');
  const names = scripts ? INSTALLED_TOOL_NAMES : ['edit'] as const;
  if (scripts) assertBuiltinScriptGuest(scripts.guest.manifest, names);
  const schemas = names.map(name => ({ name, schema: builtinInputContracts[name].inputSchema }));
  const entries: ToolContractManifestV1['entries'] = names.map(name => {
    const builtin = builtinInputContracts[name], schemaRef = canonicalSha256(builtin.inputSchema);
    const description = name === 'bash' ? `${descriptions.bash} Bash builtins and the signed executables ${scripts!.guest.manifest.node.canonicalGuestPath}, ` +
      `${scripts!.guest.manifest.git.canonicalGuestPath} and /bin/bash are available. Other external commands are not provided. ` +
      'Network is disabled; workspace and temporary files are not directly executable. Existing workspace .git is read-only; ' +
      'creating or replacing workspace Git metadata is unsupported.' : descriptions[name];
    const common = { name, version: builtin.version, description, access: builtin.access,
      replayClass: builtin.replayClass, inputSchemaRef: schemaRef, inputSchemaDigest: schemaRef };
    if (name === 'edit') return { ...common, access: 'write', replayClass: 'manual',
      execution: { kind: 'builtin', adapterId: edit.entryId, adapterVersion: edit.version, adapterCodeDigest: edit.digest } };
    if (name === 'request_input' || name === 'await_children') return { ...common, access: 'control', replayClass: 'manual', execution: {
      kind: 'supervisor_control', handlerId: name, supervisorEntryId: scripts!.supervisor.entryId,
      supervisorEntryVersion: scripts!.supervisor.version, supervisorExecutableDigest: scripts!.supervisor.digest } };
    if (name === 'delegate') return { ...common, access: 'exec', replayClass: 'retry', execution: {
      kind: 'supervisor_operation', handlerId: 'delegate', supervisorEntryId: scripts!.supervisor.entryId,
      supervisorEntryVersion: scripts!.supervisor.version, supervisorExecutableDigest: scripts!.supervisor.digest } };
    return { ...common, access: name === 'bash' ? 'exec' : 'read', replayClass: name === 'bash' ? 'manual' : 'retry', execution: {
      kind: 'builtin_script', adapterId: 'builtin_tools', adapterVersion: '1', adapterCodeDigest: scripts!.entry.digest,
      guestToolchainManifestRef: scripts!.guest.manifestRef, guestToolchainManifestDigest: scripts!.guest.manifest.manifestDigest,
      toolId: 'node', executionPath: '/usr/bin/node', executableDigest: scripts!.guest.manifest.node.digest } };
  });
  const core = { schemaVersion: 1 as const, format: 'cliq-tool-contracts-v1' as const, entries };
  const manifest: ToolContractManifestV1 = { ...core, manifestDigest: canonicalSha256(core) };
  return immutableSnapshot({ manifest, schemas });
}
