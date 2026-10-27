// Compiled contract data only; no signature, image, Run or execution proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { GuestToolchainManifest } from '../kernel/execution.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { buildInstalledToolContracts } from './installed-contracts.js';
import { loadToolContracts } from './input-contract.js';

const entry = { entryId: 'edit', role: 'tool_adapter', version: '1', executable: true, digest: canonicalSha256('inert edit'),
  relativePath: 'edit', byteCount: 100 };
const script = { ...entry, entryId: 'builtin_tools', executable: false, relativePath: 'adapters/builtin-tools.mjs', digest: canonicalSha256('inert script') };
const supervisor = { ...entry, entryId: 'supervisor', role: 'supervisor', version: 'release-9', digest: canonicalSha256('inert Supervisor') };
const image = (logicalName: string, canonicalGuestPath: string) => ({ logicalName, canonicalGuestPath, version: 'measured-test', digest: canonicalSha256(logicalName) });
const guest: { manifestRef: string; manifest: GuestToolchainManifest } = { manifestRef: canonicalSha256('inert guest bytes'), manifest: {
  schemaVersion: 1, format: 'cliq-guest-toolchain-v1', manifestDigest: canonicalSha256('inert guest semantics'),
  guestImageRef: canonicalSha256('inert image'), guestImageDigest: canonicalSha256('inert image'), guestImageByteCount: 11,
  guestImageFormat: 'raw-ext4-v1', architecture: 'x86_64', kernelAbi: 'offline-kernel', userspaceAbi: 'offline-userspace',
  publisherKeyId: 'offline-test', signatureRef: canonicalSha256('inert signature'), worker: image('worker', '/opt/cliq/worker'),
  shell: image('sh', '/bin/sh'), node: image('node', '/usr/bin/node'), git: image('git', '/usr/bin/git'),
  searchTools: [], verifiers: [], admittedExecutables: [image('bash', '/bin/bash')] } };

test('installed contracts retain old edit bytes and expose the complete distinct script/control identities', () => {
  const old = buildInstalledToolContracts({ edit: entry }), all = buildInstalledToolContracts({ edit: entry, scripts: { entry: script, supervisor, guest } });
  assert.deepEqual(old.manifest.entries.map(item => item.name), ['edit']);
  assert.deepEqual(all.manifest.entries.map(item => item.name), ['await_children', 'bash', 'delegate', 'edit', 'find', 'grep', 'ls', 'read', 'request_input', 'skill_resource']);
  assert.deepEqual(all.manifest.entries.find(item => item.name === 'edit'), old.manifest.entries[0]);
  const control = all.manifest.entries.find(item => item.name === 'request_input')!;
  assert.equal(control.execution.kind, 'supervisor_control');
  if (control.execution.kind !== 'supervisor_control') throw new Error('wrong inert identity');
  assert.equal(control.execution.supervisorEntryVersion, 'release-9'); assert.equal(control.access, 'control');
  const operation = all.manifest.entries.find(item => item.name === 'delegate')!, waiting = all.manifest.entries.find(item => item.name === 'await_children')!;
  assert.equal(operation.execution.kind, 'supervisor_operation'); assert.equal(operation.access, 'exec'); assert.equal(operation.replayClass, 'retry');
  assert.equal(waiting.execution.kind, 'supervisor_control'); assert.equal(waiting.access, 'control'); assert.equal(waiting.replayClass, 'manual');
  const resource = all.manifest.entries.find(item => item.name === 'skill_resource')!;
  assert.equal(resource.execution.kind, 'supervisor_operation'); assert.equal(resource.access, 'read'); assert.equal(resource.replayClass, 'retry');
  for (const value of [operation, waiting, resource]) {
    if (value.execution.kind !== 'supervisor_operation' && value.execution.kind !== 'supervisor_control') throw new Error('wrong closed Supervisor identity');
    assert.equal(value.execution.handlerId, value.name); assert.equal(value.execution.supervisorEntryVersion, supervisor.version);
    assert.equal(value.execution.supervisorExecutableDigest, supervisor.digest);
    assert.equal(Object.hasOwn(value.execution, 'adapterCodeDigest'), false);
  }
  const bash = all.manifest.entries.find(item => item.name === 'bash')!; assert.equal(bash.execution.kind, 'builtin_script');
  assert(bash.description.includes('/usr/bin/node')); assert(bash.description.includes('/usr/bin/git')); assert(bash.description.includes('/bin/bash'));
  assert(bash.description.includes('Other external commands are not provided')); assert(bash.description.includes('Network is disabled'));
  const resolver = loadToolContracts(all.manifest.entries.map(item => ({ ...item, inputSchema: all.schemas.find(schema => schema.name === item.name)!.schema })));
  assert.equal(resolver.projectInvocation({ callId: 'read', index: 0, toolName: 'read', input: { path: 'a' } }).kind, 'tool');
  assert.equal(resolver.projectInvocation({ callId: 'input', index: 1, toolName: 'request_input',
    input: { prompt: 'Question?', responseKind: 'text', maximumResponseBytes: 64 } }).kind, 'input');
  const awaitInvocation = resolver.projectInvocation({ callId: 'await', index: 2, toolName: 'await_children', input: { childRunIds: ['owned-child'] } });
  assert.equal(awaitInvocation.kind, 'input');
  assert.equal(awaitInvocation.execution.kind === 'supervisor_control' && awaitInvocation.execution.handlerId, 'await_children');
  const localRead = resolver.projectInvocation({ callId: 'resource', index: 3, toolName: 'skill_resource',
    input: { skillId: 'selected', canonicalRelativePath: 'scripts/data.py', offset: 0, length: 65536 } });
  assert.equal(localRead.kind, 'tool'); assert.equal(localRead.execution.kind, 'supervisor_operation');
});

test('a Node-only discovery root and executable script disguise cannot advertise the fixed complete toolset', () => {
  assert.throws(() => buildInstalledToolContracts({ edit: entry, scripts: { entry: { ...script, executable: true }, supervisor, guest } }));
  assert.throws(() => buildInstalledToolContracts({ edit: entry, scripts: { entry: script, supervisor: { ...supervisor, executable: false }, guest } }));
  assert.throws(() => buildInstalledToolContracts({ edit: entry, scripts: { entry: script, supervisor,
    guest: { ...guest, manifest: { ...guest.manifest, admittedExecutables: [] } } } }));
});
