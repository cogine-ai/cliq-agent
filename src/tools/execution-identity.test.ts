import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeToolExecutionIdentity, assertBuiltinScriptGuest } from './execution-identity.js';
import type { GuestToolchainManifest } from '../kernel/execution.js';

const control = { kind: 'supervisor_control', handlerId: 'request_input', supervisorEntryId: 'signed-supervisor',
  supervisorEntryVersion: 'release-27', supervisorExecutableDigest: canonicalSha256('inert image') };
const script = { kind: 'builtin_script', adapterId: 'builtin_tools', adapterVersion: '1', adapterCodeDigest: canonicalSha256('inert script'),
  guestToolchainManifestRef: canonicalSha256('inert manifest bytes'), guestToolchainManifestDigest: canonicalSha256('inert manifest semantics'),
  toolId: 'node', executionPath: '/usr/bin/node', executableDigest: canonicalSha256('inert guest Node') };
test('closed script and Supervisor identities retain distinct complete digest domains and immutable copies', () => {
  for (const input of [control, script]) {
    const output = decodeToolExecutionIdentity(input);
    assert.deepEqual(output, input); assert.notEqual(output, input); assert(Object.isFrozen(output));
  }
  assert.notEqual(script.adapterCodeDigest, script.executableDigest);
  for (const value of [null, [], { kind: 'native' }, { ...control, handlerVersion: '1' }, { ...control, adapterId: 'request_input' },
    { ...script, executable: true }, { ...script, executionPath: '/bin/node' }, { ...script, toolId: 'bash' },
    { ...script, guestToolchainManifestRef: '' }, { ...control, supervisorExecutableDigest: 'not-a-digest' },
    { ...control, supervisorEntryVersion: '' }]) assert.throws(() => decodeToolExecutionIdentity(value));
});
test('identity data cannot execute getters or proxy traps while being rejected', () => {
  let traps = 0;
  const accessor = { ...control };
  Object.defineProperty(accessor, 'supervisorEntryId', { enumerable: true, get() { traps++; return 'wrong'; } });
  const proxy = new Proxy(control, { ownKeys() { traps++; throw Error('trap'); }, getPrototypeOf() { traps++; throw Error('trap'); },
    get() { traps++; throw Error('trap'); }, getOwnPropertyDescriptor() { traps++; throw Error('trap'); } });
  for (const value of [accessor, proxy, Object.assign({ ...script }, { [Symbol('hidden')]: 'bad' })])
    assert.throws(() => decodeToolExecutionIdentity(value), /closed tool execution identity/);
  assert.equal(traps, 0);
});
test('fixed Bash discovery cannot be inferred from a signed Node-only root or a foreign admitted executable', () => {
  const root = (admittedExecutables: GuestToolchainManifest['admittedExecutables']) => ({ admittedExecutables }) as GuestToolchainManifest;
  const bash = { logicalName: 'bash', canonicalGuestPath: '/bin/bash', digest: canonicalSha256('inert Bash image'), version: 'measured-test-version' };
  assert.doesNotThrow(() => assertBuiltinScriptGuest(root([]), ['read', 'find']));
  assert.throws(() => assertBuiltinScriptGuest(root([]), ['bash']));
  assert.doesNotThrow(() => assertBuiltinScriptGuest(root([bash]), ['read', 'bash']));
  for (const entries of [[{ ...bash, canonicalGuestPath: '/usr/bin/bash' }], [{ ...bash, logicalName: 'sh' }],
    [bash, { ...bash, logicalName: 'python', canonicalGuestPath: '/usr/bin/python' }]])
    assert.throws(() => assertBuiltinScriptGuest(root(entries), ['bash']));
});
