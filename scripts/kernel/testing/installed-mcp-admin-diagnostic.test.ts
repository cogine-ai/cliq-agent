import assert from 'node:assert/strict';
import test from 'node:test';
import { KernelStorageError, ResourceRetirementError } from '../../../src/state/errors.js';
import { decodeMcpAdminLifecycleObservation, noteMcpAdminLifecycle, observeMcpAdminLifecycle, observeMcpAdminWork } from '../../../src/state/mcp-admin-diagnostics.js';
import { createMcpAdminLifecycleSink, MCP_ADMIN_LIFECYCLE_PREFIX } from './installed-mcp-admin-sink.js';
import { readInstalledMcpAdminJournal } from './installed-mcp-admin-journal.js';

test('unobserved MCP work preserves the exact original Promise and synchronous failure', async () => {
  const original = Promise.resolve(7); assert.equal(observeMcpAdminWork('http', 'scope_ready', () => original), original);
  const failure = new Error('inert-private-message');
  assert.throws(() => observeMcpAdminWork('http', 'scope_ready', () => { throw failure; }), error => error === failure);
  assert.equal(await original, 7);
});

test('MCP stage observation preserves real failure identity and contains a broken sink', async () => {
  const rows: unknown[] = [], stopBroken = observeMcpAdminLifecycle(() => { throw new Error('sink private payload'); });
  const stop = observeMcpAdminLifecycle(row => rows.push(row)), failure = new ResourceRetirementError('private retirement message', undefined);
  try {
    await assert.rejects(observeMcpAdminWork('http', 'native_close', () => Promise.reject(failure)), error => error === failure);
    assert.deepEqual(rows, [
      { transport: 'http', phase: 'native_close', event: 'entered', errorClass: null, code: null },
      { transport: 'http', phase: 'native_close', event: 'failed', errorClass: 'resource_retirement', code: null }
    ]);
    assert.doesNotMatch(JSON.stringify(rows), /private|payload|message/u);
  } finally { stop(); stopBroken(); }
});

test('closed MCP diagnostic grammar rejects proxies and accessors before invoking them', () => {
  let traps = 0, getters = 0;
  const proxy = new Proxy({}, { ownKeys() { traps++; throw new Error('private'); }, getPrototypeOf() { traps++; throw new Error('private'); } });
  assert.throws(() => decodeMcpAdminLifecycleObservation(proxy), TypeError); assert.equal(traps, 0);
  assert.throws(() => decodeMcpAdminLifecycleObservation({ get transport() { getters++; return 'http'; }, phase: 'scope_ready',
    event: 'entered', errorClass: null, code: null }), TypeError); assert.equal(getters, 0);
  assert.throws(() => decodeMcpAdminLifecycleObservation({ transport: 'http', phase: 'scope_ready', event: 'settled', errorClass: 'error', code: null }), TypeError);
  assert.throws(() => decodeMcpAdminLifecycleObservation({ transport: 'stdio', phase: 'caller-chosen', event: 'failed', errorClass: 'error', code: null }), TypeError);
});

test('fixed MCP sink is bounded, labels truncation and never retries a partial write', () => {
  const lines: string[] = [], sink = createMcpAdminLifecycleSink(line => { lines.push(line); return Buffer.byteLength(line); });
  const row = decodeMcpAdminLifecycleObservation({ transport: 'stdio', phase: 'scope_close', event: 'entered', errorClass: null, code: null });
  for (let index = 0; index < 200; index++) sink(row);
  assert.equal(lines.length, 129); assert.equal(lines.at(-1), MCP_ADMIN_LIFECYCLE_PREFIX + 'truncated\n');
  let writes = 0; const partial = createMcpAdminLifecycleSink(() => { writes++; return 0; });
  partial(row); partial(row); assert.equal(writes, 1);
  const broken = createMcpAdminLifecycleSink(() => { throw new Error('inert private sink failure'); }); assert.doesNotThrow(() => broken(row));
});

test('MCP errors expose only the original fixed kind/code and no error getters', async () => {
  let getters = 0; const rows: unknown[] = [], stop = observeMcpAdminLifecycle(row => rows.push(row));
  const error = new Error('inert-private-message');
  Object.defineProperty(error, 'code', { get() { getters++; return 'RECOVERY_REQUIRED'; } });
  Object.defineProperty(error, 'cause', { get() { getters++; throw new Error('private cause'); } });
  try {
    await assert.rejects(observeMcpAdminWork('http', 'scope_ready', () => Promise.reject(error)), failure => failure === error);
    noteMcpAdminLifecycle('stdio', 'protocol', 'failed', new KernelStorageError('RECOVERY_REQUIRED', 'inert private'));
    assert.equal(getters, 0); assert.equal(rows.length, 3);
    assert.deepEqual(rows.at(-1), { transport: 'stdio', phase: 'protocol', event: 'failed', errorClass: 'kernel_storage', code: 'RECOVERY_REQUIRED' });
    assert.doesNotMatch(JSON.stringify(rows), /inert|private|cause/u);
  } finally { stop(); }
});

test('MCP journal markers bind the original uid, pid and invocation without implying a join', () => {
  const binding = { uid: 1000, pid: 1234, invocationId: 'a'.repeat(32) };
  const marker = (message: string, fields = {}) => JSON.stringify({ _UID: '1000', _PID: '1234',
    _SYSTEMD_INVOCATION_ID: binding.invocationId, _TRANSPORT: 'stdout', MESSAGE: message, ...fields }) + '\n';
  const row = MCP_ADMIN_LIFECYCLE_PREFIX + 'http:native_close:entered:-:-';
  assert.deepEqual(readInstalledMcpAdminJournal(marker(row), binding), { records: [
    { transport: 'http', phase: 'native_close', event: 'entered', errorClass: null, code: null } ], truncated: false });
  assert.throws(() => readInstalledMcpAdminJournal(marker(row, { _PID: '9999' }), binding), TypeError);
  assert.throws(() => readInstalledMcpAdminJournal(marker(row + ':private'), binding), TypeError);
  assert.equal(readInstalledMcpAdminJournal(marker('unrelated fixed observation'), binding), undefined);
  assert.deepEqual(readInstalledMcpAdminJournal(marker(MCP_ADMIN_LIFECYCLE_PREFIX + 'truncated'), binding), { records: [], truncated: true });
  assert.throws(() => readInstalledMcpAdminJournal(marker(MCP_ADMIN_LIFECYCLE_PREFIX + 'truncated') + marker(row), binding), TypeError);
});
