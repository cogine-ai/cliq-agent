import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ObservedToolCallInputV1 } from '../protocol/agent-ir.js';
import { loadToolContracts, type ToolInputAuthority } from './input-contract.js';
import { builtinInputContracts } from './builtin-inputs.js';
import { createPolicyEngine } from '../policy/engine.js';
import { composePermissionTable } from '../policy/decision-table.js';

function tool<T>(inputSchema: T) {
  const ref = canonicalSha256(inputSchema);
  return { name: 'read', version: 'mcp-tool-contract-v1', access: 'exec' as const, description: 'Read a file', inputSchema,
    inputSchemaRef: ref, inputSchemaDigest: ref, replayClass: 'retry' as const, execution: {
      kind: 'mcp' as const, registrationId: 'registered-server', registryRevisionRef: canonicalSha256('registry'),
      registryManifestDigest: canonicalSha256('manifest'), serverToolName: 'remote-read', toolContractDigest: canonicalSha256('contract')
    } };
}
const resolver = (contracts: ToolInputAuthority[]) => loadToolContracts(contracts).resolveToolInput;
function observed(value: unknown): ObservedToolCallInputV1 {
  return { schemaVersion: 1, format: 'cliq-observed-tool-call-input-v1', encoding: 'jcs_json', value,
    byteCount: 0, observedInputDigest: '' }; // The compiler owns observation identity, not the schema validator.
}
const schema = { type: 'object', required: ['path'], additionalProperties: false,
  properties: { path: { type: 'string' }, start: { type: 'integer', minimum: 1 } } };
const call = { callId: 'c', index: 0, toolName: 'read' };

function builtin(name: keyof typeof builtinInputContracts): ToolInputAuthority {
  const contract = builtinInputContracts[name];
  const ref = canonicalSha256(contract.inputSchema);
  return { name, version: contract.version, description: name, access: contract.access, replayClass: contract.replayClass,
    inputSchema: contract.inputSchema, inputSchemaRef: ref, inputSchemaDigest: ref,
    execution: { kind: 'builtin', adapterId: name, adapterVersion: contract.version, adapterCodeDigest: canonicalSha256(['test-adapter', name]) } };
}

test('frozen tool schemas validate typed values directly and retain an immutable normalized input', () => {
  const contract = tool(structuredClone(schema));
  const resolve = resolver([contract]);
  contract.inputSchema.properties.path.type = 'number';
  const input = { path: 'a.ts', start: 2 };
  const resolved = resolve({ ...call, observedInput: observed(input) });
  assert.equal(resolved.kind, 'resolved');
  if (resolved.kind !== 'resolved') return;
  input.path = 'changed';
  assert.deepEqual(resolved.value, { path: 'a.ts', start: 2 });
  assert.equal(Object.isFrozen(resolved.value), true);
  for (const value of [{ path: 3 }, { path: 'a', start: '2' }, { path: 'a', start: 0 }, { path: 'a', extra: true }, {}, []]) {
    assert.equal(resolve({ ...call, observedInput: observed(value) }).kind, 'invalid_input');
  }
});

test('unknown tools and malformed arguments produce bounded deterministic diagnostics without copying arguments', () => {
  const resolve = resolver([tool(schema)]);
  const malformed: ObservedToolCallInputV1 = { schemaVersion: 1, format: 'cliq-observed-tool-call-input-v1',
    encoding: 'utf8_json_fragment', utf8: '{secret', byteCount: 7, observedInputDigest: '' };
  const invalid = resolve({ ...call, observedInput: malformed });
  assert.equal(invalid.kind, 'invalid_input');
  if (invalid.kind !== 'invalid_input') return;
  assert.doesNotMatch(Buffer.from(invalid.diagnostic.bytes).toString(), /secret/);
  assert.deepEqual(resolve({ ...call, observedInput: malformed }), invalid);
  assert.equal(resolve({ ...call, toolName: 'bash', observedInput: observed({}) }).kind, 'unknown_tool');
  assert.throws(() => resolve({ ...call, observedInput: observed({ path: Infinity }) }), /non-finite/);
});

test('schema loading fails closed on changed identities, unresolved references, unknown keywords and async contracts', () => {
  assert.throws(() => resolver([{ ...tool(schema), inputSchema: {} }]), /frozen reference/);
  assert.throws(() => resolver([tool(schema), tool(schema)]), /unique/);
  for (const value of [{ $ref: 'https://example.invalid/schema' }, { type: 'object', unknownKeyword: true },
    { $async: true, type: 'object' }]) assert.throws(() => resolver([tool(value)]));
  const resolve = resolver([tool({ type: 'object', properties: { path: { type: 'string', default: 'unsafe' } } })]);
  const input = {};
  assert.equal(resolve({ ...call, observedInput: observed(input) }).kind, 'resolved');
  assert.deepEqual(input, {});
});

test('each builtin validates its direct input, including semantic constraints, without an action envelope', () => {
  const examples: Array<[keyof typeof builtinInputContracts, Record<string, unknown>, unknown[]]> = [
    ['read', { path: 'src/a.ts', start_line: 2, end_line: 3 }, [{ path: 'a', start_line: 3, end_line: 2 }, { path: 'a', start_line: '2' }]],
    ['edit', { path: 'a', old_text: '', new_text: 'new' }, [{ path: 'a', new_text: 'new' }]],
    ['bash', { command: 'npm test' }, [{ command: '  ' }, { command: 'echo\0bad' }]],
    ['ls', {}, [{ path: 1 }]],
    ['find', { name: '*.ts' }, [{ name: '' }]],
    ['grep', { pattern: 'TODO' }, [{ pattern: '' }]],
    ['plan', { op: 'draft', title: 'Plan', content: 'Work' }, [{ op: 'draft', title: 'Plan' }, { op: 'finalize', content: 'ignored?' }]],
    ['todo', { items: [{ title: 'Work', status: 'pending' }] }, [{ items: [{ title: 'Work' }] }, { items: [{ title: 'Work', status: 'done' }] }]]
  ];
  const contracts = loadToolContracts(examples.map(([name]) => builtin(name)));
  for (const [name, value, invalid] of examples) {
    const resolve = (value: unknown) => contracts.resolveToolInput({ ...call, toolName: name, observedInput: observed(value) });
    const result = resolve(value);
    assert.equal(result.kind, 'resolved', name);
    if (result.kind !== 'resolved') continue;
    const view = contracts.projectInvocation({ ...call, toolName: name, input: result.value });
    assert.ok(view.kind === 'tool');
    assert.equal(view.subject.toolName, name);
    assert.equal(view.invocation.replayClass, builtinInputContracts[name].replayClass);
    assert.equal(Object.isFrozen(view.invocation.input), true);
    assert.equal('action' in view.subject, false);
    assert.equal('grant' in view, false);
    for (const input of [...invalid, { [name]: value }, { ...value, ignored: true }]) assert.equal(resolve(input).kind, 'invalid_input', name);
  }
  assert.deepEqual(builtinInputContracts.plan.parseInput({ op: 'update', planId: 'p', content: 'Updated' })?.input,
    { op: 'update', planId: 'p', content: 'Updated' });
  assert.equal(builtinInputContracts.plan.parseInput({ op: 'finalize', planId: 'p' })?.channel.kind, 'plan');
});

test('workspace paths have one lexical identity for input, policy, display and loop comparison', () => {
  const contracts = loadToolContracts([builtin('read'), builtin('ls')]);
  const first = contracts.resolveToolInput({ ...call, observedInput: observed({ path: './src//./a.ts' }) });
  assert.equal(first.kind, 'resolved');
  if (first.kind !== 'resolved') return;
  assert.deepEqual(first.value, { path: 'src/a.ts' });
  const view = contracts.projectInvocation({ ...call, input: first.value });
  assert.ok(view.kind === 'tool');
  assert.deepEqual(view.subject.channel, { kind: 'fs-read', path: 'src/a.ts' });
  assert.equal(view.subject.display.path, view.invocation.input.path);
  assert.equal(contracts.projectInvocation({ ...call, callId: 'other', index: 19, input: { path: 'src/a.ts' } }).loopSignature, view.loopSignature);
  assert.notEqual(contracts.projectInvocation({ ...call, input: { path: 'src/b.ts' } }).loopSignature, view.loopSignature);
  assert.throws(() => contracts.projectInvocation({ ...call, input: { path: './src/a.ts' } }), /normalized/);
  for (const path of ['../a', 'src/../a', '/etc/passwd', 'C:/Windows', 'C:relative', 'src\\a', 'src\0a']) {
    assert.equal(contracts.resolveToolInput({ ...call, observedInput: observed({ path }) }).kind, 'invalid_input', path);
  }
  for (const input of [{}, { path: '' }, { path: './' }]) {
    const result = contracts.resolveToolInput({ ...call, toolName: 'ls', observedInput: observed(input) });
    assert.equal(result.kind, 'resolved');
    if (result.kind === 'resolved') assert.deepEqual(result.value, { path: '.' });
  }
});

test('typed subjects reuse policy modes and sticky denies without going through the retiring runner', async () => {
  const contracts = loadToolContracts([builtin('edit'), builtin('bash')]);
  function subject(toolName: string, value: Record<string, unknown>) {
    const resolved = contracts.resolveToolInput({ ...call, toolName, observedInput: observed(value) });
    assert.equal(resolved.kind, 'resolved');
    if (resolved.kind !== 'resolved') throw new Error('test input rejected');
    const view = contracts.projectInvocation({ ...call, toolName, input: resolved.value });
    assert.ok(view.kind === 'tool');
    return view.subject;
  }
  const edit = subject('edit', { path: './.git//config', old_text: '', new_text: 'change' });
  const yolo = createPolicyEngine({ mode: 'yolo', table: composePermissionTable() });
  assert.equal((await yolo.decide(edit)).behavior, 'deny');
  const nested = subject('bash', { command: 'bash -c "rm file"' });
  assert.equal((await yolo.decide(nested)).behavior, 'deny');
  const ordinary = subject('edit', { path: 'src/a.ts', old_text: '', new_text: 'change' });
  for (const [mode, behavior] of [['default', 'ask'], ['accept-edits', 'allow'], ['plan', 'deny'], ['yolo', 'allow']] as const) {
    assert.equal((await createPolicyEngine({ mode }).decide(ordinary)).behavior, behavior);
  }
  const policy = createPolicyEngine({ mode: 'default', table: { deny: [], ask: [],
    allow: [{ channel: 'bash', pattern: 'npm *', source: 'cli' }] } });
  assert.equal((await policy.decide(subject('bash', { command: 'npm test' }))).behavior, 'allow');
  assert.equal((await policy.decide(subject('bash', { command: 'npm test && curl example.invalid' }))).behavior, 'ask');
});

test('a same-named MCP tool retains remote schema and registration identity instead of builtin semantics', async () => {
  const authority = tool(schema);
  const contracts = loadToolContracts([authority]);
  authority.execution.registrationId = 'mutated';
  const input = { path: '../remote-resource', start: 1 };
  const resolved = contracts.resolveToolInput({ ...call, observedInput: observed(input) });
  assert.equal(resolved.kind, 'resolved');
  const view = contracts.projectInvocation({ ...call, input });
  assert.ok(view.kind === 'tool');
  input.path = 'mutated';
  assert.deepEqual(view.subject.channel, { kind: 'mcp', server: 'registered-server', tool: 'remote-read' });
  assert.equal(view.subject.access, 'exec');
  assert.equal((await createPolicyEngine({ mode: 'default' }).decide(view.subject)).behavior, 'ask');
  assert.equal((await createPolicyEngine({ mode: 'plan' }).decide(view.subject)).behavior, 'deny');
  assert.equal(view.invocation.input.path, '../remote-resource');
  assert.equal(view.subject.display.server, 'registered-server');
  assert.equal(Object.isFrozen(view.execution), true);
  assert.notEqual(loadToolContracts([authority]).projectInvocation({ ...call, input: { path: '../remote-resource', start: 1 } }).loopSignature, view.loopSignature);
  assert.throws(() => loadToolContracts([{ ...authority, access: 'read' }]), /exec-class/);
  assert.throws(() => loadToolContracts([{ ...authority, version: 'probed-interface-v1' }]), /final exec-class/);
});

test('builtin identity, schema, access and replay class must match the compiled contract', () => {
  const read = builtin('read');
  for (const changed of [
    { ...read, access: 'exec' }, { ...read, replayClass: 'manual' }, { ...read, version: 'other' },
    { ...read, inputSchema: schema, inputSchemaRef: canonicalSha256(schema), inputSchemaDigest: canonicalSha256(schema) },
    { ...read, execution: { ...read.execution, adapterId: 'skill' } },
    { ...read, execution: { ...read.execution, adapterVersion: 'other' } }
  ]) assert.throws(() => loadToolContracts([changed as ToolInputAuthority]), /compiled input semantics/);
});

test('request_input exposes a closed control invocation, never a permission subject or same-named MCP fallback', () => {
  const contracts = loadToolContracts([builtin('request_input')]);
  const resolve = (value: unknown) => contracts.resolveToolInput({ ...call, toolName: 'request_input', observedInput: observed(value) });
  const input = { prompt: 'Cafe\u0301?', responseKind: 'text', maximumResponseBytes: 64 };
  const result = resolve(input);
  assert.ok(result.kind === 'resolved');
  assert.equal(result.value.prompt, 'Café?');
  const view = contracts.projectInvocation({ ...call, toolName: 'request_input', input: result.value });
  assert.equal(view.kind, 'input');
  assert.equal('subject' in view, false);
  assert.equal(view.display.detail, 'Café?');
  for (const value of [{ ...input, prompt: '' }, { ...input, prompt: '\0' }, { ...input, prompt: '\ud800' },
    { ...input, maximumResponseBytes: 0 }, { ...input, maximumResponseBytes: 1_048_577 },
    { ...input, maximumResponseBytes: 1.5 }, { ...input, responseSchema: {} }, { ...input, responseKind: 'json' },
    { ...input, extra: true }]) assert.equal(resolve(value).kind, 'invalid_input');
  const remote = { ...tool(schema), name: 'request_input' };
  const mcp = loadToolContracts([remote]).projectInvocation({ ...call, toolName: 'request_input', input: { path: 'a' } });
  assert.equal(mcp.kind, 'tool');
  assert.throws(() => loadToolContracts([{ ...builtin('request_input'), access: 'read' }]), /compiled input semantics/);
  assert.throws(() => loadToolContracts([{ ...remote, access: 'control' }]), /exec-class/);
});

test('input response schemas accept only the retained deterministic 2020-12 subset', () => {
  const contracts = loadToolContracts([builtin('request_input')]);
  const resolve = (responseSchema: unknown) => contracts.resolveToolInput({ ...call, toolName: 'request_input', observedInput: observed({
    prompt: 'Choose', responseKind: 'json', responseSchema, maximumResponseBytes: 1_048_576
  }) });
  for (const responseSchema of [{ type: 'string', minLength: 0, maxLength: 3 }, { type: 'number', minimum: -1, maximum: 3 },
    { type: ['string', 'null'] }, { const: { ok: true } }, { enum: [null, 1, 'a'] },
    { type: 'array', minItems: 1, maxItems: 2, items: { type: 'integer' } },
    { type: 'object', properties: { value: { type: 'boolean' } }, required: ['value'], additionalProperties: false }]) {
    assert.equal(resolve(responseSchema).kind, 'resolved');
  }
  for (const responseSchema of [{ $ref: '#/a' }, { $id: 'https://example.invalid/schema' }, { $async: true },
    { type: 'string', pattern: '.*' }, { type: 'string', format: 'email' }, { type: 'string', default: 'answer' },
    { type: 'object', additionalProperties: true }, { allOf: [{ type: 'string' }] }, { oneOf: [{ type: 'string' }] },
    { type: 'array', items: { $ref: '#/a' } }, { type: 'object', properties: { answer: { custom: true } } },
    { type: 'string', enum: ['x'.repeat(65_536)] }]) assert.equal(resolve(responseSchema).kind, 'invalid_input');
});

test('MCP schemas with the same local $id are compiled independently', () => {
  const first = tool({ $id: 'urn:cliq:test-input', type: 'object', properties: { value: { type: 'string' } }, required: ['value'] });
  const second = { ...tool({ $id: 'urn:cliq:test-input', type: 'object', properties: { value: { type: 'integer' } }, required: ['value'] }), name: 'second' };
  const resolve = resolver([first, second]);
  assert.equal(resolve({ ...call, observedInput: observed({ value: 'text' }) }).kind, 'resolved');
  assert.equal(resolve({ ...call, toolName: 'second', observedInput: observed({ value: 'text' }) }).kind, 'invalid_input');
  assert.equal(resolve({ ...call, toolName: 'second', observedInput: observed({ value: 3 }) }).kind, 'resolved');
});
