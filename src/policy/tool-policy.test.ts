import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { RunSpec, ToolContractManifestV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { createAgentFixture } from '../state/testing/agent-fixtures.js';
import { disposeFixture } from '../state/testing/fixtures.js';
import { loadToolContracts, type ToolInputAuthority } from '../tools/input-contract.js';
import { BUILTIN_POLICY_RULES, loadToolPolicy, modeDecisions, toolOperationId } from './tool-policy.js';
import { verifyToolRuntimeAuthority } from './runtime-authority.js';
import { parseCanonicalBash } from './canonical-bash.js';
import { sampleCanonicalNow } from '../state/canonical-time.js';

let fixture: Awaited<ReturnType<typeof createAgentFixture>>;
let snapshot: RunPolicySnapshotV1;
let contracts: ToolInputAuthority[];
const workspaceRef = canonicalSha256('workspace-identity');
let now: string;
let expiresAt: string;
before(async () => {
  fixture = await createAgentFixture('canonical-policy', undefined, { mode: 'default', tools: ['bash', 'edit', 'plan', 'read', 'todo'] });
  const spec = await fixture.store.artifacts.readCanonical<RunSpec>(fixture.store.getRun(fixture.runId).specRef);
  snapshot = await fixture.store.artifacts.readCanonical<RunPolicySnapshotV1>(spec.policyRef);
  const manifest = await fixture.store.artifacts.readCanonical<ToolContractManifestV1>(fixture.authority.assembly.tools.manifestRef);
  contracts = await Promise.all(manifest.entries.map(async (entry) => ({ ...entry, inputSchema: await fixture.store.artifacts.readCanonical(entry.inputSchemaRef) })));
  now = sampleCanonicalNow();
  expiresAt = new Date(Date.parse(now) + 60_000).toISOString();
});
after(async () => { if (fixture) await disposeFixture(fixture); });

function policy(mode: RunPolicySnapshotV1['mode'], rules: Array<Partial<RunPolicySnapshotV1['decisionRules'][number]>> = []) {
  const value = structuredClone(snapshot);
  value.mode = mode;
  value.decisions = modeDecisions(mode);
  value.decisionRules = [...BUILTIN_POLICY_RULES, ...rules.map((rule, index) => ({ ruleId: `rule-${index}`, order: index + 3,
    source: 'cli' as const, sourceRef: canonicalSha256('immutable-source'), channel: 'bash' as const, pattern: '*', disposition: 'allow' as const, ...rule }))];
  value.repositoryRequestRefs = [...new Set(value.decisionRules.filter((rule) => rule.source === 'repository_request').map((rule) => rule.sourceRef!))].sort();
  value.policyDigest = digestOmitting(value, 'policyDigest');
  return value;
}

function load(value: RunPolicySnapshotV1) {
  return loadToolPolicy({ policy: value, policyRef: canonicalSha256(value), assembly: fixture.authority.assembly,
    assemblyRef: fixture.authority.assemblyRef, principalId: snapshot.principalId,
    workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: snapshot.workspaceIdentityDigest, contracts });
}

function request(toolName: string, input: Record<string, unknown>): { request: ToolRequestV1; target: ToolTargetV1; call: ToolCallInputV1 } {
  const { inputSchema: _schema, ...entry } = contracts.find((entry) => entry.name === toolName)!;
  const projected = loadToolContracts(contracts).projectInvocation({ callId: 'call', index: 0, toolName, input });
  const callCore = { schemaVersion: 1, format: 'cliq-tool-call-input-v1', callId: 'call', index: 0, toolName,
    disposition: 'resolved', inputSchemaRef: entry.inputSchemaRef, inputSchemaDigest: entry.inputSchemaDigest,
    observedInputRef: canonicalSha256('raw-input'), observedInputDigest: canonicalSha256('raw-input-digest'), value: projected.invocation.input };
  const call = { ...callCore, inputDigest: canonicalSha256(callCore) } as ToolCallInputV1;
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-tool-target-v1' as const, runId: 'run-1',
    workspaceIdentityRef: workspaceRef, workspaceIdentityDigest: snapshot.workspaceIdentityDigest,
    toolManifestRef: snapshot.toolManifestRef, toolManifestDigest: snapshot.toolManifestDigest,
    toolName, toolContractDigest: canonicalSha256(entry), execution: entry.execution };
  const target: ToolTargetV1 = { ...targetCore, targetDigest: canonicalSha256(targetCore) };
  const core = { schemaVersion: 1 as const, format: 'cliq-tool-request-v1' as const, runId: 'run-1', opId: toolOperationId('run-1', 'batch', 'call'),
    frontierRef: canonicalSha256('tool-frontier'), assemblyRef: fixture.authority.assemblyRef,
    batchItemId: 'batch', callId: 'call', callIndex: 0, toolName, inputRef: canonicalSha256(call), inputDigest: call.inputDigest,
    targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  return { request: { ...core, requestDigest: canonicalSha256(core) } satisfies ToolRequestV1, target, call };
}

test('fixed mode table and rule precedence produce the actual winning evidence, never the retiring engine synthetic rule', () => {
  assert.deepEqual(Object.values(modeDecisions('yolo')), Array(10).fill('allow'));
  assert.deepEqual(modeDecisions('plan'), { read: 'allow', plan: 'allow', write: 'deny', exec: 'deny', mcp: 'deny', verifier: 'deny',
    dependency_install_scripts: 'deny', delivery: 'deny', child_read_only: 'allow', child_mutating: 'deny' });
  const call = request('bash', { command: "sh -c 'printf ok; rm a; rm b'" });
  const denied = load(policy('yolo', [{ disposition: 'allow' }])).evaluate(call.request, call.target, call.call, now);
  assert.equal(denied.effectiveDisposition, 'deny');
  assert.deepEqual(denied.matchedRuleIds, ['builtin:bash:rm']);
  assert.equal(denied.channel, 'bash');
  if (denied.channel === 'bash') assert.deepEqual(denied.nestedBuiltinDenyHeads, ['rm', 'rm']);
  const compound = request('bash', { command: 'printf a; printf b' });
  const ask = load(policy('default', [{ disposition: 'ask' }, { disposition: 'allow' }])).evaluate(compound.request, compound.target, compound.call, now);
  assert.equal(ask.effectiveDisposition, 'ask');
  assert.deepEqual(ask.matchedRuleIds, ['rule-1']);
  const direct = request('bash', { command: 'printf ok' });
  const explicit = load(policy('plan', [{ disposition: 'allow' }])).evaluate(direct.request, direct.target, direct.call, now);
  assert.equal(explicit.effectiveDisposition, 'allow'); // RFC precedence is explicit; the retiring engine is unchanged.
  const narrowed = load(policy('plan', [{ source: 'repository_request', disposition: 'ask' }])).evaluate(direct.request, direct.target, direct.call, now);
  assert.equal(narrowed.effectiveDisposition, 'deny');
  assert.deepEqual(narrowed.matchedRuleIds, []);
});

test('snapshot rejects missing builtin floor, changed mode table, duplicate/gapped rules, widening repository rules and legacy hooks', () => {
  const mutations: Array<(value: RunPolicySnapshotV1) => void> = [
    (value) => { value.decisionRules.shift(); },
    (value) => { value.decisions.exec = 'allow'; },
    (value) => { value.decisionRules[3]!.source = 'hook' as never; },
    (value) => { value.decisionRules[3]!.source = 'repository_request'; },
    (value) => { delete value.decisionRules[3]!.sourceRef; },
    (value) => { value.decisionRules[3]!.order = 10; },
    (value) => { value.decisionRules[3]!.ruleId = value.decisionRules[0]!.ruleId; }
  ];
  for (const mutate of mutations) {
    const value = policy('default', [{}]); mutate(value); value.policyDigest = digestOmitting(value, 'policyDigest');
    assert.throws(() => load(value));
  }
});

test('policy and grants bind normalized input, workspace, full target, rule evidence and separate digest domains', () => {
  const evaluator = load(policy('default'));
  const selected = request('read', { path: 'a' });
  const evidence = evaluator.evaluate(selected.request, selected.target, selected.call, now);
  const grant = evaluator.grant(selected.request, selected.target, selected.call, evidence, now, expiresAt);
  assert.equal(grant.provenance.channelEvidenceRef, canonicalSha256(evidence));
  assert.notEqual(grant.provenance.channelEvidenceRef, evidence.evidenceDigest);
  assert.equal(grant.grantDigest, digestOmitting(grant, 'grantDigest'));
  assert.throws(() => evaluator.evaluate({ ...selected.request, inputDigest: canonicalSha256('other') }, selected.target, selected.call, now));
  const target = { ...selected.target, workspaceIdentityRef: canonicalSha256('other workspace') };
  target.targetDigest = digestOmitting(target, 'targetDigest');
  const changed = { ...selected.request, targetRef: canonicalSha256(target), targetDigest: target.targetDigest };
  changed.requestDigest = digestOmitting(changed, 'requestDigest');
  assert.throws(() => evaluator.evaluate(changed, target, selected.call, now), /tool target/);
  const fake = { ...evidence, matchedRuleIds: ['caller-allow'] };
  fake.evidenceDigest = digestOmitting(fake, 'evidenceDigest');
  assert.throws(() => evaluator.grant(selected.request, selected.target, selected.call, fake, now, expiresAt), /channel evidence/);
  const shell = request('bash', { command: 'printf ok' });
  const ask = evaluator.evaluate(shell.request, shell.target, shell.call, now);
  assert.throws(() => evaluator.grant(shell.request, shell.target, shell.call, ask, now, expiresAt), /direct allow/);
});

test('MCP exposed names never inherit builtin access, target or idempotency semantics', () => {
  const prior = contracts;
  const originalAssembly = fixture.authority.assembly;
  const originalSnapshot = snapshot;
  try {
    const read = contracts.find((entry) => entry.name === 'read')!;
    contracts = [{ ...read, version: 'mcp-tool-contract-v1', access: 'exec', replayClass: 'manual',
      execution: { kind: 'mcp', registrationId: 'registry-1', registryRevisionRef: canonicalSha256('registry'), registryManifestDigest: canonicalSha256('registry-core'),
        serverToolName: 'server_read', toolContractDigest: canonicalSha256('mcp-contract') } }];
    const selected = request('read', { path: 'a' });
    selected.request.idempotencyKey = identityHash('cliq-mcp-tool-idempotency-v1', 'run-1', selected.request.opId, canonicalSha256('registry'), 'server_read');
    selected.request.requestDigest = digestOmitting(selected.request, 'requestDigest');
    const evaluated = load(policy('default')).evaluate(selected.request, selected.target, selected.call, now);
    assert.equal(evaluated.actionClass, 'mcp');
    assert.equal(evaluated.channel, 'mcp');
    assert.equal(evaluated.effectiveDisposition, 'ask');
    if (evaluated.channel === 'mcp') assert.equal(evaluated.serverToolName, 'server_read');
    delete selected.request.idempotencyKey;
    selected.request.requestDigest = digestOmitting(selected.request, 'requestDigest');
    assert.throws(() => load(policy('default')).evaluate(selected.request, selected.target, selected.call, now), /idempotency/);
  } finally { contracts = prior; fixture.authority.assembly = originalAssembly; snapshot = originalSnapshot; }
});

test('policy profile requires a real trusted signature and the exact non-executable signed entry, not semantic-hash aliasing', () => {
  const signed = fixture.signed!;
  const material = { assembly: fixture.authority.assembly, policy: snapshot, bundle: signed.bundle, profile: signed.profile,
    tools: contracts.map(({ inputSchema: _schema, ...entry }) => entry), releaseKeys: signed.releaseKeys };
  assert.doesNotThrow(() => verifyToolRuntimeAuthority(material));
  assert.throws(() => verifyToolRuntimeAuthority({ ...material, releaseKeys: [] }), /trusted release signature/);
  for (const mutate of [
    (bundle: typeof signed.bundle) => { bundle.entries.find((entry) => entry.role === 'policy_engine')!.executable = true; },
    (bundle: typeof signed.bundle) => { bundle.entries.find((entry) => entry.role === 'policy_engine')!.digest = signed.profile.profileDigest; },
    (bundle: typeof signed.bundle) => { bundle.entries.find((entry) => entry.role === 'tool_adapter')!.role = 'provider_adapter'; },
    (bundle: typeof signed.bundle) => { bundle.structuredArtifacts[0]!.memberRefs = [canonicalSha256('foreign-member')]; }
  ]) {
    const bundle = structuredClone(signed.bundle); mutate(bundle);
    const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
    bundle.manifestDigest = canonicalSha256(core);
    const assembly = structuredClone(material.assembly), policy = structuredClone(snapshot);
    assembly.runtime.runtimeBundleManifestDigest = bundle.manifestDigest;
    assembly.runtime.runtimeBundleRef = canonicalSha256(bundle); policy.engine.runtimeBundleRef = assembly.runtime.runtimeBundleRef;
    assert.throws(() => verifyToolRuntimeAuthority({ ...material, assembly, policy, bundle }), /signature/);
    const keys = generateKeyPairSync('ed25519');
    bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
    assembly.runtime.runtimeBundleRef = canonicalSha256(bundle); policy.engine.runtimeBundleRef = assembly.runtime.runtimeBundleRef;
    assert.throws(() => verifyToolRuntimeAuthority({ ...material, assembly, policy, bundle,
      releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] }));
  }
});

test('fixed Bash evidence preserves literal/nested order, refuses dynamic heads and bounds nesting/occurrences', () => {
  assert.deepEqual(parseCanonicalBash('printf ok'), { outerCommandHead: 'printf', nestedBuiltinDenyHeads: [], unsafeForAllow: false });
  assert.deepEqual(parseCanonicalBash("sh -c 'rm a; sh -c \"rm b\"; rm c'"),
    { outerCommandHead: 'sh', nestedBuiltinDenyHeads: ['rm', 'rm', 'rm'], unsafeForAllow: true });
  assert.equal(parseCanonicalBash('$COMMAND args').outerCommandHead, undefined);
  assert.equal(parseCanonicalBash('printf "unterminated').outerCommandHead, undefined);
  assert.equal(parseCanonicalBash('&& printf ok').outerCommandHead, undefined);
  assert.equal(parseCanonicalBash('printf ok |').outerCommandHead, undefined);
  assert.equal(parseCanonicalBash('python3.11 -c "print(1)"').outerCommandHead, undefined);
  assert.equal(parseCanonicalBash('git status').unsafeForAllow, false);
  assert.deepEqual(parseCanonicalBash('rm "$TARGET"').nestedBuiltinDenyHeads, ['rm']);
  for (const command of ['printf "$(rm a)"', 'printf `rm a`', 'cat <(rm a)', 'sh -c "printf $(rm a)"']) {
    const parsed = parseCanonicalBash(command);
    assert.equal(parsed.outerCommandHead, undefined, command);
    assert.deepEqual(parsed.nestedBuiltinDenyHeads, ['rm'], command);
    const call = request('bash', { command });
    assert.equal(load(policy('yolo')).evaluate(call.request, call.target, call.call, now).effectiveDisposition, 'deny', command);
  }
  assert.deepEqual(parseCanonicalBash('printf "$(printf x; rm a)"; rm b').nestedBuiltinDenyHeads, ['rm', 'rm']);
  assert.deepEqual(parseCanonicalBash("printf '%s' '$(rm a)'").nestedBuiltinDenyHeads, []);
  assert.equal(parseCanonicalBash('git\u00a0status').outerCommandHead, undefined);
  assert.equal(parseCanonicalBash('printf ok && "printf" done').outerCommandHead, 'printf');
  assert.equal(parseCanonicalBash('rm -rf *').outerCommandHead, 'rm');
  assert.deepEqual(parseCanonicalBash("printf '%s' 'rm a; rm b'").nestedBuiltinDenyHeads, []);
  assert.throws(() => parseCanonicalBash('e\u0301cho ok'), /NFC/);
  assert.throws(() => parseCanonicalBash(`sh -c '${Array(65).fill('rm a').join(';')}'`), /64 occurrences/);
});
