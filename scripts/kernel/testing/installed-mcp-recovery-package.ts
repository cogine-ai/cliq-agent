// Build-time qualification publisher only. The installed runtime consumes the
// ordinary independently signed adapter and complete RuntimeBundle closure.
// No test flag, unsigned profile, alternate native role or runtime bypass.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { sign } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeMcpInitializeResult, decodeMcpToolsListResult } from '../../../src/kernel/mcp.js';
import { decodeMcpInboundMessageData, mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData,
  mcpToolsCallRequestData } from '../../../src/kernel/mcp-wire.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryPredicate, decodeMcpRecoveryProfile, mcpProfileSigningIdentityDigest } from '../../../src/kernel/mcp-recovery.js';
import { mcpRecoveryAdapterMemberRefs } from '../../../src/policy/mcp-recovery-authority.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { qualificationPublisherMaterial, type InstalledQualificationPublisher } from '../../../src/state/testing/qualification-publisher.js';

export const MCP_RECOVERY_FIXTURE_ARGV = '--immutable-noop-effect-no-reply';
export const MCP_RECOVERY_HOLD_ARGV = '--immutable-noop-effect-and-status-no-reply';
export const MCP_RECOVERY_REFUSED_ARGV = '--immutable-noop-effect-no-reply-status-malformed';
export const MCP_RECOVERY_REFUSED_STATUS_LINE = '{"id":3,"jsonrpc":"2.0","result":{"sentinel":"cliq-fixture-refused-status-sentinel"';
export const MCP_RECOVERY_UNRESOLVED_ARGV = '--immutable-noop-status-observes-target-only';
export const MCP_RECOVERY_MISSING_ARGV = '--immutable-noop-missing-required-target';
export const MCP_RECOVERY_EFFECT = 'stdio_noop_effect', MCP_RECOVERY_STATUS = 'stdio_noop_status';
export const MCP_RECOVERY_ADAPTER = 'owned-immutable-noop-status-v1';
type Content = Omit<RuntimeBundleManifest['entries'][number], 'digest' | 'byteCount'> & { bytes: Buffer };

export async function buildInstalledMcpRecoveryPackage(input: Readonly<{
  server: string; serverBytes: Buffer; adapter: string; adapterBytes: Buffer; publisher: InstalledQualificationPublisher;
}>): Promise<Readonly<{ contents: readonly Content[]; root: RuntimeBundleManifest['structuredArtifacts'][number] }>> {
  const keys = qualificationPublisherMaterial(input.publisher);
  async function image(filename: string, bytes: Buffer) {
    assert(Buffer.isBuffer(bytes) && bytes.length > 0);
    const original = await lstat(filename, { bigint: true });
    assert(original.isFile() && original.nlink === 1n && (original.mode & 0o111n) !== 0n && original.size === BigInt(bytes.length));
    const assertCurrent = async () => {
      const current = await lstat(filename, { bigint: true });
      for (const key of ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const)
        assert.equal(current[key], original[key], 'the original compiled fixture identity changed');
      assert.deepEqual(await readFile(filename), bytes, 'the actual compiled fixture bytes changed');
    };
    await assertCurrent();
    return { filename, original, digest: sha256Bytes(bytes), assertCurrent };
  }
  const server = await image(input.server, input.serverBytes), adapter = await image(input.adapter, input.adapterBytes);
  assert.notEqual(server.filename, adapter.filename);
  assert(server.original.dev !== adapter.original.dev || server.original.ino !== adapter.original.ino,
    'the signed MCP server and recovery adapter require separate actual images');
  assert.notEqual(server.digest, adapter.digest, 'the signed RuntimeBundle cannot alias the two executable roles');
  const request = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2)]
    .map(frame => frame.json + '\n').join('');
  const effectChallenge = mcpToolsCallRequestData(3, MCP_RECOVERY_EFFECT,
    { idempotencyKey: identityHash('cliq-installed-mcp-recovery-role-qualification-v1', 'effect-challenge') });
  async function runFixture(selected: typeof server, argv: string, frames: string, expectedStatus: number) {
    await selected.assertCurrent();
    const process = spawnSync(selected.filename, [argv], { input: Buffer.from(frames),
      env: { PATH: '/usr/bin:/bin', LANG: 'C' }, timeout: 5_000, maxBuffer: 2_097_152 });
    assert.equal(process.error, undefined, 'the owned fixed discovery process must join');
    assert.equal(process.signal, null); assert.equal(process.status, expectedStatus); assert.equal(process.stderr.length, 0);
    await selected.assertCurrent();
    assert(process.stdout.length > 0 && process.stdout.length <= 1_048_576);
    return process.stdout;
  }
  async function discover(argv: string) {
    const stdout = await runFixture(server, argv, request, 0);
    assert.deepEqual(await runFixture(adapter, argv, request, 0), stdout,
      'both actual role executables must return the same signed profile discovery');
    assert.deepEqual(await runFixture(adapter, argv, request + effectChallenge.json + '\n', 65), stdout,
      'the separately compiled recovery adapter must reject the actual effect with no response');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(stdout), lines = text.split('\n');
    assert.equal(lines.length, 3); assert.equal(lines[2], '');
    const [initializeLine, toolsLine] = lines;
    if (initializeLine === undefined || toolsLine === undefined) assert.fail('fixed discovery responses must both be present');
    const initialize = decodeMcpInboundMessageData(parseJsonStrict(initializeLine)), listed = decodeMcpInboundMessageData(parseJsonStrict(toolsLine));
    if (initialize.kind !== 'result' || initialize.id !== 1 || listed.kind !== 'result' || listed.id !== 2) assert.fail('fixed discovery must return its two exact original responses');
    const negotiation = decodeMcpInitializeResult(initialize.result), tools = decodeMcpToolsListResult(listed.result);
    assert.deepEqual(tools.map(tool => tool.interface.name), [MCP_RECOVERY_EFFECT, MCP_RECOVERY_STATUS]);
    return { negotiation, tools };
  }
  const { negotiation, tools } = await discover(MCP_RECOVERY_FIXTURE_ARGV), heldStatus = await discover(MCP_RECOVERY_HOLD_ARGV);
  assert.deepEqual(heldStatus, { negotiation, tools }, 'each fixed independently signed argv must actually return the same complete discovery');
  assert.deepEqual(await discover(MCP_RECOVERY_REFUSED_ARGV), { negotiation, tools },
    'the fixed malformed-status argv still provides exact original signed discovery');
  assert.deepEqual(await discover(MCP_RECOVERY_UNRESOLVED_ARGV), { negotiation, tools },
    'the fixed unresolved argv must provide the actual original signed discovery');
  const missing = await discover(MCP_RECOVERY_MISSING_ARGV);
  assert.deepEqual(missing.negotiation, negotiation);
  assert.notDeepEqual(missing.tools, tools, 'missing-target status must sign its actual distinct output schema');
  const effect = tools[0], status = tools[1];
  if (!effect || !status || !status.interface.outputSchemaRef || !status.interface.outputSchemaDigest)
    assert.fail('the genuine fixed discovery must expose the distinct status output schema');
  const staticArguments = { idempotencyKey: '' };
  const completedCore = { schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1', expression: { op: 'and', operands: [
    { op: 'equals', jsonPointer: '/originalExecutionObserved', value: false },
    { op: 'equals', jsonPointer: '/profileClass', value: 'immutable_preexisting_noop_target' },
    { op: 'equals', jsonPointer: '/targetState', value: 'preexisting_noop' },
  ] } };
  // This fixed target cannot fail or attest prior execution. The distinct
  // failure predicate remains unmatchable under its exact signed schema.
  const failedCore = { schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1',
    expression: { op: 'equals', jsonPointer: '/targetState', value: 'confirmed_failed' } };
  const completed = decodeMcpRecoveryPredicate({ ...completedCore, predicateDigest: canonicalSha256(completedCore) });
  const failed = decodeMcpRecoveryPredicate({ ...failedCore, predicateDigest: canonicalSha256(failedCore) });
  // This independently signed profile requires evidence of original
  // execution. The real read-only server observes the immutable target only.
  const executionObservedCore = { schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1',
    expression: { op: 'equals', jsonPointer: '/originalExecutionObserved', value: true } };
  const executionObserved = decodeMcpRecoveryPredicate({ ...executionObservedCore, predicateDigest: canonicalSha256(executionObservedCore) });
  const missingTargetCore = { schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1', expression: { op: 'and', operands: [
    { op: 'equals', jsonPointer: '/originalExecutionObserved', value: false },
    { op: 'equals', jsonPointer: '/profileClass', value: 'immutable_missing_noop_target' },
    { op: 'equals', jsonPointer: '/targetState', value: 'missing_immutable_target' },
  ] } };
  const missingTarget = decodeMcpRecoveryPredicate({ ...missingTargetCore, predicateDigest: canonicalSha256(missingTargetCore) });
  const signingIdentity = (argv: string) => mcpProfileSigningIdentityDigest({ kind: 'stdio', executionIdentityGrantId: 'qualification-original-grant-shape-only',
    executionIdentityConsumptionReceiptRef: canonicalSha256('shape-only-no-authority'), executionIdentityConsumptionReceiptDigest: canonicalSha256('shape-only-no-authority-data'),
    executable: { kind: 'runtime_bundle', runtimeBundleRef: canonicalSha256('outer-selector-not-in-signing-identity'),
      executableId: 'mcp-static-stdio-fixture-v1', executableDigest: server.digest, executionPath: '/runtime/mcp-server' },
    argv: [{ kind: 'non_secret_literal', value: argv }] });
  const profileCore = { profileId: 'immutable-preexisting-noop-target-v1', profileSigningIdentityDigest: signingIdentity(MCP_RECOVERY_FIXTURE_ARGV),
    serverToolName: MCP_RECOVERY_EFFECT, initializeDigest: negotiation.initializeDigest, capabilityDigest: negotiation.capabilityDigest,
    probedToolsListDigest: canonicalSha256(tools.map(tool => tool.interface)), effectToolInterfaceDigest: effect.interface.interfaceDigest,
    statusOperationName: MCP_RECOVERY_STATUS, statusOperationSemantics: 'signed_read_only_status_query',
    statusToolInterfaceDigest: status.interface.interfaceDigest, statusInputSchemaDigest: status.interface.inputSchemaDigest,
    statusOutputSchemaDigest: status.interface.outputSchemaDigest, staticArgumentsRef: canonicalSha256(staticArguments), staticArgumentsDigest: canonicalSha256(staticArguments),
    completedPredicateRef: canonicalSha256(completed), completedPredicateDigest: completed.predicateDigest,
    failedPredicateRef: canonicalSha256(failed), failedPredicateDigest: failed.predicateDigest };
  const profile = decodeMcpRecoveryProfile({ ...profileCore, profileDigest: canonicalSha256(profileCore) });
  const heldProfileCore = { ...profileCore, profileId: 'immutable-preexisting-noop-target-v2-owning-stop',
    profileSigningIdentityDigest: signingIdentity(MCP_RECOVERY_HOLD_ARGV) };
  const heldProfile = decodeMcpRecoveryProfile({ ...heldProfileCore, profileDigest: canonicalSha256(heldProfileCore) });
  const refusedProfileCore = { ...profileCore, profileId: 'immutable-preexisting-noop-target-v3-refused-status',
    profileSigningIdentityDigest: signingIdentity(MCP_RECOVERY_REFUSED_ARGV) };
  const refusedProfile = decodeMcpRecoveryProfile({ ...refusedProfileCore, profileDigest: canonicalSha256(refusedProfileCore) });
  const unresolvedProfileCore = { ...profileCore, profileId: 'immutable-preexisting-noop-target-v4-execution-unobserved',
    profileSigningIdentityDigest: signingIdentity(MCP_RECOVERY_UNRESOLVED_ARGV),
    completedPredicateRef: canonicalSha256(executionObserved), completedPredicateDigest: executionObserved.predicateDigest };
  const unresolvedProfile = decodeMcpRecoveryProfile({ ...unresolvedProfileCore, profileDigest: canonicalSha256(unresolvedProfileCore) });
  const [missingEffect, missingStatus] = missing.tools;
  if (!missingEffect || !missingStatus?.interface.outputSchemaDigest) assert.fail('missing-target discovery lost its exact status schema');
  const missingProfileCore = { ...profileCore, profileId: 'immutable-preexisting-noop-target-v5-missing-required-target',
    profileSigningIdentityDigest: signingIdentity(MCP_RECOVERY_MISSING_ARGV), probedToolsListDigest: canonicalSha256(missing.tools.map(tool => tool.interface)),
    effectToolInterfaceDigest: missingEffect.interface.interfaceDigest, statusToolInterfaceDigest: missingStatus.interface.interfaceDigest,
    statusInputSchemaDigest: missingStatus.interface.inputSchemaDigest, statusOutputSchemaDigest: missingStatus.interface.outputSchemaDigest,
    failedPredicateRef: canonicalSha256(missingTarget), failedPredicateDigest: missingTarget.predicateDigest };
  const missingProfile = decodeMcpRecoveryProfile({ ...missingProfileCore, profileDigest: canonicalSha256(missingProfileCore) });
  const core = { schemaVersion: 1, format: 'cliq-mcp-recovery-adapter-v1', adapterId: MCP_RECOVERY_ADAPTER,
    entryId: 'owned-immutable-noop-status-adapter-v1', version: '1', executableDigest: adapter.digest,
    protocol: 'cliq-mcp-reconcile-v1', profiles: [profile, heldProfile, refusedProfile, unresolvedProfile, missingProfile],
    publisherKeyId: keys.releaseKeys[0]?.keyId };
  assert(core.publisherKeyId);
  const adapterDigest = canonicalSha256(core), signature = sign(null, Buffer.from(`cliq-mcp-recovery-adapter-v1\0${adapterDigest}`), keys.privateKey).toString('base64');
  const manifest = decodeMcpRecoveryAdapterManifest({ ...core, adapterDigest, signature }), manifestRef = canonicalSha256(manifest);
  const contents: Content[] = [
    { entryId: manifest.entryId, role: 'mcp_recovery_adapter', version: '1', relativePath: 'mcp/immutable-noop-status-adapter', executable: true, bytes: input.adapterBytes },
    { entryId: 'owned-immutable-noop-status-profile-v1', role: 'mcp_recovery_profile', version: '1', relativePath: 'mcp/immutable-noop-status-profile.json', executable: false,
      bytes: canonicalJsonBytes(manifest) },
    ...[staticArguments, completed, failed, executionObserved, missingTarget].map(value => { const ref = canonicalSha256(value); return {
      entryId: identityHash('runtime-bundle-object-v1', ref), role: 'bundle_object', version: '1', relativePath: `objects/sha256/${ref.slice(0, 2)}/${ref}`,
      executable: false, bytes: canonicalJsonBytes(value) }; }),
  ];
  return { contents, root: { kind: 'mcp_recovery_adapter', artifactId: manifest.adapterId, rootEntryId: 'owned-immutable-noop-status-profile-v1',
    artifactRef: manifestRef, semanticDigest: manifest.adapterDigest, executableEntryId: manifest.entryId, memberRefs: mcpRecoveryAdapterMemberRefs(manifest) } };
}
