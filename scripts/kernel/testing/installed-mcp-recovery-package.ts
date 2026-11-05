// Build-time qualification publisher only. The installed runtime consumes the
// ordinary independently signed adapter and complete RuntimeBundle closure.
// No test flag, unsigned profile, alternate native role or runtime bypass.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeMcpInitializeResult, decodeMcpToolsListResult } from '../../../src/kernel/mcp.js';
import { decodeMcpInboundMessageData, mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData } from '../../../src/kernel/mcp-wire.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryPredicate, decodeMcpRecoveryProfile, mcpProfileSigningIdentityDigest } from '../../../src/kernel/mcp-recovery.js';
import { mcpRecoveryAdapterMemberRefs } from '../../../src/policy/mcp-recovery-authority.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { qualificationPublisherMaterial, type InstalledQualificationPublisher } from '../../../src/state/testing/qualification-publisher.js';

export const MCP_RECOVERY_FIXTURE_ARGV = '--immutable-noop-effect-no-reply';
export const MCP_RECOVERY_HOLD_ARGV = '--immutable-noop-effect-and-status-no-reply';
export const MCP_RECOVERY_EFFECT = 'stdio_noop_effect', MCP_RECOVERY_STATUS = 'stdio_noop_status';
export const MCP_RECOVERY_ADAPTER = 'owned-immutable-noop-status-v1';
type Content = Omit<RuntimeBundleManifest['entries'][number], 'digest' | 'byteCount'> & { bytes: Buffer };

export async function buildInstalledMcpRecoveryPackage(input: Readonly<{
  server: string; serverBytes: Buffer; publisher: InstalledQualificationPublisher;
}>): Promise<Readonly<{ contents: readonly Content[]; root: RuntimeBundleManifest['structuredArtifacts'][number] }>> {
  const keys = qualificationPublisherMaterial(input.publisher);
  assert(Buffer.isBuffer(input.serverBytes) && input.serverBytes.length > 0);
  assert.deepEqual(await readFile(input.server), input.serverBytes, 'the discovery binary must be the same actually compiled signed server image');
  const request = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2)]
    .map(frame => frame.json + '\n').join('');
  async function discover(argv: string) {
    const process = spawnSync(input.server, [argv], { input: Buffer.from(request),
      env: { PATH: '/usr/bin:/bin', LANG: 'C' }, timeout: 5_000, maxBuffer: 2_097_152 });
    assert.equal(process.error, undefined, 'the owned fixed discovery process must join');
    assert.equal(process.signal, null); assert.equal(process.status, 0); assert.equal(process.stderr.length, 0);
    assert.deepEqual(await readFile(input.server), input.serverBytes, 'the original compiled server image must remain unchanged');
    assert(process.stdout.length > 0 && process.stdout.length <= 1_048_576);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(process.stdout), lines = text.split('\n');
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
  const signingIdentity = (argv: string) => mcpProfileSigningIdentityDigest({ kind: 'stdio', executionIdentityGrantId: 'qualification-original-grant-shape-only',
    executionIdentityConsumptionReceiptRef: canonicalSha256('shape-only-no-authority'), executionIdentityConsumptionReceiptDigest: canonicalSha256('shape-only-no-authority-data'),
    executable: { kind: 'runtime_bundle', runtimeBundleRef: canonicalSha256('outer-selector-not-in-signing-identity'),
      executableId: 'mcp-static-stdio-fixture-v1', executableDigest: sha256Bytes(input.serverBytes), executionPath: '/runtime/mcp-server' },
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
  const core = { schemaVersion: 1, format: 'cliq-mcp-recovery-adapter-v1', adapterId: MCP_RECOVERY_ADAPTER,
    entryId: 'owned-immutable-noop-status-adapter-v1', version: '1', executableDigest: sha256Bytes(input.serverBytes),
    protocol: 'cliq-mcp-reconcile-v1', profiles: [profile, heldProfile], publisherKeyId: keys.releaseKeys[0]?.keyId };
  assert(core.publisherKeyId);
  const adapterDigest = canonicalSha256(core), signature = sign(null, Buffer.from(`cliq-mcp-recovery-adapter-v1\0${adapterDigest}`), keys.privateKey).toString('base64');
  const manifest = decodeMcpRecoveryAdapterManifest({ ...core, adapterDigest, signature }), manifestRef = canonicalSha256(manifest);
  const contents: Content[] = [
    { entryId: manifest.entryId, role: 'mcp_recovery_adapter', version: '1', relativePath: 'mcp/immutable-noop-status-adapter', executable: true, bytes: input.serverBytes },
    { entryId: 'owned-immutable-noop-status-profile-v1', role: 'mcp_recovery_profile', version: '1', relativePath: 'mcp/immutable-noop-status-profile.json', executable: false,
      bytes: canonicalJsonBytes(manifest) },
    ...[staticArguments, completed, failed].map(value => { const ref = canonicalSha256(value); return {
      entryId: `mcp-recovery-object-${ref}`, role: 'bundle_object', version: '1', relativePath: `objects/sha256/${ref.slice(0, 2)}/${ref}`,
      executable: false, bytes: canonicalJsonBytes(value) }; }),
  ];
  return { contents, root: { kind: 'mcp_recovery_adapter', artifactId: manifest.adapterId, rootEntryId: 'owned-immutable-noop-status-profile-v1',
    artifactRef: manifestRef, semanticDigest: manifest.adapterDigest, executableEntryId: manifest.entryId, memberRefs: mcpRecoveryAdapterMemberRefs(manifest) } };
}
