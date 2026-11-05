// One derivation for Admin publication and historical frozen-registry reads.
// All input artifacts are verified as original CAS bytes before selection.
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { decodeAdminProbePayloadCore, decodeMcpAdminProbeTarget, decodeMcpAdminProbeResult, decodeMcpRecoveryContract,
  type McpAdminProbeTargetV1, type McpAdminProbeResultV1, type McpRegisterRequestV1, type McpRegistryRevisionV1,
  type RequestedMcpRecoveryV1, type McpToolContractV1 } from '../kernel/mcp.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryPredicate, decodeMcpRecoveryStatusRequestTemplate,
  decodeMcpRetryRiskConsent, decodeMcpRetrySafetyAssertion, injectMcpIdempotencyKey, mcpRetryRequestFromAssertion,
  mcpProfileSigningIdentityDigest, mcpServerExecutionIdentityDigest, type McpRecoveryStatusRequestTemplateV1 } from '../kernel/mcp-recovery.js';
import { compileInputSchema, compileOutputSchema } from '../tools/input-schema.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { selectMcpRecoveryProfile, verifyMcpRecoveryAdapterAuthority } from '../policy/mcp-recovery-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import type { AuthenticatedControlIdentity } from './control-channel.js';

type RequestedTools = McpAdminProbeTargetV1['requestedToolRecovery'];
const sortedRequests = (request: McpRegisterRequestV1) => Object.entries(request.toolRecovery)
  .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)));

/** Called before constructing the first target. A failed attempt reuses that
 * exact target; it cannot manufacture a new consent on a different channel. */
export async function publishMcpRequestedRecovery(artifacts: ArtifactCatalog, request: McpRegisterRequestV1,
  identity: AuthenticatedControlIdentity, createdAt: string): Promise<Readonly<{ requested: RequestedTools; metadata: PublishedArtifact[] }>> {
  const metadata: PublishedArtifact[] = [], requested: Array<RequestedTools[number]> = [];
  for (const [toolName, recovery] of sortedRequests(request)) {
    if (recovery.kind !== 'retry') { requested.push({ toolName, recovery }); continue; }
    const recoveryRequestDigest = canonicalSha256(recovery);
    const consentCore = { schemaVersion: 1 as const, format: 'cliq-mcp-retry-risk-consent-v1' as const,
      ownerPrincipalId: identity.principalId, registrationId: request.registrationId, serverToolName: toolName, recoveryRequestDigest,
      acknowledgedRisk: 'prior_attempt_may_have_succeeded_and_retry_may_duplicate_effect' as const,
      channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest, createdAt };
    const assertionCore = { schemaVersion: 1 as const, format: 'cliq-mcp-retry-safety-assertion-v1' as const,
      ownerPrincipalId: identity.principalId, registrationId: request.registrationId, serverToolName: toolName, recoveryRequestDigest,
      assertion: 'no_server_safety_claim_duplicate_effect_remains_possible' as const,
      ...(recovery.idempotencyKeyJsonPointer === undefined ? {} : { idempotencyKeyJsonPointer: recovery.idempotencyKeyJsonPointer }) };
    const consent = decodeMcpRetryRiskConsent({ ...consentCore, consentDigest: canonicalSha256(consentCore) });
    const assertion = decodeMcpRetrySafetyAssertion({ ...assertionCore, assertionDigest: canonicalSha256(assertionCore) });
    const consentArtifact = await artifacts.publishCanonical(consent, consent.format), assertionArtifact = await artifacts.publishCanonical(assertion, assertion.format);
    metadata.push(consentArtifact, assertionArtifact);
    requested.push({ toolName, recovery: { kind: 'retry', explicitRiskConsentRef: consentArtifact.ref, explicitRiskConsentDigest: consent.consentDigest,
      safetyAssertionRef: assertionArtifact.ref, safetyAssertionDigest: assertion.assertionDigest,
      ...(recovery.idempotencyKeyJsonPointer === undefined ? {} : { idempotencyKeyJsonPointer: recovery.idempotencyKeyJsonPointer }) } });
  }
  return { requested: immutableSnapshot(requested), metadata };
}
async function readRetry(artifacts: ArtifactCatalog, target: Pick<McpAdminProbeTargetV1, 'ownerPrincipalId' | 'registrationId'>,
  toolName: string, requested: Extract<RequestedMcpRecoveryV1, {kind: 'retry'}>) {
  const consent = decodeMcpRetryRiskConsent(await readCanonicalArtifact(artifacts, requested.explicitRiskConsentRef));
  const assertion = decodeMcpRetrySafetyAssertion(await readCanonicalArtifact(artifacts, requested.safetyAssertionRef));
  if (consent.consentDigest !== requested.explicitRiskConsentDigest || assertion.assertionDigest !== requested.safetyAssertionDigest ||
      consent.ownerPrincipalId !== target.ownerPrincipalId || assertion.ownerPrincipalId !== target.ownerPrincipalId ||
      consent.registrationId !== target.registrationId || assertion.registrationId !== target.registrationId ||
      consent.serverToolName !== toolName || assertion.serverToolName !== toolName ||
      consent.recoveryRequestDigest !== assertion.recoveryRequestDigest || assertion.idempotencyKeyJsonPointer !== requested.idempotencyKeyJsonPointer)
    throw new TypeError('MCP retry substitutes its original principal/tool/request consent or safety assertion');
  return { consent, assertion, request: mcpRetryRequestFromAssertion(assertion) };
}
export async function validateMcpOriginalRequestedRecovery(artifacts: ArtifactCatalog, request: McpRegisterRequestV1, targetValue: McpAdminProbeTargetV1): Promise<void> {
  const target = decodeMcpAdminProbeTarget(targetValue), expected = sortedRequests(request);
  if (target.requestedToolRecovery.length !== expected.length) throw new TypeError('MCP target changes its explicit original recovery tool set');
  for (let index = 0; index < expected.length; index++) {
    const pair = expected[index], selected = target.requestedToolRecovery[index];
    if (!pair || !selected || pair[0] !== selected.toolName) throw new TypeError('MCP target recovery names/order differ from its original request');
    const recovery = pair[1];
    if (recovery.kind !== 'retry') { requireEqual(selected.recovery, recovery, 'MCP original exact manual/reconcile request'); continue; }
    if (selected.recovery.kind !== 'retry') throw new TypeError('MCP target drops original duplicate-effect consent');
    const original = await readRetry(artifacts, target, selected.toolName, selected.recovery);
    requireEqual(original.request, recovery, 'MCP original normalized retry request');
    if (original.consent.channelIdentityRef !== target.channelIdentityRef || original.consent.channelIdentityDigest !== target.channelIdentityDigest ||
        original.consent.createdAt !== target.createdAt) throw new TypeError('MCP retry consent substitutes its original authenticated channel/time');
  }
}
/** Copy-only refresh reconstructs pre-final selectors, not old templates.
 * The new raw probe must independently match the same signed adapter. */
export async function mcpRequestedRecoveryFromRegistry(artifacts: ArtifactCatalog, registry: McpRegistryRevisionV1): Promise<RequestedTools> {
  const requested: Array<RequestedTools[number]> = [];
  for (const tool of registry.tools) {
    const recovery = decodeMcpRecoveryContract(tool.recovery);
    if (recovery.kind === 'manual') requested.push({ toolName: tool.name, recovery });
    else if (recovery.kind === 'retry') requested.push({ toolName: tool.name, recovery: { kind: 'retry',
      explicitRiskConsentRef: recovery.explicitRiskConsentRef, explicitRiskConsentDigest: recovery.explicitRiskConsentDigest,
      safetyAssertionRef: recovery.safetyAssertionRef, safetyAssertionDigest: recovery.safetyAssertionDigest,
      ...(recovery.idempotencyKeyInjection === undefined ? {} : { idempotencyKeyJsonPointer: recovery.idempotencyKeyInjection.jsonPointer }) } });
    else {
      const manifest = decodeMcpRecoveryAdapterManifest(await readCanonicalArtifact(artifacts, recovery.adapterRef));
      if (manifest.adapterDigest !== recovery.adapterDigest) throw new TypeError('MCP refresh changes original signed adapter digest');
      requested.push({ toolName: tool.name, recovery: { kind: 'reconcile', bundledAdapterId: manifest.adapterId,
        idempotencyKeyJsonPointer: recovery.idempotencyKeyInjection.jsonPointer } });
    }
  }
  return immutableSnapshot(requested);
}
type Derived = Readonly<{ tools: readonly McpToolContractV1[]; templates: readonly McpRecoveryStatusRequestTemplateV1[] }>;
export async function deriveMcpRecoveryToolContracts(artifacts: ArtifactCatalog, input: Readonly<{
  target: McpAdminProbeTargetV1; targetRef: string; result: McpAdminProbeResultV1; resultRef: string;
  probePayloadCoreRef: string; registryRevision: number;
}>): Promise<Derived> {
  const target = decodeMcpAdminProbeTarget(input.target), result = decodeMcpAdminProbeResult(input.result);
  if (input.targetRef !== canonicalSha256(target) || input.resultRef !== canonicalSha256(result) || result.targetRef !== input.targetRef ||
      result.targetDigest !== target.targetDigest || result.probePayloadCoreRef !== input.probePayloadCoreRef)
    throw new TypeError('MCP recovery derivation lacks its complete original target/raw probe result');
  const byName = new Map(target.requestedToolRecovery.map(item => [item.toolName, item.recovery]));
  if (target.requestedToolRecovery.some(item => result.normalizedTools.filter(tool => tool.name === item.toolName).length !== 1))
    throw new TypeError('MCP explicitly requested recovery tool is absent or ambiguous in original discovery');
  const tools: McpToolContractV1[] = [], templates: McpRecoveryStatusRequestTemplateV1[] = [];
  let bundle: RuntimeBundleManifest | undefined;
  for (const tool of result.normalizedTools) {
    const requested = byName.get(tool.name) ?? { kind: 'manual' as const };
    let recovery: McpToolContractV1['recovery'];
    if (requested.kind === 'manual') recovery = requested;
    else if (requested.kind === 'retry') {
      await readRetry(artifacts, target, tool.name, requested);
      recovery = { kind: 'retry', explicitRiskConsentRef: requested.explicitRiskConsentRef, explicitRiskConsentDigest: requested.explicitRiskConsentDigest,
        safetyAssertionRef: requested.safetyAssertionRef, safetyAssertionDigest: requested.safetyAssertionDigest,
        ...(requested.idempotencyKeyJsonPointer === undefined ? {} : { idempotencyKeyInjection: { jsonPointer: requested.idempotencyKeyJsonPointer } }) };
    } else {
      if (!bundle) {
        const core = decodeAdminProbePayloadCore(await readCanonicalArtifact(artifacts, input.probePayloadCoreRef));
        bundle = await readCanonicalArtifact(artifacts, core.runtimeBundleRef) as RuntimeBundleManifest;
        verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
        if (bundle.manifestDigest !== core.runtimeBundleManifestDigest) throw new TypeError('MCP recovery changes original signed Admin Bundle digest');
      }
      const roots = bundle.structuredArtifacts.filter(root => root.kind === 'mcp_recovery_adapter' && root.artifactId === requested.bundledAdapterId), root = roots[0];
      if (roots.length !== 1 || !root) throw new TypeError('MCP recovery adapter selector has no unique signed original Bundle root');
      const manifest = verifyMcpRecoveryAdapterAuthority({ bundle, releaseKeys: artifacts.releaseTrustRoots(), adapterId: requested.bundledAdapterId,
        adapterRef: root.artifactRef, manifest: await readCanonicalArtifact(artifacts, root.artifactRef) });
      const executable = bundle.entries.find(entry => entry.entryId === manifest.entryId);
      if (!executable) throw new TypeError('MCP signed status adapter has no original executable bytes');
      for await (const _chunk of artifacts.readChunks(executable.digest, executable.byteCount)) artifacts.assertReadActive();
      const profile = selectMcpRecoveryProfile({ bundle, target, result, manifest, serverToolName: tool.name });
      const completed = decodeMcpRecoveryPredicate(await readCanonicalArtifact(artifacts, profile.completedPredicateRef));
      const failed = decodeMcpRecoveryPredicate(await readCanonicalArtifact(artifacts, profile.failedPredicateRef));
      if (completed.predicateDigest !== profile.completedPredicateDigest || failed.predicateDigest !== profile.failedPredicateDigest ||
          completed.predicateDigest === failed.predicateDigest) throw new TypeError('MCP signed profile substitutes its distinct original predicates');
      const staticArguments = await readCanonicalArtifact(artifacts, profile.staticArgumentsRef);
      // Shape/parent validation only. The actual stable key is unavailable at
      // registration; its exact resulting arguments are schema-checked before
      // every genuine status release.
      injectMcpIdempotencyKey(staticArguments, requested.idempotencyKeyJsonPointer, identityHash('cliq-mcp-status-shape-check-v1'));
      compileInputSchema(await readCanonicalArtifact(artifacts, profile.statusInputSchemaDigest));
      compileOutputSchema(await readCanonicalArtifact(artifacts, profile.statusOutputSchemaDigest));
      const core = { schemaVersion: 1 as const, format: 'cliq-mcp-recovery-status-template-v1' as const,
        adapterRef: root.artifactRef, adapterDigest: manifest.adapterDigest, profileId: profile.profileId, profileDigest: profile.profileDigest,
        registrationId: target.registrationId, registryRevision: input.registryRevision, adminProbeTargetRef: input.targetRef, adminProbeTargetDigest: target.targetDigest,
        probeResultRef: input.resultRef, probeResultDigest: result.resultDigest, serverToolName: tool.name,
        serverExecutionIdentityDigest: mcpServerExecutionIdentityDigest(target.resolvedTransport), profileSigningIdentityDigest: mcpProfileSigningIdentityDigest(target.resolvedTransport),
        initializeDigest: profile.initializeDigest, capabilityDigest: profile.capabilityDigest, probedToolsListDigest: profile.probedToolsListDigest,
        effectToolInterfaceDigest: profile.effectToolInterfaceDigest, statusOperationName: profile.statusOperationName,
        statusOperationSemantics: profile.statusOperationSemantics, statusToolInterfaceDigest: profile.statusToolInterfaceDigest,
        statusInputSchemaDigest: profile.statusInputSchemaDigest, statusOutputSchemaDigest: profile.statusOutputSchemaDigest,
        idempotencyKeyJsonPointer: requested.idempotencyKeyJsonPointer, staticArgumentsRef: profile.staticArgumentsRef, staticArgumentsDigest: profile.staticArgumentsDigest };
      const template = decodeMcpRecoveryStatusRequestTemplate({ ...core, templateDigest: canonicalSha256(core) }); templates.push(template);
      recovery = { kind: 'reconcile', adapterRef: root.artifactRef, adapterDigest: manifest.adapterDigest, profileId: profile.profileId, profileDigest: profile.profileDigest,
        idempotencyKeyInjection: { jsonPointer: requested.idempotencyKeyJsonPointer }, statusRequestTemplateRef: canonicalSha256(template),
        statusRequestTemplateDigest: template.templateDigest, completedPredicateRef: profile.completedPredicateRef, completedPredicateDigest: profile.completedPredicateDigest,
        failedPredicateRef: profile.failedPredicateRef, failedPredicateDigest: profile.failedPredicateDigest };
    }
    const core = { ...tool, version: 'mcp-tool-contract-v1' as const, recovery: decodeMcpRecoveryContract(recovery) };
    tools.push({ ...core, toolContractDigest: canonicalSha256(core) });
  }
  return immutableSnapshot({ tools, templates });
}
export async function readMcpRecoveryTemplates(artifacts: ArtifactCatalog, derived: Derived): Promise<void> {
  for (const expected of derived.templates) {
    const actual = decodeMcpRecoveryStatusRequestTemplate(await readCanonicalArtifact(artifacts, canonicalSha256(expected)));
    requireEqual(actual, expected, 'MCP complete original per-registration status template');
  }
}
