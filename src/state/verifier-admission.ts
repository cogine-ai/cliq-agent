import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantV1 } from '../kernel/authorization.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { RunAssemblyV1, RunSpec, VerifierSpec } from '../kernel/types.js';
import type { VerifierCommandV1, VerifierEnvironmentV1 } from '../kernel/verifier.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { readAuthorizationHistory, type AuthorizationRuntime } from './authorization.js';
import { authorizationGrantCore, decodeAuthorizationConsumptionReceipt, decodeAuthorizationGrant, VerifierAuthorizationError } from './authorization-artifacts.js';
import { KernelStorageError } from './errors.js';
import { readRetainedVerifierToolchain, type RetainedVerifierToolchain } from './guest-toolchain.js';
import { consumeOrRevokeAuthorization, readAuthorizationGrant } from './repositories/authorization-grants.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierSpec } from './verifier-artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { exactKeys, verifyRuntimeBundle } from '../policy/runtime-authority.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { readCheckpoint, readControlRequest, readRun } from './rows.js';
import { readRetainedControlChannelClosure } from './control-channel.js';
import { identityHash } from '../kernel/identity.js';
import { decodeAdmittedContext, decodeRunObjective, decodeUnverifiedConsent } from './decoders.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { GUEST_EXTRACTOR_RECIPE, LINUX_VERIFIER_RESOURCE_MINIMUMS } from '../sandbox/guest-toolchain.js';

const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
/** Validate data properties before traversing arrays or cloning requests. */
export function assertVerifierRequestData(value: unknown): void {
  const ancestors = new Set<object>(); let members = 0;
  function visit(current: unknown, depth: number): void {
    if (++members > 10_000 || depth > 32) throw new TypeError('verifier request exceeds its data bound');
    if (!current || typeof current !== 'object') return;
    if (ancestors.has(current)) throw new TypeError('verifier request cannot contain a cycle');
    ancestors.add(current);
    const isArray = Array.isArray(current);
    if (Object.getPrototypeOf(current) !== (isArray ? Array.prototype : Object.prototype) &&
        !(Object.getPrototypeOf(current) === null && !isArray)) throw new TypeError('verifier request must be plain wire data');
    const fields = Object.getOwnPropertyDescriptors(current);
    if (Reflect.ownKeys(fields).some(key => typeof key !== 'string')) throw new TypeError('verifier request has a symbol field');
    if (isArray && (current.length > 10_000 || Reflect.ownKeys(fields).length !== current.length + 1 ||
        !Array.from({ length: current.length }, (_, index) => String(index)).every(key => Object.hasOwn(fields, key))))
      throw new TypeError('verifier request array has holes or extra fields');
    for (const [key, property] of Object.entries(fields)) {
      if (isArray && key === 'length') continue;
      if (!Object.hasOwn(property, 'value') || !property.enumerable) throw new TypeError('verifier request fields must be enumerable data');
      visit(property.value, depth + 1);
    }
    ancestors.delete(current);
  }
  visit(value, 0);
}
/** Supported executable identity and policy are explicit, not a cast into an
 * ordinary tool or permission inferred from Workspace Trust. */
export function assertSupportedVerifierRequests(requests: readonly VerifierRequest[], mode: string): void {
  assertVerifierRequestData(requests);
  if (!Array.isArray(requests) || requests.length > 32 || new Set(requests.map(request => request.id)).size !== requests.length ||
      new Set(requests.map(request => request.identityReadGrantId)).size !== requests.length) throw new TypeError('verifier identities must be bounded and unique');
  if (requests.length && mode !== 'yolo') throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  for (const request of requests) {
    if (!request || typeof request !== 'object' || Array.isArray(request) || !exactKeys(request,
      ['id', 'version', 'required', 'executable', 'argv', 'cwd', 'env', 'writableEphemeralPaths', 'identityReadGrantId',
        ...(request.executionGrantId === undefined ? [] : ['executionGrantId']), ...(request.timeoutMs === undefined ? [] : ['timeoutMs']),
        ...(request.retries === undefined ? [] : ['retries']), ...(request.outputLimitBytes === undefined ? [] : ['outputLimitBytes'])]) ||
        typeof request.required !== 'boolean') throw new TypeError('verifier request has unknown or missing fields');
    if (request.executionGrantId !== undefined || request.executable.kind !== 'toolchain' || request.executable.toolId !== 'node' ||
        request.writableEphemeralPaths.length || Object.keys(request.env).length || request.argv.length !== 3 ||
        request.argv[0]?.kind !== 'non_secret_literal' || request.argv[0].value !== '--test' ||
        request.argv[1]?.kind !== 'non_secret_literal' || request.argv[1].value !== '--test-concurrency=1' ||
        request.argv[2]?.kind !== 'non_secret_literal' || !request.argv[2].value.endsWith('.mjs') ||
        request.argv[2].value.startsWith('-') || request.argv[2].value.includes('\\') ||
        request.argv[2].value.split('/').some((part: string) => !part || part === '.' || part === '..' || part === '.git') ||
        (request.cwd !== '.' && (request.cwd.includes('\\') || request.cwd.split('/').some((part: string) => !part || part === '.' || part === '..' || part === '.git'))))
      throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    const timeout = request.timeoutMs ?? 600_000, retries = request.retries ?? 0, output = request.outputLimitBytes ?? 4_194_304;
    if (!Number.isSafeInteger(timeout) || timeout < 1000 || timeout > 3_600_000 || !Number.isSafeInteger(retries) || retries < 0 || retries > 3 ||
        !Number.isSafeInteger(output) || output < 65_536 || output > 16_777_216) throw new TypeError('verifier resource request is outside its fixed bounds');
  }
}

export async function readVerifierRequestIdentities(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, principalId: string, requests: readonly VerifierRequest[], historical?: {
    runId: string; admissionIntentDigest: string; admittedAt: string;
  }, signal?: AbortSignal) {
  const resolved = [];
  for (const request of requests) {
    signal?.throwIfAborted();
    const grant = readAuthorizationGrant(driver, request.identityReadGrantId);
    if (!grant || grant.ownerPrincipalId !== principalId || (historical ? grant.state !== 'consumed' : grant.state !== 'active'))
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const checkedAt = historical?.admittedAt ?? sampleCanonicalNow();
    if (checkedAt < grant.createdAt || checkedAt >= grant.expiresAt) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const history = await readAuthorizationHistory(driver, artifacts, owner, grant, runtime.releaseKeys, signal);
    if (checkedAt < history.committedAt) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const target = grant.target;
    if (target.kind !== 'execution_identity_read' || target.purpose !== 'verifier' || target.identity.kind !== 'guest_toolchain' ||
        request.executable.kind !== 'toolchain' || request.executable.toolId !== target.identity.toolId)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const selected = await readRetainedVerifierToolchain(artifacts, { ...runtime,
      guestToolchainManifestRef: target.identity.guestToolchainManifestRef, signal });
    if (selected.manifest.manifestDigest !== target.identity.manifestDigest || selected.manifest.node.logicalName !== target.identity.toolId ||
        selected.manifest.node.canonicalGuestPath !== target.identity.executionPath || selected.manifest.node.digest !== target.identity.executableDigest)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    if (selected.manifest.node.canonicalGuestPath !== '/usr/bin/node') throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    if (historical && grant.state === 'consumed') {
      const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(artifacts, grant.consumptionReceiptRef));
      if (!same(receipt.consumer, { kind: 'run_admission', runId: historical.runId, admissionIntentDigest: historical.admissionIntentDigest }) ||
          receipt.consumedAt !== historical.admittedAt) throw new TypeError('verifier identity was consumed by another admission');
    }
    resolved.push({ request, grant, selected, creationCommittedAt: history.committedAt });
  }
  if (new Set(resolved.map(({ selected }) => selected.manifestRef)).size > 1)
    throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
  return resolved;
}

/** Inert canonical composition used by the real admission producer and its
 * Linux fixture. Caller-supplied data creates no grant, StateOwner, or launch:
 * prepareVerifierSpec independently resolves and consumes actual authority. */
export function composeVerifierSpec(input: { requests: readonly VerifierRequest[]; toolchain?: RetainedVerifierToolchain;
  assembly: RunAssemblyV1; sourceProjectionRef: string }) {
  assertVerifierRequestData(input.requests);
  const values: Array<VerifierCommandV1 | VerifierEnvironmentV1 | VerifierSpec> = [], verifiers: VerifierSpec['verifiers'] = [];
  for (const [index, request] of input.requests.entries()) {
    const selected = input.toolchain;
    if (!selected || request.executable.kind !== 'toolchain' || request.executable.toolId !== selected.manifest.node.logicalName ||
        input.assembly.runtime.guestToolchainManifestRef !== selected.manifestRef ||
        input.assembly.runtime.guestToolchainManifestDigest !== selected.manifest.manifestDigest)
      throw new TypeError('verifier assembly does not bind the exact signed execution toolchain');
    const node = selected.manifest.node;
    const command: VerifierCommandV1 = { schemaVersion: 1, format: 'cliq-verifier-command-v1', verifierId: request.id,
      verifierVersion: request.version, executable: { kind: 'guest_toolchain', guestToolchainManifestRef: selected.manifestRef,
        guestToolchainManifestDigest: selected.manifest.manifestDigest, toolId: node.logicalName, executionPath: node.canonicalGuestPath,
        executableDigest: node.digest, abiFingerprint: selected.abiFingerprint }, argv: [...request.argv], cwd: request.cwd, commandDigest: '' };
    command.commandDigest = digestOmitting(command, 'commandDigest'); decodeVerifierCommand(command);
    const commandRef = canonicalSha256(command); values.push(command);
    const environment: VerifierEnvironmentV1 = { schemaVersion: 1, format: 'cliq-verifier-environment-v1', verifierId: request.id,
      verifierVersion: request.version, commandRef, commandDigest: command.commandDigest,
      variables: Object.keys(request.env).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map(name => ({ name, value: request.env[name]! })),
      writableEphemeralPaths: [...request.writableEphemeralPaths].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))),
      sourceProjectionRef: input.sourceProjectionRef, sourceAccess: 'read_only', networkAccess: 'denied', sandboxProfile: 'cliq-verifier-readonly-v1',
      runtimeBundleRef: input.assembly.runtime.runtimeBundleRef, runtimeBundleManifestDigest: input.assembly.runtime.runtimeBundleManifestDigest,
      guestToolchainManifestRef: selected.manifestRef, guestToolchainManifestDigest: selected.manifest.manifestDigest, environmentDigest: '' };
    environment.environmentDigest = digestOmitting(environment, 'environmentDigest'); decodeVerifierEnvironment(environment);
    const environmentRef = canonicalSha256(environment); values.push(environment);
    const entry: VerifierSpec['verifiers'][number] = { index, id: request.id, version: request.version, gate: request.required ? 'required' : 'advisory',
      commandRef, commandDigest: command.commandDigest, environmentRef, environmentDigest: environment.environmentDigest,
      timeoutMs: request.timeoutMs ?? 600_000, retries: request.retries ?? 0, outputLimitBytes: request.outputLimitBytes ?? 4_194_304, entryDigest: '' };
    entry.entryDigest = digestOmitting(entry, 'entryDigest'); verifiers.push(entry);
  }
  const spec: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers, specDigest: '' };
  spec.specDigest = digestOmitting(spec, 'specDigest'); decodeVerifierSpec(spec);
  values.push(spec);
  return { spec, specRef: canonicalSha256(spec), artifacts: values.map(value => ({ value, format: value.format, ref: canonicalSha256(value) })) };
}

type VerifierPreparationInput = { principalId: string; requests: readonly VerifierRequest[];
  policyMode: string; assembly: RunAssemblyV1; sourceProjectionRef: string; sandboxProfileRef: string };
type VerifierPreparationHistory = { runId: string; admissionIntentDigest: string; admittedAt: string };

async function resolveVerifierSpec(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: VerifierPreparationInput, historical?: VerifierPreparationHistory, signal?: AbortSignal) {
  assertSupportedVerifierRequests(input.requests, input.policyMode);
  const resolved = await readVerifierRequestIdentities(driver, artifacts, owner, runtime, input.principalId, input.requests, historical, signal);
  const profile = resolved.length ? decodeSandboxProfile(await readCanonicalArtifact(artifacts, input.sandboxProfileRef)) : undefined;
  for (const { selected } of resolved) {
    if (input.assembly.runtime.runtimeBundleRef !== canonicalSha256(runtime.bundle) ||
        input.assembly.runtime.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest ||
        input.assembly.runtime.guestToolchainManifestRef !== selected.manifestRef ||
        input.assembly.runtime.guestToolchainManifestDigest !== selected.manifest.manifestDigest)
      throw new TypeError('verifier assembly does not bind the exact signed execution toolchain');
    // The raw signed image conservatively bounds every extracted file. The
    // actual bwrap RO-bind copies remain under the same caller file/process
    // envelope; an unsigned inventory can neither weaken nor enlarge it.
    if (profile!.resources.maxSingleFileBytes < selected.manifest.guestImageByteCount ||
        profile!.resources.maxSingleFileBytes > GUEST_EXTRACTOR_RECIPE.maxImageBytes ||
        profile!.resources.maxProcesses < LINUX_VERIFIER_RESOURCE_MINIMUMS.maxProcesses)
      throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
  }
  return { composed: composeVerifierSpec({ ...input, toolchain: resolved[0]?.selected }), resolved };
}

async function publishVerifierArtifacts(artifacts: ArtifactCatalog, composed: ReturnType<typeof composeVerifierSpec>,
  historical?: VerifierPreparationHistory, signal?: AbortSignal) {
  const metadata: PublishedArtifact[] = [];
  for (const { value, format, ref } of composed.artifacts) {
    signal?.throwIfAborted();
    if (!historical) metadata.push(await artifacts.publishCanonical(value, format));
    else {
      if (!same(await readCanonicalArtifact(artifacts, ref), value)) throw new TypeError('verifier history substitutes an immutable artifact');
      metadata.push(await artifacts.describe(ref, 'application/json', format));
    }
  }
  return metadata;
}

/** Internal inert-data publication seam, not authorization or admission. Only
 * one verifier has exactly the three original objects plus the assembly; all
 * other counts retain the ordinary publisher without padding or republishing.
 * The fixed group's cancellation boundary is after its real complete join. */
export async function publishVerifierAssembly(artifacts: ArtifactCatalog, composed: ReturnType<typeof composeVerifierSpec>,
  assembly: RunAssemblyV1, signal?: AbortSignal): Promise<PublishedArtifact[]> {
  if (composed.spec.verifiers.length !== 1) {
    const metadata = await publishVerifierArtifacts(artifacts, composed, undefined, signal);
    await artifacts.publishCanonical(assembly, assembly.format);
    return metadata;
  }
  if (composed.artifacts.length !== 3) throw new TypeError('one verifier requires its command, environment and spec');
  const [command, environment, spec] = composed.artifacts;
  const publications = [command!, environment!, spec!, { value: assembly, format: assembly.format }];
  const expected = publications.map(({ value, format }) => {
    const bytes = canonicalJsonBytes(value);
    return { ref: sha256Bytes(bytes), byteLength: bytes.byteLength, mediaType: 'application/json', schemaKind: format };
  });
  signal?.throwIfAborted();
  const published = await artifacts.publishCanonicalFour([
    { value: command!.value, schemaKind: command!.format }, { value: environment!.value, schemaKind: environment!.format },
    { value: spec!.value, schemaKind: spec!.format }, { value: assembly, schemaKind: assembly.format }
  ]);
  if (published.length !== 4 || expected.some((wanted, index) => {
    const artifact = published[index];
    return !artifact || artifact.ref !== wanted.ref || artifact.byteLength !== wanted.byteLength ||
      artifact.mediaType !== wanted.mediaType || artifact.schemaKind !== wanted.schemaKind;
  })) throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed verifier publication does not match its complete canonical bytes');
  signal?.throwIfAborted();
  return published.slice(0, 3);
}

/** Deterministic command/environment construction, shared by installed and
 * internal admission; caller refs are never accepted as identity authority. */
export async function prepareVerifierSpec(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: VerifierPreparationInput, historical?: VerifierPreparationHistory, signal?: AbortSignal) {
  const { composed, resolved } = await resolveVerifierSpec(driver, artifacts, owner, runtime, input, historical, signal);
  const metadata = await publishVerifierArtifacts(artifacts, composed, historical, signal);
  return { spec: composed.spec, specRef: composed.specRef, metadata, resolved };
}

/** Current installed admission only. Resolve the same complete original
 * authority before publishing data; historical validation keeps the ordinary
 * read-only path above and never creates or repairs missing objects. */
export async function prepareInstalledVerifierAssembly(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: VerifierPreparationInput, signal?: AbortSignal) {
  const { composed, resolved } = await resolveVerifierSpec(driver, artifacts, owner, runtime, input, undefined, signal);
  const metadata = await publishVerifierAssembly(artifacts, composed, input.assembly, signal);
  return { spec: composed.spec, specRef: composed.specRef, metadata, resolved };
}
export async function prepareVerifierConsumption(artifacts: ArtifactCatalog, prepared: Awaited<ReturnType<typeof prepareVerifierSpec>>,
  input: { runId: string; admissionIntentDigest: string; admittedAt: string }) {
  const transitions: Array<{ prior: AuthorizationGrantV1; next: AuthorizationGrantV1; artifact: PublishedArtifact }> = [];
  for (const { grant, creationCommittedAt } of prepared.resolved) {
    if (grant.state !== 'active' || input.admittedAt < creationCommittedAt || input.admittedAt >= grant.expiresAt)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: grant.grantId, ownerPrincipalId: grant.ownerPrincipalId,
      targetDigest: grant.targetDigest, consumer: { kind: 'run_admission', runId: input.runId, admissionIntentDigest: input.admissionIntentDigest },
      consumedAt: input.admittedAt, receiptDigest: '' };
    receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); decodeAuthorizationConsumptionReceipt(receipt);
    const artifact = await artifacts.publishCanonical(receipt, 'cliq-authorization-consumption-receipt-v1');
    const next: AuthorizationGrantV1 = { ...authorizationGrantCore(grant), grantCoreDigest: grant.grantCoreDigest, rowVersion: 2,
      state: 'consumed', useCount: 1, consumptionReceiptRef: artifact.ref, consumedAt: input.admittedAt, rowDigest: '' };
    next.rowDigest = digestOmitting(next, 'rowDigest'); decodeAuthorizationGrant(next);
    transitions.push({ prior: grant, next, artifact });
  }
  return { metadata: transitions.map(transition => transition.artifact), refs: transitions.map(transition => transition.artifact.ref),
    commit(connection: SqliteConnection, now: string) {
      for (const { prior, next } of transitions) {
        if (!same(readAuthorizationGrant(connection, prior.grantId), prior) || now < input.admittedAt || now >= prior.expiresAt)
          throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
        consumeOrRevokeAuthorization(connection, prior, next);
      }
    } };
}

/** Reproduce the original frozen admission, never reconstruct lost commands or
 * derive authority from today's public request/channel/installed selection. */
export async function validateVerifierRunAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, runId: string, signal?: AbortSignal): Promise<{ authorizationReceiptRefs: string[] }> {
  signal?.throwIfAborted();
  const run = readRun(driver, runId), spec = await readCanonicalArtifact<RunSpec>(artifacts, run.specRef);
  if (spec.operation === 'delivery') {
    verifyRuntimeBundle(runtime.bundle, runtime.releaseKeys);
    const { readDeliveryRunAdmission } = await import('./reducers/delivery-admission.js');
    const original = await readDeliveryRunAdmission(driver, artifacts, runId, { signal });
    if (!same(original.run, run) || !same(original.spec, spec) ||
        original.source.assembly.runtime.runtimeBundleRef !== canonicalSha256(runtime.bundle) ||
        original.source.assembly.runtime.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest)
      throw new TypeError('delivery verifier admission changed its original retained source runtime');
    return { authorizationReceiptRefs: [] };
  }
  const frozen = decodeVerifierSpec(await readCanonicalArtifact(artifacts, spec.verifierSpecRef));
  if (!frozen.verifiers.length) return { authorizationReceiptRefs: [] };
  const admission = driver.prepare('SELECT principal_id, admission_key, admission_intent_digest, admitted_request_digest, admission_request_id FROM runs WHERE id = ?')
    .get<{ principal_id: string; admission_key: string; admission_intent_digest: string; admitted_request_digest: string; admission_request_id: string }>(runId);
  if (!admission || !admission.admission_request_id) throw new TypeError('verifier Run has no original admission request');
  const control = readControlRequest(driver, admission.principal_id, 'run.submit', admission.admission_request_id);
  if (!control || control.committedAt !== run.createdAt) throw new TypeError('verifier Run has no matching original control row');
  const { channel } = await readRetainedControlChannelClosure(artifacts, owner, { principalId: admission.principal_id,
    channelIdentityRef: control.channelIdentityRef, channelIdentityDigest: control.channelIdentityDigest });
  if (channel.openedAt > run.createdAt) throw new TypeError('verifier admission precedes its original authenticated channel');
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, control.requestDigest);
  let requests: VerifierRequest[], intent: string, objectiveText: unknown, expectedContextRevision: unknown, allowUnverified: unknown;
  if (Object.hasOwn(core, 'verifiers')) {
    const { normalizeRunSubmitRequest, runSubmitIntentDigest } = await import('./source-target.js');
    const normalized = normalizeRunSubmitRequest({ ...core, requestDigest: control.requestDigest });
    const request = normalized.request;
    if (request.requestId !== admission.admission_request_id || request.admissionKey !== admission.admission_key ||
        request.sessionId !== run.sessionId) throw new TypeError('verifier original public request names another Run');
    requests = request.verifiers; intent = runSubmitIntentDigest(admission.principal_id, request);
    objectiveText = request.objective; expectedContextRevision = request.expectedContextRevision; allowUnverified = request.allowUnverified;
  } else {
    if (!exactKeys(core, ['protocolVersion', 'requestId', 'method', 'admissionKey', 'sessionId', 'expectedContextRevision', 'workspacePath',
      'objective', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'verifierRequests', 'credentialGrantRefs',
      'budgets', 'allowUnverified', 'sourceProjectionRef', 'frozenIgnoreRulesRef', 'baseWorkspaceManifestRef']) ||
        core.protocolVersion !== 1 || core.method !== 'run.submit' || core.requestId !== admission.admission_request_id ||
        core.admissionKey !== admission.admission_key || core.sessionId !== run.sessionId || core.verifierSpecRef !== spec.verifierSpecRef ||
        core.assemblyRef !== spec.assemblyRef || core.policyRef !== spec.policyRef || core.sandboxProfileRef !== spec.sandboxProfileRef ||
        core.sourceProjectionRef !== spec.sourceProjectionRef || core.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef ||
        !same(core.budgets, spec.budgets) || !same(core.credentialGrantRefs, spec.credentialGrantRefs))
      throw new TypeError('verifier internal admission is not its original frozen request');
    const { protocolVersion: _protocol, requestId: _requestId, admissionKey: _key, ...request } = core;
    intent = canonicalSha256({ principalId: admission.principal_id, method: 'run.submit', request });
    requests = core.verifierRequests as VerifierRequest[];
    objectiveText = core.objective; expectedContextRevision = core.expectedContextRevision; allowUnverified = core.allowUnverified;
  }
  if (intent !== admission.admission_intent_digest || run.id !== identityHash('cliq-run-id-v1', admission.principal_id, 'run.submit', admission.admission_key))
    throw new TypeError('verifier admission intent no longer reproduces the original Run');
  const objective = decodeRunObjective(await readCanonicalArtifact(artifacts, spec.objectiveRef));
  const context = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
  if (objective.utf8 !== objectiveText || context.sessionId !== run.sessionId || context.sessionContextRevision !== expectedContextRevision)
    throw new TypeError('verifier admission changed its original objective or context');
  if (frozen.verifiers.some(entry => entry.gate === 'required')) {
    if (allowUnverified !== false || spec.unverifiedConsentRef !== undefined) throw new TypeError('required verifier cannot carry unverified consent');
  } else {
    const consent = decodeUnverifiedConsent(await readCanonicalArtifact(artifacts, spec.unverifiedConsentRef!));
    const { unverifiedConsentRef: _consent, ...specCore } = spec;
    if (allowUnverified !== true || consent.kind !== 'direct_unverified_consent' || consent.principalId !== admission.principal_id ||
        consent.admissionIntentDigest !== intent || consent.createdAt !== run.createdAt || consent.runSpecCoreDigest !== canonicalSha256(specCore) ||
        consent.channelIdentityRef !== control.channelIdentityRef || consent.channelIdentityDigest !== control.channelIdentityDigest ||
        !same(consent.client, channel.client)) throw new TypeError('advisory verifier changed its original direct consent');
  }
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  const bundle = await readCanonicalArtifact<AuthorizationRuntime['bundle']>(artifacts, assembly.runtime.runtimeBundleRef);
  const policy = await readCanonicalArtifact<{ mode: string }>(artifacts, spec.policyRef);
  const prepared = await prepareVerifierSpec(driver, artifacts, owner, { bundle, releaseKeys: runtime.releaseKeys },
    { principalId: admission.principal_id, requests, policyMode: policy.mode, assembly, sourceProjectionRef: spec.sourceProjectionRef,
      sandboxProfileRef: spec.sandboxProfileRef },
    { runId, admissionIntentDigest: intent, admittedAt: run.createdAt }, signal);
  if (prepared.specRef !== spec.verifierSpecRef || !same(prepared.spec, frozen)) throw new TypeError('verifier Run changed its original command/environment/spec');
  const checkpoint = readCheckpoint(driver, identityHash('cliq-checkpoint-id-v1', run.id, 'initial', 0));
  const source = await readCanonicalArtifact<{ workspaceIdentityDigest: string; frozenIgnoreRulesRef: string; git?: { repositoryIdentityDigest: string } }>(artifacts, spec.baseWorkspaceManifestRef);
  const authorizationReceiptRefs = prepared.resolved.map(({ grant }) => grant.state === 'consumed' ? grant.consumptionReceiptRef : '');
  const digest = canonicalSha256({ admissionIntentDigest: intent, objectiveRef: spec.objectiveRef, admittedContextRef: spec.admittedContextRef,
    runSpecRef: run.specRef, workspaceIdentityDigest: source.workspaceIdentityDigest, repositoryIdentityDigest: source.git?.repositoryIdentityDigest ?? null,
    sourceProjectionRef: spec.sourceProjectionRef, frozenIgnoreRulesRef: source.frozenIgnoreRulesRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
    workspaceStateRef: checkpoint.workspaceStateRef, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef,
    verifierSpecRef: spec.verifierSpecRef, unverifiedConsentRef: spec.unverifiedConsentRef ?? null, credentialGrantRefs: spec.credentialGrantRefs,
    authorizationReceiptRefs });
  if (digest !== admission.admitted_request_digest) throw new TypeError('verifier admission resolved authorization closure changed');
  const frontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-turn-id-v1', run.id, 'initial'), contextItemSeq: 0, cause: 'initial' };
  const initial = { id: run.id, sessionId: run.sessionId, specRef: run.specRef, status: 'queued', nextStep: 'agent', frontierRef: canonicalSha256(frontier),
    revision: 1, leaseEpoch: 0, latestCheckpointId: checkpoint.id, budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0, cancelRequested: false,
    createdAt: run.createdAt, deadlineAt: run.deadlineAt, updatedAt: run.createdAt };
  const expected = { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: {
    schemaVersion: 1, operation: 'agent', run: initial, latestRunItemSeq: 0 } } };
  if (!same(await readCanonicalArtifact(artifacts, control.responseRef), expected)) throw new TypeError('verifier original response substitutes its committed Run');
  return { authorizationReceiptRefs };
}
