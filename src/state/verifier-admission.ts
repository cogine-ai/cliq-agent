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
import { guestToolchainRoots, readRetainedVerifierToolchain, type RetainedVerifierToolchain } from './guest-toolchain.js';
import { consumeOrRevokeAuthorization, readAuthorizationGrant } from './repositories/authorization-grants.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { decodeVerifierCommand, decodeVerifierEnvironment, decodeVerifierSpec } from './verifier-artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { exactKeys, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { readRun } from './rows.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { GUEST_EXTRACTOR_RECIPE, LINUX_VERIFIER_RESOURCE_MINIMUMS } from '../sandbox/guest-toolchain.js';
import type { InstalledApplyDiagnosticStage } from './installed-run-diagnostics.js';

const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
type InstalledVerifierPreparationPhase = Extract<InstalledApplyDiagnosticStage, `submit_assembly_verifier_${string}`>;
/** Fixed data diagnosis only; a sink cannot replace the original operation. */
function reportInstalledVerifierPreparationPhase(observer: ((phase: InstalledVerifierPreparationPhase) => void) | undefined,
  phase: InstalledVerifierPreparationPhase): void {
  try { observer?.(phase); } catch { /* Diagnosis cannot decide verifier preparation. */ }
}
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

/** Reference selection inside an already verified installed borrow only.
 * This reads no target/history CAS and returns neither authorization nor a
 * verified toolchain. Full history, signature/image, executable and profile
 * validation still precedes Run admission and exact final grant consumption. */
export function selectVerifierReleaseReference(driver: SqliteDriver, bundle: RuntimeBundleManifest,
  principalId: string, requests: readonly VerifierRequest[], policyMode: string, signal?: AbortSignal):
Readonly<{ manifestRef: string; manifestDigest: string }> | undefined {
  signal?.throwIfAborted();
  assertSupportedVerifierRequests(requests, policyMode);
  if (!requests.length) return undefined;
  const roots = guestToolchainRoots(bundle);
  let selected: Readonly<{ manifestRef: string; manifestDigest: string }> | undefined;
  for (const request of requests) {
    signal?.throwIfAborted();
    const grant = readAuthorizationGrant(driver, request.identityReadGrantId);
    if (!grant || grant.ownerPrincipalId !== principalId || grant.state !== 'active')
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const checkedAt = sampleCanonicalNow();
    if (checkedAt < grant.createdAt || checkedAt >= grant.expiresAt) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const target = grant.target;
    if (target.kind !== 'execution_identity_read' || target.purpose !== 'verifier' || target.identity.kind !== 'guest_toolchain' ||
        request.executable.kind !== 'toolchain' || request.executable.toolId !== target.identity.toolId)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const identity = target.identity;
    const matches = roots.filter(root => root.artifactRef === identity.guestToolchainManifestRef &&
      root.semanticDigest === identity.manifestDigest);
    if (matches.length !== 1) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const root = matches[0]!;
    if (selected && (selected.manifestRef !== root.artifactRef || selected.manifestDigest !== root.semanticDigest))
      throw new VerifierAuthorizationError('UNSUPPORTED_EXECUTION_IDENTITY');
    selected = Object.freeze({ manifestRef: root.artifactRef, manifestDigest: root.semanticDigest });
  }
  signal?.throwIfAborted();
  return selected;
}

export async function readVerifierRequestIdentities(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, principalId: string, requests: readonly VerifierRequest[], historical?: {
    runId: string; admissionIntentDigest: string; admittedAt: string;
  }, signal?: AbortSignal, onPreparationPhase?: (phase: InstalledVerifierPreparationPhase) => void) {
  const resolved = [];
  for (const request of requests) {
    signal?.throwIfAborted();
    const grant = readAuthorizationGrant(driver, request.identityReadGrantId);
    if (!grant || grant.ownerPrincipalId !== principalId || (historical ? grant.state !== 'consumed' : grant.state !== 'active'))
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const checkedAt = historical?.admittedAt ?? sampleCanonicalNow();
    if (checkedAt < grant.createdAt || checkedAt >= grant.expiresAt) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    reportInstalledVerifierPreparationPhase(onPreparationPhase, 'submit_assembly_verifier_history');
    const history = await readAuthorizationHistory(driver, artifacts, owner, grant, runtime.releaseKeys, signal);
    if (checkedAt < history.committedAt) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const target = grant.target;
    if (target.kind !== 'execution_identity_read' || target.purpose !== 'verifier' || target.identity.kind !== 'guest_toolchain' ||
        request.executable.kind !== 'toolchain' || request.executable.toolId !== target.identity.toolId)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    reportInstalledVerifierPreparationPhase(onPreparationPhase, 'submit_assembly_verifier_current');
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
  runtime: AuthorizationRuntime, input: VerifierPreparationInput, historical?: VerifierPreparationHistory, signal?: AbortSignal,
  onPreparationPhase?: (phase: InstalledVerifierPreparationPhase) => void) {
  assertSupportedVerifierRequests(input.requests, input.policyMode);
  const resolved = await readVerifierRequestIdentities(driver, artifacts, owner, runtime, input.principalId, input.requests, historical, signal, onPreparationPhase);
  reportInstalledVerifierPreparationPhase(onPreparationPhase, 'submit_assembly_verifier_compose');
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
  // Fresh final resolution still republishes every complete object. Only its
  // one-verifier command/environment/spec share the existing four barriers;
  // history never enters this branch or repairs a missing retained object.
  if (!historical && composed.spec.verifiers.length === 1) {
    if (composed.artifacts.length !== 3) throw new TypeError('one verifier requires its command, environment and spec');
    signal?.throwIfAborted();
    const [command, environment, spec] = composed.artifacts;
    const expected = composed.artifacts.map(({ value, format }) => {
      const bytes = canonicalJsonBytes(value);
      return { ref: sha256Bytes(bytes), byteLength: bytes.byteLength, mediaType: 'application/json', schemaKind: format };
    });
    const published = await artifacts.publishCanonicalTriple([
      { value: command!.value, schemaKind: command!.format }, { value: environment!.value, schemaKind: environment!.format },
      { value: spec!.value, schemaKind: spec!.format }
    ]);
    if (published.length !== 3 || expected.some((wanted, index) => {
      const actual = published[index];
      return !actual || actual.ref !== wanted.ref || actual.byteLength !== wanted.byteLength ||
        actual.mediaType !== wanted.mediaType || actual.schemaKind !== wanted.schemaKind;
    })) throw new KernelStorageError('ARTIFACT_MISMATCH', 'final verifier publication differs from its complete canonical bytes');
    signal?.throwIfAborted();
    return [...published];
  }
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
    signal?.throwIfAborted();
    await artifacts.publishCanonical(assembly, assembly.format);
    signal?.throwIfAborted();
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
  runtime: AuthorizationRuntime, input: VerifierPreparationInput, signal?: AbortSignal,
  onPreparationPhase?: (phase: InstalledVerifierPreparationPhase) => void) {
  const { composed, resolved } = await resolveVerifierSpec(driver, artifacts, owner, runtime, input, undefined, signal, onPreparationPhase);
  reportInstalledVerifierPreparationPhase(onPreparationPhase, 'submit_assembly_verifier_publish');
  const metadata = await publishVerifierAssembly(artifacts, composed, input.assembly, signal);
  return { spec: composed.spec, specRef: composed.specRef, metadata, resolved };
}
type VerifierConsumer = { runId: string; admissionIntentDigest: string; admittedAt: string };
function composeVerifierConsumption({ grant, creationCommittedAt }: Awaited<ReturnType<typeof resolveVerifierSpec>>['resolved'][number],
  input: VerifierConsumer) {
  if (grant.state !== 'active' || input.admittedAt < creationCommittedAt || input.admittedAt >= grant.expiresAt)
    throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: grant.grantId, ownerPrincipalId: grant.ownerPrincipalId,
    targetDigest: grant.targetDigest, consumer: { kind: 'run_admission', runId: input.runId, admissionIntentDigest: input.admissionIntentDigest },
    consumedAt: input.admittedAt, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); decodeAuthorizationConsumptionReceipt(receipt);
  const next: AuthorizationGrantV1 = { ...authorizationGrantCore(grant), grantCoreDigest: grant.grantCoreDigest, rowVersion: 2,
    state: 'consumed', useCount: 1, consumptionReceiptRef: canonicalSha256(receipt), consumedAt: input.admittedAt, rowDigest: '' };
  next.rowDigest = digestOmitting(next, 'rowDigest'); decodeAuthorizationGrant(next);
  return { prior: grant, next, receipt };
}
function verifierConsumptionResult(transitions: Array<ReturnType<typeof composeVerifierConsumption> & { artifact: PublishedArtifact }>,
  input: VerifierConsumer) {
  return { metadata: transitions.map(transition => transition.artifact), refs: transitions.map(transition => transition.artifact.ref),
    commit(connection: SqliteConnection, now: string) {
      for (const { prior, next } of transitions) {
        if (!same(readAuthorizationGrant(connection, prior.grantId), prior) || now < input.admittedAt || now >= prior.expiresAt)
          throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
        consumeOrRevokeAuthorization(connection, prior, next);
      }
    } };
}

export async function prepareVerifierConsumption(artifacts: ArtifactCatalog, prepared: Awaited<ReturnType<typeof prepareVerifierSpec>>,
  input: VerifierConsumer, signal?: AbortSignal) {
  signal?.throwIfAborted();
  const transitions = [];
  for (const resolved of prepared.resolved) {
    signal?.throwIfAborted();
    const transition = composeVerifierConsumption(resolved, input);
    const artifact = await artifacts.publishCanonical(transition.receipt, 'cliq-authorization-consumption-receipt-v1');
    signal?.throwIfAborted();
    transitions.push({ ...transition, artifact });
  }
  return verifierConsumptionResult(transitions, input);
}

/** Data publication after the fresh resolver, never authorization by an
 * earlier assembly. The original SQL consumer remains the only transition. */
async function publishInstalledVerifierAdmission(artifacts: ArtifactCatalog, resolution: Awaited<ReturnType<typeof resolveVerifierSpec>>,
  consumer: VerifierConsumer, expectedSpecRef: string, signal?: AbortSignal) {
  const { composed, resolved } = resolution;
  signal?.throwIfAborted();
  if (composed.specRef !== expectedSpecRef)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier spec differs from the authorized public command and environment');
  if (composed.spec.verifiers.length !== 1 || composed.artifacts.length !== 3 || resolved.length !== 1)
    throw new TypeError('one verifier requires three artifacts and one original grant');
  const transition = composeVerifierConsumption(resolved[0]!, consumer), [command, environment, spec] = composed.artifacts;
  const publications = [command!, environment!, spec!, { value: transition.receipt, format: 'cliq-authorization-consumption-receipt-v1' }];
  const expected = publications.map(({ value, format }) => ({ ref: canonicalSha256(value), byteLength: canonicalJsonBytes(value).length,
    mediaType: 'application/json', schemaKind: format }));
  const published = await artifacts.publishCanonicalFour([
    { value: command!.value, schemaKind: command!.format }, { value: environment!.value, schemaKind: environment!.format },
    { value: spec!.value, schemaKind: spec!.format }, { value: transition.receipt, schemaKind: 'cliq-authorization-consumption-receipt-v1' }
  ]);
  if (published.length !== 4 || expected.some((wanted, index) => {
    const actual = published[index];
    return !actual || actual.ref !== wanted.ref || actual.byteLength !== wanted.byteLength ||
      actual.mediaType !== wanted.mediaType || actual.schemaKind !== wanted.schemaKind;
  })) throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed verifier and consumption differ from their original complete bytes');
  signal?.throwIfAborted();
  return { preparation: { spec: composed.spec, specRef: composed.specRef, metadata: published.slice(0, 3), resolved },
    consumption: verifierConsumptionResult([{ ...transition, artifact: published[3] }], consumer) };
}

/** Installed current admission has its original frozen preparation time.
 * Generic admission and historical validation retain their original paths. */
export async function prepareInstalledVerifierAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: VerifierPreparationInput, consumer: VerifierConsumer, expectedSpecRef: string, signal?: AbortSignal) {
  const resolution = await resolveVerifierSpec(driver, artifacts, owner, runtime, input, undefined, signal);
  return publishInstalledVerifierAdmission(artifacts, resolution, consumer, expectedSpecRef, signal);
}

/** Reproduce the original frozen admission, never reconstruct lost commands or
 * derive authority from today's public request/channel/installed selection. */
export async function validateVerifierRunAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, runId: string, signal?: AbortSignal): Promise<{ authorizationReceiptRefs: string[] }> {
  signal?.throwIfAborted();
  const run = readRun(driver, runId), spec = await readCanonicalArtifact<RunSpec>(artifacts, run.specRef);
  if (run.parentRunId) {
    const { readChildVerifierAdmission } = await import('./child-verifier-admission.js');
    return readChildVerifierAdmission(driver, artifacts, owner, runtime, runId, signal);
  }
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
  const { readRootRunAdmissionOrigin } = await import('./run-admission-origin.js');
  const original = await readRootRunAdmissionOrigin(driver, artifacts, runId, { signal });
  const { verifierSpec: frozen, principalId, verifierRequests: requests, admissionIntentDigest: intent } = original;
  if (!frozen.verifiers.length) return { authorizationReceiptRefs: [] };
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  const bundle = await readCanonicalArtifact<AuthorizationRuntime['bundle']>(artifacts, assembly.runtime.runtimeBundleRef);
  const policy = await readCanonicalArtifact<{ mode: string }>(artifacts, spec.policyRef);
  const prepared = await prepareVerifierSpec(driver, artifacts, owner, { bundle, releaseKeys: runtime.releaseKeys },
    { principalId, requests, policyMode: policy.mode, assembly, sourceProjectionRef: spec.sourceProjectionRef,
      sandboxProfileRef: spec.sandboxProfileRef },
    { runId, admissionIntentDigest: intent, admittedAt: run.createdAt }, signal);
  if (prepared.specRef !== spec.verifierSpecRef || !same(prepared.spec, frozen)) throw new TypeError('verifier Run changed its original command/environment/spec');
  const authorizationReceiptRefs = prepared.resolved.map(({ grant }) => grant.state === 'consumed' ? grant.consumptionReceiptRef : '');
  if (!same(authorizationReceiptRefs, original.authorizationReceiptRefs)) throw new TypeError('verifier original consumption changed');
  original.assertUnchanged(driver); signal?.throwIfAborted();
  return { authorizationReceiptRefs };
}
