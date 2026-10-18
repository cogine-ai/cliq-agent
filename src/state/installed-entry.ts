import path from 'node:path';
import { getAsset, isSea } from 'node:sea';
import { assertArtifactRef, assertRequestId, normalizeAbsolutePath } from '../kernel/identity.js';
import { canonicalJsonBytes, normalizeCanonicalText } from '../kernel/canonical.js';
import { decodeEndpointAuthorityCommandCore, type EndpointAuthorityCommandCoreV1 } from '../kernel/credential-authority.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { ReleaseTrustKey } from '../policy/runtime-authority.js';
import { openInstalledControl, type InstalledControlService } from './installed-control.js';
import { acquireInstalledAnchor, createInstalledRuntime, initializeInstalledKeeper, withHeldInstalledRuntime,
  commitEndpointAuthority, readEndpointAuthority, readCredentialAuthority, withCredentialAuthorityLock,
  type HeldInstalledAnchor, type HeldInstalledKeeper, type HeldInstalledRuntime } from './installed-runtime.js';
import { joinResourceOperations, KernelStorageError } from './errors.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { decodeCredentialWriteRequest, writeCredentialAuthority, decodeCredentialRevokeRequest, revokeCredentialAuthority, openStateStore,
  decodeCredentialCleanupRequest, cleanupCredentialAuthority,
  type CredentialWriteRequest, type CredentialRevokeRequest, type CredentialCleanupRequest, type StateStore } from './store.js';
import { installServices } from './installed-services.js';
import { loadInstalledCredentialPlatform } from './installed-runtime.js';
import { installedSandboxProfile } from './installed-sandbox-profile.js';
import { noteInstalledCredentialPhase } from './installed-diagnostics.js';

// Hidden Linux SEA entry. Default CLI startup is unchanged. Release roots are
// embedded at image construction, never selected by argv/environment/control.
// The signed companion enables the fixed Run recipe; without it the original
// credential/read-only composition remains, never a legacy execution fallback.
let selected: HeldInstalledRuntime | undefined;
let store: StateStore | undefined;
let service: InstalledControlService | undefined;
let keeper: HeldInstalledKeeper | undefined;
let anchor: HeldInstalledAnchor | undefined;
let containmentHealth: ReturnType<typeof setInterval> | undefined;
let closing: Promise<void> | undefined;
let supervisorStopRequested = false;
let credentialRole = false;

function stopSupervisorStartup(): boolean {
  if (!supervisorStopRequested) return false;
  store?.beginClose();
  return true;
}

function close(): Promise<void> {
  return closing ??= (async () => {
    if (credentialRole) noteInstalledCredentialPhase('retire');
    clearInterval(containmentHealth);
    if (keeper) {
      // Independent native ownership: even uncertain anchor retirement must
      // join the selection's descriptors. The Supervisor's Store is different:
      // its failed close must retain StateOwner, preserving the existing order.
      await joinResourceOperations([Promise.resolve().then(() => keeper!.close()), selected?.close()] as const);
      return;
    }
    // Pending handlers own complete submissions and may be waiting behind an
    // active broker. Revoke those producers before draining the service, but
    // keep final Store/StateOwner retirement after every handler has joined.
    store?.beginClose();
    await service?.close();
    await store?.close();
    // Store retirement must join before releasing containment. Afterwards both
    // independent descriptor owners retire even if one close is uncertain.
    await joinResourceOperations([Promise.resolve().then(() => anchor?.close()), selected?.close()] as const);
  })();
}

async function fail(error: unknown): Promise<void> {
  try { await close(); } catch (retirementError) { report(retirementError); process.exitCode = 1; return; }
  report(error); process.exitCode = 1;
}

function report(error: unknown): void {
  const failure = error as { code?: string; path?: string; message?: string };
  console.error(JSON.stringify({ diagnosticOnly: true, scope: 'installed-read-startup',
    code: failure?.code, path: failure?.path, message: failure?.message ?? String(error) }));
}

/** Hidden secret-free endpoint integration only. Read one bounded strict JSON
 * request from stdin; neither argv nor input can supply identity or channel. */
type EndpointRequest =
  | { schemaVersion: 1; kind: 'read'; endpointRegistrationId: string }
  | { schemaVersion: 1; kind: 'commit'; requestId: string; commandCore: EndpointAuthorityCommandCoreV1 };
async function readEndpointRequest(): Promise<EndpointRequest> {
  const chunks: Buffer[] = [];
  let byteCount = 0;
  const timer = setTimeout(() => process.stdin.destroy(new KernelStorageError('INVALID_REQUEST', 'endpoint request input timed out')), 5000);
  try {
    for await (const chunk of process.stdin) {
      const bytes = Buffer.from(chunk); byteCount += bytes.length;
      if (byteCount > 1_048_576) throw new KernelStorageError('INVALID_REQUEST', 'endpoint request exceeds its byte bound');
      chunks.push(bytes);
    }
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))) as Record<string, unknown>;
    if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== 1)
      throw new KernelStorageError('INVALID_REQUEST', 'expected a closed secret-free endpoint request');
    if (value.kind === 'commit' && exactKeys(value, ['schemaVersion', 'kind', 'requestId', 'commandCore']) && typeof value.requestId === 'string') {
      assertRequestId(value.requestId);
      return { schemaVersion: 1, kind: 'commit', requestId: value.requestId, commandCore: decodeEndpointAuthorityCommandCore(value.commandCore) };
    }
    if (!exactKeys(value, ['schemaVersion', 'kind', 'endpointRegistrationId']) || value.kind !== 'read' || typeof value.endpointRegistrationId !== 'string' ||
        !value.endpointRegistrationId || normalizeCanonicalText(value.endpointRegistrationId) !== value.endpointRegistrationId)
      throw new KernelStorageError('INVALID_REQUEST', 'expected a closed secret-free endpoint read request');
    return value as { schemaVersion: 1; kind: 'read'; endpointRegistrationId: string };
  } catch (cause) {
    if (cause instanceof KernelStorageError) throw cause;
    throw new KernelStorageError('INVALID_REQUEST', 'endpoint request input is invalid', { cause });
  } finally { clearTimeout(timer); }
}

/** Fixed secret-free metadata only. The canonical base64url envelope leaves
 * fd 0 unread, so committed replay can later decide before requesting a secret.
 * Never interpolate caller bytes into a diagnostic. */
type CredentialRequest = { schemaVersion: 1; kind: 'read'; credentialGrantId: string }
  | { schemaVersion: 1; kind: 'install_services' } | CredentialWriteRequest | CredentialRevokeRequest | CredentialCleanupRequest;
function readCredentialRequest(command: string | undefined): CredentialRequest {
  try {
    if (typeof command !== 'string' || !command.length || command.length > 87382 || !/^[A-Za-z0-9_-]+$/u.test(command))
      throw new TypeError('invalid credential metadata envelope');
    const bytes = Buffer.from(command, 'base64url');
    if (bytes.length > 65536 || bytes.toString('base64url') !== command) throw new TypeError('noncanonical credential metadata envelope');
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Record<string, unknown>;
    if (!value || typeof value !== 'object' || Array.isArray(value) || !canonicalJsonBytes(value).equals(bytes) || value.schemaVersion !== 1)
      throw new TypeError('invalid credential metadata');
    if (value.kind === 'install_services' && exactKeys(value, ['schemaVersion', 'kind'])) return value as { schemaVersion: 1; kind: 'install_services' };
    if (value.kind === 'enroll' || value.kind === 'rotate') return decodeCredentialWriteRequest(value);
    if (value.kind === 'revoke') return decodeCredentialRevokeRequest(value);
    if (value.kind === 'cleanup') return decodeCredentialCleanupRequest(value);
    if (!exactKeys(value, ['schemaVersion', 'kind', 'credentialGrantId']) || value.kind !== 'read' ||
        typeof value.credentialGrantId !== 'string' || !value.credentialGrantId || normalizeCanonicalText(value.credentialGrantId) !== value.credentialGrantId)
      throw new TypeError('invalid credential read metadata');
    return value as { schemaVersion: 1; kind: 'read'; credentialGrantId: string };
  } catch (cause) { throw new KernelStorageError('INVALID_REQUEST', 'expected bounded canonical secret-free credential metadata', { cause }); }
}

async function start(): Promise<void> {
  if (!isSea() || process.platform !== 'linux') throw new Error('expected the installed Linux SEA');
  const executable = normalizeAbsolutePath(process.execPath);
  // These fixed release roots are part of the signed application image.
  // No argv, environment, client or detached manifest can replace it.
  const releaseKeys = parseJsonStrict(new TextDecoder('utf-8', { fatal: true })
    .decode(getAsset('release-trust-roots.json'))) as ReleaseTrustKey[];
  const runtime = createInstalledRuntime({ releaseKeys });
  const mode = process.argv[2];
  credentialRole = mode === '--bootstrap-credential' || mode === '--installed-credential';
  if (mode === '--bootstrap-supervisor' || mode === '--bootstrap-keeper' || mode === '--bootstrap-endpoint' || mode === '--bootstrap-credential') {
    const runtimeRoot = path.dirname(executable);
    if (process.argv.length !== (mode === '--bootstrap-credential' ? 4 : 3) || path.basename(executable) !== 'bootstrap' || path.basename(runtimeRoot) !== 'runtime')
      throw new Error('expected only a fixed role at StateRoot/runtime/bootstrap');
    if (mode === '--bootstrap-credential') readCredentialRequest(process.argv[3]);
    if (credentialRole) noteInstalledCredentialPhase('open_selected');
    selected = await runtime.openSelected(path.dirname(runtimeRoot));
    // Bootstrap has no StateOwner, Store, control/worker handles or graceful
    // SIGTERM handler. Exec is terminal, never a running-owner restart API.
    return runtime.executeSelected(selected, mode === '--bootstrap-keeper' ? 'keeper' : mode === '--bootstrap-endpoint' ? 'endpoint' :
      mode === '--bootstrap-credential' ? 'credential' : 'supervisor', mode === '--bootstrap-credential' ? process.argv[3] : undefined);
  }
  if ((mode !== '--installed-supervisor' && mode !== '--installed-keeper' && mode !== '--installed-endpoint' && mode !== '--installed-credential') ||
      process.argv.length !== (mode === '--installed-credential' ? 7 : 6))
    throw new Error('expected a fixed installed Supervisor role');
  const stateRoot = normalizeAbsolutePath(process.argv[3]!);
  const bundleDigest = process.argv[4]!, rootLocator = process.argv[5]!;
  if (stateRoot !== process.argv[3] || !/^(0|[1-9][0-9]*):[1-9][0-9]*:(0|[1-9][0-9]*)$/u.test(rootLocator))
    throw new Error('expected canonical installed StateRoot locators');
  assertArtifactRef(bundleDigest);
  process.once('SIGTERM', () => {
    if (mode === '--installed-supervisor') {
      supervisorStopRequested = true;
      store?.beginClose();
    }
    // Final retirement still joins the original startup producer before
    // releasing Store, containment or installation descriptors.
    void starting.then(close, close).catch(error => { report(error); process.exitCode = 1; });
  });
  if (credentialRole) noteInstalledCredentialPhase('open_selected');
  selected = await runtime.openSelected(stateRoot);
  if (stopSupervisorStartup()) return;
  const supervisor = selected.bundle.entries.find(entry => entry.role === 'supervisor')!;
  if (selected.bundleDigest !== bundleDigest || executable !== path.join(stateRoot, 'runtime/bundles', bundleDigest, supervisor.relativePath))
    throw new Error('installed Supervisor differs from the fixed selected image');
  await withHeldInstalledRuntime(selected, async installed => {
    if (`${installed.stateRoot.deviceId}:${installed.stateRoot.fileId}:${installed.stateRoot.ownerUid}` !== rootLocator)
      throw new Error('installed StateRoot differs from the pre-exec root');
  });
  if (stopSupervisorStartup()) return;
  if (mode === '--installed-credential') {
    const request = readCredentialRequest(process.argv[6]);
    const response = request.kind === 'install_services' ? { schemaVersion: 1, ...await installServices(selected) }
      : request.kind === 'enroll' || request.kind === 'rotate' ? { schemaVersion: 1, operation: await writeCredentialAuthority(selected, request) }
      : request.kind === 'revoke' ? { schemaVersion: 1, operation: await revokeCredentialAuthority(selected, request) }
      : request.kind === 'cleanup' ? { schemaVersion: 1, operation: await cleanupCredentialAuthority(selected, request) }
      : await withCredentialAuthorityLock(selected, async token =>
        ({ schemaVersion: 1, record: readCredentialAuthority(token, request.credentialGrantId) }));
    await close();
    console.log(canonicalJsonBytes(response).toString('utf8'));
    return;
  }
  if (mode === '--installed-endpoint') {
    const request = await readEndpointRequest();
    const response = await withCredentialAuthorityLock(selected, async token => request.kind === 'read'
      ? { schemaVersion: 1, record: readEndpointAuthority(token, request.endpointRegistrationId) }
      : { schemaVersion: 1, operation: commitEndpointAuthority(token, request.requestId, request.commandCore) });
    await close();
    console.log(canonicalJsonBytes(response).toString('utf8'));
    return;
  }
  if (mode === '--installed-keeper') {
    keeper = await initializeInstalledKeeper(selected);
    // An FD alone does not keep Node alive. This referenced timer observes
    // native metadata, not full image/CAS hashing or another authority ledger.
    containmentHealth = setInterval(() => {
      try { keeper!.assertHeld(); } catch (error) { void fail(error); }
    }, 1_000);
    return;
  }
  // A stale/missing locator or keeper refuses before the first StateOwner
  // transaction. Never reopen a named cgroup root as an acquisition fallback.
  anchor = await acquireInstalledAnchor(selected);
  if (stopSupervisorStartup()) return;
  anchor.assertHeld();
  // Only this selected mode acquires authority. Genesis borrows these newly
  // held, verified descriptors, never the retired bootstrap's historical FDs.
  const runProfile = await withHeldInstalledRuntime(selected, async installed => {
    if (!installed.modelAuthority) return undefined;
    await installed.revalidate();
    return installedSandboxProfile();
  });
  if (stopSupervisorStartup()) return;
  const actualUser = runProfile ? (await loadInstalledCredentialPlatform(selected)).currentUser() : undefined;
  if (stopSupervisorStartup()) return;
  store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys,
    ...(runProfile ? { sourceInspection: { controlledHome: path.join(actualUser!.home, '.cliq'), sandboxProfile: runProfile } } : {}) }, selected, anchor);
  if (stopSupervisorStartup()) return;
  await store.startInstalledRuns();
  if (stopSupervisorStartup()) return;
  anchor.assertHeld();
  service = openInstalledControl(store, { serverBuild: 'cliq-installed-v1' }, report);
  containmentHealth = setInterval(() => {
    try { anchor!.assertHeld(); } catch (error) { void fail(error); }
  }, 1_000);
}

const starting = start();
void starting.catch(fail);
