// One closeable owning receiver, registered before the first await. It owns
// every already-issued image/controller/native job through real retirement.
import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData } from '../kernel/mcp-wire.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { openInstalledLinuxWorkerLauncher, type LinuxWorkerController } from '../sandbox/linux-worker.js';
import { prepareInstalledMcpStdioRecovery, readInstalledMcpStdioRecoveryJoined, type InstalledMcpStdioRecoveryScope } from '../sandbox/mcp-stdio-native.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { sealInstalledMcpRecoveryAdapter, type HeldInstalledRuntime, type HeldInstalledAnchor } from './installed-runtime.js';
import { loadInstalledMcpStdioBroker, assertInstalledMcpStdioRecoveryOwner } from './mcp-stdio-native-binding.js';
import type { NativeMcpStdioRecoveryOwner, NativeMcpStdioServerImage } from './mcp-stdio-broker-native.js';
import { openRecoveryMcpStdioInput, type HeldRecoveryMcpStdioInput } from './native-owner.js';
import { beginMcpStatusProbe, type McpStatusUserMutation } from './mcp-status-dispatch.js';
import { driveMcpStatusProtocol, hasReceivedMcpStatusResponse, publishMcpStatusCapture, publishMcpStatusRetirement } from './mcp-status-protocol.js';
import { validateMcpInvocationWait } from './mcp-status-state.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRun } from './rows.js';

type Prepared = Awaited<ReturnType<typeof beginMcpStatusProbe>>;
type Retirement = Awaited<ReturnType<typeof publishMcpStatusRetirement>>;
type Capture = Awaited<ReturnType<typeof publishMcpStatusCapture>>;
declare const taskBrand: unique symbol;
export type McpStatusProbeTask = Readonly<{ readonly [taskBrand]: true;
  result(): Promise<void>; resumeResult(): Promise<void>; close(): Promise<void>; cancel(): void; acknowledge(): void;
}>;
type Held = { driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; processId: number;
  native?: NativeMcpStdioRecoveryOwner; scope?: InstalledMcpStdioRecoveryScope; input?: HeldRecoveryMcpStdioInput; prepared?: Prepared;
  retirement?: Retirement; capture?: Capture; failure?: unknown; working: boolean; shutdown: boolean; acknowledged: boolean };
const tasks = new WeakMap<object, Held>();
export function readMcpStatusProbeNativeJoin(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, task: McpStatusProbeTask) {
  const held = tasks.get(task);
  if (!held || held.driver !== driver || held.artifacts !== artifacts || held.owner !== owner || held.processId !== process.pid || held.acknowledged)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP status producer is not its original current owning task');
  if (held.working || !held.native || !held.prepared || !held.scope || !held.input)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status producer has no complete actual original physical/native retirement');
  assertInstalledMcpStdioRecoveryOwner(held.native, held.prepared.binding);
  const actual = readInstalledMcpStdioRecoveryJoined(held.scope, held.input);
  if (actual.ownerJoined.kind === 'mcp_stdio_recovery_response_unavailable_joined')
    held.native.assertUnavailableJoined(actual.ownerJoined, held.prepared.binding);
  else held.native.assertJoined(actual.ownerJoined, held.prepared.binding);
  held.scope.assertJoined(actual.joined);
  return { ...held, native: held.native, prepared: held.prepared, scope: held.scope, input: held.input, actual };
}
export function readMcpStatusProbeTask(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, task: McpStatusProbeTask) {
  const held = readMcpStatusProbeNativeJoin(driver, artifacts, owner, task);
  if (!held.retirement) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status original physical retirement publication remains unfinished');
  requireEqual(held.actual.ownerJoined, held.retirement.physical.joined.ownerJoined, 'MCP status actual retained original owner join');
  return { ...held, retirement: held.retirement };
}

export function prepareMcpStatusProbeTask(input: Readonly<{
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor;
  runId: string; expectedRunRevision: number; signal: AbortSignal; mutation?: McpStatusUserMutation;
  assertOpen(): void; onCommitted(prepared: Prepared): void;
}>): McpStatusProbeTask {
  const { driver, artifacts, owner } = input, cancellation = new AbortController(), signal = AbortSignal.any([input.signal, cancellation.signal]);
  const reads = artifacts.withReadSignal(signal), started = new Set<Promise<unknown>>();
  const track = <T>(job: Promise<T>): Promise<T> => { started.add(job); void job.finally(() => started.delete(job)).catch(() => {}); return job; };
  const held: Held = { driver, artifacts, owner, processId: process.pid, working: true, shutdown: false, acknowledged: false };
  let launcher: Awaited<ReturnType<typeof openInstalledLinuxWorkerLauncher>> | undefined, controller: LinuxWorkerController | undefined;
  let controllerOpening: Promise<LinuxWorkerController> | undefined, image: NativeMcpStdioServerImage | undefined;
  let domainRetained = false, closing = false, resourcesClosing: Promise<void> | undefined, closeTask: Promise<void> | undefined;
  let publishing: Promise<void> | undefined;
  const assertOpen = () => { signal.throwIfAborted(); input.assertOpen(); if (closing) throw new KernelStorageError('LEASE_FENCED', 'MCP status receiver is closing'); };
  const closeResources = () => resourcesClosing ??= (async () => {
    const failures: unknown[] = [];
    if (held.scope) try { await held.scope.close(); } catch (error) { failures.push(error); }
    else {
      const joins: Promise<unknown>[] = [];
      try { if (held.native) joins.push(held.native.close()); } catch (error) { failures.push(error); }
      joins.push((async () => { const original = controller ?? await controllerOpening; await original?.close(); })());
      for (const result of await Promise.allSettled(joins)) if (result.status === 'rejected') failures.push(result.reason);
    }
    if (!held.prepared) {
      try { if (domainRetained) { held.native!.releaseDomain(); domainRetained = false; } } catch (error) { failures.push(error); }
      try { held.input?.close(); } catch (error) { failures.push(error); }
    }
    try { image?.close(); } catch (error) { failures.push(error); }
    try { await launcher?.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
      new ResourceRetirementError('MCP signed status original process/pipe/image/controller resources did not join', new AggregateError(failures));
  })();
  const publishResult = () => publishing ??= (async () => {
    if (held.working || !held.prepared || !held.native || !held.scope || !held.input)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status durable nonce has no complete original native birth; recovery must retain the wait');
    const { actual } = readMcpStatusProbeNativeJoin(driver, artifacts, owner, task);
    held.retirement ??= await publishMcpStatusRetirement(driver, artifacts, owner, held.native, held.prepared.binding, held.scope, held.input);
    if (actual.ownerJoined.kind === 'mcp_stdio_recovery_owner_joined' && !held.capture &&
        hasReceivedMcpStatusResponse(held.native, held.prepared.binding))
      held.capture = await publishMcpStatusCapture(driver, artifacts, owner, held.native, held.prepared.binding, held.scope, held.input, held.retirement);
  })().finally(() => { publishing = undefined; });
  // Promise scheduling is deliberate: RunExecution retains the receiver
  // synchronously before any callback, CAS read or native job can begin.
  const work = track(Promise.resolve().then(async () => {
    try {
      assertOpen(); assertActiveStateOwner(driver, owner);
      const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, reads, input.runId);
      const selected = await validateMcpInvocationWait(driver, reads, cut);
      if (selected.run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'MCP status receiver original revision changed');
      const { source } = selected;
      const resources = decodeSandboxProfile(await readCanonicalArtifact(reads, source.spec.sandboxProfileRef)).resources;
      const broker = await track(loadInstalledMcpStdioBroker(input.selected, signal)); assertOpen();
      if (!broker.prepareRecoveryStdio) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed signed status broker recipe is unavailable');
      image = await track(sealInstalledMcpRecoveryAdapter(input.selected, source.manifest.entryId, signal)); assertOpen();
      launcher = await track(openInstalledLinuxWorkerLauncher(input.selected, input.anchor, { signal })); assertOpen();
      controllerOpening = track(launcher.startController({ signal })); controller = await controllerOpening; assertOpen();
      const probeStartedAt = sampleCanonicalNow(), frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(),
        mcpToolsListRequestData(2), source.statusRequest];
      held.native = broker.prepareRecoveryStdio({ argv: source.transport.argv.map(arg => arg.value), serverDigest: image.identity.sha256,
        serverByteCount: image.identity.byteCount, maximumResponseBytes: 1_048_576, maximumOutputBytes: resources.maxInvocationOutputBytes,
        remainingDeadlineMs: 30_000, recipe: frames.map(frame => ({ phase: frame.phase, bodyBytes: Buffer.from(frame.json), bodyBytesDigest: frame.digest })) });
      await track(held.native.ready); assertOpen(); held.native.retainDomain(); domainRetained = true;
      held.prepared = await beginMcpStatusProbe(driver, artifacts, owner, { runId: input.runId, expectedRunRevision: input.expectedRunRevision,
        probeStartedAt, native: held.native, selected: input.selected, anchor: input.anchor, controller, signal,
        ...(input.mutation ? { mutation: input.mutation } : {}) });
      // Commit handoff has no intervening await: Stop can retain this exact
      // nonce before subsequent native birth or any failed reservation job.
      input.onCommitted(held.prepared); assertOpen();
      const prepared = held.prepared, deadline = parseCanonicalTime(prepared.preparation.probeDeadlineAt);
      requireEqual(prepared.source.subject, source.subject, 'MCP status receiver exact original signed profile');
      if (prepared.preparation.createdAt !== probeStartedAt || canonicalSha256(prepared.wait) !== prepared.binding.waitingSubjectRef)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status receiver changed its original persisted deadline or nonce');
      held.input = openRecoveryMcpStdioInput(owner.filesystem, prepared.inputBinding);
      held.scope = prepareInstalledMcpStdioRecovery({ selected: input.selected, anchor: input.anchor, controller, lock: owner.filesystem,
        input: held.input, inputBinding: prepared.inputBinding, owner: held.native, serverImage: image, resources,
        launchDeadlineMs: deadline, callDeadlineMs: deadline, signal });
      held.native.attachProtocolPeer(held.scope.peer); held.native.bindProbe(prepared.binding);
      await held.scope.reservation(); assertOpen(); prepared.assertCurrent();
      held.scope.createBlocked(); await held.scope.ready(); assertOpen(); prepared.assertCurrent();
      held.native.releaseExec(prepared.binding);
      await driveMcpStatusProtocol(held.native, prepared.binding, prepared.source, () => { assertOpen(); prepared.assertCurrent(); });
    } catch (error) { held.failure = error; }
    finally {
      try { await closeResources(); }
      finally { held.working = false; }
    }
    if (!held.prepared) {
      if (held.failure !== undefined) throw held.failure;
      return;
    }
    await publishResult();
  }));
  const cancel = () => {
    if (closing) return;
    closing = true; held.shutdown = true;
    cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP signed status original receiver is closing'));
    // Revoke now. The tracked work's finally joins resources assigned by an
    // already-issued prepare; a snapshot-only cleanup would miss those jobs.
    try { void (held.scope ? held.scope.close() : held.native?.close())?.catch(() => {}); } catch { /* joined below */ }
    if (!held.scope) void (async () => { const original = controller ?? await controllerOpening; await original?.close(); })().catch(() => {});
  };
  const methods: Pick<McpStatusProbeTask, 'result' | 'resumeResult' | 'cancel' | 'close' | 'acknowledge'> = {
    result: () => work, resumeResult: publishResult, cancel,
    close: () => closeTask ??= (async () => {
      cancel(); const results = await Promise.allSettled([work, ...started]);
      const failure = results.find(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError) ?? results.find(result => result.status === 'rejected');
      if (failure?.status === 'rejected') {
        if (failure.reason instanceof ResourceRetirementError) throw failure.reason;
        // A joined CAS failure does not revoke an actual physical join. The
        // owning finalizer must still finish these original publications and
        // durably close the nonce before acknowledgement/StateOwner release.
        if (held.prepared) readMcpStatusProbeNativeJoin(driver, artifacts, owner, task);
        else if (!held.shutdown) throw failure.reason;
      }
    })(),
    acknowledge() {
      if (this !== task) throw new KernelStorageError('ARTIFACT_MISMATCH', 'invalid MCP status acknowledgement receiver');
      if (held.acknowledged) return;
      const { actual, native } = readMcpStatusProbeTask(driver, artifacts, owner, task);
      const current = readRun(driver, input.runId);
      if (current.waitingOnRef === held.prepared!.run.waitingOnRef || current.revision <= held.prepared!.run.revision)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP status original native domain cannot be released before durable nonce/outcome closure');
      // The unique owning writer calls this only after durable nonce close
      // or signed outcome commit. No public request can obtain this method.
      if (domainRetained) {
        if (actual.ownerJoined.kind === 'mcp_stdio_recovery_response_unavailable_joined') native.releaseUnavailableDomain();
        else native.releaseDomain();
        domainRetained = false;
      }
      try { held.input!.close(); }
      catch (error) { throw new ResourceRetirementError('MCP status committed completion did not close its original input descriptor', error); }
      held.acknowledged = true;
    }
  };
  const task = Object.freeze(methods) as McpStatusProbeTask; tasks.set(task, held); return task;
}
