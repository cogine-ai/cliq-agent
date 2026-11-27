// Fixed installed call-scoped stdio composition. The synchronous receiver is
// registered by RunExecution before its first await and owns every job, image,
// native input/scope and its dedicated platform controller until real join.
import { parseCanonicalTime } from '../kernel/identity.js';
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData, mcpToolsCallRequestData } from '../kernel/mcp-wire.js';
import type { ToolRequestV1, ToolTargetV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeRunSpec } from './decoders.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { openInstalledLinuxWorkerLauncher, type LinuxWorkerController } from '../sandbox/linux-worker.js';
import { prepareInstalledMcpStdioRun, readInstalledMcpStdioRunJoined, type InstalledMcpStdioRunScope } from '../sandbox/mcp-stdio-native.js';
import { sealInstalledMcpStdioServer, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { loadInstalledMcpStdioBroker } from './mcp-stdio-native-binding.js';
import { openRunMcpStdioInput, type HeldRunMcpStdioInput, type RunMcpStdioInputBinding } from './native-owner.js';
import type { NativeMcpStdioRunOwner, NativeMcpStdioServerImage, RunMcpStdioLaunchBinding, RunMcpStdioCallBinding } from './mcp-stdio-broker-native.js';
import { readMcpRegistryClosure } from './mcp-registration.js';
import { readMcpRequestArguments } from './mcp-request-arguments.js';
import { bindMcpStdioRunCall, driveMcpStdioRunSetup, driveMcpStdioRunCall, readMcpStdioRunCustody, readMcpStdioSetupFailureState, recordMcpStdioRunJoined } from './mcp-stdio-execution.js';
import { publishMcpServerInstance, retainMcpServerInitializedInstance } from './mcp-server-retirement.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { nextJournalSequence, readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { loadToolContinuation } from './reducers/tool.js';

type Agent = Pick<Awaited<ReturnType<typeof loadToolContinuation>>, 'prepareMcpServer' | 'claimMcpServer' | 'claimTool'>;
type ToolPreparation = Readonly<{ entry: InvocationJournalEntry; request: ToolRequestV1; target: ToolTargetV1 }>;
export function prepareMcpStdioRunInvocation(input: Readonly<{
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor;
  agent: Agent; prepared: ToolPreparation; effectDispatchId: string; signal: AbortSignal; assertOpen(): void;
  onEffectClaimed(claim: Awaited<ReturnType<Agent['claimTool']>>): void;
  onLaunchClaimed(): void;
}>) {
  const { driver, artifacts, owner } = input, cancellation = new AbortController(), signal = AbortSignal.any([input.signal, cancellation.signal]);
  const reads = artifacts.withReadSignal(signal), started = new Set<Promise<unknown>>();
  const track = <T>(job: Promise<T>) => { started.add(job); void job.finally(() => started.delete(job)).catch(() => {}); return job; };
  let launcher: Awaited<ReturnType<typeof openInstalledLinuxWorkerLauncher>> | undefined, controller: LinuxWorkerController | undefined;
  let controllerOpening: Promise<LinuxWorkerController> | undefined, native: NativeMcpStdioRunOwner | undefined, image: NativeMcpStdioServerImage | undefined;
  let scope: InstalledMcpStdioRunScope | undefined, physical: HeldRunMcpStdioInput | undefined, binding: RunMcpStdioLaunchBinding | undefined;
  let serverPrepared: Awaited<ReturnType<Agent['prepareMcpServer']>> | undefined, serverClaim: Awaited<ReturnType<Agent['claimMcpServer']>> | undefined;
  let effectClaim: Awaited<ReturnType<Agent['claimTool']>> | undefined, instance: Awaited<ReturnType<typeof publishMcpServerInstance>> | undefined;
  let retainInitialized: (() => ReturnType<typeof retainMcpServerInitializedInstance>) | undefined;
  let closing = false, domainRetained = false, launchBound = false, resourcesClosing: Promise<void> | undefined, closeTask: Promise<void> | undefined;
  function assertOpen() { signal.throwIfAborted(); input.assertOpen(); if (closing) throw new KernelStorageError('LEASE_FENCED', 'MCP stdio original resource is closing'); }
  const closeResources = () => resourcesClosing ??= (async () => {
    const failures: unknown[] = [];
    // A real stdio scope owns graceful drain/ACK and its dedicated controller.
    // Killing that controller first would discard issued raw pipe tail bytes.
    if (scope) try { await scope.close(); } catch (error) { failures.push(error); }
    else {
      const jobs: Promise<unknown>[] = [];
      try { if (native) jobs.push(native.close()); } catch (error) { failures.push(error); }
      try { jobs.push((async () => { const held = controller ?? await controllerOpening; await held?.close(); })()); } catch (error) { failures.push(error); }
      for (const result of await Promise.allSettled(jobs)) if (result.status === 'rejected') failures.push(result.reason);
    }
    if (!serverPrepared) {
      try { if (domainRetained) { native!.releaseDomain(); domainRetained = false; } } catch (error) { failures.push(error); }
      try { physical?.close(); } catch (error) { failures.push(error); }
    }
    try { image?.close(); } catch (error) { failures.push(error); }
    try { await launcher?.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
      new ResourceRetirementError('MCP stdio original process/pipe/image/controller jobs did not join', new AggregateError(failures));
  })();
  // The caller must retain this closeable receiver before any preparation or
  // assertion callback can begin, including an immediately rejected job.
  const work = track(Promise.resolve().then(async () => {
    let failure: unknown, outputSchema: unknown;
    try {
      assertOpen(); assertActiveStateOwner(driver, owner);
      if (input.prepared.target.execution.kind !== 'mcp') throw new TypeError('MCP stdio owner has no exact original MCP tool request');
      const execution = input.prepared.target.execution;
      const grant = await readCanonicalArtifact<ToolOperationGrantV1>(reads, input.prepared.entry.grantRef!);
      const frozen = await readMcpRegistryClosure(driver, reads, execution.registryRevisionRef, grant.principalId);
      if (frozen.registry.transport.kind !== 'stdio' || frozen.registry.transport.executable.kind !== 'runtime_bundle')
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP stdio requires its exact signed executable closure');
      const transport = frozen.registry.transport, executable = frozen.registry.transport.executable;
      const call = await readCanonicalArtifact<import('../protocol/agent-ir.js').ToolCallInputV1>(reads, input.prepared.request.inputRef);
      const argumentsValue = await readMcpRequestArguments(reads, { request: input.prepared.request, target: input.prepared.target,
        registry: frozen.registry, registryRef: frozen.ref, call });
      const output = frozen.registry.tools.find(tool => tool.name === execution.serverToolName)?.outputSchemaRef;
      outputSchema = output ? await readCanonicalArtifact(reads, output) : undefined;
      assertOpen();
      const broker = await track(loadInstalledMcpStdioBroker(input.selected, signal)); assertOpen();
      image = await track(sealInstalledMcpStdioServer(input.selected, executable.executableId, signal)); assertOpen();
      launcher = await track(openInstalledLinuxWorkerLauncher(input.selected, input.anchor, { signal })); assertOpen();
      controllerOpening = track(launcher.startController({ signal })); controller = await controllerOpening; assertOpen();
      const run = readRun(driver, input.prepared.entry.runId), parent = readRequiredWorkerLaunch(driver, readRun(driver, input.prepared.entry.runId).activeWorkerLaunchId!);
      if (!parent.processContainmentRef || !parent.leaseExpiresAt) throw new KernelStorageError('LEASE_FENCED', 'MCP server launch lost its exact owning worker lease/domain');
      const spec = decodeRunSpec(await readCanonicalArtifact(reads, run.specRef));
      const resources = decodeSandboxProfile(await readCanonicalArtifact(reads, spec.sandboxProfileRef)).resources; assertOpen();
      const frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2),
        mcpToolsCallRequestData(3, execution.serverToolName, argumentsValue)];
      const firstPreparation = readInvocationJournal(driver, run.id).find(entry => entry.opId === input.prepared.entry.opId && entry.phase === 'prepared');
      if (!firstPreparation) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP stdio lost its original first call preparation');
      const originalRetryDeadline = await (await import('./mcp-retry-admission.js')).readMcpRetryPreparedDeadline(driver, reads, input.prepared.entry);
      const ceiling = Math.min(parseCanonicalTime(firstPreparation.timestamp) + frozen.registry.lifecycle.callTimeoutMs,
        parseCanonicalTime(run.deadlineAt), parseCanonicalTime(grant.expiresAt), parseCanonicalTime(parent.leaseExpiresAt), originalRetryDeadline ?? Number.MAX_SAFE_INTEGER);
      const remaining = ceiling - Date.now(); if (remaining <= 0) throw new KernelStorageError('LEASE_FENCED', 'MCP server original call deadline expired before closeable native preparation');
      native = broker.prepareRunStdio({ argv: transport.argv.map(arg => arg.value), serverDigest: image.identity.sha256, serverByteCount: image.identity.byteCount,
        maximumResponseBytes: 1_048_576, maximumOutputBytes: resources.maxInvocationOutputBytes, remainingDeadlineMs: remaining,
        recipe: frames.map(frame => ({ phase: frame.phase, bodyBytes: Buffer.from(frame.json), bodyBytesDigest: frame.digest })) });
      await track(native.ready); assertOpen(); native.retainDomain(); domainRetained = true;
      serverPrepared = await input.agent.prepareMcpServer({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch }, native,
        { selected: input.selected, anchor: input.anchor, controller }, signal); assertOpen();
      requireEqual(serverPrepared.request.toolRequestRef, input.prepared.entry.requestRef, 'MCP stdio original prepared owning tool request');
      const preparation = serverPrepared.preparation, plan = serverPrepared.launch, nonce = preparation.nonce, dispatchId = preparation.dispatchId;
      const callDeadlineMs = preparation.callDeadlineMs, launchDeadlineMs = preparation.launchDeadlineMs, originalSupervisor = preparation.originalSupervisor;
      const inputBinding: RunMcpStdioInputBinding = { runId: run.id, principalId: grant.principalId, launchOpId: serverPrepared.entry.opId,
        batchItemId: input.prepared.request.batchItemId, callId: input.prepared.request.callId, workerLaunchId: parent.launchId, supervisorInstanceId: owner.supervisorInstanceId,
        nonce, registryRef: frozen.ref, manifestDigest: frozen.registry.manifestDigest, toolRequestRef: input.prepared.entry.requestRef,
        toolRequestDigest: input.prepared.request.requestDigest, requestRef: serverPrepared.entry.requestRef, requestDigest: serverPrepared.request.requestDigest,
        targetRef: serverPrepared.entry.target, targetDigest: serverPrepared.target.targetDigest, grantRef: serverPrepared.entry.grantRef!, grantDigest: serverPrepared.grant.grantDigest,
        plannedContainmentRef: plan.planArtifact.ref, plannedContainmentDigest: plan.plan.planDigest, sandboxLaunchSpecRef: plan.specArtifact.ref,
        sandboxLaunchSpecDigest: plan.spec.launchSpecDigest, attempt: serverPrepared.entry.attempt, lifecycleSeq: serverPrepared.request.lifecycleSeq,
        callIndex: input.prepared.request.callIndex, leaseEpoch: run.leaseEpoch, stateOwnerEpoch: owner.ownerEpoch, callDeadlineMs, launchDeadlineMs,
        originalSupervisorPid: originalSupervisor.pid, originalSupervisorStartToken: originalSupervisor.processStartToken };
      physical = openRunMcpStdioInput(owner.filesystem, inputBinding);
      // originalSupervisor* belongs to native birth only, not the closed broker binding.
      const { originalSupervisorPid: _pid, originalSupervisorStartToken: _start, ...closedBinding } = inputBinding;
      binding = { ...closedBinding, dispatchId, dispatchJournalSeq: nextJournalSequence(driver, run.id), releaseFenceTokenDigest: native.releaseFenceTokenDigest };
      scope = prepareInstalledMcpStdioRun({ selected: input.selected, anchor: input.anchor, controller, lock: owner.filesystem,
        input: physical, inputBinding, owner: native, serverImage: image, resources, launchDeadlineMs, callDeadlineMs, signal });
      // Bind the exact prepared input synchronously before the first resource
      // await. This grants no exec but preserves a genuine bound close receipt
      // when reservation is cancelled before the permanent launch claim.
      native.attachProtocolPeer(scope.peer); native.bindLaunch(binding); launchBound = true;
      await scope.reservation(); assertOpen();
      serverClaim = await input.agent.claimMcpServer({ expectedRunRevision: serverPrepared.run.revision, leaseEpoch: run.leaseEpoch,
        opId: serverPrepared.entry.opId, attempt: serverPrepared.entry.attempt, dispatchId, sandboxLaunchSpecRef: plan.specArtifact.ref }, native, binding, { scope, input: physical }, signal);
      input.onLaunchClaimed();
      assertOpen(); scope.createBlocked(); await scope.ready(); assertOpen();
      serverClaim.assertLaunchRelease(); native.releaseExec(binding);
      const instanceInput = { driver, artifacts, owner, native, scope, input: physical, binding,
        prepared: serverPrepared.entry, claim: serverClaim.entry, assertLaunchRelease: serverClaim.assertLaunchRelease,
        plan: plan.plan, spec: plan.spec, registry: frozen.registry };
      retainInitialized = () => retainMcpServerInitializedInstance(instanceInput);
      await driveMcpStdioRunSetup(native, binding, frozen.registry, () => { assertOpen(); frozen.assertUnchanged(driver); serverClaim!.assertLaunchRelease(); });
      instance = await publishMcpServerInstance(instanceInput); assertOpen();
      const callBinding: RunMcpStdioCallBinding = { launch: binding, opId: input.prepared.entry.opId, attempt: input.prepared.entry.attempt,
        dispatchId: input.effectDispatchId, dispatchJournalSeq: nextJournalSequence(driver, run.id), requestRef: input.prepared.entry.requestRef,
        requestDigest: input.prepared.request.requestDigest, targetRef: input.prepared.entry.target, targetDigest: input.prepared.target.targetDigest,
        grantRef: input.prepared.entry.grantRef!, grantDigest: grant.grantDigest, toolContractDigest: execution.toolContractDigest,
        instanceIdentityRef: instance.ref, instanceIdentityDigest: instance.instance.identityDigest, releaseFenceTokenDigest: native.releaseFenceTokenDigest };
      native.bindCall(callBinding); bindMcpStdioRunCall(native, callBinding);
      effectClaim = await input.agent.claimTool({ expectedRunRevision: readRun(driver, run.id).revision, leaseEpoch: run.leaseEpoch,
        opId: input.prepared.entry.opId, attempt: input.prepared.entry.attempt, dispatchId: input.effectDispatchId,
        brokerFenceTokenDigest: native.releaseFenceTokenDigest }, signal, { kind: 'stdio', owner: native, binding: callBinding });
      input.onEffectClaimed(effectClaim);
      await driveMcpStdioRunCall(native, callBinding, () => { assertOpen(); frozen.assertUnchanged(driver); effectClaim!.assertMcpRelease(); }, outputSchema);
    } catch (error) {
      failure = error;
      // Keep a completed original negotiation even if phase advancement or
      // its first CAS publication failed. This synchronous retained identity
      // grants no effect authority and exists only for truthful local closure.
      if (!instance && retainInitialized && native && binding && readMcpStdioSetupFailureState(native, binding)?.setupComplete)
        instance = retainInitialized();
    }
    finally { await closeResources(); }
    if (scope && physical && native && binding && launchBound) {
      const actual = readInstalledMcpStdioRunJoined(scope, physical); recordMcpStdioRunJoined(native, actual.ownerJoined, binding);
    }
    if (effectClaim && native && binding && instance) {
      const custody = readMcpStdioRunCustody(native, binding);
      return { kind: custody.resultReceived ? 'received' as const : 'unknown' as const, native, binding, instance,
        claim: effectClaim, prepared: input.prepared, failure, outputSchema };
    }
    return { kind: 'setup_failed' as const, native, binding, scope, input: physical, serverPrepared, serverClaim, instance, prepared: input.prepared, failure };
  }));
  return Object.freeze({ result: () => work, close: () => closeTask ??= (async () => {
    closing = true; cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP stdio original resource is closing'));
    // Revoke immediately, but let the tracked work's finally retire resources
    // produced by an already-issued preparation. A snapshot-only cleanup could
    // otherwise finish before a late image/controller was assigned custody.
    const jobs: Promise<unknown>[] = [work, ...started];
    try { if (scope) jobs.push(scope.close()); else if (native) jobs.push(native.close()); } catch (error) { jobs.push(Promise.reject(error)); }
    if (!scope) jobs.push((async () => { const held = controller ?? await controllerOpening; await held?.close(); })());
    const results = await Promise.allSettled(jobs);
    const failed = results.find(result => result.status === 'rejected');
    if (failed?.status === 'rejected') throw failed.reason instanceof ResourceRetirementError ? failed.reason :
      new ResourceRetirementError('MCP stdio original task did not completely join', failed.reason);
  })() });
}
