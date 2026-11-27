// Fixed three-frame Admin composition. The registration writer retains all
// semantic rows and gates; this receiver owns only its actual native resources.
import type { McpResolvedTransportV1 } from '../kernel/mcp.js';
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData } from '../kernel/mcp-wire.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { sha256Bytes } from '../kernel/identity.js';
import { prepareInstalledMcpStdioAdmin, readInstalledMcpStdioAdminJoined, type InstalledMcpStdioAdminScope } from '../sandbox/mcp-stdio-native.js';
import type { LinuxWorkerController } from '../sandbox/linux-worker.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { sealInstalledMcpStdioServer, withHeldInstalledRuntime, type HeldInstalledRuntime, type HeldInstalledAnchor } from './installed-runtime.js';
import { loadInstalledMcpStdioBroker, readInstalledMcpStdioRecipeData, assertInstalledMcpStdioAdminJoined } from './mcp-stdio-native-binding.js';
import type { NativeMcpStdioAdminOwner, NativeMcpStdioServerImage, AdminMcpStdioBinding } from './mcp-stdio-broker-native.js';
import { openAdminMcpStdioInput, type HeldAdminMcpStdioInput, type AdminMcpStdioInputBinding } from './native-owner.js';
import { driveMcpStdioAdminProtocol } from './mcp-stdio-execution.js';
import { decodeMcpStdioRecipeData } from './mcp-stdio-recipe.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
import type { StateOwnerContext } from './state-owner.js';
import { observeMcpAdminWork } from './mcp-admin-diagnostics.js';

export function prepareMcpStdioAdminAttempt(input: Readonly<{
  selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor; controller: LinuxWorkerController; owner: StateOwnerContext;
  artifacts: ArtifactCatalog; transport: Extract<McpResolvedTransportV1, { kind: 'stdio' }>; deadlineMs: number; signal: AbortSignal;
}>) {
  const cancellation = new AbortController(), signal = AbortSignal.any([input.signal, cancellation.signal]);
  let native: NativeMcpStdioAdminOwner | undefined, image: NativeMcpStdioServerImage | undefined;
  let scope: InstalledMcpStdioAdminScope | undefined, physical: HeldAdminMcpStdioInput | undefined, binding: AdminMcpStdioBinding | undefined;
  let closing = false, closed: Promise<void> | undefined, driving: Promise<Awaited<ReturnType<typeof driveMcpStdioAdminProtocol>>> | undefined, domainRetained = false;
  function assertOpen() { signal.throwIfAborted(); if (closing) throw new KernelStorageError('LEASE_FENCED', 'MCP stdio Admin resource is closing'); }
  const preparation = Promise.resolve().then(async () => {
    assertOpen();
    if (input.transport.executable.kind !== 'runtime_bundle') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP guest executable closure is unsupported');
    const executable = input.transport.executable;
    await withHeldInstalledRuntime(input.selected, async selected => {
      await selected.revalidate(signal);
      if (selected.bundleDigest !== executable.runtimeBundleRef)
        throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP stdio Admin requires its exact current signed bundle');
    }, signal);
    const broker = await loadInstalledMcpStdioBroker(input.selected, signal); assertOpen();
    image = await sealInstalledMcpStdioServer(input.selected, executable.executableId, signal); assertOpen();
    if (image.identity.sha256 !== executable.executableDigest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP stdio Admin sealed server differs from its exact original consent');
    const remaining = input.deadlineMs - Date.now();
    if (remaining <= 0) throw new KernelStorageError('LEASE_FENCED', 'MCP stdio Admin original attempt deadline expired');
    const frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2)];
    native = broker.prepareAdminStdio({ argv: input.transport.argv.map(arg => arg.value), serverDigest: image.identity.sha256,
      serverByteCount: image.identity.byteCount, maximumResponseBytes: 1_048_576, maximumOutputBytes: DEFAULT_SANDBOX_RESOURCES.maxInvocationOutputBytes,
      remainingDeadlineMs: remaining, recipe: frames.map(frame => ({ phase: frame.phase, bodyBytes: Buffer.from(frame.json), bodyBytesDigest: frame.digest })) });
    await observeMcpAdminWork('stdio', 'native_prepare', () => native!.ready); assertOpen(); native.retainDomain(); domainRetained = true;
    const bytes = readInstalledMcpStdioRecipeData(native), decoded = decodeMcpStdioRecipeData(bytes);
    assertMcpStdioRecipeData(decoded, { purpose: 'admin', transport: input.transport, serverByteCount: image.identity.byteCount, resources: DEFAULT_SANDBOX_RESOURCES });
    const recipe = await input.artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-mcp-stdio-native-recipe-bytes-v1');
    if (recipe.ref !== decoded.recipeDigest || recipe.ref !== sha256Bytes(bytes)) throw new TypeError('MCP original Admin native recipe publication changed');
    return { recipe };
  });
  void preparation.catch(() => {});
  function original() {
    if (!scope || !physical || !native) throw new ResourceRetirementError('MCP stdio Admin has no complete original physical scope', undefined);
    return { scope, input: physical, native };
  }
  return Object.freeze({ prepare: () => preparation,
    createScope(inputBinding: AdminMcpStdioInputBinding) {
      assertOpen(); if (scope || !native || !image || !domainRetained) throw new TypeError('MCP stdio Admin scope requires its one prepared original native owner');
      physical = openAdminMcpStdioInput(input.owner.filesystem, inputBinding);
      scope = prepareInstalledMcpStdioAdmin({ selected: input.selected, anchor: input.anchor, controller: input.controller,
        lock: input.owner.filesystem, input: physical, inputBinding, owner: native, serverImage: image, resources: DEFAULT_SANDBOX_RESOURCES,
        launchDeadlineMs: input.deadlineMs, callDeadlineMs: input.deadlineMs, signal }); native.attachProtocolPeer(scope.peer);
      return scope;
    },
    original,
    bindAndDrive(next: AdminMcpStdioBinding, gate: () => void) {
      assertOpen(); const held = original(); if (binding || driving) throw new TypeError('MCP stdio Admin cannot bind or drive a second probe');
      binding = next; held.native.bindLaunch(next); gate(); held.native.releaseExec(next);
      driving = observeMcpAdminWork('stdio', 'protocol', () => driveMcpStdioAdminProtocol(held.native, next, () => { assertOpen(); gate(); })); return driving;
    },
    joined() { const held = original(), joined = readInstalledMcpStdioAdminJoined(held.scope, held.input);
      if (binding) assertInstalledMcpStdioAdminJoined(held.native, joined.ownerJoined, binding); return joined; },
    release() { const held = original(); if (!domainRetained) throw new TypeError('MCP stdio Admin original domain is not retained');
      const joined = readInstalledMcpStdioAdminJoined(held.scope, held.input); held.scope.assertJoined(joined.joined);
      if (binding) assertInstalledMcpStdioAdminJoined(held.native, joined.ownerJoined, binding);
      held.native.releaseDomain(); domainRetained = false; held.input.close(); },
    close: () => closed ??= (async () => {
      closing = true; cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP stdio Admin is closing'));
      const failures: unknown[] = [], joins: Promise<unknown>[] = [];
      // Start revocation before awaiting the actual protocol task; it may be
      // blocked in nextMessage. The scope preserves raw pipe custody through ACK.
      try { if (scope) joins.push(observeMcpAdminWork('stdio', 'scope_close', () => scope!.close()));
        else if (native) joins.push(observeMcpAdminWork('stdio', 'native_close', () => native!.close())); } catch (error) { failures.push(error); }
      const results = await Promise.allSettled([preparation, ...joins, ...(driving ? [driving] : [])]);
      for (const [index, result] of results.entries()) if (result.status === 'rejected' &&
          (index >= 1 && index <= joins.length || result.reason instanceof ResourceRetirementError)) failures.push(result.reason);
      // Preparation can assign an image/native owner after close began. Join
      // that exact late resource too; its data is never promoted as a result.
      if (!scope && native) try { await observeMcpAdminWork('stdio', 'native_close', () => native!.close()); } catch (error) { failures.push(error); }
      try { image?.close(); } catch (error) { failures.push(error); }
      if (!scope && domainRetained) try { native!.releaseDomain(); domainRetained = false; } catch (error) { failures.push(error); }
      if (failures.length) throw new ResourceRetirementError('MCP stdio Admin native resources did not completely join', new AggregateError(failures));
    })() });
}
