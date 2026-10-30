import type { createClientApplication } from './application.js';
import { clientMutation, type ClientInvocation } from './commands.js';
import type { InstalledControlFeature, InstalledControlRequestV1, InstalledControlResponseFor } from '../control/v1.js';

export type ClientApplication = ReturnType<typeof createClientApplication>;
type Response = InstalledControlResponseFor<InstalledControlFeature>;
export class ClientRefusal extends Error {
  constructor(readonly code: string) { super('Supervisor refused the explicit client command'); this.name = 'ClientRefusal'; }
}
function accepted(value: Response | void): Exclude<Response, { ok: false }> {
  if (!value || !value.ok) throw new ClientRefusal(value && !value.ok ? value.error.code : 'INVALID_REQUEST');
  return value;
}
export type ClientActionResult = Readonly<{ exitCode: number; runId?: string; follow: boolean; afterEventSeq?: number; response?: Response;
  presentationRequest?: InstalledControlRequestV1;
  artifact?: Readonly<{ digest: string; bytes: Buffer }> }>;

/** One explicit user action may compose reads and one admission. Every request
 * is sent once. A refusal, uncertain send or Session race ends this action. */
export async function executeClientAction(app: ClientApplication, invocation: ClientInvocation,
  confirmUnverified?: () => Promise<boolean>, signal?: AbortSignal): Promise<ClientActionResult> {
  const send = (request: unknown) => { signal?.throwIfAborted(); return app.execute({ kind: 'request', request: request as never }); };
  if (invocation.kind === 'request-replay') {
    if (!app.requests) throw new TypeError('this installed client has no retained original request store');
    signal?.throwIfAborted();
    const original = await app.requests.load(invocation.requestId);
    signal?.throwIfAborted();
    const response = await app.requests.replay(invocation.requestId, original.request);
    return { exitCode: response.ok ? 0 : 1, follow: false, response, presentationRequest: original.request };
  }
  if (invocation.kind === 'command') {
    signal?.throwIfAborted();
    const value = await app.execute(invocation.command);
    return { exitCode: value && !value.ok ? 1 : 0, follow: false, ...(value ? { response: value } : {}) };
  }
  if (invocation.kind === 'artifact') return { exitCode: 0, follow: false,
    artifact: { digest: invocation.digest, bytes: await app.artifact(invocation.digest, { maxBytes: 64 * 1024 * 1024, signal }) } };
  if (invocation.kind === 'result') {
    const waiting = new AbortController();
    const followSignal = signal ? AbortSignal.any([signal, waiting.signal]) : waiting.signal;
    let stoppedAtWait = false, refusal: string | undefined;
    const unsubscribe = app.subscribe(update => {
      if (update.kind !== 'response' || update.origin !== 'follow') return;
      if (!update.response.ok) { refusal = update.response.error.code; return; }
      if (update.response.result.method === 'run.attach' && update.response.result.snapshot.run.status === 'waiting') {
        stoppedAtWait = true; waiting.abort();
      }
    });
    try {
      try { await app.follow(invocation.runId, 0, followSignal); }
      catch (error) { if (signal?.aborted || !stoppedAtWait || !(error instanceof Error) || error.name !== 'AbortError') throw error; }
    } finally { unsubscribe(); }
    signal?.throwIfAborted();
    if (refusal !== undefined) throw new ClientRefusal(refusal);
    const request: InstalledControlRequestV1 = { protocolVersion: 1, method: 'run.result', runId: invocation.runId };
    const response = accepted(await send(request));
    return { exitCode: 0, follow: false, response, presentationRequest: request };
  }
  if (invocation.kind === 'attach') return { exitCode: 0, runId: invocation.runId, afterEventSeq: invocation.afterEventSeq, follow: true };
  if (invocation.kind === 'cancel') {
    let expectedRevision = invocation.expectedRevision;
    if (expectedRevision === undefined) {
      const read = accepted(await send({ protocolVersion: 1, method: 'run.get', runId: invocation.runId }));
      if (read.result.method !== 'run.get') throw new TypeError('cancel did not read its requested Run');
      expectedRevision = read.result.snapshot.run.revision;
    }
    accepted(await send(clientMutation({ method: 'run.cancel', runId: invocation.runId, expectedRevision })));
    return { exitCode: 0, follow: false };
  }
  if (invocation.kind === 'apply') {
    const read = accepted(await send({ protocolVersion: 1, method: 'run.result', runId: invocation.sourceRunId }));
    if (read.result.method !== 'run.result') throw new TypeError('Delivery did not read its immutable source result');
    if (invocation.expectedRunResultRef !== undefined && invocation.expectedRunResultRef !== read.result.result.ref)
      throw new TypeError('Delivery source differs from the explicitly reviewed result');
    const result = accepted(await send(clientMutation({ ...invocation.options, method: 'run.apply',
      sourceRunId: invocation.sourceRunId, expectedRunResultRef: read.result.result.ref }, true)));
    if (result.result.method !== 'run.apply') throw new TypeError('Delivery has no exact durable admission response');
    return { exitCode: 0, runId: result.result.snapshot.run.id, follow: !invocation.detach };
  }
  if (invocation.kind !== 'run') throw new TypeError('this local mode is not a client action');
  let intent = invocation.intent;
  if (invocation.nodeCheck && (intent.policyMode !== 'yolo' || intent.verifiers.length))
    throw new TypeError('the fixed Node check requires explicit yolo and no other verifier');
  if (!invocation.nodeCheck && !intent.verifiers.some(verifier => verifier.required) && !intent.allowUnverified) {
    if (!confirmUnverified || !await confirmUnverified()) throw new TypeError('explicit unverified consent is required');
    intent = { ...intent, allowUnverified: true };
  }
  signal?.throwIfAborted();
  let sessionId = invocation.sessionId;
  if (!sessionId) {
    const created = accepted(await send(clientMutation({ method: 'session.create', workspacePath: intent.workspacePath }, true)));
    if (created.result.method !== 'session.create') throw new TypeError('new Run did not create its requested context Session');
    sessionId = created.result.snapshot.session.id;
  }
  if (invocation.nodeCheck) {
    const authorized = accepted(await send(clientMutation({ method: 'authorization.create', decision: {
      kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain',
        guestToolchainManifestId: invocation.nodeCheck.guestToolchainManifestId, toolId: 'node' } } })));
    if (authorized.result.method !== 'authorization.create' || authorized.result.grant.state !== 'active' ||
        authorized.result.grant.purpose !== 'verifier' || authorized.result.grant.targetKind !== 'execution_identity_read' || authorized.result.grant.useCount !== 0)
      throw new TypeError('Node check did not receive its exact active identity-read grant');
    intent = { ...intent, verifiers: [{ id: 'node-tests', version: '1', required: true,
      executable: { kind: 'toolchain', toolId: 'node' },
      argv: ['--test', '--test-concurrency=1', invocation.nodeCheck.path].map(value => ({ kind: 'non_secret_literal' as const, value })),
      cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: authorized.result.grant.grantId,
      timeoutMs: 10_000, retries: 0, outputLimitBytes: 65_536 }] };
  }
  const draft = clientMutation({ ...intent, method: 'run.submit', sessionId, expectedContextRevision: 1 }, true);
  if (draft.method !== 'run.submit') throw new TypeError('new Run intent differs');
  const { requestDigest: _digest, expectedContextRevision: _revision, ...freshIntent } = draft;
  signal?.throwIfAborted();
  const submitted = accepted(await app.execute({ kind: 'resume', intent: freshIntent }));
  if (submitted.result.method !== 'run.submit') throw new TypeError('new Run has no exact durable admission response');
  return { exitCode: 0, runId: submitted.result.snapshot.run.id, follow: !invocation.detach };
}
