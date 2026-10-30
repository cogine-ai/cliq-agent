import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeInstalledControlRequest, type InstalledControlRequestV1, type InstalledControlResponseFor,
  type InstalledControlFeature, type HeadlessRunEventV3 } from '../control/v1.js';
import { ControlRefusal, readInstalledSessionContext, type InstalledControlSession, type SessionResumeInput } from '../control/session.js';
import type { Session, SessionContextProjection } from '../kernel/types.js';
import { ResourceRetirementError } from '../state/errors.js';
import { isInstalledControlCloseError } from '../state/installed-control-close-error.js';
import { readRunItemPresentation } from './artifacts.js';
import type { ClientCommand, ClientUpdate } from './types.js';
import { ClientBusyError, ClientDisconnectedError, ClientPendingRequestError, ClientRequestPersistenceError } from './errors.js';
import type { PendingClientMutation } from './request-data.js';
export type { ClientCommand, ClientUpdate } from './types.js';
export { ClientBusyError, ClientDisconnectedError, ClientPendingRequestError, ClientRequestPersistenceError } from './errors.js';

type Response = InstalledControlResponseFor<InstalledControlFeature>;

/** A connection and presentation lifetime, never a Run lifetime. One bounded
 * user command may follow one read. A transport failure prevents queued sends;
 * reconnect only reconnects and never reuses any uncertain mutation. */
export function createClientApplication(session: InstalledControlSession,
  output: (update: ClientUpdate) => void | Promise<void>) {
  let tail: Promise<void> = Promise.resolve(), commandPending = false, readPending = 0, closed = false;
  let disconnected = false, closing: Promise<void> | undefined, following: Promise<void> | undefined;
  // At most one closed, already bounded wire request. This is disposable client
  // memory, never an execution journal or permission to retry an Invocation.
  let unresolved: Extract<InstalledControlRequestV1, { requestId: string; requestDigest: string }> | undefined;
  const local = new AbortController();
  const listeners = new Set<(update: ClientUpdate) => void>();
  async function emit(update: ClientUpdate) {
    const value = immutableSnapshot(update);
    for (const listener of listeners) listener(value);
    await output(value);
  }
  function serial<T>(kind: 'read' | 'command' | 'reconnect', task: () => Promise<T>): Promise<T> {
    if (closed) return Promise.reject(new ClientDisconnectedError());
    // One active display read plus one queued display continuation, and one
    // explicit user command. All actual wire I/O remains strictly serial.
    if (kind !== 'read' && commandPending || kind === 'read' && readPending >= 2) return Promise.reject(new ClientBusyError());
    if (kind === 'read') readPending++; else commandPending = true;
    const pending = tail.then(async () => {
      if (closed || disconnected && kind !== 'reconnect') throw new ClientDisconnectedError();
      return task();
    });
    tail = pending.then(() => {}, () => {});
    void pending.finally(() => { if (kind === 'read') readPending--; else commandPending = false; }).catch(() => {});
    return pending;
  }
  async function dispatch(request: InstalledControlRequestV1, replayId?: string) {
    const mutation = 'requestId' in request && 'requestDigest' in request;
    if (mutation) {
      if (unresolved && !canonicalJsonBytes(request).equals(canonicalJsonBytes(unresolved))) throw new ClientPendingRequestError();
      if (!session.requests) {
        await emit({ kind: 'pending', method: request.method,
          requestId: request.requestId, ...('admissionKey' in request ? { admissionKey: request.admissionKey } : {}) });
        unresolved ??= immutableSnapshot(request);
      }
    }
    let response: Response;
    try { response = replayId !== undefined && session.requests && 'requestId' in request && 'requestDigest' in request
      ? await session.requests.replay(replayId, request) : await session.request(request); }
    catch (error) {
      if (session.requests && mutation) {
        unresolved = session.pendingRequest;
        if (unresolved) try { await emit({ kind: 'pending', method: unresolved.method,
          requestId: unresolved.requestId, ...('admissionKey' in unresolved ? { admissionKey: unresolved.admissionKey } : {}) }); }
        catch { /* Preserve the original transport, storage or resource failure. */ }
      }
      if (error instanceof ClientPendingRequestError || error instanceof ClientRequestPersistenceError) throw error;
      disconnected = true;
      try { await emit({ kind: 'connection', state: 'disconnected' }); } catch { /* Preserve the original transport/resource failure. */ }
      throw error;
    }
    if (mutation) unresolved = undefined; // Only a known, strict original response closes this send.
    await emit({ kind: 'response', origin: 'command', request, response });
    if (response.ok && response.result.method === 'session.get' && session.hello.enabledFeatureIds.includes('artifact.get')) {
      const original = response.result.snapshot.session;
      const projection = await readInstalledSessionContext(session, original, local.signal);
      await emit({ kind: 'context', session: original, projection });
    }
    return response;
  }
  return Object.freeze({
    get hello() { return session.hello; },
    get pendingRequest() { return unresolved ?? session.pendingRequest; },
    ...(session.requests ? { requests: Object.freeze({
      list: () => serial('read', () => session.requests!.list()),
      load: (requestId: string) => serial('read', () => session.requests!.load(requestId)),
      replay: (requestId: string, expected?: PendingClientMutation) => serial('command', async () => {
        const original = await session.requests!.load(requestId);
        if (expected && !original.bytes.equals(canonicalJsonBytes(decodeInstalledControlRequest(expected))))
          throw new ClientRequestPersistenceError(new TypeError('replay data changed its reviewed original request'));
        return dispatch(original.request, requestId);
      }),
      acknowledge: (requestId: string) => serial('command', async () => {
        await session.requests!.acknowledge(requestId);
        if (unresolved?.requestId === requestId) unresolved = undefined;
      })
    }) } : {}),
    subscribe(listener: (update: ClientUpdate) => void) {
      if (closed || listeners.size >= 4) throw new ClientBusyError();
      listeners.add(listener); return () => { listeners.delete(listener); };
    },
    artifact(digest: string, options: Readonly<{ maxBytes: number; signal?: AbortSignal }>) {
      const signal = options.signal ? AbortSignal.any([options.signal, local.signal]) : local.signal;
      return serial('read', async () => {
        try { return await session.artifact(digest, { ...options, signal }); }
        catch (error) {
          // A known refusal, view abort or local data ceiling is not a new
          // connection. A failed transport must fence any queued mutation.
          if (error instanceof ResourceRetirementError || !signal.aborted && !(error instanceof ControlRefusal) && !(error instanceof TypeError)) {
            disconnected = true;
            try { await emit({ kind: 'connection', state: 'disconnected' }); } catch { /* Preserve the original failure. */ }
          }
          throw error;
        }
      });
    },
    readRun(supplied: Extract<InstalledControlRequestV1, { method: 'run.get' }>): Promise<Response> {
      const request = decodeInstalledControlRequest(supplied);
      if (request.method !== 'run.get' || !session.hello.enabledFeatureIds.includes('run.get'))
        return Promise.reject(new TypeError('presentation requires its enabled closed Run read'));
      return serial('read', async () => {
        local.signal.throwIfAborted();
        let response: Response;
        try { response = await session.request(request); }
        catch (error) {
          disconnected = true;
          try { await emit({ kind: 'connection', state: 'disconnected' }); } catch { /* Preserve the original failure. */ }
          throw error;
        }
        local.signal.throwIfAborted();
        await emit({ kind: 'response', origin: 'presentation', request, response }); return response;
      });
    },
    execute(command: ClientCommand): Promise<Response | void> {
      if (command.kind === 'reconnect') return serial('reconnect', async () => {
        try { await session.reconnect(); }
        catch (error) {
          disconnected = true;
          try { await emit({ kind: 'connection', state: 'disconnected' }); } catch { /* Preserve the original connection/resource failure. */ }
          throw error;
        }
        disconnected = false; await emit({ kind: 'connection', state: 'connected' });
      });
      if (command.kind === 'resume') {
        if (unresolved) return Promise.reject(new ClientPendingRequestError());
        const intent = immutableSnapshot(command.intent);
        if (Object.hasOwn(intent, 'requestDigest') || Object.hasOwn(intent, 'expectedContextRevision'))
          return Promise.reject(new TypeError('resume takes a new intent without a supplied context revision'));
        const core = { ...intent, expectedContextRevision: 1 };
        decodeInstalledControlRequest({ ...core, requestDigest: canonicalSha256(core) });
        return serial('command', async () => {
          let request;
          try { request = await session.prepareResume(intent, local.signal); }
          catch (error) {
            if (error instanceof ControlRefusal) {
              await emit({ kind: 'response', origin: 'command', request: { protocolVersion: 1, method: 'session.get', sessionId: intent.sessionId }, response: error.response });
              return error.response;
            }
            disconnected = true;
            try { await emit({ kind: 'connection', state: 'disconnected' }); } catch { /* Preserve the original failure. */ }
            throw error;
          }
          return dispatch(request);
        });
      }
      const request = decodeInstalledControlRequest(command.request);
      if (request.method === 'control.hello' || !session.hello.enabledFeatureIds.includes(request.method))
        return Promise.reject(new TypeError('the authenticated connection does not enable this command'));
      return serial('command', () => dispatch(request));
    },
    replay(): Promise<Response> {
      return serial('command', async () => {
        if (!unresolved) throw new TypeError('the client has no unresolved request to replay');
        if (!session.hello.enabledFeatureIds.includes(unresolved.method)) throw new TypeError('the authenticated connection does not enable the original request');
        return dispatch(unresolved, session.requests ? unresolved.requestId : undefined);
      });
    },
    follow(runId: string, afterEventSeq = 0, signal?: AbortSignal): Promise<void> {
      if (following) return Promise.reject(new ClientBusyError());
      const readSignal = signal ? AbortSignal.any([signal, local.signal]) : local.signal;
      const pending = (async () => {
        let throughItemSeq = -1;
        async function transcript(latestItemSeq: number): Promise<void> {
          // A disposable viewport starts with the latest bounded slice. Raw
          // historical pages remain available through run.get/inspect.
          if (throughItemSeq < 0) throughItemSeq = Math.max(0, latestItemSeq - 100);
          if (!session.hello.enabledFeatureIds.includes('run.get') || !session.hello.enabledFeatureIds.includes('artifact.get')) return;
          while (throughItemSeq < latestItemSeq) {
            readSignal.throwIfAborted();
            const after = throughItemSeq;
            const response = await serial('read', () => session.request({ protocolVersion: 1, method: 'run.get', runId,
              afterItemSeq: after, itemLimit: 32, journalLimit: 1, checkpointLimit: 1 }));
            readSignal.throwIfAborted();
            if (!response.ok) throw new ControlRefusal(response);
            if (response.result.method !== 'run.get' || response.result.snapshot.run.id !== runId) throw new TypeError('transcript source changed');
            let progressed = false;
            for (const row of response.result.items) {
              if (row.itemSeq > latestItemSeq) break;
              if (row.itemSeq !== throughItemSeq + 1) throw new TypeError('transcript committed sequence is not contiguous');
              const text = await serial('read', () => readRunItemPresentation({ artifact: (digest, options) =>
                session.artifact(digest, { ...options, signal: readSignal }) }, { runId, itemId: row.itemId, payloadRef: row.payloadRef }, readSignal));
              readSignal.throwIfAborted();
              await emit({ kind: 'transcript', runId, itemId: row.itemId, itemSeq: row.itemSeq, text });
              throughItemSeq = row.itemSeq; progressed = true;
            }
            if (!progressed) throw new TypeError('transcript lacks its captured committed items');
          }
        }
        for (;;) {
          readSignal.throwIfAborted();
          const pages = session.attach({ protocolVersion: 1, method: 'run.attach', runId, afterEventSeq, limit: 100 }, readSignal);
          let terminal = false, caughtUp = false;
          try {
            for (;;) {
              const page = await serial('read', () => pages.next());
              readSignal.throwIfAborted();
              if (page.done) break;
              const { request, response, events } = page.value;
              await emit({ kind: 'response', origin: 'follow', request, response });
              for (const event of events) await emit({ kind: 'event', event });
              if (!response.ok) return; // Expiry never invents a replacement cursor.
              await transcript(response.result.snapshot.latestRunItemSeq);
              afterEventSeq = response.result.nextEventSeq;
              const status = response.result.snapshot.run.status;
              terminal = !['queued', 'running', 'waiting'].includes(status);
              caughtUp = afterEventSeq === response.result.highWaterEventSeq;
            }
          } catch (error) {
            if (!readSignal.aborted && !(error instanceof ClientBusyError) && !(error instanceof ControlRefusal) && !(error instanceof TypeError)) {
              disconnected = true;
              try { await emit({ kind: 'connection', state: 'disconnected' }); } catch { /* Preserve the original failure. */ }
            }
            throw error;
          } finally { await pages.return(undefined); }
          if (terminal && caughtUp) return;
          await delay(250, undefined, { signal: readSignal });
        }
      })();
      following = pending;
      void pending.finally(() => { if (following === pending) following = undefined; }).catch(() => {});
      return pending;
    },
    close(): Promise<void> {
      closed = true; local.abort();
      return closing ??= (async () => {
        const originalFollow = following;
        const result = await Promise.allSettled([session.close(), tail, ...(originalFollow ? [originalFollow] : [])]);
        let outputFailure: unknown;
        try { await emit({ kind: 'connection', state: 'closed' }); } catch (error) { outputFailure = error; }
        listeners.clear();
        unresolved = undefined;
        const failures = result.flatMap((value, index) => {
          if (value.status !== 'rejected') return [];
          const error = value.reason;
          if (error instanceof ResourceRetirementError) return [error];
          if (error instanceof Error && error.name === 'AbortError') return [];
          // Only the exact deliberate transport-close rejection belongs to
          // detach. The original read caller retains that same rejection;
          // protocol/peer failures and connection/output join failures remain.
          if (index === 2 && isInstalledControlCloseError(error)) return [];
          return [error];
        });
        if (outputFailure !== undefined) failures.push(outputFailure);
        const retirement = failures.find(error => error instanceof ResourceRetirementError);
        if (retirement) throw retirement;
        if (failures.length) throw failures[0];
      })();
    }
  });
}
