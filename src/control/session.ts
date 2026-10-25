import { createHash, randomBytes } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { ArtifactDescriptorV1 } from '../kernel/types.js';
import type { RunSubmitRequest } from '../kernel/control-submit.js';
import { immutableSnapshot } from '../model/immutable.js';
import { openInstalledSupervisorClient, type InstalledSupervisorClient } from '../state/installed-control-client.js';
import type { HeldInstalledRuntime } from '../state/installed-runtime.js';
import { ResourceRetirementError } from '../state/errors.js';
import { INSTALLED_CONTROL_FEATURES, decodeInstalledControlEnvelope, decodeInstalledControlRequest,
  decodeInstalledControlResponse, headlessRunEvent,
  type InstalledControlFeature, type InstalledControlRequestV1, type InstalledControlResponseFor,
  type HeadlessRunEventV3 } from './v1.js';

type Attach = Extract<InstalledControlRequestV1, { method: 'run.attach' }>;
type AttachResult = Extract<InstalledControlResponseFor<'run.attach'>, { ok: true }>['result'];
export type SessionResumeInput = Omit<RunSubmitRequest, 'requestDigest' | 'expectedContextRevision'>;
export class ControlRefusal extends Error {
  constructor(readonly response: Extract<InstalledControlResponseFor<InstalledControlFeature>, { ok: false }>) {
    super('installed Supervisor refused the request'); this.name = 'ControlRefusal';
  }
}
export type InstalledControlSession = Readonly<{
  readonly hello: InstalledSupervisorClient['hello'];
  request(value: unknown): Promise<InstalledControlResponseFor<InstalledControlFeature>>;
  cancel(runId: string, expectedRevision: number): Promise<InstalledControlResponseFor<InstalledControlFeature>>;
  prepareResume(request: SessionResumeInput, signal?: AbortSignal): Promise<RunSubmitRequest>;
  attach(request: Attach, signal?: AbortSignal): AsyncGenerator<Readonly<{
    request: Attach; response: InstalledControlResponseFor<'run.attach'>; events: readonly HeadlessRunEventV3[] }>>;
  artifact(digest: string, options: Readonly<{ maxBytes: number; signal?: AbortSignal }>): Promise<Buffer>;
  reconnect(): Promise<void>;
  close(): Promise<void>;
}>;

/** Actual installation/peer authentication remains in the original client.
 * The caller retains its selected image handles until this session joins. */
export async function openInstalledControlSession(selected: HeldInstalledRuntime): Promise<InstalledControlSession> {
  const connect = () => openInstalledSupervisorClient(selected, 3), client = await connect();
  try { return createInstalledControlSession(client, connect); }
  catch (error) { await client.close(); throw error; }
}

/** One shared protocol consumer. Reconnection is explicit and never resends a
 * request; callers retain the exact original request/admission identities.
 * Owning/closing this client detaches only, and creates no server authority. */
export function createInstalledControlSession(initial: InstalledSupervisorClient,
  connect?: () => Promise<InstalledSupervisorClient>): InstalledControlSession {
  const checkHello = (client: InstalledSupervisorClient) => {
    const hello = decodeInstalledControlEnvelope({ protocolVersion: 1, ok: true, result: client.hello }, 'control.hello');
    if (!hello.ok || hello.result.headlessSchemaRange.min > 3 || hello.result.headlessSchemaRange.max < 3)
      throw new TypeError('installed client requires headless schema 3');
  };
  checkHello(initial);
  let client = initial, stopped = false, closing: Promise<void> | undefined, switching: Promise<void> | undefined;
  let retirementFailure: ResourceRetirementError | undefined;
  let running: Promise<InstalledControlResponseFor<InstalledControlFeature>> | undefined;
  const request = (value: unknown): Promise<InstalledControlResponseFor<InstalledControlFeature>> => {
    try {
      if (retirementFailure) throw retirementFailure;
      if (stopped || closing || switching || running) throw new TypeError('control session is closed or busy');
      const candidate = decodeInstalledControlRequest(value);
      if (candidate.method === 'control.hello') throw new TypeError('control session is already authenticated');
      if (!INSTALLED_CONTROL_FEATURES.includes(candidate.method as InstalledControlFeature) || !client.hello.enabledFeatureIds.includes(candidate.method))
        throw new TypeError('control method was not enabled by the authenticated hello');
      const method = candidate.method as InstalledControlFeature;
      const pending = (async () => {
        try { return decodeInstalledControlResponse(await Reflect.apply(client[method], client, [candidate]), candidate); }
        catch (error) { if (error instanceof ResourceRetirementError) retirementFailure ??= error; throw error; }
      })();
      running = pending;
      void pending.finally(() => { if (running === pending) running = undefined; }).catch(() => {});
      return pending;
    } catch (error) { return Promise.reject(error); }
  };
  const session: InstalledControlSession = Object.freeze({
    get hello() { return immutableSnapshot(client.hello); }, request,
    async prepareResume(supplied: SessionResumeInput, signal?: AbortSignal) {
      // Return the complete new admission before dispatch. Callers can retain
      // these exact bytes across an explicit reconnect; no old Run is resumed
      // and neither an uncertain send nor a revision refusal is auto-retried.
      if (Object.hasOwn(supplied, 'requestDigest') || Object.hasOwn(supplied, 'expectedContextRevision')) throw new TypeError('resume takes new Run intent without a stale Session revision');
      const validate = { ...supplied, expectedContextRevision: 1 };
      const checked = decodeInstalledControlRequest({ ...validate, requestDigest: canonicalSha256(validate) });
      if (checked.method !== 'run.submit') throw new TypeError('resume requires a new run.submit intent');
      signal?.throwIfAborted();
      const observed = await request({ protocolVersion: 1, method: 'session.get', sessionId: checked.sessionId });
      signal?.throwIfAborted();
      if (!observed.ok) throw new ControlRefusal(observed);
      if (observed.result.method !== 'session.get') throw new TypeError('resume Session response differs');
      const { requestDigest: _digest, ...core } = checked;
      const current = { ...core, expectedContextRevision: observed.result.snapshot.session.contextRevision };
      return decodeInstalledControlRequest({ ...current, requestDigest: canonicalSha256(current) }) as RunSubmitRequest;
    },
    cancel(runId: string, expectedRevision: number) {
      // This timestamp is only UUIDv7 request identity data, never a server
      // time/authority observation. Only this explicit user action creates it.
      const bytes = randomBytes(16); bytes.writeUIntBE(Date.now(), 0, 6);
      bytes[6] = (bytes[6]! & 0x0f) | 0x70; bytes[8] = (bytes[8]! & 0x3f) | 0x80;
      const hex = bytes.toString('hex'), requestId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
      const core = { protocolVersion: 1, method: 'run.cancel', requestId, runId, expectedRevision };
      return request({ ...core, requestDigest: canonicalSha256(core) });
    },
    async *attach(supplied: Attach, signal?: AbortSignal) {
      const decoded = decodeInstalledControlRequest(supplied);
      if (decoded.method !== 'run.attach') throw new TypeError('attach requires its original request');
      let cursor = decoded.afterEventSeq, previous: AttachResult | undefined, target: number | undefined;
      for (;;) {
        signal?.throwIfAborted();
        const sent = immutableSnapshot({ ...decoded, afterEventSeq: cursor,
          limit: target === undefined ? decoded.limit : Math.min(decoded.limit!, target - cursor) });
        const response = await request(sent) as InstalledControlResponseFor<'run.attach'>;
        signal?.throwIfAborted();
        if (!response.ok) {
          if (response.error.code === 'EVENT_CURSOR_EXPIRED' && previous &&
              (response.error.snapshot.run.revision < previous.snapshot.run.revision || response.error.latestEventSeq < previous.highWaterEventSeq))
            throw new TypeError('expired attach snapshot or high-water regressed');
          yield Object.freeze({ request: sent, response, events: [] });
          // Expiry ends this cut with its authoritative snapshot. A later
          // explicit attach may start from earliest-1; this request cannot
          // chase a changing retention window or fabricate omitted events.
          return;
        }
        const page = response.result;
        target ??= page.highWaterEventSeq;
        if (previous && (page.snapshot.run.revision < previous.snapshot.run.revision || page.highWaterEventSeq < previous.highWaterEventSeq))
          throw new TypeError('attach snapshot or high-water regressed');
        if (page.nextEventSeq > target || page.nextEventSeq <= cursor && cursor < target)
          throw new TypeError('attach failed to advance within its original cut');
        yield Object.freeze({ request: sent, response, events: Object.freeze(page.events.map(headlessRunEvent)) });
        cursor = page.nextEventSeq; previous = page;
        if (cursor === target) return;
      }
    },
    async artifact(digest: string, options: Readonly<{ maxBytes: number; signal?: AbortSignal }>) {
      if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes < 0 || options.maxBytes > 64 * 1024 * 1024)
        throw new TypeError('artifact consumer requires a byte ceiling up to 64 MiB');
      let descriptor: ArtifactDescriptorV1 | undefined, offset = 0;
      const chunks: Buffer[] = [], hash = createHash('sha256');
      for (;;) {
        options.signal?.throwIfAborted();
        const response = await request({ protocolVersion: 1, method: 'artifact.get', digest, offset, length: 65536 });
        options.signal?.throwIfAborted();
        if (!response.ok) throw new ControlRefusal(response);
        if (response.result.method !== 'artifact.get') throw new TypeError('artifact response method differs');
        const page = response.result;
        if (page.artifact.sizeBytes > options.maxBytes || descriptor && !canonicalJsonBytes(descriptor).equals(canonicalJsonBytes(page.artifact)))
          throw new TypeError('artifact descriptor changed or exceeds the consumer ceiling');
        descriptor ??= page.artifact;
        const bytes = Buffer.from(page.bytesBase64, 'base64');
        chunks.push(bytes); hash.update(bytes); offset = page.nextOffset;
        if (!page.eof) continue;
        if (offset !== descriptor.sizeBytes || hash.digest('hex') !== descriptor.digest || descriptor.ref !== digest)
          throw new TypeError('complete artifact bytes do not match the requested digest');
        return Buffer.concat(chunks, offset);
      }
    },
    reconnect() {
      if (retirementFailure) return Promise.reject(retirementFailure);
      if (!connect || stopped || closing || switching || running) return Promise.reject(new TypeError('control session cannot reconnect'));
      const pending = (async () => {
        try { await client.close(); }
        catch (error) { if (error instanceof ResourceRetirementError) retirementFailure ??= error; throw error; }
        const next = await connect();
        try { checkHello(next); }
        catch (error) { await next.close(); throw error; }
        if (stopped) { await next.close(); throw new TypeError('control session is closing'); }
        client = next;
      })();
      switching = pending; void pending.finally(() => { if (switching === pending) switching = undefined; }).catch(() => {});
      return pending;
    },
    close() {
      stopped = true;
      return closing ??= (async () => {
        const failures: unknown[] = [];
        if (switching) {
          const [result] = await Promise.allSettled([switching]);
          if (result!.status === 'rejected') failures.push(result!.reason);
        }
        try { await client.close(); } catch (error) { failures.push(error); }
        // A connection/close failure cannot skip the original request's join.
        // Ordinary query rejection is expected on detach; its own caller still
        // observes it. Any uncertain retirement remains the primary failure.
        for (const result of await Promise.allSettled(running ? [running] : []))
          if (result.status === 'rejected' && result.reason instanceof ResourceRetirementError) failures.push(result.reason);
        for (const error of failures) if (error instanceof ResourceRetirementError) retirementFailure ??= error;
        if (retirementFailure) throw retirementFailure;
        if (failures.length) throw failures[0];
      })();
    }
  });
  return session;
}
