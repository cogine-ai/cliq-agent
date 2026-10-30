import type { InstalledControlFeature, InstalledControlRequestV1, InstalledControlResponseFor,
  InstalledControlResultFor, HeadlessRunEventV3 } from '../control/v1.js';
import type { RunSubmitRequest } from '../kernel/control-submit.js';
import type { RunSpec, Session, SessionContextProjection } from '../kernel/types.js';
import type { ClientRequests } from './request-data.js';

/** Copied user choices only; no filesystem factory or authority is part of
 * the SDK's command-default data contract. */
export type ClientModelSelectionV1 = Readonly<{
  alias: string; provider: 'openai-compatible'; model: string;
  endpointRegistrationId: string; credentialGrantId: string;
}>;
export type ClientPreferencesV1 = Readonly<{
  schemaVersion: 1; modelSelections: readonly ClientModelSelectionV1[];
  defaultModelAlias?: string; budgetDefaults?: Readonly<RunSpec['budgets']>;
}>;
export type SessionResumeInput = Omit<RunSubmitRequest, 'requestDigest' | 'expectedContextRevision'>;
export type ClientCommand = Readonly<{ kind: 'request'; request: InstalledControlRequestV1 }>
  | Readonly<{ kind: 'resume'; intent: SessionResumeInput }> | Readonly<{ kind: 'reconnect' }>;
type Response = InstalledControlResponseFor<InstalledControlFeature>;
export type ClientUpdate = Readonly<{ kind: 'response'; origin: 'command' | 'follow' | 'presentation'; request: InstalledControlRequestV1; response: Response }>
  | Readonly<{ kind: 'event'; event: HeadlessRunEventV3 }>
  | Readonly<{ kind: 'context'; session: Session; projection: SessionContextProjection }>
  | Readonly<{ kind: 'transcript'; runId: string; itemId: string; itemSeq: number; text: string }>
  | Readonly<{ kind: 'connection'; state: 'connected' | 'disconnected' | 'closed' }>
  | Readonly<{ kind: 'pending'; method: string; requestId: string; admissionKey?: string }>;
export type ClientUpdateSink = (update: ClientUpdate) => void | Promise<void>;
/** Public client data and lifecycle only. No Store, owner, native descriptor,
 * release key, execution grant or runtime loader enters the SDK interface. */
export type CliqClient = Readonly<{
  readonly hello: InstalledControlResultFor<'control.hello'>;
  readonly pendingRequest: InstalledControlRequestV1 | undefined;
  readonly requests?: ClientRequests;
  subscribe(listener: (update: ClientUpdate) => void): () => void;
  artifact(digest: string, options: Readonly<{ maxBytes: number; signal?: AbortSignal }>): Promise<Buffer>;
  readRun(request: Extract<InstalledControlRequestV1, { method: 'run.get' }>): Promise<Response>;
  execute(command: ClientCommand): Promise<Response | void>;
  replay(): Promise<Response>;
  follow(runId: string, afterEventSeq?: number, signal?: AbortSignal): Promise<void>;
  close(): Promise<void>;
}>;
