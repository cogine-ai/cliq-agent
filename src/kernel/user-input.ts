import type { ArtifactRef } from './types.js';

export type InputResponseSchemaV1 = {
  schemaVersion: 1; format: 'cliq-input-response-schema-v1';
  dialect: 'https://json-schema.org/draft/2020-12/schema';
  schema: Record<string, unknown>; schemaDigest: string;
};

export type InputPromptV1 = {
  schemaVersion: 1; format: 'cliq-input-prompt-v1'; runId: string;
  batchItemId: string; callId: string; index: number;
  promptTextRef: ArtifactRef; promptTextDigest: string;
  maximumResponseBytes: number; promptDigest: string;
} & (
  | { responseKind: 'text'; responseSchemaRef?: never; responseSchemaDigest?: never }
  | { responseKind: 'json'; responseSchemaRef: ArtifactRef; responseSchemaDigest: string }
);

export type InputRequestItem = {
  schemaVersion: 1; kind: 'input_request'; itemId: string; runId: string;
  batchItemId: string; callId: string; index: number;
  promptRef: ArtifactRef; promptDigest: string; createdAt: string;
};

export type InputWait = {
  schemaVersion: 1; kind: 'input'; runId: string; createdFromRevision: number;
  createdAt: string; frontierRef: ArtifactRef; inputRequestItemId: string;
  batchItemId: string; callId: string;
};

export type UserInputValue = { kind: 'text'; value: string } | { kind: 'json'; value: unknown };

export type UserInputModelContentV1 = {
  schemaVersion: 1; format: 'cliq-user-input-model-content-v1';
  inputKind: 'text' | 'json'; value: unknown; contentDigest: string;
};

export type UserInputPayloadV1 = {
  schemaVersion: 1; format: 'cliq-user-input-payload-v1'; runId: string;
  inputRequestItemId: string; batchItemId: string; callId: string; index: number;
  promptRef: ArtifactRef; promptDigest: string; principalId: string; byteCount: number;
  waitingSubjectRef: ArtifactRef; requestId: string; requestDigest: string; expectedRunRevision: number;
  channelIdentityRef: ArtifactRef; channelIdentityDigest: string;
  modelContentRef: ArtifactRef; modelContentDigest: string; payloadDigest: string;
} & ({ inputKind: 'text'; value: string } | { inputKind: 'json'; value: unknown });

export type UserInputItem = {
  schemaVersion: 1; kind: 'user_input'; itemId: string; runId: string;
  inputRequestItemId: string; batchItemId: string; callId: string; index: number;
  promptRef: ArtifactRef; promptDigest: string; inputRef: ArtifactRef; inputDigest: string;
  modelContentRef: ArtifactRef; modelContentDigest: string; principalId: string; createdAt: string;
};

export type RunInput = {
  principalId: string; channelIdentityRef: ArtifactRef; channelIdentityDigest: string;
  requestId: string; expectedRunRevision: number; waitingOnRef: ArtifactRef; input: UserInputValue;
};
