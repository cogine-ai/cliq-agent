import type { ArtifactRef, ProviderName, ReplayClass } from '../kernel/types.js';

export type AgentNegotiatedMode = 'native-tools' | 'text-only';

/** Opaque provider-owned reasoning replay data; never executable tool input. */
export type ProviderContinuation = { provider: ProviderName; model: string; items: unknown[] };

export type ModelTextV1 = {
  schemaVersion: 1;
  format: 'cliq-model-text-v1';
  utf8: string;
  byteCount: number;
  textDigest: string;
};

export type ObservedToolArguments =
  | { encoding: 'jcs_json'; value: unknown; utf8?: never }
  | { encoding: 'utf8_json_fragment'; utf8: string; value?: never };

export type ObservedToolCallInputV1 = {
  schemaVersion: 1;
  format: 'cliq-observed-tool-call-input-v1';
  byteCount: number;
  observedInputDigest: string;
} & ObservedToolArguments;

export type ToolCallInputBaseV1 = {
  schemaVersion: 1;
  format: 'cliq-tool-call-input-v1';
  callId: string;
  index: number;
  toolName: string;
  observedInputRef: ArtifactRef;
  observedInputDigest: string;
  inputDigest: string;
};

export type ToolCallInputV1 = ToolCallInputBaseV1 & (
  | {
      disposition: 'resolved';
      inputSchemaRef: ArtifactRef;
      inputSchemaDigest: string;
      value: Record<string, unknown>;
      diagnosticRef?: never;
      diagnosticDigest?: never;
    }
  | {
      disposition: 'rejected_unknown_tool';
      inputSchemaRef?: never;
      inputSchemaDigest?: never;
      value?: never;
      diagnosticRef: ArtifactRef;
      diagnosticDigest: string;
    }
  | {
      disposition: 'rejected_invalid_input';
      inputSchemaRef: ArtifactRef;
      inputSchemaDigest: string;
      value?: never;
      diagnosticRef: ArtifactRef;
      diagnosticDigest: string;
    }
);

export type AgentToolCall = {
  callId: string;
  toolName: string;
  inputRef: ArtifactRef;
  inputDigest: string;
  index: number;
};

export type AgentUsage = {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costMicros: number;
};

export type AgentModelStreamEvent =
  | { type: 'start'; provider: ProviderName; model: string; streaming: boolean }
  | { type: 'text_delta'; text: string }
  | { type: 'reasoning_delta'; text: string }
  | { type: 'tool_call_start'; index: number; wireCallId?: string; toolName?: string }
  | { type: 'tool_call_arguments_delta'; index: number; utf8: string }
  | { type: 'tool_call_complete'; index: number; wireCallId?: string; toolName?: string }
  | {
      type: 'usage';
      inputTokens: number;
      outputTokens: number;
      cacheReadTokens: number;
      cacheWriteTokens: number;
    }
  | { type: 'retry'; attempt: number; delayMs: 500 | 2000 }
  | { type: 'error'; code: string }
  | { type: 'end'; stopReason: 'end' | 'tool_calls' | 'length' | 'content_filter' | 'cancelled' | 'unknown' };

type AgentModelTurnBase = {
  continuation?: ProviderContinuation;
  schemaVersion: 1;
  format: 'cliq-agent-model-turn-v1';
  provider: ProviderName;
  model: string;
  responseId?: string;
  usage?: AgentUsage;
  usageTrusted: false;
  negotiatedMode: AgentNegotiatedMode;
  promptProjectionRef: ArtifactRef;
  promptProjectionDigest: string;
  requestDigest: string;
  responseDigest: string;
};

export type AgentModelTurn = AgentModelTurnBase & (
  | {
      stopReason: 'end';
      textRef: ArtifactRef;
      toolCalls: [];
      abortStopIntentRef?: never;
    }
  | {
      stopReason: 'tool_calls';
      textRef: ArtifactRef;
      toolCalls: [AgentToolCall, ...AgentToolCall[]];
      abortStopIntentRef?: never;
    }
  | {
      stopReason: 'cancelled';
      textRef: ArtifactRef;
      toolCalls: [];
      abortStopIntentRef: ArtifactRef;
    }
);

export type ModelResponseMediaType =
  | 'application/json'
  | 'text/event-stream'
  | 'application/x-ndjson'
  | 'unknown';

export type ModelUnusableResponseFailureCode =
  | 'malformed_transport_payload'
  | 'response_too_large'
  | 'invalid_stop_call_shape'
  | 'stop_reason_length'
  | 'stop_reason_content_filter'
  | 'stop_reason_unknown'
  | 'missing_or_duplicate_call_id'
  | 'tool_calls_forbidden_by_mode'
  | 'context_compaction_requires_end_markdown'
  | 'capability_shape_mismatch'
  | 'provider_rejected_response';

export type ModelUnusableResponseV1 = {
  schemaVersion: 1;
  format: 'cliq-model-unusable-response-v1';
  runId: string;
  opId: string;
  attempt: number;
  request:
    | { kind: 'normal'; requestRef: ArtifactRef; requestDigest: string }
    | { kind: 'context_compaction'; requestRef: ArtifactRef; requestDigest: string };
  provider: ProviderName;
  model: string;
  negotiatedMode: AgentNegotiatedMode;
  failureCode: ModelUnusableResponseFailureCode;
  observedResponse:
    | {
        kind: 'complete';
        mediaType: ModelResponseMediaType;
        bytesRef: ArtifactRef;
        bytesDigest: string;
        byteCount: number;
      }
    | {
        kind: 'prefix_over_limit';
        mediaType: ModelResponseMediaType;
        bytesRef: ArtifactRef;
        bytesDigest: string;
        byteCount: number;
        responseLimitBytes: number;
      };
  observedAt: string;
  unusableDigest: string;
};

export type ToolInvocation<TInput extends Record<string, unknown> = Record<string, unknown>> = {
  callId: string;
  index: number;
  toolName: string;
  input: TInput;
  replayClass: ReplayClass;
};
