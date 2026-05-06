import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';

import {
  emptyHeadlessArtifacts,
  HEADLESS_EXIT_FAILURE,
  HEADLESS_SCHEMA_VERSION,
  type ArtifactView,
  type HeadlessRunError,
  type HeadlessRunOptions,
  type HeadlessRunOutput,
  type HeadlessRunRequest,
  type RuntimeEventEnvelope,
  type SessionView
} from './contract.js';
import { getArtifactViewForRequest, getSessionView as defaultGetSessionView } from './artifacts.js';
import { runHeadless as defaultRunHeadless } from './run.js';

type JsonRpcId = string | number | null;

type JsonRpcRequest = {
  jsonrpc: '2.0';
  id?: JsonRpcId;
  method: string;
  params?: unknown;
};

type JsonRpcResponder = {
  result: (result: unknown) => void;
  error: (code: number, message: string) => void;
};

type RunHeadless = (
  request: HeadlessRunRequest,
  options: HeadlessRunOptions
) => HeadlessRunOutput | Promise<HeadlessRunOutput>;

export type RpcServerOptions = {
  writeLine: (line: string) => void | Promise<void>;
  makeRunId?: () => string;
  runHeadless?: RunHeadless;
  getSessionView?: (cwd: string, sessionId?: string) => Promise<SessionView>;
  getArtifactView?: (cwd: string, artifactId: string, sessionId?: string) => Promise<ArtifactView>;
};

export type RpcServer = {
  handleLine: (line: string) => Promise<void>;
  waitForIdle: () => Promise<void>;
};

type ActiveRun = {
  runId: string;
  controller: AbortController;
  promise: Promise<void>;
};

const JSON_RPC_VERSION = '2.0';

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;
const ACTIVE_RUN_ERROR = -32001;
const NOT_FOUND_ERROR = -32004;

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isJsonRpcId(value: unknown): value is JsonRpcId {
  return value === null || typeof value === 'string' || typeof value === 'number';
}

function requestId(value: unknown): JsonRpcId {
  if (!isObject(value) || !Object.hasOwn(value, 'id')) {
    return null;
  }

  return isJsonRpcId(value.id) ? value.id : null;
}

function isJsonRpcRequest(value: unknown): value is JsonRpcRequest {
  return (
    isObject(value) &&
    value.jsonrpc === JSON_RPC_VERSION &&
    typeof value.method === 'string' &&
    (!Object.hasOwn(value, 'id') || isJsonRpcId(value.id))
  );
}

function defaultMakeRunId() {
  return `run_${randomUUID().replaceAll('-', '')}`;
}

function makeEventId() {
  return `evt_${randomUUID().replaceAll('-', '')}`;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

function asCwd(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  return value.trim() ? value : null;
}

function asIdentifier(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed || value !== trimmed) {
    return null;
  }

  return value;
}

function asSessionGetParams(params: unknown): { cwd: string; sessionId?: string } | null {
  if (!isObject(params)) {
    return null;
  }

  const cwd = asCwd(params.cwd);
  if (!cwd) {
    return null;
  }

  if (!Object.hasOwn(params, 'sessionId')) {
    return { cwd };
  }

  const sessionId = asIdentifier(params.sessionId);
  if (!sessionId) {
    return null;
  }

  return { cwd, sessionId };
}

function asArtifactGetParams(params: unknown): { cwd: string; artifactId: string; sessionId?: string } | null {
  if (!isObject(params)) {
    return null;
  }

  const cwd = asCwd(params.cwd);
  const artifactId = asIdentifier(params.artifactId);
  if (!cwd || !artifactId) {
    return null;
  }

  if (!Object.hasOwn(params, 'sessionId')) {
    return { cwd, artifactId };
  }

  const sessionId = asIdentifier(params.sessionId);
  if (!sessionId) {
    return null;
  }

  return { cwd, artifactId, sessionId };
}

function isNotFoundError(error: unknown) {
  return error instanceof Error && /\b(session|artifact) not found\b/i.test(error.message);
}

export function createRpcServer(options: RpcServerOptions): RpcServer {
  const runHeadless = options.runHeadless ?? defaultRunHeadless;
  const makeRunId = options.makeRunId ?? defaultMakeRunId;
  const getSessionView = options.getSessionView ?? defaultGetSessionView;
  const getArtifactView = options.getArtifactView ?? getArtifactViewForRequest;
  const finishedRunIds = new Set<string>();
  let activeRun: ActiveRun | undefined;
  let transportClosed = false;

  const closeTransport = () => {
    if (transportClosed) {
      return;
    }
    transportClosed = true;
    activeRun?.controller.abort();
  };

  const write = (message: unknown) => {
    if (transportClosed) {
      return;
    }

    try {
      const result = options.writeLine(JSON.stringify(message));
      if (result && typeof result === 'object' && 'then' in result) {
        void result.catch(() => {
          closeTransport();
        });
      }
    } catch {
      closeTransport();
    }
  };

  const writeResult = (id: JsonRpcId, result: unknown) => {
    write({ jsonrpc: JSON_RPC_VERSION, id, result });
  };

  const writeError = (id: JsonRpcId, code: number, message: string) => {
    write({ jsonrpc: JSON_RPC_VERSION, id, error: { code, message } });
  };

  const createResponder = (request: JsonRpcRequest): JsonRpcResponder => {
    const isNotification = !Object.hasOwn(request, 'id');
    const id = request.id ?? null;

    return {
      result(result: unknown) {
        if (!isNotification) {
          writeResult(id, result);
        }
      },
      error(code: number, message: string) {
        if (!isNotification) {
          writeError(id, code, message);
        }
      }
    };
  };

  const writeEvent = (event: RuntimeEventEnvelope) => {
    write({ jsonrpc: JSON_RPC_VERSION, method: 'run.event', params: event });
  };

  const emitRunFailure = (runId: string, error: unknown) => {
    const runError: HeadlessRunError = {
      code: 'internal-error',
      stage: 'assembly',
      message: errorMessage(error),
      recoverable: false
    };
    const output: HeadlessRunOutput = {
      runId,
      status: 'failed',
      exitCode: HEADLESS_EXIT_FAILURE,
      artifacts: emptyHeadlessArtifacts(),
      error: runError
    };
    const timestamp = new Date().toISOString();

    writeEvent({
      schemaVersion: HEADLESS_SCHEMA_VERSION,
      eventId: makeEventId(),
      runId,
      timestamp,
      type: 'error',
      payload: runError
    });
    writeEvent({
      schemaVersion: HEADLESS_SCHEMA_VERSION,
      eventId: makeEventId(),
      runId,
      timestamp: new Date().toISOString(),
      type: 'run-end',
      payload: {
        status: 'failed',
        exitCode: HEADLESS_EXIT_FAILURE,
        output
      }
    });
  };

  const startRun = (responder: JsonRpcResponder, params: unknown) => {
    if (!isObject(params)) {
      responder.error(INVALID_PARAMS, 'run.start params must be an object');
      return;
    }
    if (activeRun) {
      responder.error(ACTIVE_RUN_ERROR, 'an active run is already in progress');
      return;
    }

    const runId = makeRunId();
    const controller = new AbortController();
    const request = params as HeadlessRunRequest;
    const runPromise = Promise.resolve()
      .then(async () => {
        await runHeadless(request, {
          runId,
          signal: controller.signal,
          onEvent: writeEvent
        });
      })
      .catch((error) => {
        emitRunFailure(runId, error);
      })
      .finally(() => {
        finishedRunIds.add(runId);
        if (activeRun?.runId === runId) {
          activeRun = undefined;
        }
      });

    activeRun = {
      runId,
      controller,
      promise: runPromise
    };

    responder.result({ runId });
  };

  const cancelRun = (responder: JsonRpcResponder, params: unknown) => {
    if (!isObject(params) || typeof params.runId !== 'string') {
      responder.error(INVALID_PARAMS, 'run.cancel params must include runId');
      return;
    }

    const { runId } = params;
    if (activeRun?.runId === runId) {
      activeRun.controller.abort();
      responder.result({ status: 'cancelled' });
      return;
    }

    if (finishedRunIds.has(runId)) {
      responder.result({ status: 'already-finished' });
      return;
    }

    responder.result({ status: 'not-found' });
  };

  const handleSessionGet = async (responder: JsonRpcResponder, params: unknown) => {
    const parsed = asSessionGetParams(params);
    if (!parsed) {
      responder.error(INVALID_PARAMS, 'session.get params must include cwd and optional sessionId');
      return;
    }

    try {
      responder.result(await getSessionView(parsed.cwd, parsed.sessionId));
    } catch (error) {
      if (isNotFoundError(error)) {
        responder.error(NOT_FOUND_ERROR, errorMessage(error));
        return;
      }
      throw error;
    }
  };

  const handleArtifactGet = async (responder: JsonRpcResponder, params: unknown) => {
    const parsed = asArtifactGetParams(params);
    if (!parsed) {
      responder.error(INVALID_PARAMS, 'artifact.get params must include cwd, artifactId, and optional sessionId');
      return;
    }

    try {
      responder.result(await getArtifactView(parsed.cwd, parsed.artifactId, parsed.sessionId));
    } catch (error) {
      if (isNotFoundError(error)) {
        responder.error(NOT_FOUND_ERROR, errorMessage(error));
        return;
      }
      throw error;
    }
  };

  const dispatch = async (request: JsonRpcRequest) => {
    const responder = createResponder(request);

    switch (request.method) {
      case 'run.start':
        startRun(responder, request.params);
        return;
      case 'run.cancel':
        cancelRun(responder, request.params);
        return;
      case 'session.get':
        await handleSessionGet(responder, request.params);
        return;
      case 'artifact.get':
        await handleArtifactGet(responder, request.params);
        return;
      default:
        responder.error(METHOD_NOT_FOUND, `method not found: ${request.method}`);
    }
  };

  return {
    async handleLine(line: string) {
      if (transportClosed) {
        return;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        writeError(null, PARSE_ERROR, 'parse error');
        return;
      }

      if (!isJsonRpcRequest(parsed)) {
        writeError(requestId(parsed), INVALID_REQUEST, 'invalid request');
        return;
      }

      try {
        await dispatch(parsed);
      } catch {
        createResponder(parsed).error(INTERNAL_ERROR, 'internal error');
      }
    },

    async waitForIdle() {
      while (activeRun) {
        await activeRun.promise;
      }
    }
  };
}

export function runStdioJsonRpcServer() {
  const server = createRpcServer({
    writeLine(line) {
      process.stdout.write(`${line}\n`);
    }
  });
  const rl = createInterface({
    input: process.stdin,
    crlfDelay: Infinity
  });

  rl.on('line', (line) => {
    void server.handleLine(line);
  });

  return server;
}
