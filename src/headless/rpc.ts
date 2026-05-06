import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';

import type { HeadlessRunOptions, HeadlessRunOutput, HeadlessRunRequest, RuntimeEventEnvelope } from './contract.js';
import { runHeadless as defaultRunHeadless } from './run.js';

type JsonRpcId = string | number | null;

type JsonRpcRequest = {
  jsonrpc: '2.0';
  id?: JsonRpcId;
  method: string;
  params?: unknown;
};

type RunHeadless = (
  request: HeadlessRunRequest,
  options: HeadlessRunOptions
) => HeadlessRunOutput | Promise<HeadlessRunOutput>;

export type RpcServerOptions = {
  writeLine: (line: string) => void;
  makeRunId?: () => string;
  runHeadless?: RunHeadless;
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

export function createRpcServer(options: RpcServerOptions): RpcServer {
  const runHeadless = options.runHeadless ?? defaultRunHeadless;
  const makeRunId = options.makeRunId ?? defaultMakeRunId;
  const finishedRunIds = new Set<string>();
  let activeRun: ActiveRun | undefined;

  const write = (message: unknown) => {
    options.writeLine(JSON.stringify(message));
  };

  const writeResult = (id: JsonRpcId, result: unknown) => {
    write({ jsonrpc: JSON_RPC_VERSION, id, result });
  };

  const writeError = (id: JsonRpcId, code: number, message: string) => {
    write({ jsonrpc: JSON_RPC_VERSION, id, error: { code, message } });
  };

  const writeEvent = (event: RuntimeEventEnvelope) => {
    write({ jsonrpc: JSON_RPC_VERSION, method: 'run.event', params: event });
  };

  const startRun = (id: JsonRpcId, params: unknown) => {
    if (!isObject(params)) {
      writeError(id, INVALID_PARAMS, 'run.start params must be an object');
      return;
    }
    if (activeRun) {
      writeError(id, ACTIVE_RUN_ERROR, 'an active run is already in progress');
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
      .catch(() => undefined)
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

    writeResult(id, { runId });
  };

  const cancelRun = (id: JsonRpcId, params: unknown) => {
    if (!isObject(params) || typeof params.runId !== 'string') {
      writeError(id, INVALID_PARAMS, 'run.cancel params must include runId');
      return;
    }

    const { runId } = params;
    if (activeRun?.runId === runId) {
      activeRun.controller.abort();
      writeResult(id, { status: 'cancelled' });
      return;
    }

    if (finishedRunIds.has(runId)) {
      writeResult(id, { status: 'already-finished' });
      return;
    }

    writeResult(id, { status: 'not-found' });
  };

  const dispatch = (request: JsonRpcRequest) => {
    const id = request.id ?? null;

    switch (request.method) {
      case 'run.start':
        startRun(id, request.params);
        return;
      case 'run.cancel':
        cancelRun(id, request.params);
        return;
      default:
        writeError(id, METHOD_NOT_FOUND, `method not found: ${request.method}`);
    }
  };

  return {
    async handleLine(line: string) {
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
        dispatch(parsed);
      } catch {
        writeError(parsed.id ?? null, INTERNAL_ERROR, 'internal error');
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
