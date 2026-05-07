import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import type { HeadlessRunOutput, HeadlessRunRequest, RuntimeEventEnvelope } from './contract.js';
import {
  HEADLESS_EXIT_CANCELLED,
  HEADLESS_EXIT_FAILURE,
  HEADLESS_EXIT_SUCCESS,
  emptyHeadlessArtifacts
} from './contract.js';
import { createRpcServer, runStdioJsonRpcServer } from './rpc.js';

function parseLines(lines: string[]) {
  return lines.map((line) => JSON.parse(line));
}

function completedOutput(runId: string): HeadlessRunOutput {
  return {
    runId,
    status: 'completed',
    exitCode: HEADLESS_EXIT_SUCCESS,
    finalMessage: 'done',
    artifacts: emptyHeadlessArtifacts()
  };
}

function cancelledOutput(runId: string): HeadlessRunOutput {
  return {
    runId,
    status: 'cancelled',
    exitCode: HEADLESS_EXIT_CANCELLED,
    artifacts: emptyHeadlessArtifacts(),
    error: { code: 'cancelled', stage: 'cancel', message: 'run cancelled', recoverable: false }
  };
}

function collectStreamLines(stream: PassThrough) {
  const chunks: Buffer[] = [];
  stream.on('data', (chunk: Buffer) => {
    chunks.push(chunk);
  });
  return () => Buffer.concat(chunks).toString('utf8').trim().split('\n').filter(Boolean);
}

async function waitForAbort(signal?: AbortSignal) {
  if (signal?.aborted) {
    return;
  }

  await new Promise<void>((resolve) => {
    signal?.addEventListener('abort', () => resolve(), { once: true });
  });
}

test('rpc returns parse errors for invalid JSON lines', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    }
  });

  await server.handleLine('{bad json');

  const [response] = parseLines(writes);
  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, null);
  assert.equal(response.error.code, -32700);
});

test('rpc returns method-not-found errors for unknown methods', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'missing.method' }));

  const [response] = parseLines(writes);
  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, 1);
  assert.equal(response.error.code, -32601);
});

test('rpc returns invalid params errors for malformed run params', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'run.start' }));
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'run.cancel', params: {} }));

  const messages = parseLines(writes);
  assert.equal(messages[0].id, 1);
  assert.equal(messages[0].error.code, -32602);
  assert.equal(messages[1].id, 2);
  assert.equal(messages[1].error.code, -32602);
});

test('rpc returns internal errors for synchronous dispatcher failures', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    },
    makeRunId() {
      throw new Error('id generator failed');
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'hello' }
    })
  );

  const [response] = parseLines(writes);
  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, 1);
  assert.equal(response.error.code, -32603);
});

test('rpc run.start returns a run id and emits run events with the same id', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    },
    makeRunId: () => 'run_rpc_1',
    async runHeadless(request: HeadlessRunRequest, options) {
      const event: RuntimeEventEnvelope = {
        schemaVersion: 1,
        eventId: 'evt_rpc_1',
        runId: options.runId!,
        timestamp: '2026-05-06T00:00:00.000Z',
        type: 'run-start',
        payload: {
          cwd: request.cwd,
          policy: request.policy ?? 'auto',
          model: { provider: 'ollama', model: 'fake' }
        }
      };
      await options.onEvent?.(event);
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'hello' }
    })
  );
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.deepEqual(messages[0], { jsonrpc: '2.0', id: 1, result: { runId: 'run_rpc_1' } });
  assert.equal(messages[1].method, 'run.event');
  assert.equal(messages[1].params.runId, 'run_rpc_1');
});

test('rpc rejects a second active run in the same process', async () => {
  const writes: string[] = [];
  let release!: () => void;
  const blocking = new Promise<void>((resolve) => {
    release = resolve;
  });
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    },
    makeRunId: () => `run_rpc_${writes.length}`,
    async runHeadless(_request, options) {
      await blocking;
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'run.start', params: { cwd: process.cwd(), prompt: 'one' } })
  );
  await server.handleLine(
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'run.start', params: { cwd: process.cwd(), prompt: 'two' } })
  );
  release();
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.equal(messages[1].id, 2);
  assert.equal(messages[1].error.code, -32001);
  assert.match(messages[1].error.message, /active run/i);
});

test('rpc run.cancel aborts the active run controller', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    },
    makeRunId: () => 'run_rpc_cancel',
    async runHeadless(_request, options) {
      await new Promise<void>((resolve) => {
        options.signal?.addEventListener('abort', () => resolve(), { once: true });
      });
      return {
        runId: options.runId!,
        status: 'cancelled',
        exitCode: HEADLESS_EXIT_CANCELLED,
        artifacts: emptyHeadlessArtifacts(),
        error: { code: 'cancelled', stage: 'cancel', message: 'run cancelled', recoverable: false }
      };
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'cancel me' }
    })
  );
  await server.handleLine(
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'run.cancel', params: { runId: 'run_rpc_cancel' } })
  );
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.deepEqual(messages[1], { jsonrpc: '2.0', id: 2, result: { status: 'cancelled' } });
});

test('stdio rpc aborts the active run and resolves when stdin closes', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const outputLines = collectStreamLines(output);
  let signalAborted = false;
  const done = runStdioJsonRpcServer({
    input,
    output,
    serverOptions: {
      makeRunId: () => 'run_rpc_stdin_close',
      async runHeadless(_request, options) {
        await waitForAbort(options.signal);
        signalAborted = options.signal?.aborted ?? false;
        await options.onEvent?.({
          schemaVersion: 1,
          eventId: 'evt_rpc_stdin_close',
          runId: options.runId!,
          timestamp: '2026-05-06T00:00:00.000Z',
          type: 'run-end',
          payload: {
            status: 'cancelled',
            exitCode: HEADLESS_EXIT_CANCELLED,
            output: cancelledOutput(options.runId!)
          }
        });
        return cancelledOutput(options.runId!);
      }
    }
  });

  input.write(
    `${JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'abort on stdin close' }
    })}\n`
  );
  input.end();

  await done;

  const messages = parseLines(outputLines());
  assert.equal(signalAborted, true);
  assert.deepEqual(messages[0], { jsonrpc: '2.0', id: 1, result: { runId: 'run_rpc_stdin_close' } });
  assert.equal(messages[1].method, 'run.event');
  assert.equal(messages[1].params.type, 'run-end');
  assert.equal(messages[1].params.runId, 'run_rpc_stdin_close');
});

test('stdio rpc aborts the active run when stdout errors', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let signalAborted = false;
  const done = runStdioJsonRpcServer({
    input,
    output,
    serverOptions: {
      makeRunId: () => 'run_rpc_stdout_error',
      async runHeadless(_request, options) {
        await waitForAbort(options.signal);
        signalAborted = options.signal?.aborted ?? false;
        return cancelledOutput(options.runId!);
      }
    }
  });

  input.write(
    `${JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'abort on stdout error' }
    })}\n`
  );
  output.emit('error', new Error('EPIPE'));

  await done;

  assert.equal(signalAborted, true);
});

test('rpc emits terminal failure events when an accepted run rejects', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    },
    makeRunId: () => 'run_rpc_reject',
    async runHeadless() {
      throw new Error('runner exploded');
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'explode' }
    })
  );
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.deepEqual(messages[0], { jsonrpc: '2.0', id: 1, result: { runId: 'run_rpc_reject' } });
  assert.equal(messages[1].method, 'run.event');
  assert.equal(messages[1].params.runId, 'run_rpc_reject');
  assert.equal(messages[1].params.type, 'error');
  assert.deepEqual(messages[1].params.payload, {
    code: 'internal-error',
    stage: 'assembly',
    message: 'runner exploded',
    recoverable: false
  });
  assert.equal(messages[2].method, 'run.event');
  assert.equal(messages[2].params.runId, 'run_rpc_reject');
  assert.equal(messages[2].params.type, 'run-end');
  assert.equal(messages[2].params.payload.status, 'failed');
  assert.equal(messages[2].params.payload.exitCode, HEADLESS_EXIT_FAILURE);
  assert.equal(messages[2].params.payload.output.runId, 'run_rpc_reject');
  assert.equal(messages[2].params.payload.output.status, 'failed');
});

test('rpc write failures abort the active run and close future writes', async () => {
  const writes: string[] = [];
  let eventCallbackRejected = false;
  let signalAborted = false;
  const server = createRpcServer({
    writeLine(line) {
      const message = JSON.parse(line);
      if (message.method === 'run.event') {
        throw new Error('sink failed');
      }
      writes.push(line);
    },
    makeRunId: () => `run_rpc_write_${writes.length}`,
    async runHeadless(_request, options) {
      const event: RuntimeEventEnvelope = {
        schemaVersion: 1,
        eventId: 'evt_rpc_write',
        runId: options.runId!,
        timestamp: '2026-05-06T00:00:00.000Z',
        type: 'run-start',
        payload: {
          cwd: process.cwd(),
          policy: 'auto',
          model: { provider: 'ollama', model: 'fake' }
        }
      };
      try {
        await options.onEvent?.(event);
      } catch {
        eventCallbackRejected = true;
      }
      signalAborted = options.signal?.aborted ?? false;
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'write failure' }
    })
  );
  await server.waitForIdle();
  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'after failure' }
    })
  );
  await server.waitForIdle();

  assert.equal(eventCallbackRejected, false);
  assert.equal(signalAborted, true);
  assert.deepEqual(parseLines(writes), [{ jsonrpc: '2.0', id: 1, result: { runId: 'run_rpc_write_0' } }]);
});

test('rpc async write failures abort the active run and close future writes', async () => {
  const writes: string[] = [];
  let eventCallbackRejected = false;
  let signalAborted = false;
  const server = createRpcServer({
    writeLine(line) {
      const message = JSON.parse(line);
      if (message.method === 'run.event') {
        return Promise.reject(new Error('sink closed'));
      }
      writes.push(line);
    },
    makeRunId: () => `run_rpc_async_write_${writes.length}`,
    async runHeadless(_request, options) {
      const event: RuntimeEventEnvelope = {
        schemaVersion: 1,
        eventId: 'evt_rpc_async_write',
        runId: options.runId!,
        timestamp: '2026-05-06T00:00:00.000Z',
        type: 'run-start',
        payload: {
          cwd: process.cwd(),
          policy: 'auto',
          model: { provider: 'ollama', model: 'fake' }
        }
      };
      try {
        await options.onEvent?.(event);
      } catch {
        eventCallbackRejected = true;
      }
      await Promise.resolve();
      signalAborted = options.signal?.aborted ?? false;
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'async write failure' }
    })
  );
  await server.waitForIdle();
  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'after async failure' }
    })
  );
  await server.waitForIdle();

  assert.equal(eventCallbackRejected, false);
  assert.equal(signalAborted, true);
  assert.deepEqual(parseLines(writes), [{ jsonrpc: '2.0', id: 1, result: { runId: 'run_rpc_async_write_0' } }]);
});

test('rpc accepts notifications without writing request responses', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    }
  });

  await server.handleLine(
    JSON.stringify({ jsonrpc: '2.0', method: 'run.cancel', params: { runId: 'run_missing' } })
  );
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'missing.method' }));

  assert.deepEqual(writes, []);
});

test('rpc run.start notifications start a run and emit run events without result responses', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine(line) {
      writes.push(line);
    },
    makeRunId: () => 'run_rpc_notification',
    async runHeadless(request: HeadlessRunRequest, options) {
      const event: RuntimeEventEnvelope = {
        schemaVersion: 1,
        eventId: 'evt_rpc_notification',
        runId: options.runId!,
        timestamp: '2026-05-06T00:00:00.000Z',
        type: 'run-start',
        payload: {
          cwd: request.cwd,
          policy: request.policy ?? 'auto',
          model: { provider: 'ollama', model: 'fake' }
        }
      };
      await options.onEvent?.(event);
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'hello notification' }
    })
  );
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].jsonrpc, '2.0');
  assert.equal(messages[0].method, 'run.event');
  assert.equal(messages[0].params.runId, 'run_rpc_notification');
  assert.equal(messages[0].params.type, 'run-start');
  assert.equal(Object.hasOwn(messages[0], 'id'), false);
});

test('rpc session.get returns a stable session view', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getSessionView(cwd, sessionId) {
      return {
        id: sessionId ?? 'sess_active',
        cwd,
        model: { provider: 'ollama', model: 'fake' },
        lifecycle: { status: 'idle', turn: 0 },
        records: [],
        checkpoints: [],
        compactions: []
      };
    }
  });

  await server.handleLine(
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'session.get', params: { cwd: '/tmp/project', sessionId: 'sess_1' } })
  );

  const [response] = parseLines(writes);
  assert.equal(response.result.id, 'sess_1');
  assert.equal(response.result.cwd, '/tmp/project');
});

test('rpc artifact.get returns a stable artifact view', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getArtifactView(cwd, artifactId, sessionId) {
      assert.equal(cwd, '/tmp/project');
      assert.equal(sessionId, 'sess_1');
      return {
        kind: 'compaction',
        compaction: {
          id: artifactId,
          status: 'active',
          createdAt: '2026-05-06T00:00:00.000Z',
          coveredRange: { startIndexInclusive: 0, endIndexExclusive: 1 },
          firstKeptRecordId: 'usr_1',
          createdBy: { provider: 'ollama', model: 'fake' },
          summaryMarkdown: 'summary'
        }
      };
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'artifact.get',
      params: { cwd: '/tmp/project', sessionId: 'sess_1', artifactId: 'cmp_1' }
    })
  );

  const [response] = parseLines(writes);
  assert.equal(response.result.kind, 'compaction');
  assert.equal(response.result.compaction.id, 'cmp_1');
});

test('rpc query methods map missing artifacts to application errors', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getArtifactView() {
      throw new Error('artifact not found: cmp_missing');
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'artifact.get',
      params: { cwd: '/tmp/project', artifactId: 'cmp_missing' }
    })
  );

  const [response] = parseLines(writes);
  assert.equal(response.error.code, -32004);
  assert.match(response.error.message, /artifact not found/);
});

test('rpc query methods reject empty identifiers as invalid params', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getSessionView() {
      throw new Error('query provider should not run');
    },
    async getArtifactView() {
      throw new Error('query provider should not run');
    }
  });

  const requests = [
    { method: 'session.get', params: { cwd: '' } },
    { method: 'session.get', params: { cwd: '   ' } },
    { method: 'session.get', params: { cwd: '/tmp/project', sessionId: '' } },
    { method: 'session.get', params: { cwd: '/tmp/project', sessionId: ' sess_1 ' } },
    { method: 'artifact.get', params: { cwd: '/tmp/project', artifactId: '' } },
    { method: 'artifact.get', params: { cwd: '/tmp/project', artifactId: ' cmp_1 ' } },
    { method: 'artifact.get', params: { cwd: '/tmp/project', artifactId: 'cmp_1', sessionId: ' sess_1 ' } },
    { method: 'artifact.get', params: { cwd: '/tmp/project', artifactId: 'cmp_1', sessionId: '   ' } }
  ];

  for (const [index, request] of requests.entries()) {
    await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: index + 1, ...request }));
  }

  const messages = parseLines(writes);
  assert.equal(messages.length, requests.length);
  for (const message of messages) {
    assert.equal(message.error.code, -32602);
  }
});

test('rpc query methods preserve cwd surrounding spaces', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getArtifactView(cwd, artifactId, sessionId) {
      assert.equal(cwd, ' /tmp/project ');
      assert.equal(artifactId, 'cmp_1');
      assert.equal(sessionId, undefined);
      return {
        kind: 'compaction',
        compaction: {
          id: artifactId,
          status: 'active',
          createdAt: '2026-05-06T00:00:00.000Z',
          coveredRange: { startIndexInclusive: 0, endIndexExclusive: 1 },
          firstKeptRecordId: 'usr_1',
          createdBy: { provider: 'ollama', model: 'fake' },
          summaryMarkdown: 'summary'
        }
      };
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'artifact.get',
      params: { cwd: ' /tmp/project ', artifactId: 'cmp_1' }
    })
  );

  const [response] = parseLines(writes);
  assert.equal(response.result.kind, 'compaction');
});

test('rpc query methods map missing sessions to application errors', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getSessionView() {
      throw new Error('session not found: sess_missing');
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'session.get',
      params: { cwd: '/tmp/project', sessionId: 'sess_missing' }
    })
  );

  const [response] = parseLines(writes);
  assert.equal(response.error.code, -32004);
  assert.match(response.error.message, /session not found/);
});

test('rpc query dependency failures map to internal errors', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => {
      writes.push(line);
    },
    async getSessionView() {
      throw new Error('database unavailable');
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'session.get',
      params: { cwd: '/tmp/project', sessionId: 'sess_1' }
    })
  );

  const [response] = parseLines(writes);
  assert.equal(response.error.code, -32603);
});
