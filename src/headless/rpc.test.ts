import assert from 'node:assert/strict';
import test from 'node:test';

import type { HeadlessRunOutput, HeadlessRunRequest, RuntimeEventEnvelope } from './contract.js';
import { HEADLESS_EXIT_CANCELLED, HEADLESS_EXIT_SUCCESS, emptyHeadlessArtifacts } from './contract.js';
import { createRpcServer } from './rpc.js';

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

test('rpc returns parse errors for invalid JSON lines', async () => {
  const writes: string[] = [];
  const server = createRpcServer({ writeLine: (line) => writes.push(line) });

  await server.handleLine('{bad json');

  const [response] = parseLines(writes);
  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, null);
  assert.equal(response.error.code, -32700);
});

test('rpc run.start returns a run id and emits run events with the same id', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
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
    writeLine: (line) => writes.push(line),
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
    writeLine: (line) => writes.push(line),
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
