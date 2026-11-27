import assert from 'node:assert/strict';
import test from 'node:test';
import { PassThrough } from 'node:stream';
import { render } from 'ink-testing-library';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { encodeControlCheckpointCursor } from '../kernel/control-wire.js';
import { createClientApplication } from './application.js';
import { ClientTui } from './tui.js';
import { at, hello, outputStream, protocolClient, ref, runSnapshot } from './testing/protocol.js';

// Inert strict-wire presentation only. No accepted Run, network server,
// native owner, permission, or physical closure is constructed by this test.
test('Ink retains exact manual risk under a higher Stop and never treats r as acknowledgement', async () => {
  const wait = {
    schemaVersion: 1, kind: 'reconciliation', runId: 'run', createdFromRevision: 1,
    createdAt: at, frontierRef: ref,
    subject: { kind: 'invocation', recovery: 'manual', opKind: 'mcp', opId: 'calendar-create', attempt: 0 },
    probeState: { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 }
  };
  const waitingOnRef = canonicalSha256(wait), bytes = canonicalJsonBytes(wait), snapshot = runSnapshot();
  Object.assign(snapshot.run, {
    status: 'waiting', nextStep: 'tool', revision: 3, waitingReason: 'reconciliation', waitingOnRef,
    stopIntentRef: ref, cancelRequested: true
  });
  snapshot.run.budgetConsumed.toolCalls = 1;
  let reconciliations = 0;
  const f = protocolClient({
    hello: { ...hello, enabledFeatureIds: [...hello.enabledFeatureIds, 'run.reconcile'] },
    'run.get': async () => ({ protocolVersion: 1, ok: true, result: {
      method: 'run.get', snapshot, items: [], journal: [], checkpoints: [], highWaterItemSeq: 0, highWaterJournalSeq: 0,
      highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }),
      nextItemSeq: 0, nextJournalSeq: 0
    } }),
    'run.attach': async () => ({ protocolVersion: 1, ok: false, method: 'run.attach', error: {
      schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', retryable: false, messageCode: 'expired',
      earliestEventSeq: 5, latestEventSeq: 7, snapshot
    } }),
    'artifact.get': async (request: { digest: string; offset: number; length: number }) => {
      assert.equal(request.digest, waitingOnRef);
      const part = bytes.subarray(request.offset, request.offset + request.length), nextOffset = request.offset + part.length;
      return { protocolVersion: 1, ok: true, result: {
        method: 'artifact.get', artifact: { schemaVersion: 1, ref: waitingOnRef, digest: waitingOnRef,
          sizeBytes: bytes.length, mediaType: 'application/json' },
        offset: request.offset, nextOffset, bytesBase64: part.toString('base64'), eof: nextOffset === bytes.length
      } };
    },
    'run.reconcile': async () => {
      reconciliations++;
      throw new Error('the r shortcut cannot acknowledge manual risk');
    }
  });
  const app = createClientApplication(f.session, () => {});
  const io = { input: new PassThrough(), output: outputStream().stream, diagnostic: outputStream().stream, workspacePath: '/workspace' };
  const ui = render(<ClientTui app={app} io={io} initialRunId="run" />);
  try {
    for (let count = 0; count < 200 && !ui.lastFrame()?.includes('effect may have occurred'); count++) {
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.match(ui.lastFrame() ?? '', /calendar-create/u);
    assert.match(ui.lastFrame() ?? '', /effect may have occurred/u);
    assert.match(ui.lastFrame() ?? '', /result will not be used/u);
    assert.match(ui.lastFrame() ?? '', /acknowledge-exact-risk/u);
    assert.equal(reconciliations, 0);
    ui.stdin.write('r');
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(reconciliations, 0);
    assert.equal(f.calls.some(call => ['run.cancel', 'run.approve', 'run.input'].includes(call.method)), false);
  } finally {
    ui.unmount();
    await app.close();
  }
});
