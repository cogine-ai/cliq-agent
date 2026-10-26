import { encodeControlCheckpointCursor } from '../kernel/control-wire.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { PassThrough } from 'node:stream';
import { render } from 'ink-testing-library';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { planInputWait } from '../runtime/user-input.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { createInstalledControlSession } from '../control/session.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { createClientApplication } from './application.js';
import { readWaitingPresentation } from './artifacts.js';
import { ClientTui, splitClientCommand } from './tui.js';
import { at, ref, hello, protocolClient, outputStream, runSnapshot } from './testing/protocol.js';

// Ink and the production strict wire/byte consumer only. No installation,
// accepted Run, native death or ToolPermission grant is minted here.
async function until(check: () => boolean, detail: () => unknown = () => '') {
  for (let count = 0; count < 200; count++) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 5)); }
  assert(check(), 'the owned component did not reach its expected visible condition: ' + JSON.stringify(detail()));
}
function fixture(kind: 'approval' | 'input', gate?: { enter(): void; wait: Promise<void>; failFirstArtifact?: boolean }) {
  let gets = 0, reads = 0;
  const objects = new Map<string, Buffer>();
  const save = (value: unknown) => { const bytes = canonicalJsonBytes(value), digest = canonicalSha256(value); objects.set(digest, bytes); return digest; };
  const evidence = { schemaVersion: 1, format: 'cliq-tool-policy-channel-evidence-v1', runId: 'run',
    evidenceDigest: '', display: 'Original action: edit only note.txt' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
  let item: ReturnType<typeof planInputWait>['item'] | undefined;
  const wait = kind === 'approval' ? { schemaVersion: 1, kind: 'approval', runId: 'run', createdFromRevision: 1, createdAt: at, frontierRef: ref,
    subject: { kind: 'tool_call', policySubjectKind: 'ordinary_tool', batchItemId: 'batch', callId: 'call', callIndex: 0,
      opId: 'op', target: ref, toolName: 'edit', toolContractDigest: ref, replayClass: 'manual',
      policyChannelEvidenceRef: save(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest } } : (() => {
    const call: ToolCallInputV1 = { schemaVersion: 1, format: 'cliq-tool-call-input-v1', toolName: 'request_input', callId: 'call', index: 0,
      inputDigest: ref, observedInputRef: ref, observedInputDigest: ref, inputSchemaRef: ref, inputSchemaDigest: ref, disposition: 'resolved',
      value: { prompt: 'Which name should I use?', responseKind: 'text', maximumResponseBytes: 128 } };
    const proof = planInputWait({ id: 'run', revision: 1, frontierRef: ref }, 'batch', call, at);
    for (const artifact of proof.artifacts) objects.set(artifact.ref, Buffer.from(artifact.bytes));
    item = proof.item; save(item); return proof.wait;
  })();
  const waitingOnRef = save(wait), snapshot = runSnapshot();
  snapshot.latestRunItemSeq = item ? 1 : 0;
  Object.assign(snapshot.run, { status: 'waiting', nextStep: 'tool', revision: 2, waitingReason: kind, waitingOnRef });
  const f = protocolClient({
    'run.get': async () => { if (++gets === 2 && gate) { gate.enter(); await gate.wait; } return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot,
      items: item ? [{ schemaVersion: 1, itemId: item.itemId, itemSeq: 1, payloadRef: canonicalSha256(item), payloadDigest: canonicalSha256(item), createdAt: at }] : [],
      journal: [], checkpoints: [], highWaterItemSeq: snapshot.latestRunItemSeq, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }), nextItemSeq: snapshot.latestRunItemSeq, nextJournalSeq: 0 } }; },
    'run.attach': async () => ({ protocolVersion: 1, ok: false, method: 'run.attach', error: { schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', retryable: false,
      messageCode: 'expired', earliestEventSeq: 5, latestEventSeq: 7, snapshot } }),
    'artifact.get': async (request: { digest: string; offset: number; length: number }) => {
      if (++reads === 1 && gate?.failFirstArtifact) return { protocolVersion: 1, ok: false, method: 'artifact.get', error: {
        schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
      const bytes = objects.get(request.digest)!; assert(bytes, 'only the original referenced artifacts are readable');
      const part = bytes.subarray(request.offset, request.offset + request.length), nextOffset = request.offset + part.length;
      return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: { schemaVersion: 1, ref: request.digest,
        digest: request.digest, sizeBytes: bytes.length, mediaType: 'application/json' }, offset: request.offset, nextOffset,
        bytesBase64: part.toString('base64'), eof: nextOffset === bytes.length } };
    },
    'run.cancel': async () => ({ protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.authorization_required' } }),
    'run.approve': async () => ({ protocolVersion: 1, ok: false, method: 'run.approve', error: { schemaVersion: 1,
      code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.authorization_required' } }),
    'run.input': async () => {
      const next = runSnapshot(); next.run.revision = 3; next.latestRunItemSeq = 3;
      return { protocolVersion: 1, ok: true, result: { method: 'run.input', inputItemRef: ref, snapshot: next } };
    }
  });
  const app = createClientApplication(f.session, () => {}), input = new PassThrough();
  const io = { input, output: outputStream().stream, diagnostic: outputStream().stream, workspacePath: '/workspace' };
  return { ...f, app, io, waitingOnRef, snapshot };
}

test('Ink shows the exact approval data and sends one explicit revision-bound decision; detach never cancels', async () => {
  const f = fixture('approval'), ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await until(() => ui.lastFrame()?.includes('y: allow this exact action') === true, () => ({ frame: ui.lastFrame(), calls: f.calls.map(c => c.method) }));
    assert.match(ui.lastFrame()!, /edit only/u); assert.match(ui.lastFrame()!, /note.txt/u);
    ui.stdin.write('y'); await until(() => f.calls.some(call => call.method === 'run.approve'));
    const request = f.calls.find(call => call.method === 'run.approve')!.request;
    assert.equal(request.expectedRevision, 2); assert.equal(request.waitingOnRef, f.waitingOnRef); assert.equal(request.decision, 'allow');
    ui.stdin.write('\u0003'); await until(() => ui.lastFrame() !== undefined);
    assert.equal(f.calls.some(call => call.method === 'run.cancel'), false);
  } finally { ui.unmount(); await f.app.close(); }
});

test('Ink reads the original production input prompt and submits text to that exact wait once', async () => {
  const f = fixture('input'), ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await until(() => ui.lastFrame()?.includes('Which name should I use?') === true, () => ({ frame: ui.lastFrame(), calls: f.calls.map(c => c.method) }));
    ui.stdin.write('Alice'); await new Promise(resolve => setTimeout(resolve, 20)); ui.stdin.write('\r');
    await until(() => f.calls.some(call => call.method === 'run.input'));
    const request = f.calls.find(call => call.method === 'run.input')!.request;
    assert.equal(request.expectedRevision, 2); assert.equal(request.waitingOnRef, f.waitingOnRef);
    assert.equal(canonicalJsonBytes(request.input).toString(), '{"kind":"text","value":"Alice"}');
    assert.equal(f.calls.filter(call => call.method === 'run.input').length, 1);
    assert.equal(f.calls.some(call => call.method === 'run.cancel'), false);
  } finally { ui.unmount(); await f.app.close(); }
});

test('local client tokenization preserves quoted data without shell expansion or partial quotes', () => {
  assert.deepEqual(splitClientCommand('run "literal $(not-executed)" --model \'a b\' --provider ollama'),
    ['run', 'literal $(not-executed)', '--model', 'a b', '--provider', 'ollama']);
  assert.throws(() => splitClientCommand('run "unfinished'));
  assert.deepEqual(splitClientCommand('input run --text ""'), ['input', 'run', '--text', '']);
});

test('input presentation follows the actual strict protocol fixture graph', async () => {
  const f = fixture('input');
  try { assert.equal((await readWaitingPresentation(f.app, f.snapshot)).text, 'Which name should I use?'); }
  finally { await f.app.close(); }
});

test('Ink submits a legal empty text response to its captured wait; an unrelated empty Enter does no work', async () => {
  const f = fixture('input'), ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await until(() => ui.lastFrame()?.includes('Which name should I use?') === true);
    ui.stdin.write('\r'); await until(() => f.calls.some(call => call.method === 'run.input'));
    const request = f.calls.find(call => call.method === 'run.input')!.request;
    assert.equal(request.expectedRevision, 2); assert.equal(request.waitingOnRef, f.waitingOnRef);
    assert.equal(canonicalJsonBytes(request.input).toString(), '{"kind":"text","value":""}');
    assert.equal(f.calls.filter(call => call.method === 'run.input').length, 1);
  } finally { ui.unmount(); await f.app.close(); }
  const other = fixture('approval'), unrelated = render(<ClientTui app={other.app} io={other.io} initialRunId="run" />);
  try {
    await until(() => unrelated.lastFrame()?.includes('y: allow this exact action') === true);
    unrelated.stdin.write('\r'); await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(other.calls.some(call => ['run.submit', 'run.input', 'run.approve', 'run.cancel'].includes(call.method)), false);
  } finally { unrelated.unmount(); await other.app.close(); }
});

test('a current StopIntent clears the original input prompt and cannot submit a stale answer', async () => {
  const f = fixture('input'), ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await until(() => ui.lastFrame()?.includes('Which name should I use?') === true);
    Object.assign(f.snapshot.run, { revision: 3, cancelRequested: true, stopIntentRef: ref });
    await f.app.execute({ kind: 'request', request: { protocolVersion: 1, method: 'run.get', runId: 'run' } });
    await until(() => ui.lastFrame()?.includes('Stop requested · awaiting completion') === true && !ui.lastFrame()?.includes('Which name should I use?'));
    ui.stdin.write('stale answer'); await new Promise(resolve => setTimeout(resolve, 20)); ui.stdin.write('\r');
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(f.calls.some(call => call.method === 'run.input'), false);
    assert.equal(f.calls.some(call => call.method === 'run.submit'), false);
  } finally { ui.unmount(); await f.app.close(); }
});


test('a pending prompt display read never consumes the explicit cancel command slot', async () => {
  let enter!: () => void, release!: () => void;
  const entered = new Promise<void>(resolve => { enter = resolve; }), wait = new Promise<void>(resolve => { release = resolve; });
  const f = fixture('input', { enter, wait }), ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await entered; ui.stdin.write('\u000b'); await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(f.calls.some(call => call.method === 'run.cancel'), false, 'wire I/O stays serial behind the original display read');
    release(); await until(() => f.calls.some(call => call.method === 'run.cancel'));
    assert.equal(f.calls.filter(call => call.method === 'run.cancel').length, 1);
    assert.equal(f.calls.find(call => call.method === 'run.cancel')!.request.expectedRevision, 2);
  } finally { release(); ui.unmount(); await f.app.close(); }
});


test('an explicit reattach can reread refused immutable prompt data without reissuing a mutation', async () => {
  const f = fixture('input', { enter() {}, wait: Promise.resolve(), failFirstArtifact: true });
  const ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await until(() => ui.lastFrame()?.includes('Client operation refused or unavailable.') === true);
    assert.equal(ui.lastFrame()?.includes('Which name should I use?'), false);
    ui.stdin.write(':attach run'); await new Promise(resolve => setTimeout(resolve, 20)); ui.stdin.write('\r');
    await until(() => ui.lastFrame()?.includes('Which name should I use?') === true);
    assert.equal(f.calls.some(call => ['run.submit', 'run.input', 'run.approve', 'run.cancel'].includes(call.method)), false);
  } finally { ui.unmount(); await f.app.close(); }
});

test('artifact inspection cannot hide the original approval subject while accepting its shortcut', async () => {
  const f = fixture('approval'), ui = render(<ClientTui app={f.app} io={f.io} initialRunId="run" />);
  try {
    await until(() => ui.lastFrame()?.includes('y: allow this exact action') === true);
    ui.stdin.write(':artifact ' + f.waitingOnRef); await new Promise(resolve => setTimeout(resolve, 20)); ui.stdin.write('\r');
    await until(() => ui.lastFrame()?.includes(':back') === true);
    ui.stdin.write('y'); await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(f.calls.filter(call => call.method === 'run.approve').length, 0);
    ui.stdin.write('\r'); await new Promise(resolve => setTimeout(resolve, 20));
    ui.stdin.write(':back'); await new Promise(resolve => setTimeout(resolve, 20)); ui.stdin.write('\r');
    await until(() => ui.lastFrame()?.includes('y: allow this exact action') === true);
    assert.match(ui.lastFrame()!, /edit only/u);
    ui.stdin.write('y'); await until(() => f.calls.some(call => call.method === 'run.approve'));
    assert.equal(f.calls.filter(call => call.method === 'run.approve').length, 1);
    assert.equal(f.calls.find(call => call.method === 'run.approve')!.request.waitingOnRef, f.waitingOnRef);
  } finally { ui.unmount(); await f.app.close(); }
});

test('Ink retains an unresolved original request and reconnect sends nothing until explicit replay', async () => {
  const requests: Buffer[] = []; let reconnects = 0;
  const protocol = { hello, close: async () => {}, 'run.cancel': async (request: unknown) => {
    requests.push(canonicalJsonBytes(request));
    if (requests.length === 1) throw new Error('the original reply was lost');
    return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1,
      code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
  } };
  const session = createInstalledControlSession(protocol as unknown as InstalledSupervisorClient,
    async () => { reconnects++; return protocol as unknown as InstalledSupervisorClient; });
  const app = createClientApplication(session, () => {}), input = new PassThrough();
  const io = { input, output: outputStream().stream, diagnostic: outputStream().stream, workspacePath: '/workspace' };
  const ui = render(<ClientTui app={app} io={io} />);
  async function command(value: string) { ui.stdin.write(value); await new Promise(resolve => setTimeout(resolve, 20)); ui.stdin.write('\r'); }
  try {
    await command(':cancel run --revision 1');
    await until(() => ui.lastFrame()?.includes(':replay') === true, () => ({ frame: ui.lastFrame(), sends: requests.length }));
    const original = app.pendingRequest; assert(original && 'requestId' in original);
    assert.match(ui.lastFrame()!, new RegExp(original.requestId));
    await command(':reconnect'); await until(() => reconnects === 1 && ui.lastFrame()?.includes('connected') === true);
    assert.equal(requests.length, 1);
    await command(':replay'); await until(() => requests.length === 2 && ui.lastFrame()?.includes('NOT_FOUND') === true);
    assert.deepEqual(requests[0], requests[1]); assert.equal(app.pendingRequest, undefined);
    assert.equal(ui.lastFrame()?.includes('Original request'), false);
  } finally { ui.unmount(); await app.close(); }
});
