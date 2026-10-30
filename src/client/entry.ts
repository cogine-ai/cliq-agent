import type { Readable, Writable } from 'node:stream';
import { setImmediate as yieldTurn } from 'node:timers/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { headlessControlResponse, type InstalledControlResponseFor, type InstalledControlFeature } from '../control/v1.js';
import type { InstalledControlSession } from '../control/session.js';
import { openInstalledClientHost } from './installed-host.js';
import { runInstalledHeadlessJsonl, runInstalledHeadlessRpc } from '../headless/installed.js';
import type { HeldInstalledRuntime } from '../state/installed-runtime.js';
import { ResourceRetirementError } from '../state/errors.js';
import { createClientApplication, type ClientUpdate } from './application.js';
import { parseClientInvocation, type ClientInvocation, type ClientInvocationDefaults } from './commands.js';
import { humanResponse, sessionContextLines, terminalText } from './view.js';
import { presentControlArtifacts, artifactText, type ClientDetail } from './details.js';
import { executeClientAction, ClientRefusal } from './actions.js';
import { openInstalledClientStdio } from './stdio.js';

export type ClientIO = Readonly<{ input: Readable; output: Writable & { isTTY?: boolean }; diagnostic: Writable;
  workspacePath: string; signal?: AbortSignal; confirmUnverified?: () => Promise<boolean>;
  commandDefaults?: ClientInvocationDefaults }>;
type Response = InstalledControlResponseFor<InstalledControlFeature>;
export function clientWriter(stream: Writable) {
  let tail: Promise<void> = Promise.resolve(), failure: unknown, cancellation: Error | undefined, closeWait: Promise<void> | undefined;
  let destroying = false;
  const cancelledWrite = (error: Error) => destroying && cancellation !== undefined && stream.destroyed &&
    (error as NodeJS.ErrnoException).code === 'ECANCELED' && (error as NodeJS.ErrnoException).syscall === 'write';
  const failed = (error: Error) => {
    if (!cancelledWrite(error) && (failure === undefined || failure === cancellation && error !== cancellation)) failure = error;
  };
  stream.on('error', failed);
  return { write(bytes: Buffer) {
    if (bytes.length > 1_048_576) return Promise.reject(new TypeError('one client output record exceeds its bound'));
    const pending = tail.then(() => new Promise<void>((resolve, reject) => {
      if (failure !== undefined) { reject(failure); return; }
      if (cancellation) { reject(cancellation); return; }
      if (stream.destroyed || !stream.writable) { const error = new Error('client output is closed'); failed(error); reject(error); return; }
      stream.write(bytes, error => {
        if (error) { failed(error); reject(cancelledWrite(error) ? cancellation : error); }
        else if (cancellation) reject(cancellation);
        else resolve();
      });
    }));
    tail = pending; return pending;
  }, cancel(reason: unknown) {
    cancellation ??= reason instanceof Error ? reason : new Error('client output was cancelled');
    if (!closeWait) {
      closeWait = stream.closed ? Promise.resolve() : new Promise<void>(resolve => { stream.once('close', resolve); });
      if (!stream.destroyed) { destroying = true; stream.destroy(cancellation); }
    }
  }, async join() {
    // Cancellation must finish the real pending write callbacks and stream
    // close. Rejecting a display promise alone cannot retire a blocked pipe.
    const results = await Promise.allSettled([tail, ...(closeWait ? [closeWait] : [])]);
    await yieldTurn(); // Node emits a write error after its callback.
    stream.removeListener('error', failed);
    const errors = results.filter((value): value is PromiseRejectedResult => value.status === 'rejected')
      .map(value => value.reason).filter(error => error !== cancellation);
    if (failure !== undefined && failure !== cancellation) errors.push(failure);
    if (errors.length) throw errors[0];
  } };
}
const help = `Cliq installed client\n\nrun <objective> --provider <id> --model <name> --endpoint <id> --credential-grant <id> [--session <id>] [--detach]\nresume <sessionId> <new objective> <same model options>\nlist | status <runId> | inspect <runId> | attach <runId> | cancel <runId>\napprove <runId> --revision <n> --wait <ref> --decision allow|deny\ninput <runId> --revision <n> --wait <ref> --text <value>\nreconcile <runId> --revision <n> --wait <ref>\ndiff <runId> | result <runId> | apply <runId> [--result <ref>] [--detach] | artifact <ref> > file
inspect <runId> [--after-item <n>] [--after-journal <n>] [--checkpoint-cursor <cursor>]\nsession create|list|show|fork|compact | handoff create\nauthorization create|list|revoke | supervisor status | tui [--run <id>] | jsonl | rpc\n\nRun --options takes the method's bounded JSON options; no required verifier needs explicit --allow-unverified.\nClosing a client detaches. Only an explicit cancel command cancels a Run.\n`;

/** The launcher must supply the actual held selection authenticated under its
 * fixed shipped release roots. This entry accepts no root/key/ledger override.
 * Official release-root/discovery composition is an explicit I4 dependency;
 * importing this function does not select it as the default CLI. */
export async function runInstalledClient(selected: HeldInstalledRuntime, argv: readonly string[], io: ClientIO): Promise<number> {
  const invocation = parseClientInvocation(argv, io.workspacePath, io.commandDefaults);
  if (invocation.kind === 'help') {
    const owned = await openInstalledClientStdio(selected, io);
    try { const output = clientWriter(owned.io.output); await output.write(Buffer.from(help)); await output.join(); return 0; }
    finally { await owned.close(); }
  }
  const host = await openInstalledClientHost(selected);
  try { return await host.run(invocation, io); }
  finally { await host.close(); }
}

/** Real installed entry and pure protocol/stdio regressions use this exact
 * application path. The caller keeps its selected image handles until return. */
export async function runClientInvocation(session: InstalledControlSession, invocation: ClientInvocation, io: ClientIO): Promise<number> {
  const output = clientWriter(io.output), diagnostic = clientWriter(io.diagnostic);
  let pending: Extract<ClientUpdate, { kind: 'pending' }> | undefined;
  let lastResponse: Response | undefined, rendering = false;
  const app = createClientApplication(session, async update => {
    if (update.kind === 'pending') {
      pending = update;
      if (invocation.kind === 'request-replay' && !invocation.json)
        await output.write(Buffer.from(`Replaying ${terminalText(update.method)} · ${terminalText(update.requestId)}\n`));
      return;
    }
    if (update.kind === 'connection') return;
    if (update.kind === 'context') {
      if (!rendering && !('json' in invocation && invocation.json))
        for (const text of sessionContextLines(update.projection)) await output.write(Buffer.from(terminalText(text) + '\n'));
      return;
    }
    if (update.kind === 'transcript') {
      if (rendering || 'json' in invocation && invocation.json) return;
      const bytes = Buffer.from(terminalText(update.text) + '\n');
      for (let offset = 0; offset < bytes.length; offset += 65536) await output.write(bytes.subarray(offset, offset + 65536));
      return;
    }
    if (update.kind === 'event') {
      if (rendering) return;
      if ('json' in invocation && invocation.json) await output.write(Buffer.concat([canonicalJsonBytes(update.event), Buffer.from('\n')]));
      else if (!io.output.isTTY) await output.write(Buffer.from(terminalText(update.event.type === 'progress'
        ? `Progress · ${update.event.payload.phase}\n` : `State · ${update.event.payload.status}\n`)));
      return;
    }
    const { request, response } = update; lastResponse = response;
    if ('requestId' in request && pending?.requestId === request.requestId) pending = undefined;
    if (rendering || update.origin === 'presentation') return;
    const internal = invocation.kind === 'run' && request.method === 'session.create' || invocation.kind === 'cancel' && request.method === 'run.get' ||
      invocation.kind === 'apply' && request.method === 'run.result';
    if (internal && response.ok) return;
    if ('json' in invocation && invocation.json) await output.write(Buffer.concat([canonicalJsonBytes(headlessControlResponse(response, request)), Buffer.from('\n')]));
    else if ((invocation.kind === 'run' || invocation.kind === 'apply') && invocation.detach && response.ok &&
        (response.result.method === 'run.submit' || response.result.method === 'run.apply'))
      await output.write(Buffer.from(response.result.snapshot.run.id + '\n'));
    else for (const line of humanResponse(request, response)) await output.write(Buffer.from(terminalText(line) + '\n'));
  });
  const local = new AbortController(), signal = io.signal ? AbortSignal.any([io.signal, local.signal]) : local.signal;
  function detachOnEof() {
    if (io.input.readableEnded || io.input.destroyed) local.abort();
    else { io.input.once('end', detach); io.input.once('close', detach); io.input.resume(); }
  }
  const cancelOutput = () => { output.cancel(local.signal.reason); diagnostic.cancel(local.signal.reason); };
  const detach = () => { local.abort(); cancelOutput(); void app.close().catch(() => {}); };
  const externalStop = () => { local.abort(); cancelOutput(); io.input.destroy(); void app.close().catch(() => {}); };
  io.signal?.addEventListener('abort', externalStop, { once: true });
  if (io.signal?.aborted) externalStop();
  let primary: unknown, exitCode = 0;
  let observing = ['attach', 'tui', 'jsonl', 'rpc'].includes(invocation.kind);
  try {
    if (invocation.kind === 'jsonl' || invocation.kind === 'rpc') {
      await (invocation.kind === 'jsonl' ? runInstalledHeadlessJsonl : runInstalledHeadlessRpc)(session, io.input, output.write);
    } else if (invocation.kind === 'help') await output.write(Buffer.from(help));
    else if (invocation.kind === 'tui') {
      const { runClientTui } = await import('./tui.js');
      rendering = true;
      try { await runClientTui(app, io, invocation.runId); } finally { rendering = false; }
    } else {
      const action = await executeClientAction(app, invocation, io.confirmUnverified, signal);
      exitCode = action.exitCode;
      const present = async (detail: ClientDetail) => {
        await output.write(Buffer.from(`${terminalText(detail.label)} · ${detail.artifactRef}\n`));
        // Chunk after Unicode decoding; never split a surrogate pair while
        // escaping untrusted terminal text or create an oversized write.
        for (let offset = 0; offset < detail.text.length;) {
          let end = Math.min(detail.text.length, offset + 32768);
          if (end < detail.text.length && /[\uD800-\uDBFF]/u.test(detail.text[end - 1]!)) end--;
          await output.write(Buffer.from(terminalText(detail.text.slice(offset, end)))); offset = end;
        }
        await output.write(Buffer.from('\n'));
      };
      if (action.artifact) {
        if (io.output.isTTY) await present({ label: 'Artifact', artifactRef: action.artifact.digest, text: artifactText(action.artifact.bytes) });
        else for (let offset = 0; offset < action.artifact.bytes.length; offset += 65536)
          await output.write(action.artifact.bytes.subarray(offset, offset + 65536));
      } else if (action.response && !('json' in invocation && invocation.json)) {
        const request = action.presentationRequest ?? (invocation.kind === 'command' && invocation.command.kind === 'request'
          ? invocation.command.request : undefined);
        if (request) await presentControlArtifacts(app, request, action.response, present, signal);
      }
      if (action.follow && action.runId) {
        observing = true;
        if (io.output.isTTY && !('json' in invocation && invocation.json)) {
          const { runClientTui } = await import('./tui.js'); rendering = true;
          try { await runClientTui(app, io, action.runId, invocation.kind === 'run' ? invocation.intent : undefined,
            invocation.kind === 'run' ? invocation.nodeCheck : undefined); }
          finally { rendering = false; }
        } else {
          // Natural run/apply commands are finite operations: redirected or
          // already-closed stdin does not mean their result was delivered.
          // Explicit observers retain EOF detach; signals detach either form.
          if (invocation.kind === 'attach') detachOnEof();
          await app.follow(action.runId, action.afterEventSeq ?? 0, signal);
          if (lastResponse && !lastResponse.ok) exitCode = 1;
          else if (lastResponse?.ok && 'snapshot' in lastResponse.result && 'run' in lastResponse.result.snapshot &&
              ['failed', 'cancelled'].includes(lastResponse.result.snapshot.run.status)) exitCode = 1;
        }
      }
    }
  } catch (error) {
    // Detaching an observer is normal. An interrupted finite action/export
    // cannot be reported to a shell as a complete result. No Run is cancelled.
    if (signal.aborted && (!observing || invocation.kind === 'run' || invocation.kind === 'apply')) exitCode = 1;
    if (!signal.aborted || error instanceof ResourceRetirementError || pending !== undefined) {
      primary = error; exitCode = 1;
      if (!(error instanceof ClientRefusal)) await diagnostic.write(Buffer.from(pending
        ? `No complete response. Reconnect and inspect; do not submit a new replacement. Method ${pending.method}; request ${pending.requestId}${pending.admissionKey ? `; admission ${pending.admissionKey}` : ''}.\n`
        : 'Client operation could not complete. No automatic retry was sent.\n')).catch(() => {});
    }
  } finally {
    io.signal?.removeEventListener('abort', externalStop);
    io.input.removeListener('end', detach); io.input.removeListener('close', detach);
    const results = await Promise.allSettled([app.close(), output.join(), diagnostic.join()]);
    const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected').map(result => result.reason);
    const retirement = failures.find(error => error instanceof ResourceRetirementError);
    if (retirement) throw retirement;
    if (failures.length && !primary) throw failures[0];
  }
  return exitCode;
}
