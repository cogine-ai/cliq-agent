import { ResourceRetirementError } from '../state/errors.js';
import { Box, Text, render, useApp, useInput } from 'ink';
import { useEffect, useRef, useState } from 'react';
import { parseJsonStrict } from '../kernel/json.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { ClientIO } from './entry.js';
import type { RunIntent } from './commands.js';
import { clientMutation, parseClientInvocation } from './commands.js';
import { executeClientAction, type ClientApplication } from './actions.js';
import { initialClientView, reduceClientView, runHeadline, terminalText } from './view.js';
import { artifactText, detailViewport, presentControlArtifacts, type ClientDetail } from './details.js';
import { readWaitingPresentation, type WaitingPresentation } from './artifacts.js';

/** Tokenization only. No shell, interpolation, executable or environment is
 * involved when a user enters a local client command. */
export function splitClientCommand(value: string): string[] {
  const result: string[] = []; let part = '', quote = '', escaped = false, started = false;
  for (const character of value) {
    if (escaped) { part += character; escaped = false; started = true; }
    else if (character === '\\' && quote !== "'") { escaped = true; started = true; }
    else if (quote) { if (character === quote) quote = ''; else part += character; }
    else if (character === '"' || character === "'") { quote = character; started = true; }
    else if (/\s/u.test(character)) { if (started) { result.push(part); part = ''; started = false; } }
    else { part += character; started = true; }
  }
  if (quote || escaped) throw new TypeError('client command has an unfinished quote or escape');
  if (started) result.push(part); return result;
}

export function ClientTui({ app, io, initialRunId, profile }: Readonly<{
  app: ClientApplication; io: ClientIO; initialRunId?: string; profile?: RunIntent;
}>) {
  const [view, setView] = useState(initialClientView), [input, setInput] = useState(''), [message, setMessage] = useState('');
  const [detail, setDetail] = useState<WaitingPresentation>(), [detailPage, setDetailPage] = useState(0), [busy, setBusy] = useState(false);
  const [detailRead, setDetailRead] = useState(0), [inspection, setInspection] = useState<ClientDetail>();
  const current = useRef(view); current.current = view;
  const intent = useRef(profile), operation = useRef(false), lifetime = useRef(new AbortController());
  const watch = useRef<{ abort: AbortController; promise: Promise<void> } | undefined>(undefined);
  const { exit } = useApp();
  const report = () => { setMessage('Client operation refused or unavailable. Refresh and inspect the exact current state.'); };
  const select = async (runId: string, afterEventSeq = 0) => {
    setInspection(undefined);
    const previous = current.current.run?.run;
    watch.current?.abort.abort();
    if (watch.current) await watch.current.promise.catch(error => {
      // The prior viewport already reported ordinary read/refusal failures.
      // They cannot block this new explicit attach after an explicit reconnect.
      if (error instanceof ResourceRetirementError) throw error;
    });
    const response = await app.execute({ kind: 'request', request: { protocolVersion: 1, method: 'run.get', runId } });
    if (!response || !response.ok || response.result.method !== 'run.get') return;
    if (previous?.id === runId && previous.waitingOnRef === response.result.snapshot.run.waitingOnRef)
      setDetailRead(value => value + 1); // Only this explicit reattach retries display reads.
    const abort = new AbortController();
    const signal = AbortSignal.any([abort.signal, lifetime.current.signal]);
    const promise = app.follow(runId, afterEventSeq, signal);
    watch.current = { abort, promise };
    void promise.catch(error => { if (!signal.aborted) report(); });
  };
  useEffect(() => {
    const remove = app.subscribe(update => { setView(previous => reduceClientView(previous, update)); });
    if (initialRunId) void select(initialRunId).catch(report);
    const stop = () => { lifetime.current.abort(); exit(); };
    io.input.once('end', stop); io.input.once('close', stop); io.signal?.addEventListener('abort', stop, { once: true });
    return () => {
      lifetime.current.abort(); watch.current?.abort.abort(); remove();
      io.input.removeListener('end', stop); io.input.removeListener('close', stop); io.signal?.removeEventListener('abort', stop);
    };
  }, []);
  const waitRef = view.run?.run.waitingOnRef;
  useEffect(() => {
    setDetail(undefined); setDetailPage(0); setInspection(undefined);
    const snapshot = current.current.run;
    if (!snapshot || snapshot.run.status !== 'waiting' || !snapshot.run.waitingOnRef || snapshot.run.cancelRequested || snapshot.run.stopIntentRef) return;
    const abort = new AbortController();
    void readWaitingPresentation(app, snapshot, AbortSignal.any([abort.signal, lifetime.current.signal]))
      .then(value => { if (!abort.signal.aborted) setDetail(value); }, error => { if (!abort.signal.aborted) report(); });
    return () => { abort.abort(); };
  }, [waitRef, view.run?.run.stopIntentRef, view.run?.run.cancelRequested, detailRead]);
  async function act(task: () => Promise<unknown>) {
    if (operation.current) return;
    operation.current = true; setBusy(true); setMessage('');
    try { await task(); }
    catch (error) { if (!lifetime.current.signal.aborted) report(); }
    finally { operation.current = false; setBusy(false); }
  }
  async function submit(text: string) {
    const snapshot = current.current.run;
    if (inspection && (!text.startsWith(':') || text.startsWith('::'))) throw new TypeError('return to the original wait with :back before answering');
    if ((!text.startsWith(':') || text.startsWith('::')) && snapshot?.run.status === 'waiting' && snapshot.run.waitingReason === 'input') {
      if (snapshot.run.cancelRequested || snapshot.run.stopIntentRef) throw new TypeError('the original input wait is stopping');
      if (!detail?.responseKind || detail.waitingOnRef !== snapshot.run.waitingOnRef || !app.hello.enabledFeatureIds.includes('run.input'))
        throw new TypeError('the original input prompt is not available on this installed version');
      const supplied = text.startsWith('::') ? text.slice(1) : text;
      const value = detail.responseKind === 'json' ? parseJsonStrict(supplied) : supplied;
      const bytes = detail.responseKind === 'json' ? canonicalJsonBytes(value).length : Buffer.byteLength(supplied);
      if (bytes > detail.maximumResponseBytes!) throw new TypeError('response exceeds its original prompt bound');
      const request = clientMutation({ method: 'run.input', runId: snapshot.run.id, expectedRevision: snapshot.run.revision,
        waitingOnRef: snapshot.run.waitingOnRef, input: { kind: detail.responseKind, value } });
      await app.execute({ kind: 'request', request }); return;
    }
    let invocation;
    if (text === ':back') { setInspection(undefined); return; }
    if (text === ':replay') {
      const response = await app.replay();
      if (response.ok && (response.result.method === 'run.submit' || response.result.method === 'run.apply'))
        await select(response.result.snapshot.run.id);
      return;
    }
    if (text.startsWith(':')) invocation = parseClientInvocation(splitClientCommand(text.slice(1)), io.workspacePath);
    else {
      if (!intent.current || !snapshot || !['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(snapshot.run.status))
        throw new TypeError('a new objective needs its explicit Run profile and completed context');
      invocation = { kind: 'run' as const, intent: { ...intent.current, objective: text }, sessionId: snapshot.run.sessionId, detach: false, json: false };
    }
    if (invocation.kind === 'tui' || invocation.kind === 'jsonl' || invocation.kind === 'rpc' || invocation.kind === 'help') {
      setMessage(':list · :status <id> · :attach <id> · :session list/show/fork/compact · :run <objective> <model options>'); return;
    }
    if (invocation.kind === 'run') intent.current = invocation.intent;
    const result = await executeClientAction(app, invocation, io.confirmUnverified, lifetime.current.signal);
    if (result.artifact) setInspection(detailViewport({ label: 'Artifact', artifactRef: result.artifact.digest, text: artifactText(result.artifact.bytes) }));
    else if (result.response && invocation.kind === 'command' && invocation.command.kind === 'request' && !invocation.json)
      await presentControlArtifacts(app, invocation.command.request, result.response, value => { setInspection(detailViewport(value)); setDetailPage(0); }, lifetime.current.signal);
    if (result.runId && result.follow) await select(result.runId, result.afterEventSeq ?? 0);
  }
  useInput((text, key) => {
    if (key.escape || key.ctrl && text === 'c') { lifetime.current.abort(); exit(); return; }
    const snapshot = current.current.run;
    if (key.ctrl && text === 'k' && snapshot && !['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(snapshot.run.status)) {
      void act(() => executeClientAction(app, { kind: 'cancel', runId: snapshot.run.id, expectedRevision: snapshot.run.revision, json: false }, undefined, lifetime.current.signal)); return;
    }
    if (key.pageDown) { setDetailPage(value => value + 1); return; }
    if (key.pageUp) { setDetailPage(value => Math.max(0, value - 1)); return; }
    if (!inspection && !input && snapshot?.run.status === 'waiting' && snapshot.run.waitingReason === 'approval' && detail?.waitingOnRef === snapshot.run.waitingOnRef &&
        (text === 'y' || text === 'n') && !key.ctrl && !snapshot.run.cancelRequested && !snapshot.run.stopIntentRef) {
      const request = clientMutation({ method: 'run.approve', runId: snapshot.run.id, expectedRevision: snapshot.run.revision,
        waitingOnRef: snapshot.run.waitingOnRef, decision: text === 'y' ? 'allow' : 'deny' });
      void act(() => app.execute({ kind: 'request', request })); return;
    }
    if (!inspection && !input && text === 'r' && snapshot?.run.status === 'waiting' && snapshot.run.waitingReason === 'reconciliation' &&
        !snapshot.run.cancelRequested && !snapshot.run.stopIntentRef) {
      const request = clientMutation({ method: 'run.reconcile', runId: snapshot.run.id, expectedRevision: snapshot.run.revision,
        waitingOnRef: snapshot.run.waitingOnRef, resolution: { kind: 'probe_now' } });
      void act(() => app.execute({ kind: 'request', request })); return;
    }
    if (key.return) {
      if (operation.current) return;
      const value = input;
      if (!value && !(!inspection && snapshot?.run.status === 'waiting' && snapshot.run.waitingReason === 'input' && detail?.responseKind === 'text' &&
          detail.waitingOnRef === snapshot.run.waitingOnRef)) return;
      setInput(''); void act(() => submit(value));
    }
    else if (key.backspace || key.delete) setInput(value => Array.from(value).slice(0, -1).join(''));
    else if (!key.ctrl && !key.meta) setInput(value => Buffer.byteLength(value + text) <= (detail?.maximumResponseBytes ?? 262_144) ? value + text : value);
  });
  const snapshot = view.run, run = snapshot?.run;
  const displayed = inspection?.text ?? (detail ? detail.text + (detail.responseSchema ? '\nResponse schema: ' + canonicalJsonBytes(detail.responseSchema).toString('utf8') : '') : undefined);
  const detailCharacters = displayed === undefined ? [] : Array.from(terminalText(displayed));
  const pageCount = Math.max(1, Math.ceil(detailCharacters.length / 4000)), page = Math.min(detailPage, pageCount - 1);
  return <Box flexDirection="column">
    <Text bold>Cliq · {view.connection}{snapshot ? ` · ${runHeadline(snapshot)}` : ''}</Text>
    {run ? <><Text>Run {terminalText(run.id)} · Session {terminalText(run.sessionId)} · revision {run.revision}</Text>
      <Text>Tokens {run.budgetConsumed.modelTokens} (+{run.budgetReserved.modelTokens} reserved) · cost micros {run.budgetConsumed.costMicros} (+{run.budgetReserved.costMicros}) · tools {run.budgetConsumed.toolCalls} · repairs {run.budgetConsumed.repairAttempts}</Text></> : <Text>Use :list or :attach &lt;Run id&gt; to return to durable work.</Text>}
    {view.session && <Text>Context Session {terminalText(view.session.id)} · revision {view.session.contextRevision}</Text>}
    <Box flexDirection="column" marginTop={1}>{view.lines.slice(-10).map((line, index) => <Text key={index}>{terminalText(line)}</Text>)}</Box>
    {(inspection || detail) && <Box borderStyle="round" flexDirection="column"><Text>{detailCharacters.slice(page * 4000, (page + 1) * 4000).join('')}</Text>
      <Text dimColor>{inspection ? `${inspection.label} · ${inspection.artifactRef} · :back` : `Exact wait ${detail!.waitingOnRef}`} · page {page + 1}/{pageCount} · PgUp/PgDn</Text></Box>}
    {!inspection && run?.waitingReason === 'approval' && detail && !run.cancelRequested && !run.stopIntentRef && <Text>y: allow this exact action · n: deny</Text>}
    {!inspection && run?.waitingReason === 'input' && !run.cancelRequested && !run.stopIntentRef && <Text>{detail?.responseKind === 'json' ? 'Enter the requested JSON response.' : 'Enter the requested text response.'}</Text>}
    {!inspection && run?.waitingReason === 'reconciliation' && !run.cancelRequested && !run.stopIntentRef && <Text>r: request a read-only probe of this exact wait</Text>}
    {message && <Text color="yellow">{terminalText(message)}</Text>}
    {view.refusal && <Text color="yellow">{view.refusal.code}: {view.refusal.messageCode}</Text>}
    {view.pending && <Text color="yellow">Original request {terminalText(view.pending.method)} · {terminalText(view.pending.requestId)}
      {view.pending.admissionKey ? ` · admission ${terminalText(view.pending.admissionKey)}` : ''}
      {view.connection === 'disconnected' ? ' · :reconnect, then explicitly :replay' : ' · unresolved until its original response'}</Text>}
    <Box marginTop={1}><Text>{busy ? 'Working…' : '> '}{terminalText(Array.from(input).slice(-160).join(''))}</Text></Box>
    <Text dimColor>Esc/Ctrl+C: detach · Ctrl+K: explicitly cancel · :commands use the same installed protocol</Text>
  </Box>;
}

/** The same application/connection is shared with CLI and closes once through
 * its original idempotent close. Ink never owns or cancels a Run. */
export async function runClientTui(app: ClientApplication, io: ClientIO, runId?: string, profile?: RunIntent): Promise<void> {
  if (!(io.input as { isTTY?: boolean }).isTTY || !io.output.isTTY) throw new TypeError('TUI needs a terminal; use JSONL/RPC or text commands otherwise');
  const instance = render(<ClientTui app={app} io={io} initialRunId={runId} profile={profile} />,
    { stdin: io.input as NodeJS.ReadStream, stdout: io.output as NodeJS.WriteStream, stderr: io.diagnostic as NodeJS.WriteStream, exitOnCtrlC: false, interactive: true });
  try { await instance.waitUntilExit(); }
  finally { instance.unmount(); await app.close(); }
}
