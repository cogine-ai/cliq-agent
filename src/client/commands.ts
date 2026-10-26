import { randomBytes } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { decodeInstalledControlRequest, type InstalledControlRequestV1 } from '../control/v1.js';
import type { RunSubmitRequest } from '../kernel/control-submit.js';
import type { ClientCommand } from './types.js';

export type RunIntent = Omit<RunSubmitRequest, 'method' | 'protocolVersion' | 'requestId' | 'requestDigest' | 'admissionKey' | 'sessionId' | 'expectedContextRevision'>;
export type ClientInvocation =
  | Readonly<{ kind: 'command'; command: ClientCommand; json: boolean }>
  | Readonly<{ kind: 'run'; intent: RunIntent; sessionId?: string; detach: boolean; json: boolean }>
  | Readonly<{ kind: 'attach'; runId: string; afterEventSeq: number; json: boolean }>
  | Readonly<{ kind: 'cancel'; runId: string; expectedRevision?: number; json: boolean }>
  | Readonly<{ kind: 'apply'; sourceRunId: string; options: Record<string, unknown>; json: boolean }>
  | Readonly<{ kind: 'artifact'; digest: string }>
  | Readonly<{ kind: 'tui'; runId?: string }>
  | Readonly<{ kind: 'jsonl' | 'rpc' | 'help' }>;

export function mutationIdentity(): { requestId: string; admissionKey: string } {
  const bytes = randomBytes(16); bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6]! & 0x0f) | 0x70; bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return { requestId: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    admissionKey: randomBytes(32).toString('base64url') };
}
export function clientMutation(core: object, admission = false): InstalledControlRequestV1 {
  const id = mutationIdentity(), identified = { protocolVersion: 1, requestId: id.requestId,
    ...(admission ? { admissionKey: id.admissionKey } : {}), ...core };
  return decodeInstalledControlRequest({ ...identified, requestDigest: canonicalSha256(identified) });
}
function jsonObject(value: string): Record<string, unknown> {
  const data: unknown = parseJsonStrict(value);
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new TypeError('options must be a JSON object');
  return data as Record<string, unknown>;
}
function natural(value: string, minimum = 0): number {
  if (!/^(0|[1-9][0-9]*)$/u.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < minimum)
    throw new TypeError('expected an exact nonnegative integer');
  return Number(value);
}
function parsed(argv: readonly string[]) {
  const positionals: string[] = [], flags = new Map<string, string[]>();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (arg === '--') { positionals.push(...argv.slice(index + 1)); break; }
    if (!arg.startsWith('--')) { positionals.push(arg); continue; }
    if (arg.includes('=')) throw new TypeError('use a separate value after an option');
    const boolean = ['--json', '--detach', '--allow-unverified'].includes(arg);
    const value = boolean ? 'true' : argv[++index];
    if (value === undefined || !boolean && value.startsWith('--')) throw new TypeError('option needs its explicit value');
    flags.set(arg, [...(flags.get(arg) ?? []), value]);
  }
  const take = (name: string, multiple = false): string | undefined => {
    const values = flags.get(name); flags.delete(name);
    if (!multiple && values && values.length !== 1) throw new TypeError('option may be supplied only once');
    return values?.[0];
  };
  const all = (name: string) => { const values = flags.get(name) ?? []; flags.delete(name); return values; };
  const required = (name: string) => { const value = take(name); if (value === undefined) throw new TypeError(`${name} is required`); return value; };
  return { positionals, take, all, required, done() { if (flags.size) throw new TypeError(`unknown option ${flags.keys().next().value}`); } };
}
/** Arguments describe an explicit client operation. They never load repository
 * config, model credentials, a runner, or an installation/release-key override. */
export function parseClientInvocation(argv: readonly string[], workspacePath: string): ClientInvocation {
  if (argv.length > 1000 || argv.reduce((total, value) => total + Buffer.byteLength(value), 0) > 1_048_576)
    throw new TypeError('client arguments exceed the bounded control input');
  if (!argv.length || argv[0] === 'help' || argv[0] === '--help') return { kind: 'help' };
  const p = parsed(argv), words = p.positionals, name = words.shift()!, json = p.take('--json') === 'true';
  let result: ClientInvocation;
  const command = (request: unknown): ClientInvocation => ({ kind: 'command', command: { kind: 'request', request: decodeInstalledControlRequest(request) }, json });
  const read = (method: string, values: object = {}) => command({ protocolVersion: 1, method, ...values });
  const revision = () => natural(p.required('--revision'), 1);
  const oneId = () => { const id = words.shift(); if (!id || words.length) throw new TypeError('one id is required'); return id; };
  if (name === 'jsonl' || name === 'rpc') { if (words.length || json) throw new TypeError('stdio mode has no positional or output options'); result = { kind: name }; }
  else if (name === 'tui') { const runId = p.take('--run'); if (words.length || json) throw new TypeError('TUI selection uses --run'); result = { kind: 'tui', ...(runId ? { runId } : {}) }; }
  else if (name === 'request') { const raw = oneId(); result = command(parseJsonStrict(raw)); }
  else if (name === 'reconnect') { if (words.length) throw new TypeError('reconnect has no id'); result = { kind: 'command', command: { kind: 'reconnect' }, json }; }
  else if (name === 'run' || name === 'resume') {
    const sessionId = name === 'resume' ? words.shift() : p.take('--session');
    if (name === 'resume' && !sessionId) throw new TypeError('resume requires an explicit Session id');
    const objective = words.join(' '); if (!objective) throw new TypeError('a new objective is required');
    const provider = p.required('--provider'), model = p.required('--model');
    const endpoint = p.take('--endpoint'), credentials = p.all('--credential-grant');
    const selectedModel = provider === 'ollama' ? { provider, model } : { provider, model,
      endpoint: { kind: 'registered', endpointRegistrationId: endpoint }, modelCredentialGrantIds: credentials };
    if (provider === 'ollama' ? endpoint !== undefined || credentials.length !== 0 : endpoint === undefined || !credentials.length)
      throw new TypeError('remote models need registered endpoint and credential grant ids; local models take neither');
    const supplied = p.take('--options'), options = supplied === undefined ? {} : jsonObject(supplied);
    const allowed = ['budgets', 'sandboxResources', 'verifiers', 'dependency', 'sourceIncludes', 'sourceExcludes',
      'maxChangedPaths', 'maxChangedBytes', 'registeredMcpServerIds', 'skillIds', 'sourceInspectionGrantId', 'ignoreReadGrantIds'];
    if (Object.keys(options).some(key => !allowed.includes(key))) throw new TypeError('Run options contain an unsupported field');
    const intent = { workspacePath: normalizeAbsolutePath(p.take('--workspace') ?? workspacePath), objective, model: selectedModel,
      policyMode: p.take('--policy') ?? 'default', verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
      registeredMcpServerIds: [], skillIds: [], ...options, allowUnverified: p.take('--allow-unverified') === 'true' } as RunIntent;
    // Validate the complete method-specific inline value before opening a
    // connection; these temporary ids grant no permission or execution.
    clientMutation({ method: 'run.submit', ...intent, sessionId: sessionId ?? 'new-session', expectedContextRevision: 1 }, true);
    result = { kind: 'run', intent, ...(sessionId ? { sessionId } : {}), detach: p.take('--detach') === 'true', json };
  } else if (name === 'list') {
    const sessionId = p.take('--session'), operation = p.take('--operation'), statuses = p.all('--status'), cursor = p.take('--cursor'), limit = p.take('--limit');
    if (words.length) throw new TypeError('list uses filters, not positional ids');
    result = read('run.list', { ...(sessionId ? { sessionId } : {}), ...(operation ? { operation } : {}),
      ...(statuses.length ? { statuses } : {}), ...(cursor ? { cursor } : {}), ...(limit ? { limit: natural(limit, 1) } : {}) });
  } else if (name === 'status' || name === 'inspect') {
    const runId = oneId(), fields: Record<string, unknown> = {};
    if (name === 'inspect') {
      for (const [option, field] of [['--after-item', 'afterItemSeq'], ['--after-journal', 'afterJournalSeq'],
        ['--item-limit', 'itemLimit'], ['--journal-limit', 'journalLimit'], ['--checkpoint-limit', 'checkpointLimit']]) {
        const value = p.take(option!); if (value !== undefined) fields[field!] = natural(value, option!.endsWith('limit') ? 1 : 0);
      }
      const cursor = p.take('--checkpoint-cursor'); if (cursor !== undefined) fields.checkpointCursor = cursor;
    }
    result = read('run.get', { runId, ...fields });
  } else if (name === 'artifact') {
    if (json) throw new TypeError('artifact exports verified bytes; use JSONL/RPC for artifact.get records');
    const value = decodeInstalledControlRequest({ protocolVersion: 1, method: 'artifact.get', digest: oneId(), offset: 0, length: 65536 });
    if (value.method !== 'artifact.get') throw new TypeError('invalid artifact export'); result = { kind: 'artifact', digest: value.digest };
  }
  else if (name === 'diff' || name === 'result') result = read(`run.${name}`, { runId: oneId() });
  else if (name === 'attach') result = { kind: 'attach', runId: oneId(), afterEventSeq: natural(p.take('--after') ?? '0'), json };
  else if (name === 'cancel') { const expected = p.take('--revision'); result = { kind: 'cancel', runId: oneId(), ...(expected ? { expectedRevision: natural(expected, 1) } : {}), json }; }
  else if (name === 'approve' || name === 'input' || name === 'reconcile') {
    const runId = oneId(), expectedRevision = revision(), waitingOnRef = p.required('--wait');
    const ttl = name === 'approve' ? p.take('--ttl-ms') : undefined;
    const inputText = name === 'input' ? p.take('--text') : undefined;
    const fields = name === 'approve' ? { decision: p.required('--decision'), ...(ttl !== undefined ? { ttlMs: natural(ttl, 1) } : {}) }
      : name === 'reconcile' ? { resolution: { kind: 'probe_now' } }
        : { input: inputText !== undefined ? { kind: 'text', value: inputText } : { kind: 'json', value: parseJsonStrict(p.required('--value-json')) } };
    result = command(clientMutation({ method: `run.${name}`, runId, expectedRevision, waitingOnRef, ...fields }));
  } else if (name === 'apply') {
    const options = jsonObject(p.take('--options') ?? '{}');
    if (Object.keys(options).some(key => !['budgets', 'verifierExecutionGrantIds', 'sourceInspectionGrantId', 'ignoreReadGrantIds'].includes(key)))
      throw new TypeError('Delivery options contain an unsupported field');
    result = { kind: 'apply', sourceRunId: oneId(), options, json };
  }
  else if (name === 'session') {
    const action = words.shift();
    if (action === 'list') {
      const workspace = p.take('--workspace'), cursor = p.take('--cursor'), limit = p.take('--limit');
      result = read('session.list', { ...(workspace ? { workspacePath: normalizeAbsolutePath(workspace) } : {}),
        ...(cursor ? { cursor } : {}), ...(limit ? { limit: natural(limit, 1) } : {}) });
    } else if (action === 'show') {
      const sessionId = oneId(), after = p.take('--after'), limit = p.take('--limit');
      result = read('session.get', { sessionId, ...(after === undefined ? {} : { afterItemSeq: natural(after) }),
        ...(limit === undefined ? {} : { limit: natural(limit, 1) }) });
    }
    else if (action === 'create') {
      const sessionName = p.take('--name');
      result = command(clientMutation({ method: 'session.create', workspacePath: normalizeAbsolutePath(p.take('--workspace') ?? workspacePath),
        ...(sessionName !== undefined ? { name: sessionName } : {}) }, true));
    }
    else if (action === 'fork' || action === 'compact') {
      const sessionId = oneId(), expectedContextRevision = revision(), throughItemSeq = natural(p.required('--through'));
      result = command(clientMutation({ method: `session.${action}`, sessionId, expectedContextRevision, throughItemSeq,
        ...(action === 'fork' ? {} : { fromItemSeq: natural(p.required('--from'), 1), summaryMarkdown: p.required('--summary'), retainedItemIds: p.all('--retain') }) }, action === 'fork'));
    } else throw new TypeError('unknown Session command');
  } else if (name === 'handoff') {
    if (words.shift() !== 'create') throw new TypeError('handoff supports create');
    const sessionId = oneId(), expectedContextRevision = revision(), through = p.take('--through');
    result = read('session.handoff.create', { sessionId, expectedContextRevision, ...(through ? { throughItemSeq: natural(through) } : {}) });
  } else if (name === 'authorization') {
    const action = words.shift();
    if (action === 'list') {
      const targetKind = p.take('--target-kind'), state = p.take('--state'), cursor = p.take('--cursor'), limit = p.take('--limit');
      result = read('authorization.list', { ...(targetKind ? { targetKind } : {}), ...(state ? { state } : {}),
        ...(cursor ? { cursor } : {}), ...(limit ? { limit: natural(limit, 1) } : {}) });
    } else if (action === 'revoke') result = command(clientMutation({ method: 'authorization.revoke', grantId: oneId() }));
    else if (action === 'create') result = command(clientMutation({ method: 'authorization.create', decision: jsonObject(p.required('--decision-json')) }));
    else throw new TypeError('unknown authorization command');
  } else if (name === 'supervisor' && words.shift() === 'status') result = read('supervisor.status');
  else throw new TypeError('unknown installed client command');
  p.done(); if (words.length && !['run', 'resume'].includes(name)) throw new TypeError('unexpected positional arguments');
  return result;
}
