import { randomBytes } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { assertArtifactRef, assertRequestId, normalizeAbsolutePath, normalizeBoundedText } from '../kernel/identity.js';
import { decodeInstalledControlRequest, type InstalledControlRequestV1 } from '../control/v1.js';
import { mergeBudgets, type RunModelRequest, type RunSubmitRequest } from '../kernel/control-submit.js';
import type { ClientCommand, ClientPreferencesV1 } from './types.js';

export type RunIntent = Omit<RunSubmitRequest, 'method' | 'protocolVersion' | 'requestId' | 'requestDigest' | 'admissionKey' | 'sessionId' | 'expectedContextRevision'>;
export type ClientInvocationDefaults = Readonly<{ preferences: ClientPreferencesV1; guestToolchainManifestId?: string }>;
export type ClientNodeCheck = Readonly<{ path: string; guestToolchainManifestId: string }>;
export type ClientInvocation =
  | Readonly<{ kind: 'command'; command: ClientCommand; json: boolean }>
  | Readonly<{ kind: 'run'; intent: RunIntent; sessionId?: string; nodeCheck?: ClientNodeCheck; detach: boolean; json: boolean }>
  | Readonly<{ kind: 'result'; runId: string; wait: true; json: boolean }>
  | Readonly<{ kind: 'request-replay'; requestId: string; json: boolean }>
  | Readonly<{ kind: 'attach'; runId: string; afterEventSeq: number; json: boolean }>
  | Readonly<{ kind: 'cancel'; runId: string; expectedRevision?: number; json: boolean }>
  | Readonly<{ kind: 'apply'; sourceRunId: string; expectedRunResultRef?: string; options: Record<string, unknown>; detach: boolean; json: boolean }>
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
function usdMicros(value: string): number {
  if (!/^(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,6})?$/u.test(value)) throw new TypeError('USD budget needs an exact decimal with at most six fractional digits');
  const [whole, fraction = ''] = value.split('.');
  const micros = BigInt(whole!) * 1_000_000n + BigInt(fraction.padEnd(6, '0'));
  if (micros < 1n || micros > 1_000_000_000_000n) throw new TypeError('USD budget is outside the existing Run bound');
  return Number(micros);
}
function checkNodePath(value: string): string {
  if (normalizeBoundedText(value, 1, 4096) !== value || !value.endsWith('.mjs') || value.startsWith('-') || value.includes('\\') ||
      value.split('/').some(part => !part || part === '.' || part === '..' || part === '.git' || Buffer.byteLength(part) > 255))
    throw new TypeError('Node check must be a canonical relative .mjs path');
  return value;
}
function parsed(argv: readonly string[]) {
  const positionals: string[] = [], flags = new Map<string, string[]>();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (arg === '--') { positionals.push(...argv.slice(index + 1)); break; }
    if (!arg.startsWith('--')) { positionals.push(arg); continue; }
    if (arg.includes('=')) throw new TypeError('use a separate value after an option');
    const boolean = ['--json', '--detach', '--allow-unverified'].includes(arg) || arg === '--wait' && positionals[0] === 'result';
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
export function parseClientInvocation(argv: readonly string[], workspacePath: string, defaults?: ClientInvocationDefaults): ClientInvocation {
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
  else if (name === 'requests' && words.shift() === 'replay') {
    const requestId = oneId(); assertRequestId(requestId); result = { kind: 'request-replay', requestId, json };
  }
  else if (name === 'reconnect') { if (words.length) throw new TypeError('reconnect has no id'); result = { kind: 'command', command: { kind: 'reconnect' }, json }; }
  else if (name === 'run' || name === 'resume') {
    const sessionId = name === 'resume' ? words.shift() : p.take('--session');
    if (name === 'resume' && !sessionId) throw new TypeError('resume requires an explicit Session id');
    const objective = words.join(' '); if (!objective) throw new TypeError('a new objective is required');
    const provider = p.take('--provider'), model = p.take('--model');
    const endpoint = p.take('--endpoint'), credentials = p.all('--credential-grant');
    let selectedModel: RunModelRequest, aliasSelected = false;
    if (provider === undefined) {
      if (endpoint !== undefined || credentials.length) throw new TypeError('model aliases cannot override endpoint or credential ids');
      const alias = model ?? defaults?.preferences.defaultModelAlias;
      const matches = defaults?.preferences.modelSelections.filter(selected => selected.alias === alias) ?? [];
      if (alias === undefined || matches.length !== 1) throw new TypeError('select a configured model alias or supply explicit provider options');
      const selected = matches[0]!; aliasSelected = true;
      selectedModel = { provider: selected.provider, model: selected.model,
        endpoint: { kind: 'registered', endpointRegistrationId: selected.endpointRegistrationId }, modelCredentialGrantIds: [selected.credentialGrantId] };
    } else {
      if (model === undefined) throw new TypeError('--model is required with --provider');
      if (provider === 'ollama' ? endpoint !== undefined || credentials.length !== 0 : endpoint === undefined || !credentials.length)
        throw new TypeError('remote models need registered endpoint and credential grant ids; local models take neither');
      selectedModel = (provider === 'ollama' ? { provider, model } : { provider, model,
        endpoint: { kind: 'registered', endpointRegistrationId: endpoint }, modelCredentialGrantIds: credentials }) as RunModelRequest;
    }
    const supplied = p.take('--options'), options = supplied === undefined ? {} : jsonObject(supplied);
    const allowed = ['budgets', 'sandboxResources', 'verifiers', 'dependency', 'sourceIncludes', 'sourceExcludes',
      'maxChangedPaths', 'maxChangedBytes', 'registeredMcpServerIds', 'skillIds', 'sourceInspectionGrantId', 'ignoreReadGrantIds'];
    if (Object.keys(options).some(key => !allowed.includes(key))) throw new TypeError('Run options contain an unsupported field');
    const dollars = p.take('--budget-usd'), tokens = p.take('--budget-tokens');
    if (dollars !== undefined || tokens !== undefined || aliasSelected && defaults?.preferences.budgetDefaults !== undefined) {
      const suppliedBudget = options.budgets;
      if (suppliedBudget !== undefined && (!suppliedBudget || typeof suppliedBudget !== 'object' || Array.isArray(suppliedBudget) ||
          Object.keys(suppliedBudget).some(key => !['wallTimeMs', 'modelTokens', 'costMicros', 'toolCalls', 'repairAttempts', 'childDepth', 'childConcurrency'].includes(key))))
        throw new TypeError('Run budget options contain an unsupported field');
      if (dollars !== undefined && suppliedBudget !== undefined && Object.hasOwn(suppliedBudget as object, 'costMicros'))
        throw new TypeError('USD budget cannot be combined with an explicit costMicros option');
      if (tokens !== undefined && suppliedBudget !== undefined && Object.hasOwn(suppliedBudget as object, 'modelTokens'))
        throw new TypeError('token budget cannot be combined with an explicit modelTokens option');
      options.budgets = mergeBudgets({ ...(aliasSelected ? defaults?.preferences.budgetDefaults : {}),
        ...(suppliedBudget as Partial<RunIntent['budgets']> | undefined), ...(dollars === undefined ? {} : { costMicros: usdMicros(dollars) }),
        ...(tokens === undefined ? {} : { modelTokens: natural(tokens, 1) }) });
    }
    const policyMode = p.take('--policy') ?? 'default', checkPath = p.take('--check-node');
    let nodeCheck: ClientNodeCheck | undefined;
    if (checkPath !== undefined) {
      if (policyMode !== 'yolo') throw new TypeError('the fixed Node verifier requires explicit --policy yolo');
      if (Object.hasOwn(options, 'verifiers')) throw new TypeError('Node check cannot be combined with explicit verifiers');
      const guestToolchainManifestId = defaults?.guestToolchainManifestId;
      if (typeof guestToolchainManifestId !== 'string' || normalizeBoundedText(guestToolchainManifestId, 1, 128) !== guestToolchainManifestId)
        throw new TypeError('the selected installation has no supported Node verifier toolchain');
      nodeCheck = { path: checkNodePath(checkPath), guestToolchainManifestId };
    }
    const intent = { workspacePath: normalizeAbsolutePath(p.take('--workspace') ?? workspacePath), objective, model: selectedModel,
      policyMode, verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
      registeredMcpServerIds: [], skillIds: [], ...options, allowUnverified: p.take('--allow-unverified') === 'true' } as RunIntent;
    if (nodeCheck && intent.allowUnverified) throw new TypeError('a required Node check cannot select unverified admission');
    // Validate the complete method-specific inline value before opening a
    // connection. Consent and a planned check's real grant are resolved later;
    // this unsent syntax draft is never an admission or permission decision.
    clientMutation({ method: 'run.submit', ...intent,
      allowUnverified: intent.allowUnverified || !intent.verifiers.some(verifier => verifier.required),
      sessionId: sessionId ?? 'new-session', expectedContextRevision: 1 }, true);
    result = { kind: 'run', intent, ...(sessionId ? { sessionId } : {}), ...(nodeCheck ? { nodeCheck } : {}), detach: p.take('--detach') === 'true', json };
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
  else if (name === 'diff' || name === 'result') {
    const runId = oneId();
    result = name === 'result' && p.take('--wait') === 'true' ? { kind: 'result', runId, wait: true, json } : read(`run.${name}`, { runId });
  }
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
    if (Object.keys(options).some(key => !['budgets', 'verifierExecutionGrantIds', 'sourceInspectionGrantId', 'ignoreReadGrantIds', 'sourceReadGrantIds'].includes(key)))
      throw new TypeError('Delivery options contain an unsupported field');
    const expectedRunResultRef = p.take('--result');
    if (expectedRunResultRef !== undefined) assertArtifactRef(expectedRunResultRef);
    result = { kind: 'apply', sourceRunId: oneId(), options, detach: p.take('--detach') === 'true', json,
      ...(expectedRunResultRef === undefined ? {} : { expectedRunResultRef }) };
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
