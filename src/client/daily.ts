import os from 'node:os';
import path from 'node:path';
import { lstat } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { parseClientInvocation } from './commands.js';
import { clientWriter, type ClientIO } from './entry.js';
import { openInstalledClientStdio } from './stdio.js';
import { openInstalledClientHost } from './installed-host.js';
import { openInstalledClientData } from './installed-data.js';
import { configureInstalledModel } from './model-settings.js';
import type { ModelSetupProfileV1 } from './model-setup-profile.js';
import { openPrivateClientDirectory } from './private-files.js';
import { readClientPreferences } from './preferences.js';
import { terminalText } from './view.js';
import { installServices, observeInstalledCredentialSupervisor } from '../state/installed-services.js';
import type { createInstalledRuntime } from '../state/installed-runtime.js';
import { joinResourceOperations } from '../state/errors.js';
import { createWorkspaceTrustContext, readPersistedWorkspaceTrust, writePersistedWorkspaceTrust } from '../session/trust.js';

const HELP = `Cliq installed preview\n\nsetup\nmodels list | models add <alias> [--profile <id>] [--api-key-stdin]\nrun <objective> [--model <alias>] --check-node <relative.mjs> --policy yolo --budget-usd <amount> [--budget-tokens <count>] [--detach]\nresult <runId> --wait\napply <runId> [--result <ref>] [--detach]\n\nlist | status <runId> | attach <runId> | cancel <runId> | tui\nrequests | requests show|replay|acknowledge <requestId>\nsupervisor start | supervisor status\n\nThe first task asks for Workspace Trust. Automation may use --trust-workspace.\nThe fixed Node check currently requires explicit yolo policy.\nOther control commands remain available through the installed client.\n`;
type Runtime = Pick<ReturnType<typeof createInstalledRuntime>, 'openSelected' | 'installInitial'>;
const missing = (error: unknown) => (error as NodeJS.ErrnoException)?.code === 'ENOENT';

async function closeDaily(failures: unknown[], closures: readonly (() => Promise<unknown>)[]) {
  for (const close of closures) try { await close(); } catch (error) { failures.push(error); }
  // Preserve an original retirement uncertainty even when a later ordinary
  // close also fails. The actual owners above always retire in order.
  await joinResourceOperations(failures.map(error => Promise.reject(error)));
}

/** The same system-account home used by the installed credential platform.
 * An environment value or a repository file cannot select a second home. */
export function dailyInstalledLocations() {
  const user = os.userInfo();
  if (process.platform !== 'linux' || process.geteuid?.() !== user.uid || normalizeAbsolutePath(user.homedir) !== user.homedir)
    throw new TypeError('the installed daily client requires its actual Linux account');
  const controlledHome = path.join(user.homedir, '.cliq');
  return { controlledHome, stateRoot: path.join(controlledHome, 'kernel-v1') };
}

async function write(io: ClientIO, value: unknown): Promise<void> {
  const writer = clientWriter(io.output), cancel = () => writer.cancel(io.signal?.reason);
  io.signal?.addEventListener('abort', cancel, { once: true });
  try {
    io.signal?.throwIfAborted();
    const bytes = typeof value === 'string' ? Buffer.from(value) : Buffer.concat([canonicalJsonBytes(value), Buffer.from('\n')]);
    for (let offset = 0; offset < bytes.length; offset += 65536) await writer.write(bytes.subarray(offset, offset + 65536));
  } finally { io.signal?.removeEventListener('abort', cancel); await writer.join(); }
}

async function confirm(io: ClientIO, question: string): Promise<boolean> {
  if (!(io.input as { isTTY?: boolean }).isTTY || !io.output.isTTY)
    throw new TypeError('this decision requires an interactive terminal or its explicit command option');
  const reader = createInterface({ input: io.input, output: io.output, terminal: true, historySize: 0 });
  try {
    const answer = await reader.question(question + ' [y/N] ', { signal: io.signal });
    return answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
  } finally { reader.close(); }
}

export async function trustDailyWorkspace(io: ClientIO, workspacePath: string, controlledHome: string, explicit: boolean): Promise<string> {
  io.signal?.throwIfAborted();
  const context = await createWorkspaceTrustContext(workspacePath, controlledHome);
  const decision = await readPersistedWorkspaceTrust(context);
  io.signal?.throwIfAborted();
  if (decision === 'trusted') return context.workspaceRealPath;
  if (decision === 'denied') throw new TypeError('this workspace has a retained denied Trust decision');
  const accepted = explicit || await confirm(io, `Trust workspace ${JSON.stringify(terminalText(context.workspaceRealPath))} to enter the agent runtime?`);
  io.signal?.throwIfAborted();
  await writePersistedWorkspaceTrust(context, accepted ? 'trusted' : 'denied');
  if (!accepted) throw new TypeError('workspace access was declined');
  return context.workspaceRealPath;
}

function modelCommand(argv: readonly string[]) {
  if (argv[1] === 'list' && argv.length === 2) return { kind: 'list' as const };
  if (argv[1] !== 'add' || !argv[2] || argv[2].startsWith('--')) throw new TypeError('use models add <alias> or models list');
  let profileId = 'default', input: 'stdin' | 'terminal' = 'terminal';
  const used = new Set<string>();
  for (let index = 3; index < argv.length; index++) {
    const flag = argv[index]!;
    if (used.has(flag)) throw new TypeError('model setup option may be supplied only once'); used.add(flag);
    if (flag === '--api-key-stdin') input = 'stdin';
    else if (flag === '--profile') {
      const value = argv[++index]; if (!value || value.startsWith('--')) throw new TypeError('model setup profile needs one id'); profileId = value;
    } else throw new TypeError('model setup accepts only --profile and --api-key-stdin; a key is never a command argument');
  }
  return { kind: 'add' as const, alias: argv[2], profileId, input };
}

/** Separate one explicit Trust option without reinterpreting a positional
 * objective or another option's value as a Trust decision. */
export function dailyTrustOption(argv: readonly string[]) {
  const args: string[] = [], booleans = new Set(['--json', '--detach', '--allow-unverified', '--wait']);
  let explicit = false;
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (arg === '--') { args.push(...argv.slice(index)); break; }
    if (arg === '--trust-workspace') {
      if (explicit) throw new TypeError('--trust-workspace may be supplied only once'); explicit = true;
    } else {
      args.push(arg);
      if (arg.startsWith('--') && !booleans.has(arg) && argv[index + 1] !== undefined) args.push(argv[++index]!);
    }
  }
  return { args, explicit };
}

/** Normal commands inside the same signed image. Setup and model registration
 * reuse the original installation and local auth business actions. Run, review,
 * reconnect and application use the existing shared client and v1 protocol. */
export async function runInstalledDaily(runtime: Runtime, argv: readonly string[], io: ClientIO,
  profiles: readonly ModelSetupProfileV1[]): Promise<number> {
  if (argv.length > 1000 || argv.reduce((sum, arg) => sum + Buffer.byteLength(arg), 0) > 1_048_576)
    throw new TypeError('daily client arguments exceed the existing control bound');
  if (!argv.length || ['help', '--help'].includes(argv[0]!)) { await write(io, HELP); return 0; }
  const locations = dailyInstalledLocations(), command = argv[0]!;
  if (command === 'setup') {
    if (argv.length !== 1) throw new TypeError('setup has no root, key or package override');
    let exists = true;
    try { await lstat(locations.stateRoot); } catch (error) { if (!missing(error)) throw error; exists = false; }
    if (!exists) {
      const home = await openPrivateClientDirectory(locations.controlledHome, { create: true });
      try { await home.assertCurrent(); } finally { await home.close(); }
      io.signal?.throwIfAborted();
      await runtime.installInitial({ packageRoot: path.dirname(process.execPath), stateRoot: locations.stateRoot });
    }
    const selected = await runtime.openSelected(locations.stateRoot);
    const failures: unknown[] = [];
    let stdio: Awaited<ReturnType<typeof openInstalledClientStdio>> | undefined;
    try {
      await installServices(selected);
      stdio = await openInstalledClientStdio(selected, io);
      await write(stdio.io, 'Installed. Use this signed executable with models add <alias> to configure a model.\n');
    } catch (error) { failures.push(error); }
    finally { await closeDaily(failures, [async () => stdio?.close(), () => selected.close()]); }
    return 0;
  }
  const selected = await runtime.openSelected(locations.stateRoot);
  const failures: unknown[] = [];
  let stdio: Awaited<ReturnType<typeof openInstalledClientStdio>> | undefined;
  try {
    if (command === 'models' || command === 'requests' && argv[1] !== 'replay' || command === 'supervisor' && argv[1] === 'start') {
      stdio = await openInstalledClientStdio(selected, io); io = stdio.io;
    }
    if (command === 'supervisor' && argv[1] === 'start') {
      if (argv.length !== 2) throw new TypeError('supervisor start has no unit or manager override');
      await observeInstalledCredentialSupervisor(selected, true); await write(io, 'Supervisor started.\n'); return 0;
    }
    const data = await openInstalledClientData(selected);
    const dataFailures: unknown[] = [];
    try {
      if (command === 'models') {
        const request = modelCommand(argv);
        if (request.kind === 'list') {
          const preferences = await readClientPreferences(data.directory);
          await write(io, { models: preferences.modelSelections.map(({ alias, provider, model }) => ({ alias, provider, model })),
            profiles: profiles.map(({ id, provider, model }) => ({ id, provider, model })) }); return 0;
        }
        const profile = profiles.find(value => value.id === request.profileId);
        if (!profile) throw new TypeError('the signed image has no selected model setup profile');
        await write(io, `Configure ${terminalText(request.alias)} with ${terminalText(profile.model)} at ${terminalText(profile.target.hostAscii)}.\n`);
        const choice = await configureInstalledModel(selected, data, profile, request.alias, request.input);
        await write(io, `Model ${terminalText(choice.alias)} configured.\n`); return 0;
      }
      if (command === 'requests') {
        if (argv.length === 1) { await write(io, await data.requests.list()); return 0; }
        const [_, action, requestId, ...extra] = argv;
        if (!requestId || extra.length) throw new TypeError('one original request id is required');
        if (action === 'show') {
          const record = await data.requests.load(requestId);
          await write(io, { requestId: record.metadata.requestId, method: record.metadata.method, request: record.request,
            state: record.response === undefined ? 'unresolved' : 'known', ...(record.response === undefined ? {} : { response: record.response }) }); return 0;
        }
        if (action === 'acknowledge') { await data.requests.acknowledge(requestId); await write(io, 'Known response acknowledged.\n'); return 0; }
        if (action !== 'replay') throw new TypeError('use requests show, replay or acknowledge');
        const host = await openInstalledClientHost(selected, data);
        try {
          return await host.run({ kind: 'request-replay', requestId, json: false }, io);
        } finally { await host.close(); }
      }
      const { args, explicit: explicitTrust } = dailyTrustOption(argv);
      const defaults = await data.commandDefaults();
      let invocation = parseClientInvocation(args, io.workspacePath, defaults);
      if (invocation.kind === 'run') {
        const workspacePath = await trustDailyWorkspace(io, invocation.intent.workspacePath, locations.controlledHome, explicitTrust);
        invocation = { ...invocation, intent: { ...invocation.intent, workspacePath } };
      }
      else if (invocation.kind === 'tui' && invocation.runId === undefined) {
        // Ask before Ink owns terminal input. Further explicit workspaces still
        // face the server's original Trust gate; opening an existing Run is a
        // read and needs no new workspace decision.
        io = { ...io, workspacePath: await trustDailyWorkspace(io, io.workspacePath, locations.controlledHome, explicitTrust) };
      }
      else if (explicitTrust) throw new TypeError('--trust-workspace belongs to an explicit new Run');
      if (invocation.kind === 'run' || invocation.kind === 'apply') await observeInstalledCredentialSupervisor(selected, true);
      const host = await openInstalledClientHost(selected, data);
      try { return await host.run(invocation, { ...io, commandDefaults: defaults,
        confirmUnverified: () => confirm(io, 'No required check was selected. Continue with an unverified result?') }); }
      finally { await host.close(); }
    } catch (error) { dataFailures.push(error); throw error; }
    finally { await closeDaily(dataFailures, [() => data.close()]); }
  } catch (error) { failures.push(error); throw error; }
  finally { await closeDaily(failures, [async () => stdio?.close(), () => selected.close()]); }
}
