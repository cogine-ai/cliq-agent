import os from 'node:os';
import path from 'node:path';
import { lstat } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { mutationIdentity, parseClientInvocation } from './commands.js';
import { clientWriter, type ClientIO } from './entry.js';
import { openInstalledClientStdio } from './stdio.js';
import { openInstalledClientHost } from './installed-host.js';
import { openInstalledClientData } from './installed-data.js';
import { configureInstalledModel } from './model-settings.js';
import { configureInstalledLocalModel, listInstalledLocalModels, retireInstalledLocalModelAlias, selectInstalledLocalModel } from './local-model-settings.js';
import { modelCommand } from './model-command.js';
import type { ModelSetupProfileV1 } from './model-setup-profile.js';
import { openPrivateClientDirectory } from './private-files.js';
import { readClientPreferences } from './preferences.js';
import { readRunScheduling, schedulingCommand, writeRunScheduling } from './run-scheduling.js';
import { terminalText } from './view.js';
import { installServices, observeInstalledCredentialSupervisor } from '../state/installed-services.js';
import { openInstalledControlTransport } from '../state/installed-control-transport.js';
import type { createInstalledRuntime, HeldInstalledRuntime } from '../state/installed-runtime.js';
import { joinResourceOperations } from '../state/errors.js';
import { createWorkspaceTrustContext, readPersistedWorkspaceTrust, writePersistedWorkspaceTrust } from '../session/trust.js';
import { decodeInstalledControlRequest, type InstalledMigrationRequestV1 } from '../kernel/control-wire.js';

const HELP = `Cliq installed preview\n\nsetup\nmodels list | models add <alias> [--profile <id>] [--api-key-stdin]\nmodels add <alias> --manifest <model-manifest.json> | --local <enrolled-model>\nmodels retire <local-alias>\nrun <objective> [--model <alias>] --check-node <relative.mjs> [--policy default|accept-edits|plan|yolo] --budget-usd <amount> [--budget-tokens <count>] [--detach]\nresult <runId> --wait\napply <runId> [--result <ref>] [--detach]\n\nlist | status <runId> | attach <runId> | cancel <runId> | tui\nrequests | requests show|replay|acknowledge <requestId>\nsupervisor start | supervisor status\nstate migrate | state rollback --to-legacy <migrationId> [--allow-plaintext-legacy-credentials]\n\nThe first task asks for Workspace Trust. Automation may use --trust-workspace.\nSelecting a Node check requests its identity; default and accept-edits ask before executing each candidate.\nVerifier execution and applying a complete Delivery plan have separate approvals.\nOther control commands remain available through the installed client.\n`;
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

function migrationCommand(argv: readonly string[], legacyRootCanonicalAbsolutePath: string): InstalledMigrationRequestV1 {
  const { requestId, admissionKey } = mutationIdentity();
  const [command, action, flag, migrationId, plaintext] = argv;
  if (command !== 'state') throw new TypeError('invalid state command');
  if (action === 'migrate' && argv.length === 2)
    return decodeInstalledControlRequest({ protocolVersion: 1, method: 'state.migrate', requestId,
      migrationId: admissionKey, legacyRootCanonicalAbsolutePath }) as InstalledMigrationRequestV1;
  if (action === 'rollback' && flag === '--to-legacy' && migrationId &&
      (argv.length === 4 || argv.length === 5 && plaintext === '--allow-plaintext-legacy-credentials'))
    return decodeInstalledControlRequest({ protocolVersion: 1, method: 'state.rollback', requestId, migrationId,
      allowPlaintextLegacyCredentials: plaintext !== undefined }) as InstalledMigrationRequestV1;
  throw new TypeError('use state migrate or state rollback --to-legacy <migrationId>');
}

async function runMigration(selected: HeldInstalledRuntime, request: InstalledMigrationRequestV1, io: ClientIO): Promise<number> {
  io.signal?.throwIfAborted();
  const control = await openInstalledControlTransport(selected, 'control', 3);
  const failures: unknown[] = [];
  const cancel = () => { void control.close().catch(() => {}); };
  io.signal?.addEventListener('abort', cancel, { once: true });
  try {
    io.signal?.throwIfAborted();
    await write({ ...io, output: io.diagnostic }, `${request.method} · request ${request.requestId} · migration ${request.migrationId}\n`);
    io.signal?.throwIfAborted();
    const result = request.method === 'state.migrate' ? await control.request<'state.migrate'>(request)
      : await control.request<'state.rollback'>(request);
    await write(io, result.ok ? result.result : result.error);
    return result.ok ? 0 : 1;
  } catch (error) { failures.push(error); }
  finally {
    io.signal?.removeEventListener('abort', cancel);
    await closeDaily(failures, [() => control.close()]);
  }
  throw new Error('migration ended without a complete response');
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
  if (!argv.length || ['help', '--help'].includes(argv[0]!)) {
    await write(io, HELP + '\nsettings [--run-concurrency 1]  Configure the Linux preview for one active task on the next Supervisor start.\n'); return 0;
  }
  const locations = dailyInstalledLocations(), command = argv[0]!;
  const migration = command === 'state' ? migrationCommand(argv, locations.controlledHome) : undefined;
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
    if (migration) {
      stdio = await openInstalledClientStdio(selected, io);
      return await runMigration(selected, migration, stdio.io);
    }
    if (command === 'models' || command === 'settings' || command === 'requests' && argv[1] !== 'replay' || command === 'supervisor' && argv[1] === 'start') {
      stdio = await openInstalledClientStdio(selected, io); io = stdio.io;
    }
    if (command === 'supervisor' && argv[1] === 'start') {
      if (argv.length !== 2) throw new TypeError('supervisor start has no unit or manager override');
      await observeInstalledCredentialSupervisor(selected, true); await write(io, 'Supervisor started.\n'); return 0;
    }
    const data = await openInstalledClientData(selected);
    const dataFailures: unknown[] = [];
    try {
      if (command === 'settings') {
        const change = schedulingCommand(argv);
        const settings = change === undefined ? await readRunScheduling(data.directory) : await writeRunScheduling(data.directory, change);
        await write(io, { ...settings, applies: 'on_supervisor_restart' });
        return 0;
      }
      if (command === 'models') {
        const request = modelCommand(argv);
        if (request.kind === 'list') {
          const preferences = await readClientPreferences(data.directory);
          const local = await listInstalledLocalModels(selected, io.signal);
          await write(io, { models: preferences.modelSelections.map(({ alias, provider, model }) => ({ alias, provider, model })),
            localModels: local.map(({ provider, model, state }) => ({ provider, model, state })),
            profiles: profiles.map(({ id, provider, model }) => ({ id, provider, model })) }); return 0;
        }
        if (request.kind === 'enroll' || request.kind === 'local') {
          const configured = request.kind === 'enroll'
            ? await configureInstalledLocalModel(selected, data, request.alias, path.resolve(io.workspacePath, request.manifestPath), io.signal)
            : await selectInstalledLocalModel(selected, data, request.alias, request.model, io.signal);
          await write(io, `Local model ${terminalText(configured.choice.alias)} configured.\n`); return 0;
        }
        if (request.kind === 'retire') {
          const model = await retireInstalledLocalModelAlias(selected, data, request.alias, io.signal);
          await write(io, `Local model ${terminalText(model.model)} retired for new Runs.\n`); return 0;
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
