import assert from 'node:assert/strict';
import path from 'node:path';
import { rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { canonicalJsonBytes } from '../../kernel/canonical.js';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../config.js';
import { ArtifactCatalog, insertArtifactMetadata } from '../artifacts.js';
import { ContentAddressedStore } from '../cas.js';
import type { AuthenticatedControlIdentity } from '../control-channel.js';
import { iterateNodeSqliteStatement, openSqliteDriver, type SqliteInputValue } from '../sqlite-driver.js';
import { openStateStore, publishInProcessChannel, type StateStore } from '../store.js';
import { admissionKey, makePrivateDir, uuidv7 } from './fixtures.js';

export async function stopActualListChild(stateRoot: string, target: 'capture' | 'prepare' | 'final', diagnostic: (text: string) => void, method: 'session.list' | 'run.list' | 'authorization.list' = 'session.list') {
  // Original production Store/SQL/query and real SIGTERM, with markers only
  // around its unmodified synchronous scopes. No process is paused, no clock
  // or native evidence is supplied, and parent never writes while it runs.
  const source = `
    import assert from 'node:assert/strict';
    import {openStateStore,publishInProcessChannel} from ${JSON.stringify(new URL('../store.ts', import.meta.url).href)};
    import {seedControlListStopFixture} from ${JSON.stringify(import.meta.url)};
    process.on('message',()=>{});
    const [originalRoot,target,method,freshRoot,workspace]=process.argv.slice(1),root=freshRoot??originalRoot;
    if(method!=='session.list'){
      await assert.rejects(openStateStore(originalRoot),error=>error?.code==='RECOVERY_REQUIRED'&&error.message===
        (method==='run.list'?'verifier admission source history is not closed':'authorization history requires its signed runtime trust roots'));
    }
    const store=await openStateStore(root),identity=await publishInProcessChannel(store);
    if(method!=='session.list')await seedControlListStopFixture(store,identity,originalRoot,workspace,method);
    const driver=Reflect.get(store,'driver'),prototype=Object.getPrototypeOf(driver),transaction=prototype.transaction;
    let armed=false,writes=0,sent=false,enteredNs,returnedNs;
    const mark=phase=>{if(phase===target&&!sent){sent=true;enteredNs=process.hrtime.bigint();process.send({kind:'cut',phase,nodeVersion:process.version,enteredNs:String(enteredNs)});return true;}return false;};
    prototype.transaction=function(...args){
      const number=armed?++writes:0,capture=number===2,final=number===3;
      if(final&&target==='prepare'&&returnedNs===undefined)returnedNs=process.hrtime.bigint();
      const measured=capture&&mark('capture')||final&&mark('final');
      try{const value=Reflect.apply(transaction,this,args);if(capture)mark('prepare');return value;}
      finally{if(measured){returnedNs=process.hrtime.bigint();process.send({kind:'scope_returned',phase:target,enteredNs:String(enteredNs),returnedNs:String(returnedNs)});}}
    };
    let resolveStop,rejectStop;const stopped=new Promise((resolve,reject)=>{resolveStop=resolve;rejectStop=reject;});
    process.once('SIGTERM',()=>{process.send({kind:'stopping',enteredNs:String(process.hrtime.bigint())});void store.close().then(resolveStop,rejectStop);});
    armed=true;
    const request={protocolVersion:1,method,limit:100};
    const pending=method==='session.list'?store.sessionContinuity(request,identity):store.listControl(request,identity);
    void pending.finally(()=>{if(target==='prepare'&&returnedNs===undefined)returnedNs=process.hrtime.bigint();}).catch(()=>{});
    const [query,closed]=await Promise.allSettled([pending,stopped]);
    if(closed.status==='rejected')throw closed.reason;
    if(query.status==='rejected')assert.equal(query.reason.code,'LEASE_FENCED');
    assert(sent&&enteredNs!==undefined&&returnedNs!==undefined);process.send({kind:'closed',outcome:query.status,ownerEpoch:store.ownerEpoch,nodeVersion:process.version,
      enteredNs:String(enteredNs),returnedNs:String(returnedNs),...(method==='session.list'?{}:{originalSourceHistoryRefused:true})});
    process.disconnect();
  `;
  const freshRoot = method === 'session.list' ? undefined : await makePrivateDir('.cliq-list-stop-state-');
  const workspace = method === 'session.list' ? undefined : await makePrivateDir('.cliq-list-stop-ws-');
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source, stateRoot, target, method,
    ...(freshRoot === undefined ? [] : [freshRoot, workspace!])], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let stderr = '', received: any, closed: any, scopeReturned: any, stopping: any;
  let signalStarted: number | undefined, deadlineExceeded = false, processAndPipesJoined = false;
  let signalSentNs: bigint | undefined;
  child.stderr!.on('data', bytes => { stderr += bytes.toString('utf8'); assert(Buffer.byteLength(stderr) <= 65536); });
  const exited = once(child, 'close');
  let enter!: (value: any) => void;
  const entered = new Promise<any>(resolve => { enter = resolve; });
  child.on('message', message => { if ((message as any)?.kind === 'cut') { received = message; enter(message); } else if ((message as any)?.kind === 'closed') closed = message; else if ((message as any)?.kind === 'scope_returned') scopeReturned = message; else if ((message as any)?.kind === 'stopping') stopping = message; });
  let setupTimer: ReturnType<typeof setTimeout> | undefined, stopTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([entered, exited.then(() => { throw new Error('list child exited before its actual scope: ' + stderr); }), new Promise<never>((_, reject) => {
      setupTimer = setTimeout(() => reject(new Error('actual list child did not enter its bounded fixture scope')), 60000);
    })]);
    clearTimeout(setupTimer);
    const start = performance.now(), sentNs = process.hrtime.bigint(); signalStarted = start; signalSentNs = sentNs; assert(child.kill('SIGTERM'));
    const [code, signal] = await Promise.race([exited, new Promise<never>((_, reject) => {
      stopTimer = setTimeout(() => { deadlineExceeded = true; reject(new Error('actual large list SIGTERM exceeded the unchanged 2000ms stop budget')); }, 2000);
    })]);
    const elapsedMs = performance.now() - start;
    assert.equal(code, 0, stderr); assert.equal(signal, null); assert(elapsedMs < 2000);
    assert.equal(received.phase, target); assert.equal(closed?.kind, 'closed');
    assert(BigInt(closed.enteredNs) <= sentNs && sentNs <= BigInt(closed.returnedNs), 'the real signal must be sent inside the original measured scope, never after an idle result');
    let componentInspection;
    if (freshRoot !== undefined) {
      assert.equal(closed.originalSourceHistoryRefused, true);
      const audit = openSqliteDriver(path.join(freshRoot, KERNEL_DATABASE_FILENAME)), rows = method === 'run.list' ? 50_000 : 100_000;
      try {
        assert.equal(audit.prepare('SELECT state FROM state_owners WHERE owner_epoch=?').get(closed.ownerEpoch)?.state, 'terminal');
        assert.equal(audit.prepare("SELECT count(*) AS n FROM state_owners WHERE state='active'").get<{ n: bigint }>()!.n, 0n);
        const cuts = audit.prepare(`SELECT count(e.ordinal) AS n,min(e.ordinal) AS first,max(e.ordinal) AS last,
          sum(length(CAST(e.payload_json AS BLOB))) AS bytes FROM list_read_cuts c
          LEFT JOIN list_read_cut_entries e ON e.cut_id=c.cut_id GROUP BY c.cut_id`).all<{ n: bigint; first: bigint; last: bigint; bytes: bigint }>();
        for (const cut of cuts) {
          assert.equal(cut.n, BigInt(rows)); assert.equal(cut.first, 1n); assert.equal(cut.last, cut.n);
          assert.equal(cut.bytes, 64n * 1024n * 1024n);
        }
        componentInspection = { originalSourceHistoryRefused: true, originalOwnerTerminal: true, activeOwners: 0,
          completeRowsPerPublishedCut: rows, completeBytesPerPublishedCut: 64 * 1024 * 1024, publishedCuts: cuts.length,
          dataCopiedOnlyAfterGenuineStoreOpen: true, physicalInstalledSupervisorQualified: false };
      } finally { audit.close(); }
    }
    return { phase: target, elapsedMs, ownerEpoch: closed.ownerEpoch, outcome: closed.outcome, nodeVersion: closed.nodeVersion,
      scopeEnteredNs: closed.enteredNs, signalSentNs: sentNs.toString(), scopeReturnedNs: closed.returnedNs,
      originalProcessJoined: true, ...(componentInspection ? { componentInspection } : {}), physicalInstalledSupervisorQualified: false };
  } finally {
    clearTimeout(setupTimer); clearTimeout(stopTimer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited; processAndPipesJoined = true;
    diagnostic(JSON.stringify({ diagnosticOnly: true,
      kind: method === 'session.list' ? 'session_list_actual_sigterm_attempt' : 'control_list_actual_sigterm_attempt',
      ...(method === 'session.list' ? {} : { method }), phase: target,
      nodeVersion: received?.nodeVersion ?? process.version, deadlineMs: 2000, deadlineExceeded,
      ...(signalStarted === undefined ? {} : { signalToProcessAndPipesJoinMs: performance.now() - signalStarted }),
      ...(signalSentNs === undefined ? {} : { signalSentNs: signalSentNs.toString() }),
      ...(received?.enteredNs === undefined ? {} : { scopeEnteredNs: received.enteredNs }),
      ...(scopeReturned?.returnedNs === undefined ? {} : { scopeReturnedNs: scopeReturned.returnedNs }),
      ...(stopping?.enteredNs === undefined ? {} : { signalHandlerEnteredNs: stopping.enteredNs }),
      originalProcessAndPipesJoined: processAndPipesJoined, originalCloseObserved: closed?.kind === 'closed',
      scopeReturnedObserved: scopeReturned?.kind === 'scope_returned', physicalInstalledSupervisorQualified: false }));
    if (freshRoot !== undefined) await rm(freshRoot, { recursive: true, force: true });
    if (workspace !== undefined) await rm(workspace, { recursive: true, force: true });
  }
}

/** Test display data only. Startup first validates an empty genuine Store and
 * creates its real Session/channel; no history, FK or trigger is disabled. The
 * original source uses a truly read-only SQLite connection, joined before measuring
 * the unchanged production query. No source authority or owner is adopted. */
export async function seedControlListStopFixture(store: StateStore, identity: AuthenticatedControlIdentity,
  sourceRoot: string, workspace: string, method: 'run.list' | 'authorization.list') {
  assert.equal(store.supportsInstalledRuns(), false);
  const session = await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('list-stop-' + method), workspacePath: workspace });
  const driver = openSqliteDriver(path.join(store.stateRoot, KERNEL_DATABASE_FILENAME));
  const source = new DatabaseSync(path.join(sourceRoot, KERNEL_DATABASE_FILENAME), { readOnly: true });
  try {
    assert.equal(driver.prepare('PRAGMA foreign_keys').get<{ foreign_keys: bigint }>()!.foreign_keys, 1n);
    if (method === 'run.list') {
      const original = source.prepare('SELECT spec_ref,session_id FROM runs ORDER BY id LIMIT 1').get()!;
      assert(typeof original.spec_ref === 'string' && typeof original.session_id === 'string');
      assert.equal(Buffer.byteLength(session.session.id), Buffer.byteLength(original.session_id));
      const data = new ArtifactCatalog(new ContentAddressedStore(path.join(sourceRoot, KERNEL_CAS_DIRECTORY)));
      const spec = await store.artifacts.publishCanonical(await data.readCanonical(original.spec_ref), 'cliq-run-spec-v1');
      assert.equal(spec.ref, original.spec_ref);
      driver.transaction(connection => {
        insertArtifactMetadata(connection, spec, session.session.createdAt);
        for (const table of ['checkpoints', 'runs'] as const) {
          const statement = source.prepare('SELECT * FROM ' + table); statement.setReadBigInts(true);
          let insert: ReturnType<typeof connection.prepare> | undefined, keys: string[] = [];
          for (const row of iterateNodeSqliteStatement(statement)) {
            if (!insert) {
              keys = Object.keys(row);
              // Column names come only from this test-owned same-version
              // schema. A stored value cannot become an SQL identifier.
              assert(keys.every(key => /^[a-z_]+$/u.test(key)));
              insert = connection.prepare(`INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`);
            }
            if (table === 'runs') { row.session_id = session.session.id; row.principal_id = identity.principalId; }
            insert.run(...keys.map(key => row[key] as SqliteInputValue));
          }
        }
      });
    } else {
      driver.transaction(connection => {
        const query = source.prepare('SELECT grant_id,state,row_json FROM authorization_grants');
        const insert = connection.prepare('INSERT INTO authorization_grants(grant_id,owner_principal_id,state,row_json) VALUES(?,?,?,?)');
        for (const row of iterateNodeSqliteStatement(query)) {
          assert(typeof row.grant_id === 'string' && typeof row.state === 'string' && typeof row.row_json === 'string');
          const data = JSON.parse(row.row_json); data.ownerPrincipalId = identity.principalId;
          insert.run(row.grant_id, identity.principalId, row.state, canonicalJsonBytes(data).toString('utf8'));
        }
      });
    }
    for (const table of ['worker_launches', 'run_journal'])
      assert.equal(driver.prepare(`SELECT count(*) AS n FROM ${table}`).get<{ n: bigint }>()!.n, 0n);
    assert.equal(driver.prepare(`SELECT count(*) AS n FROM ${method === 'run.list' ? 'runs' : 'authorization_grants'}`)
      .get<{ n: bigint }>()!.n, method === 'run.list' ? 50_000n : 100_000n);
  } finally { try { source.close(); } finally { driver.close(); } }
}
export async function listFixture(label: string) {
  const stateRoot = await makePrivateDir(`.cliq-session-${label}-state-`), workspace = await makePrivateDir(`.cliq-session-${label}-ws-`);
  let store = await openStateStore(stateRoot), identity = await publishInProcessChannel(store);
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  return { stateRoot, workspace, driver, get store() { return store; }, get identity() { return identity; },
    async create(name: string) { return (await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey(name), workspacePath: workspace, name })).session; },
    async reopen() { await store.close(); store = await openStateStore(stateRoot); identity = await publishInProcessChannel(store); },
    async close() { driver.close(); await store.close(); await rm(stateRoot, { recursive: true, force: true }); await rm(workspace, { recursive: true, force: true }); } };
}
