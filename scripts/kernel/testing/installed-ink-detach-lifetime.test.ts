// Actual PTY/component lifetime, not installed authentication or a native Run.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { build } from 'esbuild';
import { installedClientBuildOptions } from './installed-client-build.js';

const pty = String.raw`import json,os,pty,re,select,signal,sys,time
pid,fd=pty.fork()
if pid==0:
 os.execv(sys.argv[1],[sys.argv[1],sys.argv[2]])
data=b''; sent=False; reaped=False; observed=False
try:
 by=time.monotonic()+5
 while True:
  assert time.monotonic()<by
  ready,_,_=select.select([fd],[],[],max(0,by-time.monotonic()))
  if ready:
   try: chunk=os.read(fd,65536)
   except OSError: chunk=b''
   if chunk: data+=chunk
   assert len(data)<=1048576
   clean=re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]',b'',data)
   if not sent and b'Run '+b'a'*43 in clean and b'CLIQ_REAL_TTY_READ_ENTERED' in clean:
    observed=True;os.write(fd,b'\x1b');sent=True;by=time.monotonic()+10
  done,status=os.waitpid(pid,os.WNOHANG)
  if done:
   reaped=True
   print(json.dumps({'realTtyReadObserved':observed,'escSent':sent,'exitCode':os.waitstatus_to_exitcode(status),'processJoined':True}))
   break
finally:
 if not reaped:
  os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
 os.close(fd)
`;

test('real PTY Esc during the original read restores raw mode and exits after all original close joins', async () => {
  const root = fileURLToPath(new URL('../../..', import.meta.url)), temporary = await mkdtemp(path.join(os.tmpdir(), 'cliq-ink-detach-'));
  const runId = 'a'.repeat(43), ref = 'b'.repeat(64), at = '2026-10-26T00:00:00.000Z';
  const snapshot = { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 0, run: { id: runId, sessionId: 'session', specRef: ref,
    status: 'completed_unverified', terminalReason: 'no_required_verifier', resultRef: ref, nextStep: null, revision: 2, leaseEpoch: 0,
    latestCheckpointId: 'checkpoint', budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0, cancelRequested: false,
    createdAt: at, updatedAt: at, deadlineAt: '2026-10-27T00:00:00.000Z' } };
  try {
    const filename = path.join(temporary, 'client.mjs');
    const program = `import assert from 'node:assert/strict';
import{runClientInvocation}from${JSON.stringify(path.join(root, 'src/client/entry.ts'))};
import{createInstalledControlSession}from${JSON.stringify(path.join(root, 'src/control/session.ts'))};
import{encodeControlCheckpointCursor}from${JSON.stringify(path.join(root, 'src/kernel/control-wire.ts'))};
import{installedControlCloseError}from${JSON.stringify(path.join(root, 'src/state/installed-control-close-error.ts'))};
const snapshot=${JSON.stringify(snapshot)},runId=${JSON.stringify(runId)},ref=${JSON.stringify(ref)},at=${JSON.stringify(at)};
let rejectRead,cancels=0,joined=false;
const session=createInstalledControlSession({hello:{method:'control.hello',protocolVersion:1,serverBuild:'pure-pty-component',supervisorInstanceId:'supervisor',
 controlSchemaRange:{min:1,max:1},headlessSchemaRange:{min:3,max:3},activeRuntimeBundle:{schemaVersion:1,runtimeBundleRef:ref,bundleDigest:ref,bundleVersion:'inert'},
 enabledFeatureIds:['run.get','run.attach','run.cancel']},
 close:async()=>{joined=true;rejectRead?.(installedControlCloseError());},
 'run.get':async()=>({protocolVersion:1,ok:true,result:{method:'run.get',snapshot,items:[],journal:[],checkpoints:[],highWaterItemSeq:0,highWaterJournalSeq:0,
 highWaterCheckpointCursor:encodeControlCheckpointCursor(runId,{createdAt:at,checkpointId:'checkpoint'}),nextItemSeq:0,nextJournalSeq:0}}),
 'run.attach':async()=>{assert(process.stdin.isTTY&&process.stdout.isTTY&&process.stdin.isRaw);process.stdout.write('CLIQ_REAL_TTY_READ_ENTERED\\n');return new Promise((_resolve,reject)=>{rejectRead=reject;});},
 'run.cancel':async()=>{cancels++;throw new Error('no mutation in this component');}});
try{const code=await runClientInvocation(session,{kind:'tui',runId},{input:process.stdin,output:process.stdout,diagnostic:process.stderr,workspacePath:process.cwd()});
 assert.equal(code,0);assert(joined);assert.equal(cancels,0);assert.equal(process.stdin.isRaw,false);process.exitCode=0;}
catch{process.exitCode=1;}`;
    const bundled = await build({ stdin: { contents: program, resolveDir: root, loader: 'ts', sourcefile: 'inert-pty-component.ts' },
      outfile: filename, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', write: false, metafile: true, ...installedClientBuildOptions() });
    assert.equal(bundled.outputFiles!.length, 1);
    assert(Object.values(bundled.metafile!.outputs).flatMap(value => value.imports).every(value => value.external && value.path.startsWith('node:')));
    await writeFile(filename, bundled.outputFiles![0]!.contents, { flag: 'wx', mode: 0o400 });
    const child = spawnSync('/usr/bin/python3', ['-c', pty, process.execPath, filename], { encoding: 'utf8', cwd: root,
      env: { PATH: '/usr/bin:/bin', TERM: 'xterm-256color', LANG: 'C', LC_ALL: 'C' }, timeout: 20000, killSignal: 'SIGKILL', maxBuffer: 65536 });
    assert.equal(child.error, undefined, 'the actual PTY component must join'); assert.equal(child.signal, null); assert.equal(child.status, 0);
    assert.equal(child.stderr, '');
    const result = JSON.parse(child.stdout) as Record<string, unknown>;
    assert.deepEqual(result, { realTtyReadObserved: true, escSent: true, exitCode: 0, processJoined: true });
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
