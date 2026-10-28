// Fixed trusted-image data and real child pipes only; no native/Run or Linux qualification.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const sender = { uid: 1000, pid: 2000, invocationId: 'a'.repeat(32) };
const journal = (messages: string[]) => messages.map(MESSAGE => JSON.stringify({ _UID: '1000', _PID: '2000',
  _TRANSPORT: 'stdout', _SYSTEMD_INVOCATION_ID: sender.invocationId, MESSAGE })).join('\n');
const emptyNumbers = Array<number>(25).fill(0);
const frame = (ordinal: number, phase: string, elapsed: number, numbers = emptyNumbers, cpu = '-:-') =>
  `CLIQ_ASSEMBLY_WORK_V1:${ordinal}:${phase}:${elapsed}:${numbers.join(':')}:${cpu}`;

async function journeySource() {
  const source = await readFile(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('journey.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const nodes: ts.Node[] = [];
  const visit = (node: ts.Node) => { nodes.push(node); ts.forEachChild(node, visit); };
  visit(parsed); return { parsed, nodes };
}

test('abnormal assembly diagnostics retain the original absence gate without claiming a joined server', async () => {
  const { parsed, nodes } = await journeySource();
  const candidates = nodes.filter((node): node is ts.ObjectLiteralExpression => ts.isObjectLiteralExpression(node) &&
    node.properties.some(property => ts.isPropertyAssignment(property) && property.name.getText(parsed) === 'cuts') &&
    node.properties.some(property => ts.isPropertyAssignment(property) && ts.isStringLiteral(property.initializer) &&
      property.initializer.text === 'actual_absent_original_supervisor_journal'));
  assert.equal(candidates.length, 1);
  const object = candidates[0]!, names = object.properties.map(property => property.name?.getText(parsed));
  assert.deepEqual(names, ['diagnosticOnly', 'kind', 'source', 'preexistingProcessStartAndFullImageBound',
    'originalInvocationBound', 'originalPidObservedAbsent', 'cuts']);
  assert(!names.includes('originalServerJoined'));
  const ancestors: ts.Node[] = [];
  for (let parent = object.parent; parent; parent = parent.parent) ancestors.push(parent);
  assert(ancestors.some(node => ts.isIfStatement(node) && node.expression.getText(parsed) === 'originalStopFailed'));
  const bound = ancestors.find(node => ts.isTryStatement(node) && node.getText(parsed).includes("await assert.rejects(lstat('/proc/' + storeFailureBinding.pid), { code: 'ENOENT' })"));
  assert(bound && bound.getText(parsed).indexOf("await assert.rejects(lstat('/proc/' + storeFailureBinding.pid)") < object.pos - bound.pos);
  assert(ancestors.some(node => ts.isIfStatement(node) && node.expression.getText(parsed).includes('storeFailureBinding.invocationId === before[0]!.InvocationID') &&
    node.expression.getText(parsed).includes('String(storeFailureBinding.pid) === before[0]!.MainPID')));
  const text = parsed.getText();
  assert(text.includes('} catch (error) { originalStopFailed = true; throw error; }'));
  assert(text.includes("assert.equal(stopped.TimeoutStopUSec, '2s')"));
});

test('the abnormal assembly stream keeps independent original bounds, scan and closure', async () => {
  const { parsed, nodes } = await journeySource();
  const calls = nodes.filter((node): node is ts.CallExpression => ts.isCallExpression(node) &&
    node.expression.getText(parsed) === 'spawnSync' && node.arguments[1]?.getText(parsed).includes("'--grep=^CLIQ_ASSEMBLY_WORK_V1:'"));
  assert.equal(calls.length, 1);
  const call = calls[0]!, args = call.arguments[1]!.getText(parsed), options = call.arguments[2]!.getText(parsed);
  for (const field of ['windowOpenedAt', 'pid', 'invocationId']) assert(args.includes('storeFailureBinding.' + field));
  assert(args.includes('_UID=${ledger.uid}') && args.includes('--until=${timestamp(until)}'));
  for (const field of ['timeout: Math.min(5000, remaining)', "killSignal: 'SIGKILL'", 'maxBuffer: 256 * 1024']) assert(options.includes(field));
  const text = parsed.getText();
  assert.equal(text.split("'--grep=^(CLIQ_PUBLICATION_STAGE_V1:|CLIQ_STORE_STOP_PHASE_V1:|CLIQ_PUBLICATION_WORK_V2:)'" ).length, 2,
    'the earlier publication stream keeps its exact independent entry bound');
  for (const field of ['scanBytes(assemblyLog.stdout)', 'scanBytes(assemblyLog.stderr)',
    'assemblyLog.stdout?.fill(0)', 'assemblyLog.stderr?.fill(0)', 'assertRetained()', 'assert(Date.now() < logBy']) assert(text.includes(field));
});

test('the original publication V2 projection is saved before an optional assembly query can consume its remaining budget', async () => {
  const { parsed, nodes } = await journeySource();
  const publication = nodes.filter((node): node is ts.CallExpression => ts.isCallExpression(node) &&
    node.expression.getText(parsed) === 'readInstalledPublicationWorkJournal');
  const assembly = nodes.filter((node): node is ts.CallExpression => ts.isCallExpression(node) &&
    node.expression.getText(parsed) === 'spawnSync' && node.arguments[1]?.getText(parsed).includes("'--grep=^CLIQ_ASSEMBLY_WORK_V1:'"));
  assert.equal(publication.length, 1); assert.equal(assembly.length, 1);
  let projectionTry: ts.Node | undefined = publication[0]!.parent;
  while (projectionTry && !ts.isTryStatement(projectionTry)) projectionTry = projectionTry.parent;
  assert(projectionTry && ts.isTryStatement(projectionTry) && projectionTry.catchClause);
  assert(projectionTry.tryBlock.getText(parsed).includes('report.publicationWorkDiagnostics ='));
  assert(projectionTry.tryBlock.getText(parsed).includes('...work'));
  assert(projectionTry.end < assembly[0]!.pos,
    'the original V2 parser, deadline/retention checks and projection must complete before the optional child starts');
  let optional: ts.Node | undefined = assembly[0]!.parent;
  while (optional && !ts.isIfStatement(optional)) optional = optional.parent;
  assert(optional && ts.isIfStatement(optional));
  assert.equal(optional.expression.getText(parsed), 'originalStopFailed');
  assert.equal(optional.parent, projectionTry.parent, 'both streams keep the original shared outer deadline');
  assert(!optional.getText(parsed).includes('report.publicationWorkDiagnostics'),
    'a timed-out or malformed optional stream cannot overwrite already retained V2 data');
});

test('a missing original binding reports only the fixed local failed stage before client authentication', async () => {
  const { parsed, nodes } = await journeySource();
  const stages = nodes.filter((node): node is ts.BinaryExpression => ts.isBinaryExpression(node) &&
    node.left.getText(parsed) === 'bindingStage').map(node => node.right.getText(parsed));
  const initial = nodes.find((node): node is ts.VariableDeclaration => ts.isVariableDeclaration(node) && node.name.getText(parsed) === 'bindingStage');
  assert.equal(initial?.initializer?.getText(parsed), "'owner_history'");
  assert.deepEqual(stages, ['`owner_history_${stage}`', "'owner_cardinality'", "'owner_state'", "'owner_bundle'", "'owner_process'", "'process_start'", "'unit_recheck'"]);
  const catchClause = nodes.find((node): node is ts.CatchClause => ts.isCatchClause(node) &&
    node.block.getText(parsed).includes('storeBindingFailureStage = bindingStage'));
  assert(catchClause && !catchClause.variableDeclaration, 'no exception field may become a binding stage');
  assert.equal(catchClause.block.statements.length, 1);
  assert(catchClause.end < parsed.getText().indexOf('try { client = await persistentClient(); inspectionClient = await persistentClient(); }'));
  const literal = nodes.filter((node): node is ts.PropertyAssignment => ts.isPropertyAssignment(node) &&
    node.name.getText(parsed) === 'bindingFailureStage');
  assert.equal(literal.length, 2);
  for (const field of literal) assert.equal(field.initializer.getText(parsed), 'storeBindingFailureStage');
});

test('first-submit diagnostics can bind the original ready cut after an early busy read without manufacturing a source', async () => {
  const { parsed, nodes } = await journeySource();
  const fallback = nodes.find((node): node is ts.IfStatement => ts.isIfStatement(node) &&
    node.expression.getText(parsed) === 'storeFailureDiagnostics && !storeFailureBinding');
  assert(fallback, 'the original complete readiness cut must remain usable after the early optional history read failed');
  const body = fallback.thenStatement.getText(parsed);
  const ready = nodes.find((node): node is ts.VariableDeclaration => ts.isVariableDeclaration(node) &&
    node.name.getText(parsed) === 'originalOwner');
  assert(ready?.initializer && ts.isAwaitExpression(ready.initializer));
  assert.equal(ready.initializer.expression.getText(parsed), 'waitForInstalledOwnerHistory(recipe.stateRoot, readinessBy)');
  assert(ready.end < fallback.pos);
  const sessions = nodes.filter((node): node is ts.CallExpression => ts.isCallExpression(node) &&
    node.expression.getText(parsed) === 'request' && node.arguments[0]?.getText(parsed).includes("method: 'session.create'"));
  assert(sessions.length > 0 && sessions.every(node => fallback.end < node.pos),
    'every original Session and source producer must follow this actual live binding attempt');
  assert(body.includes('originalOwner.owners[0]!'));
  assert(!/inspectInstalledOwnerHistory|waitForInstalledOwnerHistory|DatabaseSync|readCas|readInstalledOwnerHistory/u.test(body),
    'the already acquired SQL cut is reused without another history transaction or a new readiness budget');
  assert(body.includes('const actual = await qualifyInstalledOwnerProcess('));
  for (const field of ['stateRoot: recipe.stateRoot', 'uid: ledger.uid', 'pid, selectedImage: installedImage', 'imageDigest: entry.digest',
    "'linux-proc-start-ticks:' + await fixtureProcess(pid, ledger.uid)", 'actual.processStartToken',
    'same.MainPID, supervisorBefore.MainPID', 'same.InvocationID, supervisorBefore.InvocationID']) assert(body.includes(field));
  const assignment = nodes.find((node): node is ts.BinaryExpression => ts.isBinaryExpression(node) &&
    node.left.getText(parsed) === 'storeFailureBinding' && fallback.pos < node.pos && node.end < fallback.end);
  assert(assignment && assignment.right.getText(parsed).startsWith('Object.freeze('));
  assert(body.indexOf('await qualifyInstalledOwnerProcess(') < body.indexOf('storeFailureBinding =') &&
    body.indexOf('same.InvocationID, supervisorBefore.InvocationID') < body.indexOf('storeFailureBinding ='));
  for (const field of ['pid, processStartToken: actual.processStartToken', 'invocationId: supervisorBefore.InvocationID!', 'windowOpenedAt: Date.now()'])
    assert(assignment.right.getText(parsed).includes(field));
  const caught = nodes.find((node): node is ts.CatchClause => ts.isCatchClause(node) && fallback.pos < node.pos && node.end < fallback.end);
  assert(caught && !caught.variableDeclaration && caught.block.statements.length === 0,
    'a failed live recheck retains absence and the original fixed failed-stage observation without inspecting an error');
  assert(!body.includes('storeBindingFailureStage =') && !body.includes('serverAuthenticationBinding =') &&
    !body.includes('originalServerJoined') && !body.includes('originalPidObservedAbsent'));
});

test('the independent reader accepts only original-sender complete numeric prefix records, never reconstructed windows', async () => {
  const readers = await import('./installed-store-diagnostic-journal.js');
  const read = Reflect.get(readers, 'readInstalledAssemblyWorkJournal') as typeof readers.readInstalledAssemblyWorkJournal;
  assert.equal(typeof read, 'function', 'the original whole journal needs its closed independent reader');
  const rows = [frame(1, 'submit_request', 0, emptyNumbers, '30:7'),
    frame(2, 'submit_assembly_verifier_publish', 4), frame(3, 'original_store_stop', 9, emptyNumbers, '31:8')];
  const result = read(journal(rows), sender)!;
  assert.equal(result.cuts.length, 3); assert.deepEqual(result.cuts[0].process, { userCPUTime: 30, systemCPUTime: 7 });
  assert.equal(result.cuts[1].process, null); assert(Object.isFrozen(result.cuts[2].runtime.package));
  assert.equal(read(journal(['ordinary fixed service text']), sender), undefined);
  const invalid = [
    [rows[1]!], [rows[0]!, rows[0]!], [rows[0]!, rows[2]!, rows[1]!],
    [rows[0]!, 'CLIQ_ASSEMBLY_WORK_V1:truncated'], [rows[0]!.replace(':1:', ':01:')],
    [rows[0]!.replace(':submit_request:0:', ':unknown:0:')], [rows[0]! + ':0'], [rows[0]! + '\n'],
    [rows[0]!, frame(2, 'submit_assembly_policy', 1, emptyNumbers, '29:8')],
    [rows[0]!, frame(2, 'original_store_stop', 1, emptyNumbers, '-:1')],
    [frame(1, 'submit_request', 1)], [frame(1, 'submit_request', 0, [Number.MAX_SAFE_INTEGER + 1, ...emptyNumbers.slice(1)])],
    [frame(1, 'submit_request', 0, [0, 1, ...emptyNumbers.slice(2)])]
  ];
  for (const bad of invalid) assert.throws(() => read(journal(bad), sender), { code: 'ERR_ASSERTION' }, 'malformed fixed work prefix must reject');
  const foreign = JSON.parse(journal([rows[0]!])); foreign._PID = '2001';
  assert.throws(() => read(JSON.stringify(foreign), sender));
  assert.throws(() => read(journal(Array<string>(81).fill('ordinary')), sender));
  let accessed = 0;
  const bad = () => { accessed++; throw Error('private getter'); };
  assert.throws(() => read(journal(rows), Object.defineProperty({ ...sender }, 'pid', { get: bad })));
  assert.throws(() => read(journal(rows), new Proxy(sender, { get: bad, ownKeys: bad, getPrototypeOf: bad })));
  assert.equal(accessed, 0);
});

test('malformed banner packets invoke no getters and can only truncate this non-authoritative stream', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const mutations = [
    `{...row,path:'private input'}`, `{...row,phase:['submit_request']}`, `{...row,phase:'other'}`, `{...row,elapsedMs:-1}`,
    `{...row,elapsedMs:1}`, `{...row,casRead:{...row.casRead,settled:2}}`,
    `{...row,casRead:{...row.casRead,bytesRead:Number.MAX_SAFE_INTEGER+1}}`,
    `{...row,runtime:{...row.runtime,createCompare:{...row.runtime.createCompare,bytesRead:1}}}`,
    `Object.defineProperty({...row},'phase',{get:bad})`,
    `{...row,casRead:Object.defineProperty({...row.casRead},'bytesRead',{get:bad})}`,
    `new Proxy(row,{get:bad,ownKeys:bad,getPrototypeOf:bad,getOwnPropertyDescriptor:bad})`,
    `{...row,runtime:new Proxy(row.runtime,{get:bad,ownKeys:bad,getPrototypeOf:bad})}`,
    `{...row,[Symbol('private')]:1}`, `Object.defineProperty({...row},'elapsedMs',{value:0,enumerable:false})`
  ];
  for (const mutation of mutations) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
      let accessed=0;const bad=()=>{accessed++;throw Error('private getter')};
      const r={started:0,completed:0,bytesRead:0,spanElapsedMs:0},s={started:0,settled:0,spanElapsedMs:0};
      const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:r},
        casRead:{...s,bytesRead:0},publishFour:s,fileSync:s,rootSync:s};
      require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1').publish(${mutation});
      require('node:fs').writeSync(1,'accessed:'+accessed);
    `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
    assert.equal(child.stdout, 'accessed:0'); assert.equal(child.stderr, 'CLIQ_ASSEMBLY_WORK_V1:truncated\n');
  }
});

test('actual fragmented child output preserves numeric cuts and sampling fallback without affecting the operation', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const { readInstalledAssemblyWorkJournal: read } = await import('./installed-store-diagnostic-journal.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `
    process.argv[2]='--installed-supervisor';const fs=require('node:fs'),write=fs.writeSync;let samples=0;
    fs.writeSync=(fd,text)=>{const b=Buffer.from(text);for(let n=0;n<b.length;n+=3)write(fd,b.subarray(n,n+3));return b.length};
    process.resourceUsage=()=>{samples++;if(samples===2)throw Error('unavailable own sample');
      return {userCPUTime:30+samples,systemCPUTime:7+samples}};
  ` + banner + `
    const r={started:0,completed:0,bytesRead:0,spanElapsedMs:0},s={started:0,settled:0,spanElapsedMs:0};
    const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:r},
      casRead:{...s,bytesRead:0},publishFour:s,fileSync:s,rootSync:s};
    const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
    d.publish(row);d.publish({...row,phase:'submit_assembly_material',elapsedMs:1});
    d.publish({...row,phase:'original_store_stop',elapsedMs:2});fs.writeSync(1,'original result');
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  assert.equal(child.stdout, 'original result');
  const cuts = read(journal(child.stderr.trimEnd().split('\n')), sender)!.cuts;
  assert.deepEqual(cuts.map(cut => cut.process), [{ userCPUTime: 31, systemCPUTime: 8 }, null, { userCPUTime: 33, systemCPUTime: 10 }]);
});

test('the independent server banner is absent in credential/ordinary roles and bounds every attempted output', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  for (const role of ['--installed-credential', '--bootstrap-credential', '--ordinary']) {
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]=${JSON.stringify(role)};` + banner + `
      const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
      if(d.hasSubscribers)throw Error('unexpected subscription');d.publish('truncated');
    `], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
    assert.equal(child.stdout, ''); assert.equal(child.stderr, '');
  }
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
    const m=Number.MAX_SAFE_INTEGER,r={started:m,completed:m,bytesRead:m,spanElapsedMs:m},s={started:m,settled:m,spanElapsedMs:m};
    process.resourceUsage=()=>({userCPUTime:m,systemCPUTime:m});
    const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:{...r,bytesRead:0}},
      casRead:{...s,bytesRead:m},publishFour:s,fileSync:s,rootSync:s};
    const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
    d.publish(row);d.publish({...row,phase:'submit_assembly_verifier_history',elapsedMs:m});
    d.publish({...row,phase:'original_store_stop',elapsedMs:m});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null);
  assert(child.stderr.endsWith('CLIQ_ASSEMBLY_WORK_V1:truncated\n'));
  assert(child.stderr.split('\n').filter(Boolean).every(row => Buffer.byteLength(row + '\n') <= 512));
  assert(Buffer.byteLength(child.stderr) <= 4096);
});

test('the server-only work banner carries bounded numeric phase cuts without private data', async () => {
  const builder = await import('./supervisor-sea-builder.js');
  const banner = Reflect.get(builder, 'INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER');
  assert.equal(typeof banner, 'string', 'the trusted server requires its independent fixed work banner');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
    const r={started:1,completed:1,bytesRead:3,spanElapsedMs:4}, s={started:2,settled:1,spanElapsedMs:5};
    const cut={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:{...r,bytesRead:0}},
      casRead:{...s,bytesRead:11},publishFour:s,fileSync:s,rootSync:s};
    require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1').publish(cut);
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0); assert.equal(child.signal, null); assert.equal(child.stdout, '');
  assert.match(child.stderr, /^CLIQ_ASSEMBLY_WORK_V1:1:submit_request:0:(?:[0-9]+:){26}[0-9]+\n$/u);
  assert(Buffer.byteLength(child.stderr) <= 512);
});

test('the actual source first-submit observer, real CAS and trusted child banner round-trip without another request window', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const { readInstalledAssemblyWorkJournal: read } = await import('./installed-store-diagnostic-journal.js');
  const cas = new URL('../../../src/state/cas.ts', import.meta.url).href;
  const diagnostics = new URL('../../../src/state/installed-run-diagnostics.ts', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--no-warnings', '--import', 'tsx', '--input-type=commonjs', '--eval',
    `process.argv[2]='--installed-supervisor';` + banner + `
    (async()=>{const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
      const {ContentAddressedStore}=await import(${JSON.stringify(cas)});
      const {beginInstalledSubmitDiagnostic,noteInstalledStoreStop}=await import(${JSON.stringify(diagnostics)});
      const root=await fs.mkdtemp(path.join(os.tmpdir(),'cliq-actual-work-'));
      try {const store=new ContentAddressedStore(root),first=beginInstalledSubmitDiagnostic();
        const ref=await store.publish(Buffer.from('hello'));await store.read(ref);await store.verify(ref);
        first.stage('submit_assembly_material');first.stage('submit_assembly_material');
        first.stage('submit_assembly_verifier_publish');
        await store.publishFour([Buffer.from('1'),Buffer.from('2'),Buffer.from('3'),Buffer.from('4')]);
        first.stage('submit_assembly_policy');
        first.stage('submit_postcommit_load');first.stage('submit_assembly_final_check');
        const second=beginInstalledSubmitDiagnostic();second?.stage('submit_assembly_final_check');
        noteInstalledStoreStop({driverTasks:0,agentLoads:0,admissions:0,retainedFailures:0,globalFailure:false,phases:[]});
      }finally{await fs.rm(root,{recursive:true,force:true})}
    })().catch(()=>{process.exitCode=1});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536, cwd: new URL('../../..', import.meta.url) });
  assert.equal(child.error, undefined); assert.equal(child.status, 0, child.stderr); assert.equal(child.signal, null);
  const cuts = read(journal(child.stderr.trimEnd().split('\n')), sender)!.cuts;
  assert.deepEqual(cuts.map(cut => cut.phase), ['submit_request', 'submit_assembly_material', 'submit_assembly_verifier_publish', 'submit_assembly_policy']);
  assert.equal(cuts[1]!.casRead.bytesRead, 10); assert.equal(cuts[1]!.casRead.settled, 2);
  assert.equal(cuts[3]!.publishFour.settled, 1); assert.equal(cuts[3]!.fileSync.settled, 5); assert.equal(cuts[3]!.rootSync.settled, 8);
  assert.equal(child.stdout, '');
});

test('the fixed four-KiB output bound includes its final explicit truncation record', async () => {
  const { INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER: banner } = await import('./installed-assembly-work-banner.js');
  const { INSTALLED_ASSEMBLY_WORK_PHASES: phases } = await import('../../../src/state/installed-work-diagnostics.js');
  const child = spawnSync(process.execPath, ['--input-type=commonjs', '--eval', `process.argv[2]='--installed-supervisor';` + banner + `
    const m=99999999999999,r={started:m,completed:m,bytesRead:m,spanElapsedMs:m},s={started:m,settled:m,spanElapsedMs:m};
    process.resourceUsage=()=>({userCPUTime:999999999999,systemCPUTime:999999999999});
    const row={phase:'submit_request',elapsedMs:0,runtime:{package:r,revalidate:r,createCompare:{...r,bytesRead:0}},
      casRead:{...s,bytesRead:m},publishFour:s,fileSync:s,rootSync:s};
    const d=require('node:diagnostics_channel').channel('cliq.installed.assembly.work.v1');
    for(const [index,phase] of ${JSON.stringify(phases)}.entries())d.publish({...row,phase,elapsedMs:index===0?0:m});
    d.publish({...row,phase:'original_store_stop',elapsedMs:m});
  `], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0);
  assert(child.stderr.endsWith('CLIQ_ASSEMBLY_WORK_V1:truncated\n'));
  assert(Buffer.byteLength(child.stderr) <= 4096, 'all measurement records including truncation must obey the existing four-KiB bound');
});
