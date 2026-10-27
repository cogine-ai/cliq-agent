// Fixed additional consumers of the existing real installed journey. No Store,
// SQL writer, native handle, host npm fallback or new runner exists here.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { chown, lstat, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { gzipSync } from 'node:zlib';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeDependencyAcquisitionPlan, decodeDependencyReadyItem, decodePackageCacheManifest } from '../../../src/kernel/dependency.js';
import { decodeDependencyClaimEvidence } from '../../../src/kernel/dependency-claim.js';
import { decodeDependencyRequest, decodeDependencyTarget } from '../../../src/kernel/dependency-invocation.js';
import { decodeBudgetSettlement, decodeRunSpec, decodeWorkspaceEntries, decodeWorkspaceState } from '../../../src/state/decoders.js';
import { decodeDependencyRetirement, dependencyReadyCheckpointId, dependencyInstalledTreeDigest } from '../../../src/state/dependency-retirement.js';
import { decodeDependencyProcessCapture } from '../../../src/state/dependency-capture.js';
import { decodeRunResult, decodeVerificationClosure } from '../../../src/state/result-artifacts.js';

export const INSTALLED_DEPENDENCY_PROFILE = 'public_npm_ci_v1_root_ignore_and_exact_scripts_v1';
export const INSTALLED_DEPENDENCY_PACKAGE_PATH = '/cliq-owned-dependency/-/cliq-owned-dependency-1.0.0.tgz';
const packageName = 'cliq-owned-dependency';
const childParentObjective = 'Owned installed locked Node parent: inherit ready after repair.';
const childTaskObjective = 'Owned installed locked Node child: change only answer.txt to after.';
const objective = (scripts: boolean) => `Owned installed locked Node case: ${scripts ? 'exact_scripts' : 'ignore_scripts'}. End with the frozen candidate; do not edit any input.`;
type Data = Record<string, any>;
type Response = { protocolVersion: 1; ok: boolean; method?: string; result?: Data; error?: Data };

function tar(files: readonly { name: string; bytes: Buffer; mode?: number }[]): Buffer {
  const parts: Buffer[] = [];
  for (const file of files) {
    const header = Buffer.alloc(512), name = `package/${file.name}`;
    assert(Buffer.byteLength(name) < 100);
    header.write(name); header.write((file.mode ?? 0o644).toString(8).padStart(7, '0') + '\0', 100);
    for (const offset of [108, 116]) header.write('0000000\0', offset);
    header.write(file.bytes.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
    header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257); header.write('00', 263);
    header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
    parts.push(header, file.bytes, Buffer.alloc((512 - file.bytes.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...parts, Buffer.alloc(1024)]));
}
/** Owned public test package, not an official registry distribution. Its
 * real incompressible payload exercises the separate >1 MiB raw channel. */
export function installedDependencyPackage(): Buffer {
  const payload = Buffer.alloc(1_100_000);
  for (let offset = 0, index = 0; offset < payload.length; offset += 32, index++)
    createHash('sha256').update(`cliq-owned-dependency-payload:${index}`).digest().copy(payload, offset, 0, Math.min(32, payload.length - offset));
  const bytes = tar([
    { name: 'package.json', bytes: Buffer.from(JSON.stringify({ name: packageName, version: '1.0.0', main: 'index.cjs',
      bin: { 'cliq-owned-dependency': 'cli.cjs' }, scripts: { postinstall: 'node lifecycle.cjs' } })) },
    { name: 'index.cjs', bytes: Buffer.from("exports.compile=s=>new(require('node:vm').Script)(s).runInNewContext(Object.create(null));\n") },
    { name: 'cli.cjs', mode: 0o755, bytes: Buffer.from("#!/usr/bin/env node\nprocess.stdout.write('42\\n');\n") },
    { name: 'lifecycle.cjs', bytes: Buffer.from("require('node:fs').writeFileSync('dependency-script.marker','ran');\n") },
    { name: 'payload.bin', bytes: payload },
  ]);
  assert(bytes.length > 1_048_576 && bytes.length < 2 * 1_048_576); return bytes;
}

export function installedDependencyFiles(registryOrigin: string, archive: Buffer, scripts: boolean) {
  const manifest = { name: 'cliq-owned-node-application', version: '1.0.0', private: true,
    dependencies: { [packageName]: '1.0.0' }, scripts: { postinstall: 'node build.cjs', build: 'node build.cjs', test: 'node --test check.test.mjs' } };
  const lock = { name: manifest.name, version: manifest.version, lockfileVersion: 3, requires: true, packages: {
    '': { name: manifest.name, version: manifest.version, dependencies: manifest.dependencies, hasInstallScript: true },
    [`node_modules/${packageName}`]: { version: '1.0.0', resolved: registryOrigin + INSTALLED_DEPENDENCY_PACKAGE_PATH,
      integrity: 'sha512-' + createHash('sha512').update(archive).digest('base64'), hasInstallScript: true,
      bin: { 'cliq-owned-dependency': 'cli.cjs' } },
  } };
  const files = [
    { path: 'package.json', text: JSON.stringify(manifest) }, { path: 'package-lock.json', text: JSON.stringify(lock) },
    { path: 'program.js', text: '6 * 7\n' },
    { path: 'build.cjs', text: "const fs=require('node:fs'),a=require('node:assert/strict');const n=require('cliq-owned-dependency').compile(fs.readFileSync('program.js','utf8'));a.equal(n,42);fs.writeFileSync('node_modules/build-output.json',JSON.stringify({answer:n}));fs.writeFileSync('node_modules/root-script.marker','ran');\n" },
    { path: 'check.test.mjs', text: "import test from 'node:test';import assert from 'node:assert/strict';import {readFile,lstat,readlink} from 'node:fs/promises';import {createRequire} from 'node:module';const require=createRequire(import.meta.url);\n" +
      "test('real locked package and Node build',async()=>{assert.equal(require('cliq-owned-dependency').compile(await readFile('program.js','utf8')),42);" +
      (scripts ? "assert.deepEqual(JSON.parse(await readFile('node_modules/build-output.json','utf8')),{answer:42});assert.equal(await readFile('node_modules/root-script.marker','utf8'),'ran');assert.equal(await readFile('node_modules/cliq-owned-dependency/dependency-script.marker','utf8'),'ran');"
        : "for(const p of ['node_modules/root-script.marker','node_modules/build-output.json','node_modules/cliq-owned-dependency/dependency-script.marker'])await assert.rejects(lstat(p),{code:'ENOENT'});") +
      "assert((await lstat('node_modules/.bin/cliq-owned-dependency')).isSymbolicLink());assert.equal(await readlink('node_modules/.bin/cliq-owned-dependency'),'../cliq-owned-dependency/cli.cjs');});\n" },
  ];
  return Object.freeze(files.map(value => Object.freeze(value)));
}

export function createInstalledDependencyResponder(input: { model: string; readCas(ref: string): Promise<Buffer>; readCut(runId: string): Promise<Data> }) {
  let posts = 0, parentId: string | undefined, childId: string | undefined, parentPosts = 0, childPosts = 0;
  const call = (id: string, name: string, value: unknown) => ({ id, type: 'function', function: { name, arguments: JSON.stringify(value) } });
  return { get posts() { return posts; }, get parentPosts() { return parentPosts; }, get childPosts() { return childPosts; },
    bindParent(runId: string) { assert(!parentId); parentId = runId; },
    get childRunId() { return childId; },
    assertTools(body: Data, parentTools: readonly string[]) {
      const child = body.messages.some((message: Data) => message.role === 'user' && message.content === childTaskObjective);
      assert.deepEqual(body.tools.map((entry: Data) => entry.function.name), child ? ['edit'] : parentTools);
    },
    async respond(body: Data): Promise<Data | undefined> {
      const isChild = body.messages.some((message: Data) => message.role === 'user' && message.content === childTaskObjective);
      const isParent = body.messages.some((message: Data) => message.role === 'user' && message.content === childParentObjective);
      const matches = [false, true].filter(scripts => body.messages.some((message: Data) => message.role === 'user' && message.content === objective(scripts)));
      if (!matches.length && !isParent && !isChild) return undefined;
      assert.equal(body.model, input.model); assert.equal(body.stream, false); posts++;
      let calls: Data[] | undefined;
      if (isParent || isChild) {
        const by = Date.now() + 5000;
        while (!parentId) { assert(Date.now() < by); await delay(10); }
        const ordinal = isChild ? ++childPosts : ++parentPosts;
        assert(ordinal <= (isChild ? 2 : 4), 'a fixed original parent/child model claim cannot resend');
        if (!isChild && ordinal === 2) calls = [call('owned-node-delegate', 'delegate', {
          objective: childTaskObjective, mode: 'mutating', context: { source: 'parent_current', additionalArtifactRefs: [] },
          requestedBudgets: { wallTimeMs: 120000, modelTokens: 200000, costMicros: 1000000, toolCalls: 10, repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
          capabilities: { builtinToolNames: ['edit'], registeredMcpServerIds: [], allowShell: false, allowSourceWrite: true },
          verifierMode: 'inherit_parent', allowUnverifiedHelper: false })];
        else if (!isChild && ordinal === 3) {
          const cut = await input.readCut(parentId!);
          const items = await Promise.all(cut.items.map((row: Data) => object(input.readCas, row.payloadRef)));
          const handles = items.filter(item => item.kind === 'child_handle'); assert.equal(handles.length, 1);
          childId = handles[0]!.childRunId; assert.notEqual(childId, parentId);
          calls = [call('owned-node-await', 'await_children', { childRunIds: [childId] })];
        } else if (isChild && ordinal === 1) calls = [call('owned-node-child-edit', 'edit', { path: 'answer.txt', old_text: 'before\n', new_text: 'after\n' })];
        else if (!isChild && ordinal === 4) assert(body.messages.some((message: Data) => message.role === 'tool' && message.tool_call_id === 'owned-node-await'));
      } else assert.equal(matches.length, 1);
      assert(posts <= 8);
      return { id: `owned-locked-node-${posts}`, object: 'chat.completion', model: input.model,
        choices: [{ index: 0, finish_reason: calls ? 'tool_calls' : 'stop', message: calls ? { role: 'assistant', content: '', tool_calls: calls }
          : { role: 'assistant', content: isChild ? 'Owned inherited dependency child complete.' : 'The owned locked Node candidate is ready for its required verifier.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
    } };
}

async function object(read: (ref: string) => Promise<Buffer>, ref: string): Promise<Data> {
  const bytes = await read(ref); assert.equal(sha256Bytes(bytes), ref);
  const value = parseJsonStrict(new TextDecoder('utf8', { fatal: true, ignoreBOM: true }).decode(bytes));
  assert(canonicalJsonBytes(value).equals(bytes)); return value as Data;
}

/** Inspect actual registered public history and original physical proof refs.
 * This cannot mint a result, birth, death, grant or native permission. */
export async function assertInstalledDependencyResult(input: { cut: Data; readCas(ref: string): Promise<Buffer>;
  readPackage(ref: string, byteCount: number): Promise<Buffer>; archive: Buffer; scripts: boolean; expectedAcquisitions?: 1 | 2; assertParentRetired(runId: string, launchId: string): Promise<void> }) {
  const { cut, readCas } = input, run = cut.snapshot.run;
  assert.equal(run.status, 'succeeded'); assert.equal(run.terminalReason, 'verified'); assert(run.resultRef && !run.activeWorkerLaunchId);
  const spec = decodeRunSpec(await object(readCas, run.specRef)); assert(spec.dependencyPolicyRef);
  const items = await Promise.all(cut.items.map((row: Data) => object(readCas, row.payloadRef)));
  const ready = items.filter(item => item.kind === 'dependency_ready').map(decodeDependencyReadyItem);
  assert.equal(ready.length, input.expectedAcquisitions ?? 1);
  for (const item of ready) {
  assert.equal(item.origin, 'acquired'); if (item.origin !== 'acquired') assert.fail();
  const rows = cut.journal.filter((row: Data) => row.opId === item.opId); assert.deepEqual(rows.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
  const [prepared, claim, terminal] = rows;
  assert.equal(prepared.target, 'builtin:dependency-acquire'); assert.equal(prepared.attempt, 0); assert.equal(terminal.attempt, 0);
  const request = decodeDependencyRequest(await object(readCas, prepared.requestRef)), target = decodeDependencyTarget(await object(readCas, request.targetRef));
  const plan = decodeDependencyAcquisitionPlan(await object(readCas, item.planRef));
  assert.equal(plan.allowInstallScripts, input.scripts); assert.equal(plan.packageCount, 1); assert.equal(target.allowInstallScripts, input.scripts);
  assert.equal(!!target.scriptAuthorizationTemplateRef, input.scripts);
  const evidence = decodeDependencyClaimEvidence(await object(readCas, claim.evidenceRef));
  const capture = decodeDependencyProcessCapture(await object(readCas, terminal.resultRef));
  assert.equal(capture.terminationReason, 'exit'); if (capture.terminationReason !== 'exit') assert.fail(); assert.equal(capture.exitCode, 0);
  const proof = decodeDependencyRetirement(await object(readCas, terminal.receiptRef));
  assert.equal(proof.captureRef, terminal.resultRef); assert.equal(proof.captureDigest, capture.captureDigest);
  assert.equal(proof.dependencyPlanRef, item.planRef); assert.equal(proof.installedTreeDigest, item.installedTreeDigest);
  assert.equal(proof.checkpointId, dependencyReadyCheckpointId(run.id, item.opId, 0));
  const cp = cut.checkpoints.find((row: Data) => row.id === proof.checkpointId); assert(cp);
  assert.equal(cp.workspaceStateRef, proof.workspaceStateRef); assert.equal(cp.journalSeq, terminal.seq);
  const workspace = decodeWorkspaceState(await object(readCas, cp.workspaceStateRef));
  const entries = decodeWorkspaceEntries(await object(readCas, workspace.entriesRef));
  assert.equal(dependencyInstalledTreeDigest(entries), item.installedTreeDigest);
  const bin = entries.entries.find(entry => entry.path === 'node_modules/.bin/cliq-owned-dependency');
  assert(bin?.kind === 'symlink' && bin.target === '../cliq-owned-dependency/cli.cjs');
  assert.equal(entries.entries.some(entry => entry.path === 'node_modules/root-script.marker'), input.scripts);
  assert.equal(entries.entries.some(entry => entry.path === 'node_modules/cliq-owned-dependency/dependency-script.marker'), input.scripts);
  const cache = decodePackageCacheManifest(await object(readCas, item.packageCacheManifestRef)); assert.equal(cache.entries.length, 1);
  const cached = cache.entries[0]!; assert.equal(cached.blobRef, sha256Bytes(input.archive)); assert.equal(cached.blobBytes, input.archive.length);
  assert((await input.readPackage(cached.blobRef, cached.blobBytes)).equals(input.archive));
  assert.deepEqual(cached.fetchAttempts.map(attempt => attempt.attempt), [1]); assert.equal(cached.fetchAttempts[0]!.outcome, 'completed');
  assert.equal(cache.totalTransferredBytes, input.archive.length);
  const settlement = decodeBudgetSettlement(await object(readCas, terminal.budgetSettlementRef));
  assert.deepEqual(settlement.consumed, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
  assert.equal(settlement.terminalJournalSeq, terminal.seq);
  await input.assertParentRetired(run.id, evidence.workerLaunchId);
  }
  const item = ready.at(-1)!;
  const lastTerminal = cut.journal.filter((row: Data) => row.opId === (item.origin === 'acquired' ? item.opId : '')).at(-1); assert(lastTerminal);
  const result = decodeRunResult(await object(readCas, run.resultRef)); assert.equal(result.dependencyPlanRef, item.planRef);
  const closure = decodeVerificationClosure(await object(readCas, result.verificationClosureRef));
  assert.equal(closure.dependency.kind, 'ready'); assert(closure.verification.kind === 'local' && closure.verification.outcome === 'verified');
  if (closure.dependency.kind !== 'ready') assert.fail();
  assert.equal(closure.dependency.dependencyReadyItemId, item.itemId); assert.equal(closure.dependency.dependencyPlanRef, item.planRef);
  assert(cut.journal.some((row: Data) => row.opKind === 'verifier' && row.seq > lastTerminal.seq));
  return { kind: input.expectedAcquisitions === 2 ? 'parent_ready_child' : input.scripts ? 'exact_scripts' : 'ignore_scripts', runId: run.id, resultRef: run.resultRef, dependencyPlanRef: item.planRef,
    oneWholeJournalClaimPerCandidate: true, acquisitionCount: ready.length, downloadedPackageBytes: input.archive.length * ready.length, packageGetAttempts: ready.length,
    realNpmCiExitZero: true, requiredNodeBuildAndTestPassed: true, originalParentRetired: true,
    relativeBinSymlinkRetained: true, generalDirectBinExecQualified: false, nativeAddonQualified: false };
}

async function assertInstalledInheritedDependencyChild(input: { parent: Data; child: Data; readCas(ref: string): Promise<Buffer>;
  assertParentRetired(runId: string, launchId: string): Promise<void> }) {
  const root = input.parent.snapshot.run, run = input.child.snapshot.run;
  assert.equal(run.parentRunId, root.id); assert.equal(run.status, 'succeeded'); assert.equal(root.repairCount, 1);
  assert.equal(input.child.journal.filter((row: Data) => row.target === 'builtin:dependency-acquire').length, 0);
  const parentItems = await Promise.all(input.parent.items.map((row: Data) => object(input.readCas, row.payloadRef)));
  const childItems = await Promise.all(input.child.items.map((row: Data) => object(input.readCas, row.payloadRef)));
  const readyItems = childItems.filter(item => item.kind === 'dependency_ready'); assert.equal(readyItems.length, 1);
  const ready = decodeDependencyReadyItem(readyItems[0]); assert.equal(ready.origin, 'inherited_parent_ready');
  if (ready.origin !== 'inherited_parent_ready') assert.fail();
  assert.equal(ready.parentRunId, root.id);
  const originalParentReady = parentItems.filter(item => item.kind === 'dependency_ready')[0]; assert(originalParentReady);
  assert.equal(ready.parentReadyItemRef, canonicalSha256(originalParentReady));
  assert.equal(ready.installedTreeDigest, originalParentReady.installedTreeDigest);
  const localAdmission = input.parent.journal.filter((row: Data) => row.opKind === 'child_admission');
  assert.deepEqual(localAdmission.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
  assert.equal(ready.childAdmissionRequestRef, localAdmission[0]!.requestRef);
  const childResults = parentItems.filter(item => item.kind === 'child_result'); assert.equal(childResults.length, 1);
  assert.equal(childResults[0]!.childRunId, run.id); assert.equal(childResults[0]!.resultRef, run.resultRef);
  assert.deepEqual(childResults[0]!.inclusiveBudgetUsage, run.budgetConsumed);
  const cp = input.child.checkpoints.find((row: Data) => row.id === ready.readyCheckpointId); assert(cp);
  const m = decodeWorkspaceState(await object(input.readCas, cp.workspaceStateRef));
  assert.equal(dependencyInstalledTreeDigest(decodeWorkspaceEntries(await object(input.readCas, m.entriesRef))), ready.installedTreeDigest);
  const childResult = decodeRunResult(await object(input.readCas, run.resultRef));
  const closure = decodeVerificationClosure(await object(input.readCas, childResult.verificationClosureRef));
  assert(closure.dependency.kind === 'ready' && closure.dependency.origin === 'inherited_parent_ready');
  if (closure.dependency.kind !== 'ready' || closure.dependency.origin !== 'inherited_parent_ready') assert.fail();
  assert.equal(closure.dependency.parentReadyItemRef, ready.parentReadyItemRef);
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: root.repairCount }, seen = new Set<string>();
  for (const row of input.parent.journal) if (row.budgetSettlementRef && !seen.has(row.budgetSettlementRef)) {
    seen.add(row.budgetSettlementRef); const settlement = decodeBudgetSettlement(await object(input.readCas, row.budgetSettlementRef));
    assert.equal(settlement.runId, root.id); assert.equal(settlement.terminalJournalSeq, row.seq);
    for (const key of Object.keys(budget) as Array<keyof typeof budget>) budget[key] += settlement.consumed[key];
  }
  for (const key of Object.keys(budget) as Array<keyof typeof budget>) budget[key] += run.budgetConsumed[key];
  assert.deepEqual(root.budgetConsumed, budget);
  assert.equal(root.budgetReserved.toolCalls, 0); assert.equal(run.budgetReserved.toolCalls, 0);
  await input.assertParentRetired(run.id, ready.childPreparation.workerLaunchId);
}

export async function runInstalledDependencyCases(input: {
  root: string; cliqHome: string; uid: number; gid: number; model: string; modelEndpointId: string; modelCredentialId: string;
  registryEndpointId: string; registryOrigin: string; archive: Buffer; guestManifestId: string;
  request(core: Data): Data; send(core: Data, timeout?: number): Promise<Response>; nextId(): string;
  responder: ReturnType<typeof createInstalledDependencyResponder>;
  readCas(ref: string): Promise<Buffer>; readPackage(ref: string, byteCount: number): Promise<Buffer>; download(cut: Data): Promise<void>;
  assertParentRetired(runId: string, launchId: string): Promise<void>;
}) {
  const accept = (response: Response, method: string) => { assert.equal(response.ok, true, 'fixed installed dependency public request refused');
    assert(response.result && response.result.method === method); return response.result; };
  const output = [];
  let deliverySource: Data | undefined;
  for (const selection of [{ scripts: false, child: false }, { scripts: true, child: false }, { scripts: false, child: true }]) {
    const { scripts, child } = selection;
    const workspace = path.join(input.root, child ? 'node_parent_ready_child' : scripts ? 'node_exact_scripts' : 'node_ignore_scripts');
    await mkdir(workspace, { mode: 0o700 }); await chown(workspace, input.uid, input.gid);
    const files = [...installedDependencyFiles(input.registryOrigin, input.archive, scripts)], identities = [];
    const boundaryCheck = files.find(file => file.path === 'check.test.mjs')!;
    files[files.indexOf(boundaryCheck)] = { ...boundaryCheck, text: boundaryCheck.text +
      "\nimport {spawnSync} from 'node:child_process';test('actual private bin direct execution remains denied',()=>{const r=spawnSync('./node_modules/.bin/cliq-owned-dependency',[],{encoding:'utf8',timeout:1000,maxBuffer:65536});assert(r.error&&['EACCES','EPERM'].includes(r.error.code));assert.equal(r.status,null);assert.equal(r.stdout,null);assert.equal(r.stderr,null);});\n" };
    if (child) {
      const check = files.find(file => file.path === 'check.test.mjs')!;
      files[files.indexOf(check)] = { ...check, text: check.text + "\ntest('original parent fails then actual child patch passes',async()=>assert.equal(await readFile('answer.txt','utf8'),'after\\n'));\n" };
      files.push({ path: 'answer.txt', text: 'before\n' });
    }
    for (const file of files) {
      const name = path.join(workspace, file.path); await writeFile(name, file.text, { flag: 'wx', mode: 0o644 }); await chown(name, input.uid, input.gid);
      identities.push(await lstat(name, { bigint: true }));
    }
    const workspaceId = sha256Bytes(Buffer.from(workspace)), trustDirectory = path.join(input.cliqHome, 'workspaces', workspaceId);
    await mkdir(trustDirectory, { recursive: true, mode: 0o700 }); await chown(trustDirectory, input.uid, input.gid);
    const trustFile = path.join(trustDirectory, 'trust.json');
    await writeFile(trustFile, canonicalJsonBytes({ version: 1, workspaceId, workspaceRealPath: workspace,
      decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trustFile, input.uid, input.gid);
    const session = accept(await input.send(input.request({ protocolVersion: 1, method: 'session.create', requestId: input.nextId(),
      admissionKey: randomBytes(32).toString('base64url'), workspacePath: workspace, name: 'Owned locked Node' })), 'session.create').snapshot.session;
    const identity = accept(await input.send(input.request({ protocolVersion: 1, method: 'authorization.create', requestId: input.nextId(),
      decision: { kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: input.guestManifestId, toolId: 'node' } } })), 'authorization.create').grant;
    let submit = input.request({ protocolVersion: 1, method: 'run.submit', requestId: input.nextId(), admissionKey: randomBytes(32).toString('base64url'),
      sessionId: session.id, expectedContextRevision: session.contextRevision, workspacePath: workspace, objective: child ? childParentObjective : objective(scripts),
      model: { provider: 'openai-compatible', model: input.model, endpoint: { kind: 'registered', endpointRegistrationId: input.modelEndpointId }, modelCredentialGrantIds: [input.modelCredentialId] },
      policyMode: 'yolo', budgets: { wallTimeMs: 300000, modelTokens: child ? 500000 : 200000, costMicros: 2000000, toolCalls: child ? 50 : 10, repairAttempts: child ? 1 : 0, childDepth: child ? 1 : 0, childConcurrency: 1 },
      verifiers: [{ id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
        argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })), cwd: '.', env: {},
        writableEphemeralPaths: [], identityReadGrantId: identity.grantId, timeoutMs: 10000, retries: 0, outputLimitBytes: 65536 }],
      dependency: { mode: 'locked', registryEndpointIds: [input.registryEndpointId], credentialGrantIds: [], allowInstallScripts: scripts },
      sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: false });
    if (scripts) {
      // Actual public capture of adversarial project configuration must refuse
      // before AUTH, Run creation, package GET or any npm/script execution.
      const configuration = path.join(workspace, '.npmrc');
      await writeFile(configuration, 'registry=https://unapproved.invalid/\nproxy=http://unapproved.invalid/\n' +
        'cache=/work/unapproved-cache\nnode-options=--require=/work/unapproved-module.cjs\nscript-shell=/work/unapproved-shell\n',
      { flag: 'wx', mode: 0o644 }); await chown(configuration, input.uid, input.gid);
      const { requestDigest: _digest, ...body } = submit;
      const refusedRequest = input.request({ ...body, requestId: input.nextId(), admissionKey: randomBytes(32).toString('base64url') });
      let refused: Response;
      try {
        refused = await input.send(refusedRequest, 30000);
        assert.equal(refused.ok, false); assert.equal(refused.error?.code, 'INVALID_REQUEST');
        assert.equal(refused.error?.messageCode, 'source_capture_rejected');
        const current = accept(await input.send({ protocolVersion: 1, method: 'session.get', sessionId: session.id }), 'session.get').snapshot.session;
        assert.equal(current.latestItemSeq, 0); assert.equal(current.contextRevision, session.contextRevision);
        for (const name of ['unapproved-cache', 'node_modules/root-script.marker', 'node_modules/cliq-owned-dependency/dependency-script.marker'])
          await assert.rejects(lstat(path.join(workspace, name)), { code: 'ENOENT' });
      } finally { await unlink(configuration); }
      assert.deepEqual(await input.send(refusedRequest, 30000), refused!, 'project-config refusal keeps its original first response after source changes');
    }
    let response = await input.send(submit, 30000);
    if (scripts) {
      assert.equal(response.ok, false); assert.equal(response.error?.code, 'AUTHORIZATION_REQUIRED');
      assert.equal(response.error?.messageCode, 'dependency_script_authorization_required');
      const refused = response, refusedSubmit = submit;
      assert.deepEqual(await input.send(submit, 30000), refused, 'original admission key must replay its original captured refusal');
      const unchanged = accept(await input.send({ protocolVersion: 1, method: 'session.get', sessionId: session.id }), 'session.get').snapshot.session;
      assert.equal(unchanged.latestItemSeq, 0); assert.equal(unchanged.contextRevision, session.contextRevision);
      const grant = accept(await input.send(input.request({ protocolVersion: 1, method: 'authorization.create', requestId: input.nextId(),
        decision: response.error!.requiredAuthorization })), 'authorization.create').grant;
      const { requestDigest: _oldDigest, ...original } = submit;
      submit = input.request({ ...original, requestId: input.nextId(), admissionKey: randomBytes(32).toString('base64url'),
        dependency: { ...submit.dependency, installScriptsGrantId: grant.grantId } });
      response = await input.send(submit, 30000);
      assert.deepEqual(await input.send(refusedSubmit, 30000), refused);
    }
    const admitted = accept(response, 'run.submit').snapshot.run, by = Date.now() + 90000;
    if (child) input.responder.bindParent(admitted.id);
    let cut: Data;
    for (;;) {
      cut = accept(await input.send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }), 'run.get');
      if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(cut.snapshot.run.status)) break;
      assert(Date.now() < by, 'locked dependency case exceeded the original 90-second case deadline'); await delay(25);
    }
    const proof = await assertInstalledDependencyResult({ cut, readCas: input.readCas, readPackage: input.readPackage,
      archive: input.archive, scripts, ...(child ? { expectedAcquisitions: 2 as const } : {}), assertParentRetired: input.assertParentRetired });
    await input.download(cut); assert.deepEqual(await input.send(submit, 30000), response);
    if (!scripts && !child) deliverySource = cut;
    if (child) {
      const id = input.responder.childRunId; assert(id);
      const childCut = accept(await input.send({ protocolVersion: 1, method: 'run.get', runId: id }), 'run.get');
      await assertInstalledInheritedDependencyChild({ parent: cut, child: childCut, readCas: input.readCas, assertParentRetired: input.assertParentRetired });
      await input.download(childCut);
      assert.equal(input.responder.parentPosts, 4); assert.equal(input.responder.childPosts, 2);
    }
    for (const [index, file] of files.entries()) {
      const name = path.join(workspace, file.path), current = await lstat(name, { bigint: true });
      for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const) assert.equal(current[key], identities[index]![key]);
      assert.equal(await readFile(name, 'utf8'), file.text);
    }
    output.push({ ...proof, ...(scripts ? { untrustedProjectConfigRefusedBeforeRun: true } : {}) });
  }
  // An identical-source Delivery inherits verification facts. It does not
  // pretend its captured M already contains the source Run's node_modules.
  assert(deliverySource);
  const sourceRun = deliverySource.snapshot.run;
  const apply = input.request({ protocolVersion: 1, method: 'run.apply', requestId: input.nextId(),
    admissionKey: randomBytes(32).toString('base64url'), sourceRunId: sourceRun.id,
    expectedRunResultRef: sourceRun.resultRef, budgets: { wallTimeMs: 300000, toolCalls: 10 } });
  const applied = await input.send(apply, 30000), delivery = accept(applied, 'run.apply').snapshot.run;
  const deliveryBy = Date.now() + 90000; let deliveryCut: Data;
  for (;;) {
    deliveryCut = accept(await input.send({ protocolVersion: 1, method: 'run.get', runId: delivery.id }), 'run.get');
    const run = deliveryCut.snapshot.run;
    if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) break;
    assert(Date.now() < deliveryBy, 'dependency Delivery exceeded the original 90-second case deadline');
    if (run.status === 'waiting' && run.waitingReason === 'approval') {
      const wait = await object(input.readCas, run.waitingOnRef);
      assert.equal(wait.subject.kind, 'delivery_publish');
      const approve = input.request({ protocolVersion: 1, method: 'run.approve', requestId: input.nextId(), runId: run.id,
        expectedRevision: run.revision, waitingOnRef: run.waitingOnRef, decision: 'allow' });
      const response = await input.send(approve); accept(response, 'run.approve'); assert.deepEqual(await input.send(approve), response);
    }
    await delay(25);
  }
  assert.equal(deliveryCut.snapshot.run.status, 'succeeded');
  const deliveryResult = decodeRunResult(await object(input.readCas, deliveryCut.snapshot.run.resultRef));
  const deliveryClosure = decodeVerificationClosure(await object(input.readCas, deliveryResult.verificationClosureRef));
  assert.equal(deliveryClosure.dependency.kind, 'inherited_verification'); assert.equal(deliveryClosure.verification.kind, 'inherited_verified');
  if (deliveryClosure.dependency.kind !== 'inherited_verification' || deliveryClosure.verification.kind !== 'inherited_verified') assert.fail();
  assert.equal(deliveryClosure.dependency.sourceRunId, sourceRun.id); assert.equal(deliveryClosure.dependency.sourceRunResultRef, sourceRun.resultRef);
  assert.equal(deliveryClosure.dependency.inheritedProvenanceRef, deliveryClosure.verification.inheritedProvenanceRef);
  assert.equal(deliveryResult.dependencyPlanRef, output[0]!.dependencyPlanRef);
  assert.equal(deliveryCut.journal.filter((row: Data) => row.target === 'builtin:dependency-acquire' || row.opKind === 'verifier' || row.opKind === 'model').length, 0);
  for (const row of deliveryCut.items) assert.notEqual((await object(input.readCas, row.payloadRef)).kind, 'dependency_ready');
  const finalCp = deliveryCut.checkpoints.find((row: Data) => row.id === deliveryCut.snapshot.run.latestCheckpointId); assert(finalCp);
  const deliveryM = decodeWorkspaceState(await object(input.readCas, finalCp.workspaceStateRef));
  assert((decodeWorkspaceEntries(await object(input.readCas, deliveryM.entriesRef))).entries.every(entry => entry.path !== 'node_modules' && !entry.path.startsWith('node_modules/')));
  await input.download(deliveryCut); assert.deepEqual(await input.send(apply, 30000), applied);
  const childId = input.responder.childRunId; assert(childId);
  const child = accept(await input.send({ protocolVersion: 1, method: 'run.get', runId: childId }), 'run.get');
  return { diagnosticOnly: true, profile: INSTALLED_DEPENDENCY_PROFILE, cases: output,
    child: { runId: childId, resultRef: child.snapshot.run.resultRef },
    delivery: { runId: delivery.id, resultRef: deliveryCut.snapshot.run.resultRef, sourceRunId: sourceRun.id, sourceRunResultRef: sourceRun.resultRef },
    actualPublicRegistryOnly: true, actualScriptConsentReplayPreserved: true, sourceHostUnchanged: true,
    childReadyReuseQualified: true, physicalParallelismQualified: false, deliveryInheritanceQualified: true, deliveryCreatedLocalReady: false, allUnknownCutsQualified: false,
    allDependencyEcosystemsQualified: false };
}
