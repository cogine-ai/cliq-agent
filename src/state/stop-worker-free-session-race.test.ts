// Real StateStore/SQLite/CAS atomicity with the existing offline signed owner
// fixture. No MCP/native dispatch, process-death proof or installed qualification.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { sha256Bytes } from '../kernel/identity.js';
import { decodeSessionContextHead } from '../kernel/session-context-page-reader.js';
import type { SessionRunTerminalItem } from '../kernel/types.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { fixtureSessionContextSegments } from './testing/session-context.js';
import { openStateStore, publishInProcessChannel } from './store.js';

test('a worker-free terminal Session CAS retry never treats its second loop ordinal as an MCP finalization', async t => {
  const clock = Date.now(); t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('stop-worker-free-session-race', undefined, { mode: 'plan' });
  let release: (() => void) | undefined, first: Promise<{ run: ReturnType<typeof fixture.store.getRun> }> | undefined;
  try {
    const base = await fixture.store.readRecoveryClosure(fixture.runId), spec = base.runSpec;
    const source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.sourceProjectionRef);
    const admit = async (name: string) => fixture.store.admitRun({ requestId: uuidv7(), admissionKey: admissionKey(name),
      sessionId: base.run.sessionId, expectedContextRevision: 1, workspacePath: fixture.workspace, objective: name, allowUnverified: true,
      assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef,
      sourceProjectionRef: spec.sourceProjectionRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
      frozenIgnoreRulesRef: source.frozenIgnoreRulesRef, credentialGrantRefs: spec.credentialGrantRefs, budgets: spec.budgets,
      ...await publishInProcessChannel(fixture.store) });
    const one = await admit('worker-free-delayed-terminal'), two = await admit('worker-free-winning-terminal');
    const load = (runId: string) => fixture.store.loadAgentRun({ runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    const [agent, peer] = await Promise.all([load(one.run.id), load(two.run.id)]);
    const stop = await agent.cancelRun({ requestId: uuidv7(), expectedRunRevision: one.run.revision, ...await publishInProcessChannel(fixture.store) });
    const peerStop = await peer.cancelRun({ requestId: uuidv7(), expectedRunRevision: two.run.revision, ...await publishInProcessChannel(fixture.store) });
    const before = await fixture.store.readRecoveryClosure(one.run.id);
    assert.equal(before.run.activeWorkerLaunchId, undefined); assert.equal(before.workerLaunches.length, 0); assert.equal(before.journal.length, 0);
    const sample = await fs.open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, spec.assemblyRef), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] }, originalWrite = prototype.writeFile; await sample.close();
    let reached!: () => void; const blocked = new Promise<void>(resolve => { reached = resolve; });
    const resume = new Promise<void>(resolve => { release = resolve; });
    let terminalRef: string | undefined, delayedHeads = 0;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(originalWrite, this, args);
      if (!Buffer.isBuffer(args[0])) return;
      const bytes = args[0], text = bytes.toString('utf8');
      if (text.includes('"format":"cliq-session-run-terminal-v1"')) {
        const item = JSON.parse(text) as SessionRunTerminalItem; if (item.runId === one.run.id) terminalRef = sha256Bytes(bytes);
      } else if (text.includes('"format":"cliq-session-context-v2"')) {
        const head = decodeSessionContextHead(JSON.parse(text));
        if (head.sessionId !== base.run.sessionId) return;
        const segments = await fixtureSessionContextSegments(fixture.store.artifacts, head);
        if (segments.some(segment => segment.kind === 'raw' && segment.items.some(item => item.payloadRef === terminalRef))) {
          delayedHeads++; if (delayedHeads === 1) { reached(); await resume; }
        }
      }
    });
    first = agent.commitTerminalStop({ expectedRunRevision: stop.run.revision });
    await Promise.race([blocked, first.then(() => assert.fail('first worker-free terminal bypassed its real Session head write'), error => { throw error; })]);
    const winner = await peer.commitTerminalStop({ expectedRunRevision: peerStop.run.revision });
    assert.equal(winner.run.status, 'cancelled'); assert.equal(fixture.store.getSession(base.run.sessionId).latestItemSeq, 1);
    release!(); release = undefined;
    const result = await first; writer.mock.restore();
    assert.equal(result.run.status, 'cancelled'); assert.equal(result.run.stopIntentRef, stop.run.stopIntentRef);
    assert.equal(delayedHeads, 2, 'the original worker-free reducer regenerates its graph exactly once after the genuine competing Session CAS');
    const oneCut = await fixture.store.readRecoveryClosure(one.run.id), twoCut = await fixture.store.readRecoveryClosure(two.run.id);
    assert.deepEqual(oneCut.journal, before.journal); assert.deepEqual(oneCut.run.budgetConsumed, before.run.budgetConsumed);
    assert.deepEqual(oneCut.run.budgetReserved, before.run.budgetReserved); assert.equal(oneCut.workerLaunches.length, 0);
    const session = fixture.store.getSession(base.run.sessionId); assert.equal(session.latestItemSeq, 2); assert.equal(session.contextRevision, 3);
    const segments = await fixtureSessionContextSegments(fixture.store.artifacts, session.contextProjectionRef);
    const references = segments.flatMap(segment => segment.kind === 'raw' ? segment.items : []);
    const items = await Promise.all(references.map(item => fixture.store.artifacts.readCanonical<SessionRunTerminalItem>(item.payloadRef)));
    assert.deepEqual(items.map(item => item.runId), [two.run.id, one.run.id]);
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    assert.deepEqual(await fixture.store.readRecoveryClosure(one.run.id), oneCut);
    assert.deepEqual(await fixture.store.readRecoveryClosure(two.run.id), twoCut);
    assert.deepEqual(fixture.store.getSession(base.run.sessionId), session);
  } finally { release?.(); await first?.catch(() => {}); t.mock.restoreAll(); await disposeFixture(fixture); }
});
