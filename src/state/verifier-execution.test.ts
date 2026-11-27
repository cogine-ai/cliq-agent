// Pure routing refusal only. This never constructs a verified-source graph,
// grants execution or substitutes for the installed inherited-delivery proof.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Script } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { assertLocalDeliveryVerifierSelection } from './verifier-execution.js';

test('the shared verifier gate refuses inherited delivery and every non-local mode', () => {
  assert.doesNotThrow(() => assertLocalDeliveryVerifierSelection({ kind: 'local' }));
  for (const mode of [{ kind: 'inherited' }, { kind: 'unknown' }, {}, undefined, null])
    assert.throws(() => assertLocalDeliveryVerifierSelection(mode as never), { code: 'STATE_TRANSITION_INVALID' });
});

// Original release-reader code and real CAS only. Cancellation happens before
// a grant, transaction or native invocation can be reached.
test('verifier release cancels and joins its read lifetime independently of the received-result lifetime', async t => {
  const source = await readFile(new URL('./verifier-execution.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('verifier-execution.ts', source, ts.ScriptTarget.Latest, true);
  let release: ts.ArrowFunction | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isPropertyAssignment(node) && node.name.getText(parsed) === 'release' && ts.isCallExpression(node.initializer)) {
      const operation = node.initializer.arguments[1];
      if (operation && ts.isArrowFunction(operation)) release = operation;
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert(release);
  const directory = await mkdtemp(path.join(tmpdir(), 'cliq-verifier-release-read-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const catalog = new ArtifactCatalog(new ContentAddressedStore(directory));
  const bytes = Buffer.alloc(128 * 1024, 7), file = await catalog.publishBytes(bytes, 'application/octet-stream', 'test-data');
  for (const abortParent of [false, true]) {
    const parent = new AbortController(), closing = new AbortController(), reason = new KernelStorageError('LEASE_FENCED', 'original read cancelled');
    let joined = false, readBytes = 0, grantCalls = 0;
    const context = { AbortSignal, KernelStorageError, stateOperation, consumed: false, signal: parent.signal,
      reads: catalog.withReadSignal(parent.signal), input: { expectedRunRevision: 1 },
      cut: async (_revision: number, _signal: AbortSignal, reads: ArtifactCatalog) => {
        try {
          for await (const chunk of reads.readChunks(file.ref, bytes.length)) {
            readBytes += chunk.length;
            (abortParent ? parent : closing).abort(reason);
            reads.assertReadActive();
          }
        } finally { joined = true; }
        assert.fail('cancelled release reader cannot yield a verifier cut');
      },
      grantFor: () => { grantCalls++; assert.fail('cancelled release cannot reach the grant gate'); },
      invoke: undefined as undefined | ((target: unknown, signal: AbortSignal) => Promise<void>) };
    new Script(ts.transpileModule(`globalThis.invoke = stateOperation('RECOVERY_REQUIRED', ${release.getText(parsed)});`,
      { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText).runInNewContext(context);
    await assert.rejects(context.invoke!(undefined, closing.signal), error => error === reason);
    assert(readBytes > 0); assert(joined); assert.equal(grantCalls, 0);
    assert.equal(parent.signal.aborted, abortParent);
    await assert.rejects(context.invoke!(undefined, closing.signal), { code: 'LEASE_FENCED' });
  }
});
