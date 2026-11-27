import assert from 'node:assert/strict';
import test from 'node:test';
import { effectiveSourceExcludes } from './dependency-source.js';
import type { DependencyRequest, SourceSelectorRequest } from './control-submit.js';
const locked: DependencyRequest = { mode: 'locked', registryEndpointIds: ['registry'], credentialGrantIds: [], allowInstallScripts: false };
const input = (sourceExcludes: Array<Omit<SourceSelectorRequest, 'readGrantId'>> = [], sourceIncludes: SourceSelectorRequest[] = [], dependency: DependencyRequest = locked) => ({ dependency, sourceIncludes, sourceExcludes });
test('fixed managed Node output exclusion derives from original intent and preserves the original selector bound', () => {
  const request = input([{ path: 'build', scope: 'subtree' }]), before = structuredClone(request);
  assert.deepEqual(effectiveSourceExcludes(request), [{ path: 'build', scope: 'subtree' }, { path: 'node_modules', scope: 'subtree' }]);
  assert.deepEqual(request, before); assert.deepEqual(effectiveSourceExcludes(input([], [], { mode: 'none' })), []);
  const full = Array.from({ length: 128 }, (_, i) => ({ path: `cache${i}`, scope: 'subtree' as const }));
  assert.throws(() => effectiveSourceExcludes(input(full)));
  full[127] = { path: 'node_modules', scope: 'subtree' }; assert.equal(effectiveSourceExcludes(input(full)).length, 128);
  for (const scope of ['entry', 'subtree'] as const) for (const path of ['node_modules', 'node_modules/pkg'])
    assert.throws(() => effectiveSourceExcludes(input([], [{ path, scope, readGrantId: 'separate read consent' }])));
  assert.throws(() => effectiveSourceExcludes(input([{ path: 'x', scope: 'entry' }, { path: 'x', scope: 'entry' }])));
  assert.deepEqual(effectiveSourceExcludes(input([], [{ path: 'other/node_modules', scope: 'subtree' }])), [{ path: 'node_modules', scope: 'subtree' }]);
});
test('managed selector derivation rejects caller accessors and proxies before invoking them', () => {
  let invoked = 0; const request = input();
  assert.throws(() => effectiveSourceExcludes(new Proxy(request, { get() { invoked++; return undefined; } })));
  assert.throws(() => effectiveSourceExcludes({ ...request, sourceIncludes: [Object.defineProperty({ scope: 'subtree' }, 'path', { enumerable: true, get() { invoked++; return 'x'; } }) as SourceSelectorRequest] }));
  assert.equal(invoked, 0);
});
