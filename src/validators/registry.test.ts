import test from 'node:test';
import assert from 'node:assert/strict';

import { buildValidatorRegistry } from './registry.js';

test('buildValidatorRegistry includes all built-ins by default', () => {
  const reg = buildValidatorRegistry();
  assert.deepEqual(
    reg.map((v) => v.name),
    ['builtin:diff-sanity', 'builtin:index-clean', 'builtin:size-limit']
  );
});

test('buildValidatorRegistry filters disabled list', () => {
  const reg = buildValidatorRegistry({ disabled: ['builtin:size-limit'] });
  assert.deepEqual(
    reg.map((v) => v.name),
    ['builtin:diff-sanity', 'builtin:index-clean']
  );
});

test('buildValidatorRegistry appends shell validators after built-ins', () => {
  const reg = buildValidatorRegistry({
    shell: [{ name: 'tsc', command: 'echo ok', severity: 'blocking' }]
  });
  assert.deepEqual(
    reg.map((v) => v.name),
    ['builtin:diff-sanity', 'builtin:index-clean', 'builtin:size-limit', 'tsc']
  );
  // Shell hook severity must propagate to defaultSeverity
  assert.equal(reg[3].defaultSeverity, 'blocking');
});

test('buildValidatorRegistry filters disabled shell validators by name', () => {
  const reg = buildValidatorRegistry({
    disabled: ['tsc'],
    shell: [
      { name: 'tsc', command: 'echo ok', severity: 'blocking' },
      { name: 'eslint', command: 'echo ok', severity: 'advisory' }
    ]
  });
  assert.deepEqual(
    reg.map((v) => v.name),
    ['builtin:diff-sanity', 'builtin:index-clean', 'builtin:size-limit', 'eslint']
  );
});
