import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { activateSkill } from '../skills/loader.js';
import { createSession } from '../session/store.js';
import { skillResourceTool } from './skill-resource.js';

async function writeSkill(root: string, name: string) {
  const dir = path.join(root, name);
  await mkdir(path.join(dir, 'references'), { recursive: true });
  await writeFile(
    path.join(dir, 'SKILL.md'),
    `---
name: ${name}
description: ${name} instructions
---

Use bundled references when needed.`,
    'utf8'
  );
  await writeFile(path.join(dir, 'references', 'guide.md'), 'Guide text.\n', 'utf8');
}

test('skillResourceTool reads resources relative to an activated skill directory', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-resource-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    const session = createSession(cwd);
    await activateSkill(cwd, session, 'reviewer', { activatedBy: 'model' });

    const result = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: 'references/guide.md' } },
      { cwd, session }
    );

    assert.equal(result.status, 'ok');
    assert.match(result.content, /Guide text/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('skillResourceTool lists resources with a capped shallow directory view', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-resource-list-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    const session = createSession(cwd);
    await activateSkill(cwd, session, 'reviewer', { activatedBy: 'model' });

    const result = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: 'references', mode: 'list' } },
      { cwd, session }
    );

    assert.equal(result.status, 'ok');
    assert.match(result.content, /guide\.md/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('skillResourceTool rejects traversal and symlink escapes', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-resource-escape-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-resource-outside-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    await writeFile(path.join(outside, 'secret.md'), 'secret\n', 'utf8');
    await symlink(path.join(outside, 'secret.md'), path.join(cwd, '.cliq', 'skills', 'reviewer', 'references', 'secret.md'));
    const session = createSession(cwd);
    await activateSkill(cwd, session, 'reviewer', { activatedBy: 'model' });

    const traversal = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: '../SKILL.md' } },
      { cwd, session }
    );
    const normalizedTraversal = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: 'references/../SKILL.md' } },
      { cwd, session }
    );
    const link = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: 'references/secret.md' } },
      { cwd, session }
    );

    assert.equal(traversal.status, 'error');
    assert.match(traversal.content, /relative/i);
    assert.equal(normalizedTraversal.status, 'error');
    assert.match(normalizedTraversal.content, /relative/i);
    assert.equal(link.status, 'error');
    assert.match(link.content, /outside/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('skillResourceTool rejects oversized and binary resources', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-resource-size-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'references', 'large.md'),
      'x'.repeat(64_001),
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'references', 'binary.bin'),
      Buffer.from([65, 0, 66])
    );
    const session = createSession(cwd);
    await activateSkill(cwd, session, 'reviewer', { activatedBy: 'model' });

    const large = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: 'references/large.md' } },
      { cwd, session }
    );
    const binary = await skillResourceTool.execute(
      { skillResource: { skill: 'reviewer', path: 'references/binary.bin' } },
      { cwd, session }
    );

    assert.equal(large.status, 'error');
    assert.match(large.content, /exceeds/i);
    assert.equal(binary.status, 'error');
    assert.match(binary.content, /binary/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
