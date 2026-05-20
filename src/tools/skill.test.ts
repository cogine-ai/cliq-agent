import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { skillTool } from './skill.js';

async function writeSkill(root: string, name: string) {
  await mkdir(path.join(root, name), { recursive: true });
  await writeFile(
    path.join(root, name, 'SKILL.md'),
    `---
name: ${name}
description: ${name} instructions
---

Use the ${name} workflow.`,
    'utf8'
  );
}

test('skillTool activates a catalog skill into the active session context', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-tool-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    const session = createSession(cwd);

    const result = await skillTool.execute({ skill: { name: 'reviewer' } }, { cwd, session });

    assert.equal(result.status, 'ok');
    assert.equal(session.activeSkills.length, 1);
    assert.equal(session.activeSkills[0]?.name, 'reviewer');
    assert.equal(session.activeSkills[0]?.activatedBy, 'model');
    assert.match(result.content, /activated/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('skillTool dedupes repeated activation', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-tool-dedupe-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    const session = createSession(cwd);

    await skillTool.execute({ skill: { name: 'reviewer' } }, { cwd, session });
    const result = await skillTool.execute({ skill: { name: 'reviewer' } }, { cwd, session });

    assert.equal(result.status, 'ok');
    assert.equal(session.activeSkills.length, 1);
    assert.match(result.content, /already-active/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
