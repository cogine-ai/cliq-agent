import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { activateSkill, discoverSkillCatalog, loadSkills, mergeSkillNames, parseSkillMarkdown } from './loader.js';
import { createSession } from '../session/store.js';

test('mergeSkillNames preserves order and removes duplicates', () => {
  assert.deepEqual(mergeSkillNames(['reviewer', 'safe-edit'], ['safe-edit', 'planner']), [
    'reviewer',
    'safe-edit',
    'planner'
  ]);
});

async function writeSkill(root: string, name: string, body = 'Prefer read-only inspection before edits.') {
  const dir = path.join(root, name);
  await mkdir(dir, { recursive: true });
  await writeFile(
    path.join(dir, 'SKILL.md'),
    `---
name: ${name}
description: ${name}: use focused instructions
---

${body}`,
    'utf8'
  );
}

test('parseSkillMarkdown reads frontmatter metadata, colon values, CRLF, and allowed tools without granting them', () => {
  const parsed = parseSkillMarkdown(
    '---\r\nname: reviewer\r\ndescription: Review: inspect before editing\r\nlicense: MIT\r\ncompatibility: cliq >=0.10\r\nallowed-tools:\r\n  - read\r\n  - grep\r\nmetadata:\r\n  owner: agents\r\n---\r\n\r\nPrompt body.\r\n'
  );

  assert.equal(parsed.manifest.name, 'reviewer');
  assert.equal(parsed.manifest.description, 'Review: inspect before editing');
  assert.equal(parsed.manifest.license, 'MIT');
  assert.equal(parsed.manifest.compatibility, 'cliq >=0.10');
  assert.deepEqual(parsed.manifest.allowedTools, ['read', 'grep']);
  assert.deepEqual(parsed.manifest.metadata, { owner: 'agents' });
  assert.equal(parsed.prompt, 'Prompt body.');
  assert.equal(parsed.diagnostics.some((diagnostic) => diagnostic.level === 'error'), false);
});

test('parseSkillMarkdown reports missing required description', () => {
  const parsed = parseSkillMarkdown(`---
name: reviewer
---

Prompt body.`);

  assert.equal(parsed.manifest.name, 'reviewer');
  assert.equal(parsed.manifest.description, '');
  assert.match(
    parsed.diagnostics.find((diagnostic) => diagnostic.code === 'missing-description')?.message ?? '',
    /description/i
  );
});

test('loadSkills reads SKILL.md from the workspace skill directory', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
    assert.equal(loaded[0]?.scope, 'project');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with missing required frontmatter', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-invalid-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'broken'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'broken', 'SKILL.md'),
      `---
description: missing name
---

Prompt body.`,
      'utf8'
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /must declare a name/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills records a warning rather than rejecting a blank prompt body', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-empty-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'empty'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'empty', 'SKILL.md'),
      `---
name: empty
description: intentionally empty
---
`,
      'utf8'
    );

    const loaded = await loadSkills(cwd, ['empty']);
    assert.equal(loaded[0]?.prompt, '');
    assert.equal(
      loaded[0]?.diagnostics.some((diagnostic) => diagnostic.code === 'empty-body' && diagnostic.level === 'warning'),
      true
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills accepts CRLF frontmatter and body separators', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-crlf-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
      '---\r\nname: reviewer\r\ndescription: windows-style newlines\r\n---\r\n\r\nPrefer read-only inspection.\r\n',
      'utf8'
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects invalid skill names before resolving paths', async () => {
  await assert.rejects(
    () => loadSkills('/tmp/workspace', ['../escape']),
    /Invalid skill name: \.\.\/escape/i
  );
});

test('discoverSkillCatalog finds project .cliq, project .agents, and user skill roots', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-catalog-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-home-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer');
    await writeSkill(path.join(cwd, '.agents', 'skills'), 'planner');
    await writeSkill(path.join(home, '.cliq', 'skills'), 'writer');
    await writeSkill(path.join(home, '.agents', 'skills'), 'tester');

    const catalog = await discoverSkillCatalog(cwd, {
      homeDir: home,
      cliqHome: path.join(home, '.cliq')
    });

    assert.deepEqual(
      catalog.entries.map((entry) => `${entry.name}:${entry.scope}:${entry.sourceKind}`).sort(),
      [
        'planner:project:project-agents',
        'reviewer:project:project-cliq',
        'tester:user:user-agents',
        'writer:user:user-cliq'
      ]
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('discoverSkillCatalog gives project skills precedence over user skills and marks shadowed entries', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-shadow-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-shadow-home-'));
  try {
    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer', 'Project skill.');
    await writeSkill(path.join(home, '.cliq', 'skills'), 'reviewer', 'User skill.');

    const catalog = await discoverSkillCatalog(cwd, {
      homeDir: home,
      cliqHome: path.join(home, '.cliq')
    });
    const entries = catalog.entries.filter((entry) => entry.name === 'reviewer');

    assert.equal(entries.length, 2);
    assert.equal(entries.find((entry) => entry.scope === 'project')?.status, 'available');
    assert.equal(entries.find((entry) => entry.scope === 'user')?.status, 'shadowed');
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('loadSkills can require project-owned skills for workspace defaultSkills', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-project-only-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-project-only-home-'));
  try {
    await writeSkill(path.join(home, '.cliq', 'skills'), 'reviewer', 'User skill.');

    await assert.rejects(
      () =>
        loadSkills(cwd, ['reviewer'], {
          discovery: { homeDir: home, cliqHome: path.join(home, '.cliq') },
          projectOnly: true
        }),
      /not project-owned/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('activateSkill replaces a same-name active user skill with the selected project skill', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-activate-precedence-'));
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-activate-precedence-home-'));
  try {
    await writeSkill(path.join(home, '.cliq', 'skills'), 'reviewer', 'User skill.');
    const session = createSession(cwd);
    const userCatalog = await discoverSkillCatalog(cwd, {
      homeDir: home,
      cliqHome: path.join(home, '.cliq')
    });
    await activateSkill(cwd, session, 'reviewer', {
      catalog: userCatalog,
      activatedBy: 'cli'
    });

    await writeSkill(path.join(cwd, '.cliq', 'skills'), 'reviewer', 'Project skill.');
    const projectCatalog = await discoverSkillCatalog(cwd, {
      homeDir: home,
      cliqHome: path.join(home, '.cliq')
    });
    const result = await activateSkill(cwd, session, 'reviewer', {
      catalog: projectCatalog,
      projectOnly: true,
      activatedBy: 'workspace-default'
    });

    assert.equal(result.status, 'activated');
    assert.equal(session.activeSkills.length, 1);
    assert.equal(session.activeSkills[0]?.scope, 'project');
    assert.equal(session.activeSkills[0]?.activatedBy, 'workspace-default');
    assert.match(session.activeSkills[0]?.prompt ?? '', /Project skill/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
