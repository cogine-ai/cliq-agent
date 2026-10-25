// Syntax/classification data only. Production calls this solely in the fixed
// signed source helper after its original same-attempt capture permission.
import assert from 'node:assert/strict';
import { test } from 'node:test';

test('ordinary clone inert settings disappear while safe Git semantics remain exact', async () => {
  const module = await import('./source-git-config.js').catch(() => undefined);
  assert.equal(typeof module?.classifySourceGitConfig, 'function');
  const classify = module!.classifySourceGitConfig;
  const source = Buffer.from('[core]\nrepositoryformatversion=1\nfilemode = true\nbare=false\nignorecase = no\n' +
    '[extensions]\nobjectformat = "sha256" # fixed hash\n[remote "origin"]\nurl=https://user:do-not-retain@example.invalid/repo\n' +
    'pushurl=ssh://private.invalid/repo\nfetch=+refs/heads/*:refs/remotes/origin/*\n' +
    '[branch "main"]\nremote=origin\nmerge=refs/heads/main\n[user]\nname="Private User"\nemail=private@example.invalid\n');
  const result = classify(source);
  assert.deepEqual(result.config.core, { repositoryFormatVersion: 1, fileMode: true, bare: false, ignoreCase: false });
  assert.equal(result.objectFormat, 'sha256'); assert.deepEqual(result.config.extensions, { objectFormat: 'sha256' });
  assert.equal(result.gitConfigUtf8, '[core]\nrepositoryformatversion = 1\nfilemode = true\nbare = false\nignorecase = false\n[extensions]\nobjectformat = sha256\n');
  assert(!/Private|private|origin|remote|user:|do-not-retain/u.test(JSON.stringify(result)));
});

test('dangerous, unknown and inherited-property keys fail without reflecting any original value', async () => {
  const module = await import('./source-git-config.js').catch(() => undefined); assert.equal(typeof module?.classifySourceGitConfig, 'function');
  const classify = module!.classifySourceGitConfig;
  const cases = ['[core]\nconstructor=true', '[core]\n__proto__=true', '[core]\nsshCommand=raw-private-value',
    '[core]\nfsmonitor=raw-private-value', '[core]\nhooksPath=raw-private-value', '[core]\nexcludesFile=raw-private-value',
    '[core]\nattributesFile=raw-private-value', '[include]\npath=raw-private-value', '[includeIf "gitdir:raw-private-value"]\npath=x',
    '[credential]\nhelper=raw-private-value', '[alias]\nexample=raw-private-value', '[filter "x"]\nprocess=raw-private-value',
    '[remote "origin"]\nproxy=raw-private-value', '[branch "main"]\nrebase=true', '[core]\nbare=true',
    '[extensions]\nobjectformat=sha256', '[core]\nrepositoryformatversion=2', '[core]\nfilemode="bad\\q"',
    '[core]\nfilemode="unterminated', '[user]\nname=bad\0value'];
  for (const source of cases) assert.throws(() => classify(Buffer.from(source)),
    error => error instanceof TypeError && error.message === 'source Git configuration is outside the fixed safe grammar');
  assert.throws(() => classify(Buffer.alloc(1_048_577)), TypeError);
});
