// Data contract only; never a genuine installed/natively executed tool proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

test('the complete installed tool batch uses the original compiled normalizers and exact fixed scope capacity', () => {
  const script = `
    import assert from 'node:assert/strict';
    import {installedToolsCalls,installedReadOnlyGitCall} from './scripts/kernel/testing/installed-tools-result.ts';
    import {installedBashStopCall} from './scripts/kernel/testing/installed-tools-stop.ts';
    import {builtinInputContracts} from './src/tools/builtin-inputs.ts';
    const calls=installedToolsCalls('before\\n','after\\n');
    assert.equal(calls.length,19);assert.equal(new Set(calls.map(call=>call.callId)).size,19);
    for(const call of calls)assert(builtinInputContracts[call.name].parseInput(call.input),call.name+' must keep its exact compiled grammar');
    assert.equal(calls.slice(0,15).filter(call=>['read','ls','find','grep'].includes(call.name)).length,15);
    assert.deepEqual(calls.slice(15).map(call=>call.name),['edit','bash','bash','request_input']);
    assert.equal(calls[16].input.command,"/usr/bin/node --no-addons -e \\"process.stdout.write('owned native bash output\\\\n')\\"; exit 7");
    assert(builtinInputContracts.bash.parseInput(installedBashStopCall.input));
    assert(builtinInputContracts.bash.parseInput(installedReadOnlyGitCall('after\\n').input));
    const gitCommand=installedReadOnlyGitCall('after\\n').input.command;
    assert(gitCommand.startsWith('set -eu\\n/usr/bin/node --no-addons -e '));
    assert(gitCommand.includes('CLIQ_SIGNED_NODE_FROM_BASH_OK'));
    assert(installedBashStopCall.input.command.includes("/usr/bin/node --no-addons -e 'setInterval(()=>{},1000)'; :"));
  `;
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], {
    cwd: fileURLToPath(new URL('../../../', import.meta.url)), encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.signal, null); assert.equal(result.error, undefined);
});

test('the fixed no-cost Node probe keeps the original verifier campaign and complete lifecycle owner', () => {
  const read = file => readFileSync(new URL(file, import.meta.url), 'utf8');
  const owner = read('./installed-node-journey.ts'), entry = read('../qualify-installed-verifier-journey.ts');
  assert(entry.includes("if (mode === '--builtin-node-campaign')"));
  assert(entry.includes("assert.equal(extra.length, 0)"));
  assert(entry.includes("await runInstalledNodeJourney(filename, 'builtin-node-probe')"));
  assert(entry.includes("await runInstalledNodeJourney(filename, 'verifier', npmDependencyArchive ? { npmDependencyArchive } : {})"));
  assert(owner.includes("format: 'cliq-installed-builtin-node-probe-v1'"));
  assert(owner.includes("assert(reply[0].content.includes('CLIQ_SIGNED_NODE_FROM_BASH_OK'))"));
  assert(owner.includes("await createSource('ordinary_git');\n      assert.equal(postCount, 2)"));
  assert(owner.includes("} else if (journeyKind === 'verifier') {\n    for (const kind of cases) await createSource(kind)"));
  assert(owner.includes('await scanCredentialSecretCorpus('));
  const workflow = read('../../../.github/workflows/kernel-foundation.yml');
  const probe = workflow.slice(workflow.indexOf('  linux-installed-builtin-node:'), workflow.indexOf('  linux-installed-verifier:'));
  assert(probe.includes('runs-on: ubuntu-22.04')); assert(probe.includes('timeout-minutes: 10'));
  assert(probe.includes('--run-builtin-node-probe')); assert(!probe.includes('secrets.'));
});
