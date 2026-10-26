// Data contract only; never a genuine installed/natively executed tool proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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
    assert.equal(calls[16].input.command,"printf 'owned native bash output\\\\n'; exit 7");
    assert(builtinInputContracts.bash.parseInput(installedBashStopCall.input));
    assert(builtinInputContracts.bash.parseInput(installedReadOnlyGitCall('after\\n').input));
    assert(installedBashStopCall.input.command.includes("/usr/bin/node --no-addons -e 'setInterval(()=>{},1000)'; :"));
  `;
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], {
    cwd: fileURLToPath(new URL('../../../', import.meta.url)), encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.signal, null); assert.equal(result.error, undefined);
});
