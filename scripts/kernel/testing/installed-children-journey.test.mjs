// Controlled endpoint data only. No installed child, Supervisor, native owner,
// process/death proof, provider request or platform qualification is created.
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('both installed child scenarios use the real compiled delegate grammar and exact unverified bounded subset', () => {
  const script = `
    import assert from 'node:assert/strict';
    import {installedChildDelegateCall,INSTALLED_CHILD_CASES,INSTALLED_CHILDREN_PROFILE,createInstalledChildrenResponder} from './scripts/kernel/testing/installed-children-journey.ts';
    import {decodeDelegateRequest} from './src/tools/child-inputs.ts';
    import {builtinInputContracts} from './src/tools/builtin-inputs.ts';
    import {canonicalJsonBytes} from './src/kernel/canonical.ts';
    assert.equal(INSTALLED_CHILDREN_PROFILE,'verifier_eight_plus_children_merge_restart_and_cancel_v1');
    for(const kind of INSTALLED_CHILD_CASES){
      const call=installedChildDelegateCall(kind), value=JSON.parse(call.function.arguments);
      assert.equal(call.function.name,'delegate');
      assert(canonicalJsonBytes(decodeDelegateRequest(value)).equals(canonicalJsonBytes(value)));
      assert(builtinInputContracts.delegate.parseInput(value));
      assert.equal(value.allowUnverifiedHelper,true);assert.equal(value.verifierMode,'none');
      assert.equal(value.requestedBudgets.toolCalls,5);assert.equal(value.requestedBudgets.childDepth,0);
      assert.equal(value.requestedBudgets.modelTokens,200000);
      assert.deepEqual(value.capabilities.builtinToolNames,['edit','read','request_input']);
      assert.deepEqual(value.capabilities.registeredMcpServerIds,[]);assert.equal(value.capabilities.allowShell,false);
      assert.throws(()=>decodeDelegateRequest({...value,allowUnverifiedHelper:false}));
    }
    assert.throws(()=>installedChildDelegateCall('unknown'));
    let reads=0, observations=0;
    const responder=createInstalledChildrenResponder({model:'data-only',before:'before',after:'after',expectedParentTools:()=>['delegate'],
      readCas:async()=>{reads++;throw new Error('no CAS authority in this data fixture');},readCut:async()=>{reads++;throw new Error('no Run authority');},
      observeWorker:async()=>{observations++;throw new Error('no physical proof');}});
    const kind=INSTALLED_CHILD_CASES[0];responder.begin(kind);responder.bind(kind,'data-only-run');
    assert.throws(()=>responder.begin(kind));assert.throws(()=>responder.bind(kind,'another-run'));
    const malformed={messages:[{role:'user',content:responder.objective(kind)}],tools:[]};
    await assert.rejects(responder.respond(malformed));
    assert.equal(reads,0);assert.equal(observations,0);
    assert.equal(await responder.respond({messages:[{role:'user',content:'unrelated actual campaign'}],tools:[]}),undefined);
  `;
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], {
    cwd: fileURLToPath(new URL('../../../', import.meta.url)), encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.signal, null); assert.equal(result.error, undefined);
});
