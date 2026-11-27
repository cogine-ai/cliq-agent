import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { emitQualificationFailure, qualificationFailureDiagnostic } from './qualification-failure-diagnostic.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

test('qualification failure diagnostics contain only closed numbers and fixed source identities', () => {
  const inner = Object.assign(new Error('must not disclose the private error message'),{code:'ENOTFOUND'});
  Object.defineProperty(inner,'stack',{value:'Error: private error\n at prepare (/private/source/supervisor-sea-builder.ts:160:22)'});
  const error = new TypeError('another private value',{cause:inner});
  Object.defineProperty(error,'stack',{value:'TypeError: private\n at build (/private/source/installed-supervisor-package.ts:60:61)'});
  const value = qualificationFailureDiagnostic('package',error);
  assert.deepEqual(value,{version:1,stage:1,phase:0,failures:[
    {type:2,code:0,frames:[{source:1,line:60,column:61}]},
    {type:1,code:8,frames:[{source:2,line:160,column:22}]}
  ]});
  assert(!JSON.stringify(value).includes('private'));
});

test('diagnostic observation never invokes caller accessors, proxies, or arbitrary toString methods', () => {
  let accessed = 0;
  const value = Object.create(null,{code:{enumerable:true,get(){accessed++;throw Error('getter');}},
    stack:{enumerable:true,get(){accessed++;throw Error('getter');}},toString:{value(){accessed++;throw Error('stringification');}}});
  const proxy = new Proxy({},{get(){accessed++;throw Error('proxy');},ownKeys(){accessed++;throw Error('proxy');}});
  const altered = new Error('not printed');
  Object.defineProperty(altered,'stack',{get(){accessed++;throw Error('caller stack getter');}});
  for (const error of [value,proxy,undefined,'private thrown text']) {
    assert.deepEqual(qualificationFailureDiagnostic('tls',error),{version:1,stage:2,phase:0,failures:[{type:0,code:0,frames:[]}]});
  }
  assert.equal(accessed,0);
  assert.deepEqual(qualificationFailureDiagnostic('package',altered).failures[0]!.frames,[]);
  assert.equal(accessed,0);
  assert.throws(()=>qualificationFailureDiagnostic('unknown' as never,undefined),TypeError);
});

test('diagnostics bound cause cycles, aggregate branches, frames and source coordinates', () => {
  const error = new AggregateError(Array.from({length:20},()=>new Error('not printed')),'not printed');
  Object.defineProperty(error,'cause',{value:error});
  Object.defineProperty(error,'stack',{value:Array.from({length:30},()=> 'at x (/private/source/installed-upgrade-tls.ts:12:3)').join('\n')});
  const value = qualificationFailureDiagnostic('tls',error);
  assert.equal(value.failures.length,5);
  assert.equal(value.failures[0]!.frames.length,8);
  let chain = new Error('not printed');
  for (let index=0;index<20;index++) chain = new Error('not printed',{cause:chain});
  assert.equal(qualificationFailureDiagnostic('package',chain).failures.length,8);
  for (const stack of ['at /outside.ts:12:3','at /supervisor-sea-builder.ts:99999999:1','at /supervisor-sea-builder.ts:1:0']) {
    const cause = new Error('not printed');Object.defineProperty(cause,'stack',{value:stack});
    assert.deepEqual(qualificationFailureDiagnostic('package',cause).failures[0]!.frames,[]);
  }
});

test('error classification never walks a caller Proxy prototype, including aggregate causes and assertion actual values', () => {
  let accessed = 0;
  const prototype = new Proxy({}, { getPrototypeOf() { accessed++; throw new Error('caller prototype trap'); },
    get() { accessed++; throw new Error('caller property trap'); } });
  const lookalike = Object.create(prototype);
  const native = new Error('private');
  Object.setPrototypeOf(native, Object.create(prototype));
  assert.equal(qualificationFailureDiagnostic('tls', lookalike).failures[0]!.type, 0);
  assert.equal(qualificationFailureDiagnostic('tls', native).failures[0]!.type, 1);
  const aggregate = new AggregateError([lookalike, native], 'private', { cause: lookalike });
  assert.deepEqual(qualificationFailureDiagnostic('tls', aggregate).failures.map(value => value.type), [5, 0, 1]);
  const assertion = Object.assign(new Error('private'), { code: 'ERR_ASSERTION', actual: lookalike });
  assert.equal(qualificationFailureDiagnostic('package', assertion).failures.length, 1);
  assertion.actual = native;
  assert.equal(qualificationFailureDiagnostic('package', assertion).failures.length, 2);
  assert.equal(accessed, 0);
});

test('a closed diagnostic output cannot escape to the owning failure and cleanup path', t => {
  const original = new Error('the original private error must remain the failure');
  t.mock.method(fs,'writeSync',()=>{throw Object.assign(new Error('closed diagnostic pipe'),{code:'EPIPE'});});
  syncBuiltinESMExports();
  try { assert.doesNotThrow(()=>emitQualificationFailure('package',original)); }
  finally { t.mock.restoreAll();syncBuiltinESMExports(); }
  assert.equal(original.message,'the original private error must remain the failure');
});

test('a real abort-signal timeout and closed Undici causes remain diagnosable without error text or caller accessors',async()=>{
  const signal=AbortSignal.timeout(1);
  await new Promise(resolve=>setTimeout(resolve,10));
  assert.equal(signal.aborted,true);
  assert.equal(qualificationFailureDiagnostic('package',signal.reason).failures[0]!.type,6);
  const abort=new DOMException('private text','AbortError');let accessed=0;
  Object.defineProperty(abort,'name',{get(){accessed++;throw Error('caller name getter');}});
  assert.equal(qualificationFailureDiagnostic('tls',abort).failures[0]!.type,7);
  assert.equal(accessed,0);
  const cause=Object.assign(new Error('private transport message'),{code:'UND_ERR_CONNECT_TIMEOUT'});
  assert.equal(qualificationFailureDiagnostic('package',cause).failures[0]!.code,18);
});

test('the real package producer records its source-resolution refusal before any carrier preparation',async t=>{
  const values: string[]=[];
  const original=fs.writeSync;
  t.mock.method(fs,'writeSync',((...args: Parameters<typeof fs.writeSync>)=>{
    if (args[0]===2 && typeof args[1]==='string' && args[1].startsWith('CLIQ_QUALIFICATION_FAILURE_V1:')) {
      values.push(args[1]);return Buffer.byteLength(args[1]);
    }
    return Reflect.apply(original,fs,args);
  }) as typeof fs.writeSync);
  syncBuiltinESMExports();
  try {
    await assert.rejects(buildInstalledSupervisorPackage('/unused-before-source-authority','complete',undefined,{source:{} as never}),TypeError);
  } finally {t.mock.restoreAll();syncBuiltinESMExports();}
  assert.equal(values.length,1);
  const value=JSON.parse(values[0]!.slice('CLIQ_QUALIFICATION_FAILURE_V1:'.length));
  assert.equal(value.stage,1);assert.equal(value.phase,1);
  assert.equal(value.failures[0].type,2);
  assert(!values[0]!.includes('/unused-before-source-authority'));
});
