import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp,mkdir,readdir,rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readDependencyScriptDenialCause } from './dependency-script-approval.js';

test('denial source abort and malformed locators stop before SQL or CAS without getters, traps, fallback or mutation',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'cliq-script-denial-'));
 const cas=path.join(root,'cas');await mkdir(cas,{mode:0o700});
 const driver=openSqliteDriver(path.join(root,'actual.sqlite'));
 try{
  const artifacts=new ArtifactCatalog(new ContentAddressedStore(cas));let sql=0,effects=0;
  const prepare=driver.prepare.bind(driver);driver.prepare=text=>{sql++;return prepare(text);};
  const abort=new AbortController(),reason=new Error('owned already-aborted read');abort.abort(reason);
  await assert.rejects(readDependencyScriptDenialCause(driver,artifacts,'no Run',{observedAt:'2026-10-27T00:00:00.000Z'},abort.signal),error=>error===reason);
  const getter=Object.defineProperty({},'observedAt',{enumerable:true,get(){effects++;return '2026-10-27T00:00:00.000Z';}});
  const proxy=new Proxy({},{get(){effects++;throw new Error('get');},ownKeys(){effects++;throw new Error('ownKeys');}});
  for(const input of [getter,proxy,{observedAt:'2026-10-27T00:00:00.000Z',retained:null},
   {observedAt:'2026-10-27T00:00:00.000Z',retained:{}},{observedAt:'2026-10-27T00:00:00.000Z',extra:true},
   {observedAt:'not-a-time'},{observedAt:'2026-10-27T00:00:00.000Z',retained:proxy}])
    await assert.rejects(readDependencyScriptDenialCause(driver,artifacts,'no Run',input as never));
  assert.equal(sql,0);assert.equal(effects,0);assert.deepEqual(await readdir(cas),[]);
 }finally{driver.close();await rm(root,{recursive:true,force:true});}
});
