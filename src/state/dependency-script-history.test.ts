import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp,mkdir,readdir,rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readDependencyScriptsTemplateHistoryData } from './dependency-script-history.js';

// Real independent SQLite/CAS, no StateOwner, runtime, grant or candidate.
// Abort must precede even the first retained-root SQL/CAS operation.
test('an already aborted template history read touches neither the actual SQL driver nor independent CAS',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'cliq-dependency-history-abort-'));
 const casRoot=path.join(root,'cas');await mkdir(casRoot,{mode:0o700});
 const driver=openSqliteDriver(path.join(root,'state.sqlite'));
 try {
  const artifacts=new ArtifactCatalog(new ContentAddressedStore(casRoot));let sql=0;
  const prepare=driver.prepare.bind(driver);driver.prepare=(text:string)=>{sql++;return prepare(text);};
  const abort=new AbortController();abort.abort();
  await assert.rejects(readDependencyScriptsTemplateHistoryData(driver,artifacts,undefined as never,
    {runId:'no Run exists',templateRef:canonicalSha256('no template exists')},abort.signal),{name:'AbortError'});
  assert.equal(sql,0);assert.deepEqual(await readdir(casRoot),[]);
 }finally{driver.close();await rm(root,{recursive:true,force:true});}
});
