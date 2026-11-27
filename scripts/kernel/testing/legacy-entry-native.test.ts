// Actual no-StateOwner Linux account SH/fixed-leaf reader campaign. This
// intentionally has no opt-in skip, HOME override, authority marker or Owner.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('fixed Legacy rendezvous reader is no-write, same-account SH-held, complete-byte and joined on a real disposable Linux account',
  { timeout: 180000 }, async () => {
    assert.equal(process.platform, 'linux'); assert.equal(process.env.CLIQ_DISPOSABLE_ACCOUNT_QUALIFICATION, '1');
    const user = os.userInfo(); assert.equal(user.username, 'cliq-kernel-gate-test'); assert.equal(user.homedir, '/home/cliq-kernel-gate-test');
    assert.ok(user.uid >= 1000); assert.equal(process.geteuid?.(), user.uid);
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-entry-native-'));
    try {
      const carrier = await prepareSupervisorSeaCarrier(root, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE), helper = path.join(root, 'state-owner.node');
      const source = fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url));
      const compile = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
        '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), source, '-o', helper], { encoding: 'utf8', timeout: 60000 });
      assert.equal(compile.error, undefined); assert.equal(compile.status, 0, compile.stderr);
      const result = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
        const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
        const loaded={exports:{}};process.dlopen(loaded,${JSON.stringify(helper)});const native=loaded.exports;
        const root=${JSON.stringify(root)},legacy=path.join(root,'legacy'),marker=path.join(legacy,'.cliq-generation-v1.json');
        const descriptors=()=>fs.readdirSync('/proc/self/fd').filter(name=>/^[0-9]+$/.test(name)).sort();
        const shared=native.acquireKernelGlobalShared();shared.assertHeld();
        assert.throws(()=>native.acquireKernelGlobalExclusive());shared.assertHeld();
        let before=descriptors();assert.deepEqual(native.inspectLegacyEntry(shared,legacy),{kind:'legacy_root_absent'});
        assert(!fs.existsSync(legacy));assert.deepEqual(descriptors(),before);
        fs.mkdirSync(legacy,{mode:0o700});
        before=descriptors();assert.deepEqual(native.inspectLegacyEntry(shared,legacy),{kind:'rendezvous_absent'});
        assert.deepEqual(descriptors(),before);assert.deepEqual(fs.readdirSync(legacy),[]);
        // Deliberately invalid ordinary bytes, never a fabricated authority.
        const bytes=Buffer.from('untrusted-rendezvous-data-'.repeat(6000));fs.writeFileSync(marker,bytes,{mode:0o600,flag:'wx'});
        const previous=fs.statSync(marker,{bigint:true});before=descriptors();
        const observed=native.inspectLegacyEntry(shared,legacy);
        assert.equal(observed.kind,'rendezvous_present');assert.deepEqual(observed.bytes,bytes);
        assert.equal(observed.contentDigest,crypto.createHash('sha256').update(bytes).digest('hex'));
        const actualRoot=fs.statSync(legacy,{bigint:true});
        assert.deepEqual(observed.rootIdentity,{deviceId:actualRoot.dev.toString(),fileId:actualRoot.ino.toString(),ownerUid:Number(actualRoot.uid)});
        const after=fs.statSync(marker,{bigint:true});
        for(const field of ['dev','ino','mode','size','nlink','mtimeNs','ctimeNs'])assert.equal(after[field],previous[field],field);
        assert.deepEqual(descriptors(),before);assert.deepEqual(fs.readdirSync(legacy),['.cliq-generation-v1.json']);
        // Raw native byte equality is not the closed business marker decoder.
        // It must export neither source bytes nor a credential authority.
        const auth=path.join(legacy,'auth.json'),authBytes=Buffer.from('ordinary-auth-byte-equality-data');
        fs.writeFileSync(auth,authBytes,{mode:0o600,flag:'wx'});
        const authDigest=crypto.createHash('sha256').update(authBytes).digest('hex');before=descriptors();
        assert.deepEqual(native.verifyLegacyMigratedAuth(shared,legacy,authDigest,authBytes.length),
          {kind:'matched_auth_bytes',byteCount:authBytes.length,contentDigest:authDigest,rootIdentity:observed.rootIdentity});
        assert.throws(()=>native.verifyLegacyMigratedAuth(shared,legacy,'0'.repeat(64),authBytes.length));
        assert.throws(()=>native.verifyLegacyMigratedAuth(shared,legacy,authDigest,authBytes.length+1));
        assert.deepEqual(descriptors(),before);fs.unlinkSync(auth);
        assert.throws(()=>native.inspectLegacyEntry({},legacy));shared.assertHeld();
        fs.linkSync(marker,marker+'-link');assert.throws(()=>native.inspectLegacyEntry(shared,legacy));assert.deepEqual(descriptors(),before);
        fs.unlinkSync(marker+'-link');fs.chmodSync(marker,0o644);assert.throws(()=>native.inspectLegacyEntry(shared,legacy));assert.deepEqual(descriptors(),before);
        fs.chmodSync(marker,0o600);fs.unlinkSync(marker);fs.symlinkSync('/etc/passwd',marker);
        assert.throws(()=>native.inspectLegacyEntry(shared,legacy));assert.deepEqual(descriptors(),before);
        fs.unlinkSync(marker);shared.assertHeld();shared.close();
        assert.throws(()=>native.inspectLegacyEntry(shared,legacy));
      `], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
      assert.equal(result.error, undefined); assert.equal(result.signal, null, result.stderr); assert.equal(result.status, 0, result.stderr);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
