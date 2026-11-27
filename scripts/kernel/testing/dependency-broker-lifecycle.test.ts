import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:https';
import type { Duplex } from 'node:stream';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';

type Binding = Buffer;
type Reader = { readChunk(): Buffer; assertComplete(): void; close(): void };
type Package = { byteCount: number; sha256: string; openReader(): Reader; close(): void };
type Outcome = { kind: 'complete' | 'http_error' | 'integrity_mismatch'; status: number; receivedBytes: number;
  eof: boolean; packageIndex: number; attempt: number; package?: Package };
type Fence = { assertCurrent(): void; close(): void };
type Owner = { ready: Promise<void>; brokerFenceTokenDigest: string; registerPackagePage(bytes: Buffer): void;
  sealPackagePlan(): void; retainDispatchFence(): void; bindInvocation(bytes: Binding): void;
  connect(bytes: Binding, index: number, attempt: number): Promise<void>; releaseGet(bytes: Binding, index: number, attempt: number): Promise<Outcome>;
  sealPackageInputs(bytes: Binding): Promise<void>;
  observeFailure(error: unknown): { brokerCode: string; packageIndex: number; attempt: number; receivedBytes: number; eof: boolean;
    networkStarted: boolean; requestStarted: boolean; ioJoined: boolean; retryableTransport: boolean };
  acquireSettlementFence(bytes: Binding): Fence; releaseDispatchFence(): void; close(): Promise<{
    kind: 'dependency_transport_closed'; dispatchFenceRetained: boolean; settlementFenceBorrowed: boolean;
    networkStarted: boolean; requestStarted: boolean; processClaimed: boolean }> };
type Module = { interfaceVersion: number; prepareDependencyTransport(configuration: Buffer, trust: Buffer): Owner };
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

// Actual addon/TLS/memfd/reader lifecycle mechanism. No StateOwner, Journal,
// execution grant or worker is fabricated. This is not installed qualification.
test('public GET owns full large sealed data, retries only three original fetches, and joins cancellation',
  { skip: process.platform !== 'linux' || process.arch !== 'x64', timeout: 120_000 }, async () => {
    assert(process.getuid!() > 0);
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-native-'));
    const sockets = new Set<Duplex>();
    let server: ReturnType<typeof createServer> | undefined;
    try {
      const recipe = fileURLToPath(new URL('../build-linux-dependency-broker.mjs', import.meta.url));
      const compiled = spawnSync(process.execPath, [recipe, path.join(root, 'native')],
        { encoding: 'utf8', timeout: 65_000, maxBuffer: 65_536 });
      assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, compiled.stderr);
      const bindingModule = createRequire(import.meta.url)(path.join(root, 'native/linux-dependency-broker.node')) as Module;
      assert.equal(bindingModule.interfaceVersion, 1);
      const key = path.join(root, 'owned.key'), cert = path.join(root, 'owned.pem');
      const certificate = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', key, '-out', cert], { encoding: 'utf8', timeout: 15_000, maxBuffer: 65_536 });
      assert.equal(certificate.error, undefined); assert.equal(certificate.signal, null); assert.equal(certificate.status, 0);
      const trust = await readFile(cert), secretKey = await readFile(key);
      const pin = digest(new X509Certificate(trust).publicKey.export({ type: 'spki', format: 'der' }));
      const payload = Buffer.alloc(3 * 1_048_576 + 71, 0x91), wrong = Buffer.alloc(payload.length, 0x92);
      let requests = 0, heldArrived: (() => void) | undefined;
      let scenario: 'retry' | 'hold' = 'retry';
      server = createServer({ cert: trust, key: secretKey, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, (request, response) => {
        requests++;
        assert.equal(request.method, 'GET'); assert.equal(request.url, '/registry/pkg/-/pkg-1.0.0.tgz');
        assert.equal(request.headers.authorization, undefined); assert.equal(request.headers.cookie, undefined);
        assert.equal(request.headers['accept-encoding'], 'identity');
        if (scenario === 'hold') { heldArrived!(); return; }
        if (requests === 1) { response.writeHead(404, { 'Content-Length': 3 }); response.end('raw'); }
        else { const body = requests === 2 ? wrong : payload; response.writeHead(200, { 'Content-Length': body.length }); response.end(body); }
      });
      server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
      await new Promise<void>((resolve, reject) => { server!.once('error', reject); server!.listen(0, '127.0.0.1', resolve); });
      const address = server.address(); assert(address && typeof address !== 'string');
      const ref = 'a'.repeat(64), trustRef = digest(trust);
      const descriptor = { packageName: 'pkg', packageVersion: '1.0.0', endpointRegistrationRef: ref,
        canonicalPackagePath: '/pkg/-/pkg-1.0.0.tgz', integrityAlgorithm: 'sha512', integrityDigest: createHash('sha512').update(payload).digest('base64') };
      const bytes = canonicalJsonBytes(descriptor), size = Buffer.alloc(4); size.writeUInt32LE(bytes.length);
      const sequence = createHash('sha256').update('cliq-dependency-package-descriptors-v1\0', 'ascii').update(size).update(bytes).digest('hex');
      const config = canonicalJsonBytes({ schemaVersion: 1, transport: 'public_integrity_get_v1', descriptorSequenceDigest: sequence,
        maxPackageBytes: 67_108_864, maxTransferBytes: 5 * 1_073_741_824, packageCount: 1, packageDescriptorBytes: 4 + bytes.length,
        planDigest: ref, runRemainingMs: 60_000, sandboxLaunchSpecRef: ref, trustStoreDigest: trustRef,
        targets: [{ basePath: '/registry', endpointRegistrationRef: ref, hostAscii: '127.0.0.1', port: address.port,
          serverNameAscii: '127.0.0.1', spkiSha256Pins: [pin], tlsPolicyDigest: digest(canonicalJsonBytes({ serverNameAscii: '127.0.0.1', minimumVersion: 'TLSv1.3',
            trustStoreRuntimeBundleRef: ref, trustStoreRuntimeBundleManifestDigest: ref, trustStoreEntryId: 'default_https_trust_store',
            trustStoreRef: trustRef, trustStoreDigest: trustRef, spkiSha256Pins: [pin] })) }] });
      const page = canonicalJsonBytes({ schemaVersion: 1, firstIndex: 0, descriptors: [descriptor] });
      function prepare(bind = true) {
        const owner = bindingModule.prepareDependencyTransport(config, trust);
        owner.registerPackagePage(page); owner.sealPackagePlan(); owner.retainDispatchFence();
        const binding = canonicalJsonBytes({ attempt: 0, brokerFenceTokenDigest: owner.brokerFenceTokenDigest, dispatchId: 'dispatch-1',
          dispatchJournalSeq: 1, grantRef: ref, leaseEpoch: 1, opId: 'op-1', requestDigest: ref, requestRef: ref, runId: 'run-1',
          stateOwnerEpoch: 1, supervisorInstanceId: 'supervisor-1', targetDigest: ref, targetRef: ref });
        if (bind) owner.bindInvocation(binding); return { owner, binding };
      }
      const unclaimed = prepare(false); await unclaimed.owner.ready;
      const unclaimedStart = performance.now(), unclaimedClosing = unclaimed.owner.close();
      const unclaimedReturnedAt = performance.now(), unclaimedClosed = await unclaimedClosing;
      const unclaimedJoinedAt = performance.now();
      assert(unclaimedJoinedAt - unclaimedStart < 2000,
        `original unclaimed close exceeded 2000ms: synchronous=${Math.ceil(unclaimedReturnedAt - unclaimedStart)}ms, total=${Math.ceil(unclaimedJoinedAt - unclaimedStart)}ms`);
      assert.deepEqual({ kind: unclaimedClosed.kind, dispatchFenceRetained: unclaimedClosed.dispatchFenceRetained,
        settlementFenceBorrowed: unclaimedClosed.settlementFenceBorrowed, networkStarted: unclaimedClosed.networkStarted,
        requestStarted: unclaimedClosed.requestStarted, processClaimed: unclaimedClosed.processClaimed },
      { kind: 'dependency_transport_closed', dispatchFenceRetained: true, settlementFenceBorrowed: false,
        networkStarted: false, requestStarted: false, processClaimed: false });
      unclaimed.owner.releaseDispatchFence(); assert.equal(requests, 0);
      const first = prepare(); await first.owner.ready;
      let packageOwner: Package | undefined;
      for (const attempt of [1, 2, 3]) {
        await first.owner.connect(first.binding, 0, attempt);
        const outcome = await first.owner.releaseGet(first.binding, 0, attempt);
        assert.deepEqual({ kind: outcome.kind, status: outcome.status, receivedBytes: outcome.receivedBytes,
          eof: outcome.eof, packageIndex: outcome.packageIndex, attempt: outcome.attempt },
        { kind: attempt === 1 ? 'http_error' : attempt === 2 ? 'integrity_mismatch' : 'complete',
          status: attempt === 1 ? 404 : 200, receivedBytes: attempt === 1 ? 3 : payload.length, eof: true, packageIndex: 0, attempt });
        assert.equal(Object.hasOwn(outcome, 'package'), attempt === 3); packageOwner = outcome.package;
      }
      assert(packageOwner); assert.equal(requests, 3);
      await assert.rejects(async () => first.owner.connect(first.binding, 0, 4)); assert.equal(requests, 3);
      assert.equal(packageOwner.byteCount, payload.length); assert.equal(packageOwner.sha256, digest(payload));
      const cursors = [packageOwner.openReader(), packageOwner.openReader()];
      assert.throws(() => packageOwner!.close());
      for (const cursor of cursors) {
        const hash = createHash('sha256'); let count = 0;
        for (;;) { const chunk = cursor.readChunk(); assert(chunk.length <= 65_536); if (!chunk.length) break; hash.update(chunk); count += chunk.length; }
        cursor.assertComplete(); assert.equal(count, payload.length); assert.equal(hash.digest('hex'), digest(payload)); cursor.close();
      }
      // A simulated consumer failure does not release this package or issue
      // another GET: the same genuine sealed owner supports a fresh full read.
      const retry = packageOwner.openReader(); const again = createHash('sha256');
      for (;;) { const chunk = retry.readChunk(); if (!chunk.length) break; again.update(chunk); }
      retry.assertComplete(); retry.close(); assert.equal(again.digest('hex'), digest(payload)); assert.equal(requests, 3);
      packageOwner.close(); await first.owner.sealPackageInputs(first.binding);
      const fence = first.owner.acquireSettlementFence(first.binding); fence.assertCurrent();
      assert.throws(() => first.owner.observeFailure(new Error('foreign')));
      let traps = 0; const substituted = new Proxy(new Error('foreign'), { get() { traps++; throw new Error('trap'); } });
      assert.throws(() => first.owner.observeFailure(substituted)); assert.equal(traps, 0);
      fence.close(); first.owner.releaseDispatchFence();
      const closeStart = performance.now(); await first.owner.close(); assert(performance.now() - closeStart < 2000);
      scenario = 'hold'; const second = prepare(); await second.owner.ready;
      await second.owner.connect(second.binding, 0, 1);
      const arrival = new Promise<void>(resolve => { heldArrived = resolve; });
      const get = second.owner.releaseGet(second.binding, 0, 1); const rejected = assert.rejects(get);
      await arrival; const stopStarted = performance.now(); const closing = second.owner.close();
      await rejected;
      const ioClosed = await closing; assert.equal(ioClosed.dispatchFenceRetained, true);
      const stoppedFence = second.owner.acquireSettlementFence(second.binding); stoppedFence.assertCurrent(); stoppedFence.close();
      second.owner.releaseDispatchFence(); assert(performance.now() - stopStarted < 2000);
      assert.equal(requests, 4);
    } finally {
      for (const socket of sockets) socket.destroy();
      if (server) await new Promise<void>(resolve => server!.close(() => resolve()));
      await rm(root, { recursive: true, force: true });
    }
  });
