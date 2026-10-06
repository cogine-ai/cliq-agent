import { createHash, randomBytes } from 'node:crypto';
import { closeSync, fstatSync, readSync } from 'node:fs';
import { Socket } from 'node:net';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, LocalSocketPeerObservationV1, PlatformProcessIdentityV1 } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import {
  decodeControlChannel,
  decodeLocalPrincipalIdentity,
  decodeLocalSocketPeerObservation,
  decodePlatformProcessIdentity,
  decodeStateLockIdentity,
  decodeStateRootIdentity
} from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readLatestStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readCanonicalArtifact } from './agent-context.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { sampleCanonicalNow } from './canonical-time.js';
import type { HeldControlListener, HeldControlPeer, NativePeerObservation } from './native-owner.js';

export type AuthenticatedControlIdentity = Readonly<{
  principalId: string;
  channelIdentityRef: string;
  channelIdentityDigest: string;
}>;

/** Internal transport seam, not a wire method or a caller-selected mutation.
 * Every frame must cross dispatch before any StateStore read/replay/mutation. */
export type LocalControlConnection = Readonly<{
  socket: Socket;
  dispatch<T>(operation: (identity: AuthenticatedControlIdentity) => Promise<T>): Promise<T>;
  close(): void;
}>;
/** Owner lifecycle only: close drains dispatches, so never await it inside one. */
export type LocalControlListener = Readonly<{ close(): Promise<void> }>;
type LiveChannel = { digest: string; assertCurrent(): void };
const liveChannels = new WeakMap<StateOwnerContext, Map<string, LiveChannel>>();
type AuthenticatedFrame = { owner: StateOwnerContext; identity: AuthenticatedControlIdentity; channel: LiveChannel; active: boolean };
const authenticatedFrames = new AsyncLocalStorage<AuthenticatedFrame>();

function hashNativeImage(peer: HeldControlPeer, observation: NativePeerObservation): string {
  const before = fstatSync(observation.imageFd, { bigint: true });
  if (!before.isFile() || before.size !== BigInt(observation.imageByteCount) ||
      observation.imageByteCount <= 0 || observation.imageByteCount > 256 * 1024 * 1024) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control peer executable image is unavailable or unbounded');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(Math.min(observation.imageByteCount, 64 * 1024));
  for (let offset = 0; offset < observation.imageByteCount;) {
    const count = readSync(observation.imageFd, buffer, 0, Math.min(buffer.length, observation.imageByteCount - offset), offset);
    if (count === 0) throw new KernelStorageError('ARTIFACT_MISMATCH', 'control peer executable image ended early');
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  const after = fstatSync(observation.imageFd, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode ||
      before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control peer executable image changed while hashing');
  }
  peer.assertObservation(observation);
  return hash.digest('hex');
}

/** Owner-bound native listener. Historical JSON never populates this registry. */
export function openLocalControlListener(artifacts: ArtifactCatalog, owner: StateOwnerContext,
  onConnection: (connection: LocalControlConnection) => void, onError: (error: Error) => void): LocalControlListener {
  const channels = new Map<string, LiveChannel>();
  if (liveChannels.has(owner)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'the owner already has a control listener');
  let closing = false;
  let drain: Promise<void> | undefined;
  const connections = new Set<LocalControlConnection>();
  const pending = new Set<Promise<unknown>>();
  let native: HeldControlListener;
  const accept = (peer: HeldControlPeer) => {
    if (closing || connections.size >= 64) { peer.close(); return; }
    let socket: Socket;
    const fd = peer.takeSocketFd();
    try { socket = new Socket({ fd, readable: true, writable: true }); }
    catch (error) { closeSync(fd); peer.close(); throw error; }
    let closed = false;
    let capture: NativePeerObservation | undefined;
    let published: Promise<AuthenticatedControlIdentity> | undefined;
    let identity: AuthenticatedControlIdentity | undefined;
    const assertCurrent = () => {
      if (closing || closed || !capture) throw new KernelStorageError('ARTIFACT_MISMATCH', 'control connection is closed or unauthenticated');
      try { peer.assertObservation(capture); }
      catch (error) { throw new KernelStorageError('ARTIFACT_MISMATCH', 'control peer native identity changed or became unavailable', { cause: error }); }
    };
    const publish = async () => {
      const observedAt = sampleCanonicalNow();
      capture = peer.capture();
      const processIdentity: PlatformProcessIdentityV1 = {
        schemaVersion: 1, format: 'cliq-platform-process-identity-v1', platform: process.platform === 'linux' ? 'linux' : 'macos',
        pid: capture.pid, ownerUid: capture.uid, processStartToken: capture.processStartToken,
        executableImageDigest: hashNativeImage(peer, capture), observedAt, identityDigest: ''
      };
      processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
      const processArtifact = await artifacts.publishCanonical(processIdentity, processIdentity.format);
      const principal: LocalPrincipalIdentityV1 = {
        schemaVersion: 1, format: 'cliq-local-principal-identity-v1', platform: processIdentity.platform,
        stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
        effectiveUid: capture.uid,
        principalId: identityHash('cliq-local-principal-v1', owner.stateRootIdentityDigest, processIdentity.platform, capture.uid), identityDigest: ''
      };
      principal.identityDigest = digestOmitting(principal, 'identityDigest');
      const principalArtifact = await artifacts.publishCanonical(principal, principal.format);
      const observation: LocalSocketPeerObservationV1 = {
        schemaVersion: 1, format: 'cliq-local-socket-peer-observation-v1', platform: processIdentity.platform,
        stateRootIdentityRef: owner.stateRootIdentityRef, stateRootIdentityDigest: owner.stateRootIdentityDigest,
        listener: { canonicalRootRelativePath: 'runtime/control-v1.sock', fileType: 'unix_stream_socket',
          ...capture.listener, mode: 384 },
        acceptedSocket: { socketType: 'SOCK_STREAM', deviceId: capture.acceptedSocket.deviceId, fileId: capture.acceptedSocket.fileId },
        credentialApi: processIdentity.platform === 'linux' ? 'linux_so_peercred' : 'macos_getpeereid_local_peerpid',
        peerUid: capture.uid, peerGid: capture.gid, peerPid: capture.pid,
        peerProcessIdentityRef: processArtifact.ref, peerProcessIdentityDigest: processIdentity.identityDigest,
        observedAt, observationDigest: ''
      };
      observation.observationDigest = digestOmitting(observation, 'observationDigest');
      const peerArtifact = await artifacts.publishCanonical(observation, observation.format);
      const channel: LocalControlChannelIdentityV1 = {
        schemaVersion: 1, format: 'cliq-local-control-channel-identity-v1', client: 'rpc',
        principalIdentityRef: principalArtifact.ref, principalIdentityDigest: principal.identityDigest, principalId: principal.principalId,
        transport: { kind: 'uds_peer', peerObservationRef: peerArtifact.ref, peerObservationDigest: observation.observationDigest },
        openedAt: sampleCanonicalNow(), channelNonceDigest: sha256Bytes(randomBytes(32)), channelIdentityDigest: ''
      };
      channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
      decodeLocalPrincipalIdentity(principal);
      decodeLocalSocketPeerObservation(observation);
      decodeControlChannel(channel);
      const channelArtifact = await artifacts.publishCanonical(channel, channel.format);
      assertCurrent();
      identity = Object.freeze({ principalId: principal.principalId, channelIdentityRef: channelArtifact.ref,
        channelIdentityDigest: channel.channelIdentityDigest });
      channels.set(identity.channelIdentityRef, { digest: identity.channelIdentityDigest, assertCurrent });
      return identity;
    };
    const connection: LocalControlConnection = Object.freeze({
      socket,
      dispatch<T>(operation: (identity: AuthenticatedControlIdentity) => Promise<T>): Promise<T> {
        if (this !== connection || closing || closed || typeof operation !== 'function') return Promise.reject(new TypeError('invalid control connection dispatch'));
        const running = (async () => {
          if (pending.size >= 64) throw new KernelStorageError('INVALID_REQUEST', 'control dispatch capacity is exhausted');
          const authenticated = await (published ??= publish().catch(error => { connection.close(); throw error; }));
          assertCurrent();
          const authority = channels.get(authenticated.channelIdentityRef)!;
          const frame: AuthenticatedFrame = { owner, identity: authenticated, channel: authority, active: true };
          try { return await authenticatedFrames.run(frame, () => operation(authenticated)); }
          finally { frame.active = false; }
        })();
        pending.add(running);
        void running.finally(() => pending.delete(running)).catch(() => {});
        return running;
      },
      close() {
        if (this !== connection) throw new TypeError('invalid control connection');
        if (closed) return;
        closed = true;
        if (identity) channels.delete(identity.channelIdentityRef);
        capture?.close();
        peer.close();
        socket.destroy();
        connections.delete(connection);
      }
    });
    socket.on('error', () => connection.close());
    socket.once('close', () => connection.close());
    connections.add(connection);
    try { onConnection(connection); } catch (error) { connection.close(); throw error; }
  };
  native = owner.filesystem.openControlListener(accept, onError);
  liveChannels.set(owner, channels);
  const listener: LocalControlListener = Object.freeze({
    close() {
      if (this !== listener) return Promise.reject(new TypeError('invalid control listener'));
      if (drain) return drain;
      closing = true;
      native.close();
      for (const connection of connections) connection.close();
      liveChannels.delete(owner);
      drain = Promise.allSettled([...pending]).then(() => {});
      return drain;
    }
  });
  return listener;
}

/** Rewalk a historical channel against this database's retained StateRoot, without authenticating new input. */
export async function readHistoricalControlChannel(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: { channelIdentityRef: string; channelIdentityDigest: string; principalId: string }) {
  const owner = readLatestStateOwner(driver);
  if (!owner) throw new TypeError('control history has no retained state owner');
  const lock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, owner.stateLockIdentityRef));
  if (lock.identityDigest !== owner.stateLockIdentityDigest) throw new TypeError('control history state-owner lock mismatch');
  return readRetainedControlChannelClosure(artifacts, {
    stateRootIdentityRef: lock.stateRootIdentityRef, stateRootIdentityDigest: lock.stateRootIdentityDigest,
    filesystem: { root: { ownerUid: lock.ownerUid } }
  }, input);
}

export async function validateControlChannelClosure(
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: {
    channelIdentityRef: string;
    channelIdentityDigest: string;
    principalId: string;
  }
): Promise<{ channel: LocalControlChannelIdentityV1; metadata: PublishedArtifact[] }> {
  const closure = await readRetainedControlChannelClosure(artifacts, owner, input);
  const channel = closure.channel;
  if (channel.transport.kind === 'uds_peer') {
    const live = liveChannels.get(owner)?.get(input.channelIdentityRef);
    const frame = authenticatedFrames.getStore();
    if (!live || live.digest !== input.channelIdentityDigest || !frame?.active || frame.owner !== owner ||
        frame.channel !== live || frame.identity.channelIdentityRef !== input.channelIdentityRef ||
        frame.identity.channelIdentityDigest !== input.channelIdentityDigest || frame.identity.principalId !== input.principalId) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'control peer has no current native authenticated frame');
    }
    live.assertCurrent();
    return closure;
  }
  const [processIdentity, ownerProcessIdentity] = await Promise.all([
    artifacts.readCanonical(channel.transport.processIdentityRef).then(decodePlatformProcessIdentity),
    artifacts.readCanonical(owner.processIdentityRef).then(decodePlatformProcessIdentity)
  ]);
  if (ownerProcessIdentity.identityDigest !== owner.processIdentityDigest ||
      processIdentity.ownerUid !== ownerProcessIdentity.ownerUid ||
      processIdentity.platform !== ownerProcessIdentity.platform || processIdentity.pid !== ownerProcessIdentity.pid ||
      processIdentity.pid !== process.pid || processIdentity.processStartToken !== ownerProcessIdentity.processStartToken ||
      processIdentity.executableImageDigest !== ownerProcessIdentity.executableImageDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel process identity does not match the current owner');
  }
  return closure;
}

/** Historical audit only. A control-row owner must also bind these bytes; this never authenticates a new request. */
export async function readRetainedControlChannelClosure(
  artifacts: ArtifactCatalog,
  owner: Pick<StateOwnerContext, 'stateRootIdentityRef' | 'stateRootIdentityDigest'> & {
    filesystem: { root: Pick<StateOwnerContext['filesystem']['root'], 'ownerUid'> };
  },
  input: { channelIdentityRef: string; channelIdentityDigest: string; principalId: string }
): Promise<{ channel: LocalControlChannelIdentityV1; metadata: PublishedArtifact[] }> {
  const channel = decodeControlChannel(await artifacts.readCanonical(input.channelIdentityRef));
  if (
    channel.channelIdentityDigest !== input.channelIdentityDigest ||
    channel.principalId !== input.principalId
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel identity does not match the caller');
  }
  const principal = decodeLocalPrincipalIdentity(
    await artifacts.readCanonical(channel.principalIdentityRef)
  );
  const root = decodeStateRootIdentity(await artifacts.readCanonical(owner.stateRootIdentityRef));
  if (
    root.identityDigest !== owner.stateRootIdentityDigest ||
    root.ownerUid !== owner.filesystem.root.ownerUid ||
    principal.identityDigest !== channel.principalIdentityDigest ||
    principal.principalId !== input.principalId ||
    principal.stateRootIdentityRef !== owner.stateRootIdentityRef ||
    principal.stateRootIdentityDigest !== owner.stateRootIdentityDigest ||
    principal.platform !== root.platform ||
    principal.effectiveUid !== owner.filesystem.root.ownerUid
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel principal identity is not current');
  }
  const metadata = await Promise.all([
    artifacts.describe(input.channelIdentityRef, 'application/json', 'cliq-local-control-channel-identity-v1'),
    artifacts.describe(channel.principalIdentityRef, 'application/json', 'cliq-local-principal-identity-v1')
  ]);
  if (channel.transport.kind === 'in_process') {
    const processIdentity = decodePlatformProcessIdentity(await artifacts.readCanonical(channel.transport.processIdentityRef));
    if (
      processIdentity.identityDigest !== channel.transport.processIdentityDigest ||
      processIdentity.ownerUid !== owner.filesystem.root.ownerUid ||
      processIdentity.platform !== principal.platform ||
      processIdentity.observedAt !== channel.openedAt
    ) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'control channel process identity does not match');
    }
    metadata.push(
      await artifacts.describe(
        channel.transport.processIdentityRef,
        'application/json',
        'cliq-platform-process-identity-v1'
      )
    );
  } else {
    const peer = decodeLocalSocketPeerObservation(await artifacts.readCanonical(channel.transport.peerObservationRef));
    const processIdentity = decodePlatformProcessIdentity(await artifacts.readCanonical(peer.peerProcessIdentityRef));
    if (peer.observationDigest !== channel.transport.peerObservationDigest ||
        peer.stateRootIdentityRef !== principal.stateRootIdentityRef ||
        peer.stateRootIdentityDigest !== principal.stateRootIdentityDigest || peer.platform !== principal.platform ||
        peer.peerUid !== principal.effectiveUid || processIdentity.identityDigest !== peer.peerProcessIdentityDigest ||
        processIdentity.platform !== peer.platform || processIdentity.pid !== peer.peerPid ||
        processIdentity.ownerUid !== peer.peerUid || processIdentity.observedAt !== peer.observedAt ||
        parseCanonicalTime(channel.openedAt) < parseCanonicalTime(peer.observedAt)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained control peer closure does not match');
    }
    metadata.push(
      await artifacts.describe(channel.transport.peerObservationRef, 'application/json', 'cliq-local-socket-peer-observation-v1'),
      await artifacts.describe(peer.peerProcessIdentityRef, 'application/json', 'cliq-platform-process-identity-v1')
    );
  }
  return { channel, metadata };
}
