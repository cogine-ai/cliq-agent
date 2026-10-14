// Test-private, read-only identification of initial hello publication, not
// NativeProof, hello acknowledgement, readSecret entry or credential authority.
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, opendir, readFile, stat, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseCanonicalTime, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { PlatformProcessIdentityV1 } from '../../../src/kernel/types.js';
import { decodeControlChannel, decodeLocalPrincipalIdentity, decodeLocalSocketPeerObservation,
  decodePlatformProcessIdentity, decodeStateRootIdentity } from '../../../src/state/decoders.js';

type Input = Readonly<{ stateRoot: string; originalAuth: Readonly<{ pid: number; start: string; uid: number }>;
  selectedImage: string; selectedImageDigest: string; expectedRootDigest: string; expectedPrincipalId: string;
  baselineCASrefs: readonly string[] }>;
type ObservedHello = Readonly<{ channelIdentityRef: string; channelIdentityDigest: string; peerObservationRef: string;
  peerProcessIdentityRef: string; principalIdentityRef: string; stateRootIdentityRef: string;
  processIdentity: PlatformProcessIdentityV1 }>;
const refPattern = /^[0-9a-f]{64}$/u, fileLimit = 1048576, totalLimit = 8 * fileLimit;
const channelPrefix = Buffer.from('{"channelIdentityDigest":');
const physical = (info: BigIntStats) => [info.dev, info.ino, info.uid, info.gid, info.mode, info.nlink,
  info.size, info.mtimeNs, info.ctimeNs].join(':');
const directoryIdentity = (info: BigIntStats) => [info.dev, info.ino, info.uid, info.gid, info.mode].join(':');
const check = (value: unknown): void => { if (!value) throw new Error('initial credential hello observation refused'); };

/** Caller owns the actual signed auth child and leaves its input unwritten.
 * Source order is initial classifier -> initial hello -> input -> reconnect;
 * publication identifies only the first hello dispatch, never its ACK. */
export async function observeInitialCredentialHello(input: Input): Promise<ObservedHello | undefined> {
  const directories: { handle: FileHandle; filename: string; info: BigIntStats }[] = [];
  const handles = new Set<FileHandle>(), publicationPending = Symbol();
  const retire = async (handle: FileHandle) => { handles.delete(handle); await handle.close(); };
  try {
    check(process.platform === 'linux' && process.geteuid!() === 0);
    check(/^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/probe\/credential-state$/u.test(input.stateRoot));
    const { pid, start, uid } = input.originalAuth;
    check(Number.isSafeInteger(pid) && pid > 0 && Number.isSafeInteger(uid) && uid > 0 && /^[1-9][0-9]*$/u.test(start));
    check(refPattern.test(input.selectedImageDigest) && refPattern.test(input.expectedRootDigest));
    check(path.isAbsolute(input.selectedImage) && path.normalize(input.selectedImage) === input.selectedImage &&
      path.dirname(input.selectedImage).startsWith(`${input.stateRoot}/runtime/bundles/`) &&
      /^runtime\/bundles\/[0-9a-f]{64}\/supervisor$/u.test(path.relative(input.stateRoot, input.selectedImage)));
    check(Array.isArray(input.baselineCASrefs) && input.baselineCASrefs.length <= 1024);
    const baseline = new Set(input.baselineCASrefs);
    check(baseline.size === input.baselineCASrefs.length && [...baseline].every(ref => refPattern.test(ref)));
    const selected = await lstat(input.selectedImage, { bigint: true });
    check(selected.isFile() && !selected.isSymbolicLink() && selected.uid === BigInt(uid) &&
      selected.nlink === 1n && (selected.mode & 0o7777n) === 0o500n && selected.size > 0n);
    const currentAuth = async () => {
      try {
        const raw = await readFile(`/proc/${pid}/stat`, 'utf8'); check(raw.length <= 8192 && raw.startsWith(`${pid} (`));
        const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u); check(fields.length > 19);
        if (fields[19] !== start) return false;
        const status = await readFile(`/proc/${pid}/status`, 'utf8'); check(status.length <= 16384);
        const observedUid = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu); check(observedUid);
        if (!observedUid!.slice(1).every(value => Number(value) === uid)) return false;
        const image = await stat(`/proc/${pid}/exe`, { bigint: true });
        const again = await readFile(`/proc/${pid}/stat`, 'utf8'); check(again.length <= 8192 && again.startsWith(`${pid} (`));
        return again.slice(again.lastIndexOf(')') + 2).trim().split(/\s+/u)[19] === start && physical(image) === physical(selected);
      } catch (error) { if (['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) return false; throw error; }
    };
    if (!await currentAuth()) return undefined;
    const openDirectory = async (filename: string, parent?: typeof directories[number]) => {
      const locator = parent ? `/proc/self/fd/${parent.handle.fd}/${path.basename(filename)}` : filename;
      const before = await lstat(locator, { bigint: true }); check(before.isDirectory() && !before.isSymbolicLink());
      const handle = await open(locator, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      handles.add(handle);
      const directory = { handle, filename, info: before }; directories.push(directory);
      check(directoryIdentity(await handle.stat({ bigint: true })) === directoryIdentity(before)); return directory;
    };
    let directory = await openDirectory('/');
    for (const component of input.stateRoot.split('/').filter(Boolean)) directory = await openDirectory(path.join(directory.filename, component), directory);
    const root = directory;
    for (const [index, ancestor] of directories.entries()) {
      check(ancestor.info.uid === BigInt(index < 4 ? 0 : uid));
      check((ancestor.info.mode & 0o7777n) === BigInt(index === 2 ? 0o1777 : index < 4 ? 0o755 : 0o700));
    }
    let imageParent = root;
    for (const component of path.relative(input.stateRoot, path.dirname(input.selectedImage)).split('/')) {
      imageParent = await openDirectory(path.join(imageParent.filename, component), imageParent);
      check(imageParent.info.uid === BigInt(uid) && (imageParent.info.mode & 0o7777n) === 0o700n);
    }
    check(physical(await lstat(`/proc/self/fd/${imageParent.handle.fd}/supervisor`, { bigint: true })) === physical(selected));
    const cas = await openDirectory(path.join(input.stateRoot, 'cas'), root);
    check(cas.info.uid === BigInt(uid) && (cas.info.mode & 0o7777n) === 0o700n);
    const names = async () => {
      const entries: string[] = [], enumeration = await opendir(`/proc/self/fd/${cas.handle.fd}`);
      try { for (;;) { const entry = await enumeration.read(); if (!entry) break; check(entries.length < 1024); entries.push(entry.name); } }
      finally { await enumeration.close(); }
      check(entries.every(name => refPattern.test(name) || /^\.tmp-(?:stream|[0-9a-f]{64})-[0-9a-f]{32}$/u.test(name))); return entries;
    };
    const candidates = (await names()).filter(name => refPattern.test(name) && !baseline.has(name));
    let bytesRead = 0;
    const values = new Map<string, unknown>();
    const read = async (ref: string, channelCandidate = false): Promise<unknown> => {
      check(refPattern.test(ref)); if (values.has(ref)) return values.get(ref);
      const filename = `/proc/self/fd/${cas.handle.fd}/${ref}`, before = await lstat(filename, { bigint: true });
      check(before.isFile() && !before.isSymbolicLink() && before.uid === BigInt(uid) &&
        (before.mode & 0o7777n) === 0o400n && before.size > 0n && before.size <= BigInt(fileLimit));
      if (before.nlink !== 1n) {
        check(before.nlink === 2n);
        const linked = (await names()).filter(name => new RegExp(`^\\.tmp-${ref}-[0-9a-f]{32}$`, 'u').test(name)); check(linked.length === 1);
        const temporary = `/proc/self/fd/${cas.handle.fd}/${linked[0]}`, staged = await lstat(temporary, { bigint: true });
        check(staged.isFile() && !staged.isSymbolicLink() && physical(staged) === physical(before));
        check(physical(await lstat(filename, { bigint: true })) === physical(before) &&
          physical(await lstat(temporary, { bigint: true })) === physical(staged));
        throw publicationPending; // Only a positively observed same-inode link/unlink publication is pending.
      }
      bytesRead += Number(before.size); check(bytesRead <= totalLimit);
      const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      handles.add(handle);
      let bytes: Buffer | undefined, extra: Buffer | undefined;
      try {
        bytes = Buffer.alloc(Number(before.size)); extra = Buffer.alloc(1);
        check(physical(await handle.stat({ bigint: true })) === physical(before));
        let offset = 0; while (offset < bytes.length) { const item = await handle.read(bytes, offset, bytes.length - offset, offset); check(item.bytesRead > 0); offset += item.bytesRead; }
        check((await handle.read(extra, 0, 1, offset)).bytesRead === 0 && sha256Bytes(bytes) === ref);
        check(physical(await handle.stat({ bigint: true })) === physical(before) && physical(await lstat(filename, { bigint: true })) === physical(before));
        // CAS also contains opaque bytes. The source canonical channel prefix
        // selects candidates only; closure bytes always pass strict decoders.
        if (channelCandidate && !bytes.subarray(0, channelPrefix.length).equals(channelPrefix)) return undefined;
        const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); check(canonicalJsonBytes(value).equals(bytes));
        values.set(ref, value); return value;
      } finally { bytes?.fill(0); extra?.fill(0); await retire(handle); }
    };
    let result: ObservedHello | undefined;
    for (const ref of candidates) {
      const value = await read(ref, true); if ((value as { format?: unknown })?.format !== 'cliq-local-control-channel-identity-v1') continue;
      const channel = decodeControlChannel(value); if (channel.client !== 'rpc' || channel.transport.kind !== 'uds_peer') continue;
      const peer = decodeLocalSocketPeerObservation(await read(channel.transport.peerObservationRef));
      const processIdentity = decodePlatformProcessIdentity(await read(peer.peerProcessIdentityRef));
      if (processIdentity.pid !== pid || processIdentity.processStartToken !== `linux-proc-start-ticks:${start}`) continue;
      const principal = decodeLocalPrincipalIdentity(await read(channel.principalIdentityRef));
      const retainedRoot = decodeStateRootIdentity(await read(principal.stateRootIdentityRef));
      check(channel.principalId === input.expectedPrincipalId && channel.principalIdentityDigest === principal.identityDigest &&
        principal.principalId === input.expectedPrincipalId && principal.effectiveUid === uid && principal.platform === 'linux' &&
        retainedRoot.platform === 'linux' && retainedRoot.identityDigest === input.expectedRootDigest && retainedRoot.ownerUid === uid &&
        retainedRoot.canonicalAbsolutePath === input.stateRoot && retainedRoot.deviceId === root.info.dev.toString() && retainedRoot.directoryFileId === root.info.ino.toString());
      check(principal.stateRootIdentityDigest === retainedRoot.identityDigest && peer.stateRootIdentityRef === principal.stateRootIdentityRef &&
        peer.stateRootIdentityDigest === retainedRoot.identityDigest && peer.platform === 'linux' && peer.peerUid === uid && peer.peerPid === pid &&
        peer.observationDigest === channel.transport.peerObservationDigest && processIdentity.identityDigest === peer.peerProcessIdentityDigest &&
        processIdentity.platform === 'linux' && processIdentity.ownerUid === uid && processIdentity.executableImageDigest === input.selectedImageDigest &&
        processIdentity.observedAt === peer.observedAt && parseCanonicalTime(channel.openedAt) >= parseCanonicalTime(peer.observedAt));
      check(!result); // Unwritten input permits only the initial hello, never an arbitrary choice among channels.
      result = Object.freeze({ channelIdentityRef: ref, channelIdentityDigest: channel.channelIdentityDigest,
        peerObservationRef: channel.transport.peerObservationRef, peerProcessIdentityRef: peer.peerProcessIdentityRef,
        principalIdentityRef: channel.principalIdentityRef, stateRootIdentityRef: principal.stateRootIdentityRef,
        processIdentity: Object.freeze(processIdentity) });
    }
    for (const held of directories) check(directoryIdentity(await held.handle.stat({ bigint: true })) === directoryIdentity(held.info) &&
      directoryIdentity(await lstat(held.filename, { bigint: true })) === directoryIdentity(held.info));
    check(physical(await lstat(input.selectedImage, { bigint: true })) === physical(selected));
    return await currentAuth() ? result : undefined;
  } catch (error) { if (error === publicationPending) return undefined; throw new Error('initial credential hello observation refused'); }
  finally {
    const retired = await Promise.allSettled([...handles].reverse().map(retire));
    check(retired.every(result => result.status === 'fulfilled'));
  }
}
