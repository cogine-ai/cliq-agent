import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { KernelStorageError } from '../state/errors.js';

export const CONTROL_LISTENER_ENTRY_ID = 'control_listener_native';
export const CONTROL_LISTENER_RELATIVE_PATH = `native/${process.platform}-${process.arch}/control-listener`;
const LOCAL_BINARY = fileURLToPath(new URL(`../../dist/${CONTROL_LISTENER_RELATIVE_PATH}`, import.meta.url));
const MAX_FRAME = 8 * 1024 * 1024;
const HEADER_SIZE = 13;

const enum EventKind { Ready = 1, Open = 2, Frame = 3, Closed = 4, Rechecked = 5 }
const enum CommandKind { Response = 6, Shutdown = 7, Close = 8, Recheck = 9 }

export type NativePeerObservation = Readonly<{
  platform: 'macos' | 'linux';
  endpoint: Readonly<{ deviceId: string; fileId: string; ownerUid: number; mode: number }>;
  listenerSocket: Readonly<{ deviceId: string; fileId: string }>;
  acceptedSocket: Readonly<{ deviceId: string; fileId: string }>;
  credentialApi: 'macos_getpeereid' | 'linux_so_peercred';
  peerUid: number;
  peerGid: number;
}>;

export type NativeControlConnection = Readonly<{
  id: string;
  peer: NativePeerObservation;
}>;

export type NativeControlRoot = Readonly<{
  root: Readonly<{ deviceId: string; fileId: string }>;
  runtime: Readonly<{ deviceId: string; fileId: string }>;
}>;

export type NativeControlHandlers = Readonly<{
  onOpen(connection: NativeControlConnection): Promise<void> | void;
  onFrame(connection: NativeControlConnection, frame: Buffer): Promise<Buffer> | Buffer;
  onClosed(connection: NativeControlConnection): void;
}>;

function sameStat(before: import('node:fs').BigIntStats, after: import('node:fs').BigIntStats): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.uid === after.uid &&
    before.mode === after.mode && before.nlink === after.nlink && before.size === after.size &&
    before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

async function verifyNativeBinary(bundle?: RuntimeBundleManifest): Promise<void> {
  const file = await open(LOCAL_BINARY, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.geteuid!()) || before.nlink !== 1n ||
        (before.mode & 0o7777n) !== 0o500n || before.size <= 0n || before.size > 16n * 1024n * 1024n) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native control listener must be an owner-only 0500 regular file');
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    if (!sameStat(before, after) || BigInt(bytes.byteLength) !== after.size) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'native control listener changed during verification');
    }
    if (bundle) {
      const entry = bundle.entries.find((candidate) => candidate.entryId === CONTROL_LISTENER_ENTRY_ID);
      const digest = createHash('sha256').update(bytes).digest('hex');
      if (!entry || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
          entry.relativePath !== CONTROL_LISTENER_RELATIVE_PATH || entry.digest !== digest ||
          entry.byteCount !== bytes.byteLength) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'native control listener differs from the signed RuntimeBundle');
      }
    }
  } finally {
    await file.close();
  }
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function decimal(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9]\d*)$/u.test(value);
}

function safeUid(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function parseNativePeer(bytes: Buffer): NativePeerObservation {
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native control peer observation is not JSON');
  }
  if (!exactRecord(value, ['platform', 'endpoint', 'listenerSocket', 'acceptedSocket', 'credentialApi', 'peerUid', 'peerGid']) ||
      !['macos', 'linux'].includes(String(value.platform)) ||
      value.platform !== (process.platform === 'darwin' ? 'macos' : 'linux') ||
      value.credentialApi !== (value.platform === 'macos' ? 'macos_getpeereid' : 'linux_so_peercred') ||
      !safeUid(value.peerUid) || !safeUid(value.peerGid) ||
      !exactRecord(value.endpoint, ['deviceId', 'fileId', 'ownerUid', 'mode']) ||
      !decimal(value.endpoint.deviceId) || !decimal(value.endpoint.fileId) ||
      !safeUid(value.endpoint.ownerUid) || value.endpoint.mode !== 384 ||
      !exactRecord(value.listenerSocket, ['deviceId', 'fileId']) ||
      !decimal(value.listenerSocket.deviceId) || !decimal(value.listenerSocket.fileId) ||
      !exactRecord(value.acceptedSocket, ['deviceId', 'fileId']) ||
      !decimal(value.acceptedSocket.deviceId) || !decimal(value.acceptedSocket.fileId) ||
      value.peerUid !== value.endpoint.ownerUid) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native control peer observation has an invalid closed shape');
  }
  return value as NativePeerObservation;
}

function encodeCommand(kind: CommandKind, id: bigint, payload: Buffer = Buffer.alloc(0)): Buffer {
  if (payload.byteLength > MAX_FRAME) throw new RangeError('control response exceeds the frame limit');
  const header = Buffer.allocUnsafe(HEADER_SIZE);
  header.writeUInt8(kind, 0);
  header.writeBigUInt64BE(id, 1);
  header.writeUInt32BE(payload.byteLength, 9);
  return payload.byteLength ? Buffer.concat([header, payload]) : header;
}

type ConnectionState = { connection: NativeControlConnection; opened: Promise<void>; closed: boolean };

/** Owns the native child and its private pipes; the child owns all UDS handles. */
export class NativeControlListener {
  private readonly connections = new Map<bigint, ConnectionState>();
  private readonly pendingRechecks = new Map<bigint, { resolve(): void; reject(error: Error): void }>();
  private input = Buffer.alloc(0);
  private stopped = false;
  private exitError: Error | undefined;
  private readonly exited: Promise<void>;
  private readonly ready: Promise<void>;
  private resolveReady!: () => void;
  private rejectReady!: (error: Error) => void;
  private resolveExit!: () => void;
  private readySeen = false;
  private stderr = '';

  private constructor(private readonly child: ChildProcessWithoutNullStreams,
                      private readonly handlers: NativeControlHandlers) {
    this.ready = new Promise<void>((resolve, reject) => { this.resolveReady = resolve; this.rejectReady = reject; });
    this.exited = new Promise<void>((resolve) => { this.resolveExit = resolve; });
    child.stdout.on('data', (chunk: Buffer) => this.receive(chunk));
    child.stderr.on('data', (chunk: Buffer) => {
      this.stderr = `${this.stderr}${chunk.toString('utf8')}`.slice(-8192);
    });
    child.on('error', (error) => this.fail(error));
    child.on('exit', (code, signal) => {
      if (!this.stopped) this.fail(new Error(`native control listener exited: ${signal ?? code}; ${this.stderr.trim()}`));
      for (const pending of this.pendingRechecks.values()) pending.reject(new Error('native control listener exited before recheck'));
      this.pendingRechecks.clear();
      for (const state of this.connections.values()) {
        if (!state.closed) { state.closed = true; this.handlers.onClosed(state.connection); }
      }
      this.connections.clear();
      this.resolveExit();
    });
    child.on('close', () => this.resolveExit());
  }

  static async start(stateRoot: string, expected: NativeControlRoot, handlers: NativeControlHandlers,
                     bundle?: RuntimeBundleManifest): Promise<NativeControlListener> {
    await verifyNativeBinary(bundle);
    for (const id of [expected.root.deviceId, expected.root.fileId,
      expected.runtime.deviceId, expected.runtime.fileId]) {
      if (!decimal(id) || id.length > 20) {
        throw new TypeError('native control requires held root/runtime descriptor identities');
      }
    }
    const child = spawn(LOCAL_BINARY, [stateRoot, expected.root.deviceId, expected.root.fileId,
      expected.runtime.deviceId, expected.runtime.fileId], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: path.parse(stateRoot).root,
      env: { PATH: '/usr/bin:/bin' }
    });
    const listener = new NativeControlListener(child, handlers);
    const startupTimeout = setTimeout(() => {
      listener.fail(new Error('native control listener did not become ready within 10 seconds'));
      child.kill('SIGKILL');
    }, 10_000);
    try {
      await listener.ready;
      return listener;
    } catch (error) {
      await listener.close().catch(() => {});
      throw error;
    } finally {
      clearTimeout(startupTimeout);
    }
  }

  private fail(error: Error): void {
    if (this.exitError) return;
    this.exitError = error;
    for (const pending of this.pendingRechecks.values()) pending.reject(error);
    this.pendingRechecks.clear();
    this.rejectReady(error);
    this.stopped = true;
    this.child.stdin.destroy();
  }

  private receive(chunk: Buffer): void {
    if (this.exitError) return;
    this.input = Buffer.concat([this.input, chunk]);
    if (this.input.byteLength > MAX_FRAME + HEADER_SIZE + 64 * 1024) {
      this.fail(new Error('native control pipe frame exceeds its bound'));
      return;
    }
    while (this.input.byteLength >= HEADER_SIZE) {
      const kind = this.input.readUInt8(0);
      const id = this.input.readBigUInt64BE(1);
      const length = this.input.readUInt32BE(9);
      if (length > MAX_FRAME) { this.fail(new Error('native control pipe declared an oversized frame')); return; }
      if (this.input.byteLength < HEADER_SIZE + length) return;
      const payload = this.input.subarray(HEADER_SIZE, HEADER_SIZE + length);
      this.input = this.input.subarray(HEADER_SIZE + length);
      try { this.deliver(kind, id, payload); } catch (error) {
        this.fail(error instanceof Error ? error : new Error('native control pipe protocol failed'));
        return;
      }
    }
  }

  private deliver(kind: number, id: bigint, payload: Buffer): void {
    if (kind === EventKind.Ready && id === 0n && payload.byteLength === 0) {
      if (this.readySeen) throw new Error('native control listener sent duplicate ready event');
      this.readySeen = true;
      this.resolveReady(); return;
    }
    if (!this.readySeen) throw new Error('native control listener sent a connection before ready');
    if (kind === EventKind.Open && id > 0n) {
      if (this.connections.has(id)) throw new Error('native control connection id repeated');
      const connection = Object.freeze({ id: id.toString(10), peer: parseNativePeer(payload) });
      const state: ConnectionState = {
        connection, closed: false,
        opened: Promise.resolve().then(() => this.handlers.onOpen(connection))
      };
      state.opened.catch(() => this.command(CommandKind.Close, id));
      this.connections.set(id, state);
      return;
    }
    const state = this.connections.get(id);
    if (!state) throw new Error('native control event has no open connection');
    if (kind === EventKind.Closed && payload.byteLength === 0) {
      this.pendingRechecks.get(id)?.reject(new Error('control connection closed before recheck'));
      this.pendingRechecks.delete(id);
      if (!state.closed) { state.closed = true; this.handlers.onClosed(state.connection); }
      this.connections.delete(id);
      return;
    }
    if (kind === EventKind.Rechecked && payload.byteLength === 0) {
      const pending = this.pendingRechecks.get(id);
      if (!pending) throw new Error('native control recheck had no pending request');
      this.pendingRechecks.delete(id);
      pending.resolve();
      return;
    }
    if (kind !== EventKind.Frame || state.closed) throw new Error('native control event kind is invalid');
    // The native child emits a frame only after revalidating the held socket and
    // endpoint. An already emitted frame may finish after a disconnect.
    void state.opened.then(() => {
      if (state.closed) throw new Error('control connection closed before request authentication');
      return this.handlers.onFrame(state.connection, payload);
    })
      .then((response) => this.command(CommandKind.Response, id, response))
      .catch(() => this.command(CommandKind.Close, id));
  }

  private command(kind: CommandKind, id: bigint, payload?: Buffer): void {
    if (this.exitError || this.child.stdin.destroyed || this.child.stdin.writableEnded) return;
    this.child.stdin.write(encodeCommand(kind, id, payload));
  }

  /** Recheck the same held descriptor and named endpoint immediately before the request cut. */
  recheck(connection: NativeControlConnection): Promise<void> {
    const id = BigInt(connection.id);
    const state = this.connections.get(id);
    if (this.stopped || this.exitError || !state || state.closed || state.connection !== connection ||
        this.pendingRechecks.has(id)) {
      return Promise.reject(new Error('control connection is not live for recheck'));
    }
    return new Promise<void>((resolve, reject) => {
      this.pendingRechecks.set(id, { resolve, reject });
      this.command(CommandKind.Recheck, id);
    });
  }

  async close(): Promise<void> {
    if (this.child.exitCode !== null || this.child.signalCode !== null) {
      await this.exited;
      return;
    }
    this.stopped = true;
    this.command(CommandKind.Shutdown, 0n);
    this.child.stdin.end();
    const term = setTimeout(() => this.child.kill('SIGTERM'), 5_000);
    const kill = setTimeout(() => this.child.kill('SIGKILL'), 8_000);
    let deadline: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        this.exited,
        new Promise<never>((_resolve, reject) => {
          deadline = setTimeout(() => reject(new Error('native control listener did not exit after shutdown')), 10_000);
        })
      ]);
    } finally {
      clearTimeout(term);
      clearTimeout(kill);
      if (deadline) clearTimeout(deadline);
    }
  }
}
