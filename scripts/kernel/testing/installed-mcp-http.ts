// Owned external service adapter. It supplies no Cliq authority, response
// receipt, retry instruction or replacement for the installed consumer.
import assert from 'node:assert/strict';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { INSTALLED_MCP_CASES, createInstalledMcpResponder, type InstalledMcpCase } from './installed-mcp-responder.js';

export function createInstalledMcpHttpHandler(scan: (bytes: Uint8Array) => void) {
  const responder = createInstalledMcpResponder();
  const pendingPings = new Map<InstalledMcpCase, ServerResponse>();
  const sockets = new Map<InstalledMcpCase, Set<IncomingMessage['socket']>>();
  const socketCases = new WeakMap<IncomingMessage['socket'], InstalledMcpCase>();
  const lastClosedAt = new Map<InstalledMcpCase, number>();
  let posts = 0, continuationFailed = false;
  return {
    responder,
    posts: () => posts,
    async waitForCaseJoined(kind: InstalledMcpCase, deadlineAt: number): Promise<void> {
      const original = sockets.get(kind); assert(original, 'the owned endpoint never observed an original MCP connection');
      // Observe the peer's real socket close before the surrounding finally
      // force-closes test services. Service cleanup cannot establish this.
      while (original.size) {
        assert(Date.now() < deadlineAt, 'the original MCP peer sockets did not actually join within the source window');
        await delay(Math.min(10, Math.max(1, deadlineAt - Date.now())));
      }
      assert((lastClosedAt.get(kind) ?? Infinity) < deadlineAt, 'the original MCP peer joined after the source window');
    },
    assertJoined(): void {
      assert.equal(pendingPings.size, 0, 'the owned MCP service still holds an original ping response');
      assert.equal(continuationFailed, false, 'the owned MCP continuation failed before it joined');
      for (const active of sockets.values()) assert.equal(active.size, 0, 'the owned MCP endpoint still observes an original live socket');
    },
    async handle(incoming: IncomingMessage, outgoing: ServerResponse): Promise<boolean> {
      if (!incoming.url?.startsWith('/mcp/')) return false;
      const kind = incoming.url.slice('/mcp/'.length);
      assert(INSTALLED_MCP_CASES.includes(kind as InstalledMcpCase), 'owned MCP route is outside the fixed campaign');
      const selected = kind as InstalledMcpCase;
      const prior = socketCases.get(incoming.socket);
      assert(prior === undefined || prior === selected, 'a logical MCP client reused another case connection');
      if (prior === undefined) {
        socketCases.set(incoming.socket, selected);
        let active = sockets.get(selected);
        if (!active) { active = new Set(); sockets.set(selected, active); }
        active.add(incoming.socket);
        incoming.socket.once('close', () => { active!.delete(incoming.socket); lastClosedAt.set(selected, Date.now()); });
      }
      assert.equal(incoming.method, 'POST', 'the owned MCP recipe has no GET, DELETE, session or replay endpoint');
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const value of incoming) {
        size += value.length;
        assert(size <= 1_048_576, 'owned MCP request exceeds the original byte bound');
        chunks.push(Buffer.from(value));
      }
      const bytes = Buffer.concat(chunks);
      scan(bytes);
      assert.equal(Number(incoming.headers['content-length']), bytes.length);
      const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      const reply = responder.accept(selected, value, incoming.headers);
      posts++;
      if (reply.kind === 'disconnect_after_effect') {
        // The actual external counter has advanced. There are deliberately no
        // response bytes to convert into a successful result or safe retry.
        outgoing.destroy(); return true;
      }
      if (reply.kind === 'ack' || reply.kind === 'ping_ack') {
        outgoing.writeHead(202, { 'Content-Length': '0', Connection: 'close' });
        if (reply.kind === 'ping_ack') {
          const original = pendingPings.get(selected);
          assert(original && !original.destroyed && !original.writableEnded, 'the exact original ping stream has already closed');
          pendingPings.delete(selected);
          scan(reply.continuation);
          // The whole finite record is one write, including the deliberate
          // read-ahead tail. The installed capture must account for whatever
          // the real transport receives; this adapter does not mint a receipt.
          outgoing.once('finish', () => {
            try {
              assert(!original.destroyed && !original.writableEnded);
              original.write(reply.continuation);
            } catch { continuationFailed = true; original.destroy(); }
          });
        }
        outgoing.end(); return true;
      }
      scan(reply.bytes);
      outgoing.writeHead(200, { 'Content-Type': reply.mediaType, Connection: 'close',
        ...(!reply.holdOpen ? { 'Content-Length': String(reply.bytes.length) } : {}) });
      if (reply.awaitingPingReply) {
        assert(!pendingPings.has(selected), 'an owned case cannot replace its pending original stream');
        pendingPings.set(selected, outgoing);
        outgoing.once('error', () => { continuationFailed = true; });
        outgoing.once('close', () => { if (pendingPings.get(selected) === outgoing) pendingPings.delete(selected); });
      }
      if (reply.holdOpen) outgoing.write(reply.bytes);
      else outgoing.end(reply.bytes);
      return true;
    }
  };
}
