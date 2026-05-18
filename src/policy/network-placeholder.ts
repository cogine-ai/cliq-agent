/**
 * Network channel placeholder for the AccessChannel permission system (#62).
 *
 * Like mcp-placeholder.ts, this file documents the integration contract
 * for a feature whose runtime hasn't landed. Cliq tools do not perform
 * outbound HTTP today (the model client's fetch() is plumbing, not a
 * model-issued tool call), so no permission subject is ever built with
 * `channel: { kind: 'network', … }` outside tests.
 *
 * What IS shipped:
 *
 *   - src/policy/types.ts                  AccessChannel kind 'network'
 *   - src/policy/permissions-grammar.ts    "network: <host>" parser
 *   - src/policy/decision-table.ts         matcher + primary-key helper
 *   - workspace config / CLI / TUI scopes  already accept network rules
 *
 * TODO(#63): real enforcement is the job of the OS sandbox layer. Recording
 * a `deny: network: api.example.com` rule today changes what the modal
 * asks (and may auto-deny a model-issued network tool call once #63
 * lands) but it does NOT prevent process-level egress on its own. The
 * sandbox layer (netns / firewall / DNS allowlist) is the only place
 * where a `deny` rule can be enforced against an adversarial tool.
 *
 * When a network-capable tool gets added before #63 sandboxing exists:
 *
 *   1. Build the subject at the network call site:
 *
 *        const subject = buildToolApprovalSubject({
 *          definition: { name: 'http', access: 'exec' },
 *          action: { http: { url, method } }
 *        });
 *
 *      and have `deriveChannel` in src/policy/subjects.ts return
 *      `{ kind: 'network', host: new URL(url).host }`.
 *
 *   2. Document loudly in README that without #63, network rules are
 *      "intent only" — they keep humans honest but don't stop a malicious
 *      action from making a side-channel egress.
 */
export {};
