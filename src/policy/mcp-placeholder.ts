/**
 * MCP runtime placeholder for the AccessChannel permission system (#62).
 *
 * This file exists ONLY to document the integration contract for whoever
 * lands the MCP server runtime in a follow-up. It exports nothing
 * meaningful at runtime; the type-only `mcp` channel and its grammar /
 * decision-table support are already shipped in:
 *
 *   - src/policy/types.ts                  AccessChannel kind 'mcp'
 *   - src/policy/permissions-grammar.ts    "mcp: <server>/<tool>" parser
 *   - src/policy/decision-table.ts         matcher + primary-key helper
 *   - src/policy/compose-runtime.ts        layering across config / persisted / CLI
 *   - src/cli.ts                           --allow/--deny/--ask flags
 *   - .cliq/config.json `permissions:`     workspace-level rules
 *   - TUI ApprovalModal                    `[s]ession` / `Shift+W` scopes
 *
 * What's missing: the MCP runtime itself. Cliq does not invoke any MCP
 * server today, so no permission subject is ever built with
 * `channel: { kind: 'mcp', … }` outside tests.
 *
 * TODO(no-issue: MCP runtime). When MCP lands:
 *
 *   1. Build the subject at the MCP call site (NOT at the decision site)
 *      so the runner-driven PolicyEngine path applies uniformly:
 *
 *        const subject = buildToolApprovalSubject({
 *          definition: { name: 'mcp', access: 'exec' },
 *          action: { mcp: { server, tool, arguments } }
 *        });
 *
 *      Have `deriveChannel` in src/policy/subjects.ts return
 *      `{ kind: 'mcp', server, tool }` for that shape.
 *
 *   2. Add an "unknown server defaults to deny" rule to BUILTIN_DENY in
 *      src/policy/decision-table.ts once we know the server identifier
 *      convention. Until then, fail-closed via the preset (confirm-* or
 *      read-only will refuse mcp; auto will allow). Document the choice
 *      in README under ## Tool permissions.
 *
 *   3. Add `server` and `tool` fields to the ApprovalModal `ToolBody`
 *      renderer so users see the target before approving, mirroring how
 *      the bash modal already shows `command:`.
 *
 *   4. The "Always allow in this workspace" scope already persists
 *      `mcp: <server>/<tool>` rules via accessChannelPrimaryKey —
 *      no extra work needed there.
 */
export {};
