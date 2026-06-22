/**
 * MCP runtime placeholder for the AccessChannel permission system (#62).
 *
 * This file exists ONLY to document the integration contract for whoever
 * lands the MCP server runtime in a follow-up. It exports nothing
 * meaningful at runtime; the type-only `mcp` channel and its grammar /
 * decision-table support are already shipped in:
 *
 *   - src/policy/types.ts                  AccessChannel kind 'mcp'
 *   - src/protocol/model/actions.ts        "mcp" model action shape
 *   - src/policy/subjects.ts               action-driven MCP approval subject
 *   - src/policy/permissions-grammar.ts    "mcp: <server>/<tool>" parser
 *   - src/policy/decision-table.ts         matcher + primary-key helper
 *   - src/policy/compose-runtime.ts        layering across config / persisted / CLI
 *   - src/cli.ts                           --allow/--deny/--ask flags
 *   - .cliq/config.json `permissions:`     workspace-level rules
 *   - TUI ApprovalModal                    `[s]ession` / `Shift+W` scopes
 *                                        and MCP target fields
 *
 * What's missing: the MCP runtime itself. Cliq does not invoke any MCP
 * server today, so the runtime cannot execute `{ mcp: ... }` actions yet.
 *
 * TODO(no-issue: MCP runtime): When the MCP execution runtime lands:
 *
 *   1. Register MCP-backed tools or otherwise route MCP actions through the
 *      runner so the existing PolicyEngine path applies uniformly:
 *
 *        const subject = buildToolApprovalSubject({
 *          definition: { name: 'mcp', access: 'exec' },
 *          action: { mcp: { server, tool, arguments } }
 *        });
 *
 *   2. Add an "unknown server defaults to deny" rule to BUILTIN_DENY in
 *      src/policy/decision-table.ts once we know the server identifier
 *      convention. Until then, fail-closed via the preset (plan refuses
 *      non-read MCP; yolo allows normal MCP). Document the choice
 *      in README under ## Tool permissions.
 *
 *   3. The "Always allow in this workspace" scope already persists
 *      `mcp: <server>/<tool>` rules via accessChannelPrimaryKey —
 *      no extra work needed there.
 */
export {};
