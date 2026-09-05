import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import type { ToolContractManifestV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ResolveToolInput } from '../model/attempt.js';
import type { PolicySubject } from '../policy/decision.js';
import type { ToolInvocation } from '../protocol/agent-ir.js';
import { builtinInputContracts } from './builtin-inputs.js';
import { compileInputSchema } from './input-schema.js';

export type ToolInputAuthority = ToolContractManifestV1['entries'][number] & { inputSchema: unknown };
type ParsedInput = { input: Record<string, unknown> } & Pick<Extract<PolicySubject, { kind: 'tool' }>, 'channel' | 'display'>;

/** One frozen contract owns validation, normalized intent and invocation display. None is execution permission. */
export function loadToolContracts(tools: readonly ToolInputAuthority[]) {
  const contracts = new Map(tools.map((value) => {
    const { inputSchema, ...entry } = immutableSnapshot(value);
    if (canonicalSha256(inputSchema) !== entry.inputSchemaRef || entry.inputSchemaRef !== entry.inputSchemaDigest) {
      throw new TypeError('tool input schema does not match its frozen reference');
    }
    let parseInput: (value: unknown) => ParsedInput | undefined;
    if (entry.execution.kind === 'builtin') {
      const builtin = Object.hasOwn(builtinInputContracts, entry.execution.adapterId)
        ? builtinInputContracts[entry.execution.adapterId as keyof typeof builtinInputContracts] : undefined;
      if (!builtin || entry.name !== builtin.name || entry.version !== builtin.version || entry.execution.adapterVersion !== builtin.version ||
          entry.access !== builtin.access || entry.replayClass !== builtin.replayClass || canonicalSha256(builtin.inputSchema) !== entry.inputSchemaDigest) {
        throw new TypeError('builtin contract differs from the compiled input semantics');
      }
      parseInput = builtin.parseInput;
    } else if (entry.execution.kind === 'mcp') {
      if (entry.access !== 'exec' || entry.version !== 'mcp-tool-contract-v1') throw new TypeError('MCP input requires a final exec-class tool contract');
      const execution = entry.execution;
      const parse = compileInputSchema(inputSchema);
      parseInput = (value) => {
        const input = parse(value);
        return input === undefined ? undefined : { input,
          channel: { kind: 'mcp', server: execution.registrationId, tool: execution.serverToolName },
          display: { title: 'Allow MCP tool?', server: execution.registrationId, tool: execution.serverToolName } };
      };
    } else throw new TypeError('unknown tool execution contract');
    return [entry.name, { entry, entryDigest: canonicalSha256(entry), parseInput }] as const;
  }));
  if (contracts.size !== tools.length) throw new TypeError('tool names must be unique');
  const resolveToolInput: ResolveToolInput = ({ callId, index, toolName, observedInput }) => {
    const contract = contracts.get(toolName);
    const parsed = contract && observedInput.encoding === 'jcs_json' ? contract.parseInput(observedInput.value) : undefined;
    if (contract && parsed) return { kind: 'resolved', inputSchemaRef: contract.entry.inputSchemaRef,
      inputSchemaDigest: contract.entry.inputSchemaDigest, value: immutableSnapshot(parsed.input) };
    // Rejected arguments never enter diagnostics or ordinary model-visible error content.
    const base = { schemaVersion: 1, format: 'cliq-tool-input-diagnostic-v1', callId, index, toolName,
      code: contract ? 'TOOL_INPUT_INVALID' : 'TOOL_NOT_FOUND' };
    const diagnosticDigest = canonicalSha256(base);
    const diagnostic = planCanonicalArtifact({ ...base, diagnosticDigest }, base.format);
    return contract
      ? { kind: 'invalid_input', inputSchemaRef: contract.entry.inputSchemaRef, inputSchemaDigest: contract.entry.inputSchemaDigest, diagnostic, diagnosticDigest }
      : { kind: 'unknown_tool', diagnostic, diagnosticDigest };
  };
  return Object.freeze({ resolveToolInput,
    projectInvocation(call: { callId: string; index: number; toolName: string; input: Record<string, unknown> }) {
      const contract = contracts.get(call.toolName);
      const parsed = contract?.parseInput(call.input);
      if (!contract || !parsed || canonicalSha256(parsed.input) !== canonicalSha256(call.input) ||
          typeof call.callId !== 'string' || !call.callId || call.callId.includes('\0') || Buffer.byteLength(call.callId) > 512 ||
          !Number.isSafeInteger(call.index) || call.index < 0) throw new TypeError('invocation requires a resolved, normalized tool input');
      const invocation: ToolInvocation = { callId: call.callId, index: call.index, toolName: call.toolName,
        input: parsed.input, replayClass: contract.entry.replayClass };
      const subject: Extract<PolicySubject, { kind: 'tool' }> = { kind: 'tool', toolName: call.toolName,
        access: contract.entry.access, channel: parsed.channel, display: parsed.display };
      return immutableSnapshot({ invocation, subject, execution: contract.entry.execution, manifestEntryDigest: contract.entryDigest,
        loopSignature: canonicalSha256(['cliq-tool-loop-v1', contract.entryDigest, parsed.input]) });
    }
  });
}
