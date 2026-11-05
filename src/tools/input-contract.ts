import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { decodeMcpRecoveryContract, type McpRecoveryContractV1 } from '../kernel/mcp.js';
import { injectMcpIdempotencyKey } from '../kernel/mcp-recovery.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import type { ToolContractManifestV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ResolveToolInput } from '../model/attempt.js';
import type { PolicySubject } from '../policy/decision.js';
import type { ToolInvocation } from '../protocol/agent-ir.js';
import { builtinInputContracts } from './builtin-inputs.js';
import { compileInputSchema } from './input-schema.js';
import { BUILTIN_SCRIPT_TOOL_NAMES, decodeToolExecutionIdentity } from './execution-identity.js';

export type ToolInputAuthority = ToolContractManifestV1['entries'][number] & { inputSchema: unknown;
  /** Reproduced from the exact original registry, not part of manifest bytes
   * or authority independent of that original registry's full validation. */
  mcpRecovery?: McpRecoveryContractV1 };
type ParsedInput = { input: Record<string, unknown>; channel?: Extract<PolicySubject, { kind: 'tool' }>['channel'];
  display: Extract<PolicySubject, { kind: 'tool' }>['display'] };

/** One frozen contract owns validation, normalized intent and invocation display. None is execution permission. */
export function loadToolContracts(tools: readonly ToolInputAuthority[]) {
  const contracts = new Map(tools.map((value) => {
    const { inputSchema, mcpRecovery, ...entry } = immutableSnapshot(value);
    if (canonicalSha256(inputSchema) !== entry.inputSchemaRef || entry.inputSchemaRef !== entry.inputSchemaDigest) {
      throw new TypeError('tool input schema does not match its frozen reference');
    }
    const execution = decodeToolExecutionIdentity(entry.execution);
    if (execution.kind !== 'mcp' && mcpRecovery !== undefined) throw new TypeError('ordinary input cannot borrow MCP normalization metadata');
    const recovery = mcpRecovery === undefined ? undefined : decodeMcpRecoveryContract(mcpRecovery);
    if (execution.kind === 'mcp' && (recovery?.kind ?? 'manual') !== entry.replayClass)
      throw new TypeError('MCP input lacks its exact original recovery contract');
    let parseInput: (value: unknown) => ParsedInput | undefined;
    if (execution.kind === 'builtin' || execution.kind === 'builtin_script' || execution.kind === 'supervisor_control' || execution.kind === 'supervisor_operation') {
      const name = execution.kind === 'builtin' ? execution.adapterId : entry.name;
      const builtin = Object.hasOwn(builtinInputContracts, name)
        ? builtinInputContracts[name as keyof typeof builtinInputContracts] : undefined;
      const script = execution.kind === 'builtin_script';
      const control = execution.kind === 'supervisor_control';
      if (!builtin || entry.name !== builtin.name || entry.version !== builtin.version ||
          ('adapterVersion' in execution && execution.adapterVersion !== builtin.version) ||
          entry.access !== builtin.access || entry.replayClass !== builtin.replayClass || canonicalSha256(builtin.inputSchema) !== entry.inputSchemaDigest ||
          (script && !BUILTIN_SCRIPT_TOOL_NAMES.some(name => name === entry.name)) ||
          (entry.access === 'control') !== control || (execution.kind === 'supervisor_operation' &&
            (!['delegate', 'skill_resource'].includes(entry.name) || execution.handlerId !== entry.name)) ||
          (control && (entry.name !== execution.handlerId || !['request_input', 'await_children'].includes(entry.name) ||
            Object.hasOwn(entry, 'outputSchemaRef') || Object.hasOwn(entry, 'outputSchemaDigest')))) {
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
          display: { title: 'Allow MCP tool?', server: execution.registrationId, tool: execution.serverToolName, detail: canonicalJsonBytes(input).toString('utf8') } };
      };
    } else throw new TypeError('unknown tool execution contract');
    return [entry.name, { entry, entryDigest: canonicalSha256(entry), parseInput, recovery }] as const;
  }));
  if (contracts.size !== tools.length) throw new TypeError('tool names must be unique');
  const resolveToolInput: ResolveToolInput = ({ runId, batchItemId, callId, index, toolName, observedInput }) => {
    const contract = contracts.get(toolName);
    let parsed: ParsedInput | undefined;
    if (contract && observedInput.encoding === 'jcs_json') {
      let value: unknown = observedInput.value;
      const pointer = contract.recovery?.kind === 'retry' || contract.recovery?.kind === 'reconcile'
        ? contract.recovery.idempotencyKeyInjection?.jsonPointer : undefined;
      if (pointer !== undefined) {
        const execution = contract.entry.execution;
        if (execution.kind !== 'mcp' || !runId || !batchItemId) throw new TypeError('MCP normalization lacks its original Run/batch identities');
        const opId = identityHash('cliq-tool-operation-v1', runId, batchItemId, callId);
        const key = identityHash('cliq-mcp-tool-idempotency-v1', runId, opId, execution.registryRevisionRef, execution.serverToolName);
        try { value = injectMcpIdempotencyKey(value, pointer, key); }
        catch (error) { if (!(error instanceof TypeError)) throw error; value = undefined; }
      }
      if (value !== undefined) parsed = contract.parseInput(value);
    }
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
      const common = { invocation, execution: contract.entry.execution, manifestEntryDigest: contract.entryDigest,
        display: parsed.display, loopSignature: canonicalSha256(['cliq-tool-loop-v1', contract.entryDigest, parsed.input]) };
      if (contract.entry.access === 'control') return immutableSnapshot({ ...common, kind: 'input' as const });
      if (!parsed.channel) throw new TypeError('ordinary tool has no policy intent');
      const subject: Extract<PolicySubject, { kind: 'tool' }> = { kind: 'tool', toolName: call.toolName,
        access: contract.entry.access, channel: parsed.channel, display: parsed.display };
      return immutableSnapshot({ ...common, kind: 'tool' as const, subject });
    }
  });
}
