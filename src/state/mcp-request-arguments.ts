// One exact argument derivation for actual HTTP/stdio wire recipes and their
// historical audits. It grants no release or retry permission.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodeMcpRegistryRevision, type McpRegistryRevisionV1 } from '../kernel/mcp.js';
import { injectMcpIdempotencyKey } from '../kernel/mcp-recovery.js';
import type { ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { compileInputSchema } from '../tools/input-schema.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';

export async function readMcpRequestArguments(artifacts: ArtifactCatalog, input: Readonly<{
  request: ToolRequestV1; target: ToolTargetV1; registry: McpRegistryRevisionV1; registryRef: string; call: ToolCallInputV1;
}>): Promise<Readonly<Record<string, unknown>>> {
  const { request, target, call } = input, registry = decodeMcpRegistryRevision(input.registry), execution = target.execution;
  if (execution.kind !== 'mcp' || canonicalSha256(registry) !== input.registryRef || execution.registryRevisionRef !== input.registryRef ||
      execution.registryManifestDigest !== registry.manifestDigest || execution.registrationId !== registry.registrationId ||
      request.format !== 'cliq-tool-request-v1' || request.requestDigest !== digestOmitting(request, 'requestDigest') ||
      target.targetDigest !== digestOmitting(target, 'targetDigest') || request.targetRef !== canonicalSha256(target) || request.targetDigest !== target.targetDigest ||
      call.format !== 'cliq-tool-call-input-v1' || call.disposition !== 'resolved' || call.inputDigest !== digestOmitting(call, 'inputDigest') ||
      request.inputRef !== canonicalSha256(call) || request.inputDigest !== call.inputDigest || request.toolName !== call.toolName ||
      request.callId !== call.callId || request.callIndex !== call.index || request.runId !== target.runId ||
      request.idempotencyKey !== identityHash('cliq-mcp-tool-idempotency-v1', request.runId, request.opId, input.registryRef, execution.serverToolName))
    throw new TypeError('MCP arguments substitute the exact frozen original request/target/call/stable key');
  const tools = registry.tools.filter(tool => tool.name === execution.serverToolName), tool = tools[0];
  if (tools.length !== 1 || !tool || tool.toolContractDigest !== execution.toolContractDigest || tool.inputSchemaRef !== call.inputSchemaRef ||
      tool.inputSchemaDigest !== call.inputSchemaDigest) throw new TypeError('MCP arguments have no exact frozen input schema/recovery contract');
  const schema = await readCanonicalArtifact(artifacts, tool.inputSchemaRef), validate = compileInputSchema(schema);
  if (canonicalSha256(schema) !== tool.inputSchemaDigest || !validate(call.value)) throw new TypeError('MCP original resolved input no longer validates its frozen schema');
  const pointer = tool.recovery.kind === 'manual' ? undefined : tool.recovery.idempotencyKeyInjection?.jsonPointer;
  const reproduced = injectMcpIdempotencyKey(call.value, pointer, request.idempotencyKey);
  if (canonicalSha256(reproduced) !== canonicalSha256(call.value))
    throw new TypeError('MCP stable key was not frozen in the resolved input before request/target/grant authorization');
  // No post-authorization normalization or replacement occurs here.
  return call.value;
}
