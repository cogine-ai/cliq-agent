import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type {
  Run, RunSpec, RunAssemblyV1, ContextManifest, ContinuationItem, SessionContextProjection,
  ToolResultPayloadV1, ToolResultModelContentV1
} from '../kernel/types.js';
import type { AgentModelTurn, ModelTextV1, ToolCallInputV1, ObservedToolCallInputV1 } from '../protocol/agent-ir.js';
import type { UserInputModelContentV1 } from '../kernel/user-input.js';
import { verifyModelText } from '../model/attempt.js';
import type { NormalPromptProjectionV1, NormalPromptMessageV1 } from '../model/request.js';
import type { RunAssemblyToolAuthority } from '../model/run-assembly.js';
import type { ModelTurnMaterial } from '../runtime/continuation.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAdmittedContext, decodeRunObjective, decodeSessionProjection } from './decoders.js';
import { KernelStorageError } from './errors.js';

export async function readCanonicalArtifact<T>(artifacts: ArtifactCatalog, ref: string): Promise<T> {
  const value = await artifacts.readCanonical<T>(ref);
  if (canonicalSha256(value) !== ref) throw new KernelStorageError('ARTIFACT_MISMATCH', 'artifact bytes are not canonical JSON');
  return value;
}

export async function readText(artifacts: ArtifactCatalog, ref: string, digest?: string): Promise<ModelTextV1> {
  const value = await readCanonicalArtifact<ModelTextV1>(artifacts, ref);
  verifyModelText(value);
  if (digest !== undefined && value.textDigest !== digest) throw new TypeError('model text digest mismatch');
  return value;
}

export async function readModelTurnMaterial(artifacts: ArtifactCatalog, ref: string): Promise<ModelTurnMaterial> {
  const turn = await readCanonicalArtifact<AgentModelTurn>(artifacts, ref);
  return { turn, text: await readText(artifacts, turn.textRef), inputs: await Promise.all(turn.toolCalls.map(async (call) => {
    const value = await readCanonicalArtifact<ToolCallInputV1>(artifacts, call.inputRef);
    const observed = await readCanonicalArtifact<ObservedToolCallInputV1>(artifacts, value.observedInputRef);
    if (value.diagnosticRef !== undefined) await artifacts.readBytes(value.diagnosticRef);
    return { value, observed };
  })) };
}

/** Static, post-Trust instruction projection. Reads retained CAS only, never live repository files. */
export async function loadInstructionText(artifacts: ArtifactCatalog, assembly: RunAssemblyV1): Promise<string> {
  const instructions = assembly.instructions;
  const system = await readText(artifacts, instructions.systemPromptRef, instructions.systemPromptDigest);
  if (!system.utf8.trim()) throw new TypeError('system instruction is empty');
  const pieces = [system.utf8];
  const workspace = await readCanonicalArtifact<{
    schemaVersion: 1; format: string; manifestDigest: string;
    entries: Array<{ order: number; canonicalRootRelativePath: string; appliesToSubtree: true;
      contentRef: string; contentDigest: string }>;
  }>(artifacts, instructions.workspaceInstructionsRef);
  if (workspace.schemaVersion !== 1 || workspace.format !== 'cliq-workspace-instructions-v1' ||
      workspace.manifestDigest !== instructions.workspaceInstructionsDigest ||
      digestOmitting(workspace, 'manifestDigest') !== workspace.manifestDigest) throw new TypeError('workspace instructions mismatch');
  if (workspace.entries.length > 0) {
    const entries = await Promise.all(workspace.entries.map(async (entry, index) => {
      if (entry.order !== index || entry.appliesToSubtree !== true) throw new TypeError('workspace instruction scope mismatch');
      return { order: entry.order, canonicalRootRelativePath: entry.canonicalRootRelativePath, appliesToSubtree: true,
        instructionUtf8: (await readText(artifacts, entry.contentRef, entry.contentDigest)).utf8 };
    }));
    pieces.push(canonicalJsonBytes({ format: 'cliq-workspace-instruction-prompt-v1', entries }).toString('utf8'));
  }
  for (const selected of instructions.skills) {
    const skill = await readCanonicalArtifact<{
      schemaVersion: 1; format: string; skillId: string; sourceScope: string;
      instructionRef: string; instructionDigest: string; manifestDigest: string;
    }>(artifacts, selected.manifestRef);
    if (skill.schemaVersion !== 1 || skill.format !== 'cliq-skill-manifest-v1' || skill.skillId !== selected.skillId ||
        skill.manifestDigest !== selected.manifestDigest || digestOmitting(skill, 'manifestDigest') !== skill.manifestDigest) {
      throw new TypeError('selected skill does not match retained manifest');
    }
    const instructionUtf8 = (await readText(artifacts, skill.instructionRef, skill.instructionDigest)).utf8;
    if (!instructionUtf8.trim()) throw new TypeError('selected skill instruction is empty');
    pieces.push(canonicalJsonBytes({ format: 'cliq-skill-instruction-prompt-v1', skillId: skill.skillId,
      sourceScope: skill.sourceScope, instructionUtf8 }).toString('utf8'));
  }
  return pieces.join('\n\n');
}

type ContextProjectionInput = {
  artifacts: ArtifactCatalog; run: Run; spec: RunSpec; assembly: RunAssemblyV1;
  context: ContextManifest; systemInstruction: string; tools: RunAssemblyToolAuthority[];
};

/** Model-visible context, shared by request projection and resource-stop recovery. */
export async function readModelContext(input: ContextProjectionInput): Promise<Pick<NormalPromptProjectionV1, 'messages' | 'tools'>> {
  const { artifacts, run, spec, assembly, context } = input;
  if (context.runId !== run.id || context.assemblyRef !== spec.assemblyRef || context.admittedContextRef !== spec.admittedContextRef) {
    throw new TypeError('context does not belong to the current Run');
  }
  const messages: NormalPromptMessageV1[] = [];
  const user = (sourceKind: Extract<NormalPromptMessageV1, { role: 'system' | 'user' }>['sourceKind'], sourceId: string, contentUtf8: string) => {
    messages.push({ index: messages.length, role: 'user', sourceKind, sourceId, contentUtf8 });
  };
  messages.push({ index: 0, role: 'system', sourceKind: 'assembly_instructions', sourceId: spec.assemblyRef, contentUtf8: input.systemInstruction });
  const admitted = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
  const session: SessionContextProjection = decodeSessionProjection(await readCanonicalArtifact(artifacts, admitted.sessionProjectionRef));
  if (session.sessionId !== admitted.sessionId || session.contextRevision !== admitted.sessionContextRevision ||
      session.throughItemSeq !== admitted.throughSessionItemSeq) throw new TypeError('admitted Session context mismatch');
  for (const segment of session.segments) {
    if (segment.kind === 'summary') user('session_summary', segment.compactionItemId,
      (await readText(artifacts, segment.summaryRef, segment.summaryDigest)).utf8);
    else if (segment.kind === 'raw') for (const item of segment.items) {
      if (item.kind !== 'run_terminal') throw new TypeError('legacy Session items cannot enter the model context');
      const terminal = await readCanonicalArtifact<{
        format: string; kind: string; runId: string; operation: string; status: string; terminalReason: string;
        resultRef?: string; summaryRef?: string;
      }>(artifacts, item.payloadRef);
      if (terminal.format !== 'cliq-session-run-terminal-v1' || terminal.kind !== 'run_terminal') throw new TypeError('invalid terminal Session item');
      user('session_terminal', item.itemId, canonicalJsonBytes({ kind: terminal.kind, runId: terminal.runId,
        operation: terminal.operation, status: terminal.status, terminalReason: terminal.terminalReason,
        ...(terminal.resultRef === undefined ? {} : { resultRef: terminal.resultRef }),
        ...(terminal.summaryRef === undefined ? {} : { summaryRef: terminal.summaryRef }) }).toString('utf8'));
    }
  }
  for (const ref of admitted.parentContextRefs) user('parent_context', ref, (await readText(artifacts, ref)).utf8);
  for (const ref of admitted.additionalArtifactRefs) user('additional_context', ref, (await readText(artifacts, ref)).utf8);
  user('run_objective', spec.objectiveRef, decodeRunObjective(await readCanonicalArtifact(artifacts, spec.objectiveRef)).utf8);
  let pendingCalls: string[] = [];
  const pendingInputs: Array<{ itemId: string; content: string }> = [];
  const projectItem = async (itemRef: string) => {
      const item = await readCanonicalArtifact<ContinuationItem>(artifacts, itemRef);
      if (item.runId !== run.id) throw new TypeError('context item belongs to another Run');
      if (item.kind === 'model_turn') {
        const { turn, text, inputs } = await readModelTurnMaterial(artifacts, item.modelTurnRef);
        if (pendingCalls.length) throw new TypeError('model turn overtakes an unanswered tool call');
        pendingCalls = turn.toolCalls.map((call) => call.callId);
        messages.push({ index: messages.length, role: 'assistant', sourceItemId: item.itemId, contentUtf8: text.utf8,
          toolCalls: turn.toolCalls.map((call, index) => {
            const observed = inputs[index]!.observed;
            return { ...call, arguments: observed.encoding === 'jcs_json'
              ? { encoding: 'jcs_json', value: observed.value } : { encoding: 'utf8_json_fragment', utf8: observed.utf8 } };
          }), ...(turn.continuation === undefined ? {} : { continuation: turn.continuation }) });
      } else if (item.kind === 'tool_result') {
        const result = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
        const content = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, result.modelContentRef);
        if (result.callId !== item.callId || result.batchItemId !== item.batchItemId || result.index !== item.index ||
            result.outcome !== item.outcome || result.runId !== run.id || result.format !== 'cliq-tool-result-payload-v1' ||
            digestOmitting(result, 'payloadDigest') !== result.payloadDigest || content.format !== 'cliq-tool-result-model-content-v1' ||
            content.callId !== item.callId || content.index !== item.index || content.outcome !== item.outcome ||
            content.contentDigest !== result.modelContentDigest || digestOmitting(content, 'contentDigest') !== content.contentDigest) {
          throw new TypeError('tool result context does not match its retained payload');
        }
        messages.push({ index: messages.length, role: 'tool', sourceItemId: item.itemId,
          toolCallId: item.callId, contentUtf8: canonicalJsonBytes(content.content).toString('utf8') });
        if (pendingCalls.shift() !== item.callId) throw new TypeError('tool result projection order mismatch');
        // Native providers require all tool results before another user message.
        if (!pendingCalls.length) for (const input of pendingInputs.splice(0)) user('user_input', input.itemId, input.content);
      } else if (item.kind === 'user_input') {
        const content = await readCanonicalArtifact<UserInputModelContentV1>(artifacts, item.modelContentRef);
        if (content.schemaVersion !== 1 || content.format !== 'cliq-user-input-model-content-v1' ||
            content.contentDigest !== item.modelContentDigest || digestOmitting(content, 'contentDigest') !== content.contentDigest ||
            !['text', 'json'].includes(content.inputKind) || pendingCalls[0] !== item.callId) throw new TypeError('input context does not belong to its open call');
        pendingInputs.push({ itemId: item.itemId, content: content.inputKind === 'text'
          ? content.value as string : canonicalJsonBytes(content.value).toString('utf8') });
      } else throw new TypeError(`control item ${item.kind} cannot be projected as raw model context`);
  };
  for (const segment of context.segments) {
    if (segment.kind === 'summary') {
      user('run_summary', segment.compactionItemId, (await readText(artifacts, segment.summaryRef, segment.summaryDigest)).utf8);
      for (const ref of segment.preservedItemRefs) await projectItem(ref);
    } else if (segment.kind === 'raw') for (const entry of segment.items) await projectItem(entry.itemRef);
  }
  if (pendingCalls.length || pendingInputs.length) throw new TypeError('model context contains an open tool batch');
  return { messages,
    tools: assembly.provider.negotiation.mode === 'text-only' ? [] : input.tools.map(({ replayClass: _, ...tool }, index) => ({ index, ...tool })) };
}

export async function projectNormalContext(input: ContextProjectionInput & { contextRef: string }): Promise<NormalPromptProjectionV1> {
  const { run, spec, assembly, context, contextRef } = input;
  const visible = await readModelContext(input);
  const value: NormalPromptProjectionV1 = { schemaVersion: 1, format: 'cliq-normal-prompt-projection-v1', runId: run.id,
    basedOnRunRevision: run.revision, frontierDigest: run.frontierRef!, runSpecRef: run.specRef,
    assemblyRef: spec.assemblyRef, assemblyDigest: assembly.assemblyDigest, contextManifestRef: contextRef,
    contextManifestDigest: context.projectionDigest, ...visible,
    projectionDigest: '' };
  value.projectionDigest = digestOmitting(value, 'projectionDigest');
  return value;
}
