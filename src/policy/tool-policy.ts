import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { PolicyActionClass, PolicyDisposition, RunPolicySnapshotV1, ToolOperationGrantV1, ToolApprovalWait, ToolApprovalDecisionV1,
  ToolPolicyChannel, ToolPolicyChannelEvidenceV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { immutableSnapshot } from '../model/immutable.js';
import { loadToolContracts, type ToolInputAuthority } from '../tools/input-contract.js';
import { parseCanonicalBash } from './canonical-bash.js';
import { exactKeys, requireEqual } from './runtime-authority.js';
import { toolApprovalDecision } from './tool-approval.js';

const CLASSES: PolicyActionClass[] = ['read', 'plan', 'write', 'exec', 'mcp', 'verifier',
  'dependency_install_scripts', 'delivery', 'child_read_only', 'child_mutating'];
const CHANNELS = ['fs-read', 'fs-write', 'bash', 'mcp', 'plan', 'plan-progress', 'named-action'];
const SOURCES = ['builtin', 'cli', 'user_config', 'session', 'repository_request'];
const RANK = { allow: 0, ask: 1, deny: 2 };
const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0 &&
  !value.includes('\0') && value === value.normalize('NFC');
const sorted = (values: string[]) => [...new Set(values)].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

export function modeDecisions(mode: RunPolicySnapshotV1['mode']): RunPolicySnapshotV1['decisions'] {
  if (!['default', 'accept-edits', 'plan', 'yolo'].includes(mode)) throw new TypeError('unknown policy mode');
  return Object.fromEntries(CLASSES.map((action) => [action,
    mode === 'yolo' || ['read', 'plan'].includes(action) ||
    (mode === 'accept-edits' && ['write', 'child_read_only'].includes(action)) || (mode === 'plan' && action === 'child_read_only')
      ? 'allow' : mode === 'plan' ? 'deny' : 'ask'])) as RunPolicySnapshotV1['decisions'];
}

export const BUILTIN_POLICY_RULES: Readonly<RunPolicySnapshotV1['decisionRules']> = immutableSnapshot([
  { ruleId: 'builtin:bash:rm', order: 0, source: 'builtin', channel: 'bash', pattern: 'rm', disposition: 'deny' },
  { ruleId: 'builtin:fs-write:git-tree', order: 1, source: 'builtin', channel: 'fs-write', pattern: '.git/*', disposition: 'deny' },
  { ruleId: 'builtin:fs-write:git-root', order: 2, source: 'builtin', channel: 'fs-write', pattern: '.git', disposition: 'deny' }
]);

function matches(pattern: string, key: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('**') && pattern.endsWith(' *')) {
    const prefix = pattern.slice(0, -2);
    return key === prefix || key.startsWith(`${prefix} `);
  }
  if (!pattern.includes('**') && pattern.endsWith('/*')) return key.startsWith(pattern.slice(0, -1));
  return key === pattern;
}

export function toolOperationId(runId: string, batchItemId: string, callId: string): string {
  return identityHash('cliq-tool-operation-v1', runId, batchItemId, callId);
}

/** The same immutable request identity feeds admission, policy and stop recovery. */
export function planToolRequest(input: {
  runId: string; frontierRef: string; batchItemId: string; assemblyRef: string; assembly: RunAssemblyV1;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; entry: ToolInputAuthority; call: ToolCallInputV1;
}) {
  const { runId, frontierRef, batchItemId, assemblyRef, assembly, workspaceIdentityRef, workspaceIdentityDigest, entry, call } = input;
  const { inputSchema: _schema, ...contract } = entry;
  const targetCore = { schemaVersion: 1 as const, format: 'cliq-tool-target-v1' as const, runId,
    workspaceIdentityRef, workspaceIdentityDigest, toolManifestRef: assembly.tools.manifestRef,
    toolManifestDigest: assembly.tools.manifestDigest, toolName: call.toolName, toolContractDigest: canonicalSha256(contract), execution: entry.execution };
  const target: ToolTargetV1 = { ...targetCore, targetDigest: canonicalSha256(targetCore) };
  const opId = toolOperationId(runId, batchItemId, call.callId);
  const core = { schemaVersion: 1 as const, format: 'cliq-tool-request-v1' as const, runId, opId, frontierRef, assemblyRef,
    batchItemId, callId: call.callId, callIndex: call.index, toolName: call.toolName, inputRef: canonicalSha256(call), inputDigest: call.inputDigest,
    targetRef: canonicalSha256(target), targetDigest: target.targetDigest,
    ...(entry.execution.kind === 'mcp' ? { idempotencyKey: identityHash('cliq-mcp-tool-idempotency-v1', runId, opId,
      entry.execution.registryRevisionRef, entry.execution.serverToolName) } : {}) };
  return { request: { ...core, requestDigest: canonicalSha256(core) } satisfies ToolRequestV1, target, entry };
}

/** Fixed evaluator over immutable requests. It accepts no caller-selected channel, primary key or decision. */
export function loadToolPolicy(input: {
  policy: RunPolicySnapshotV1; policyRef: string; assembly: RunAssemblyV1; assemblyRef: string;
  principalId: string; workspaceIdentityRef: string; workspaceIdentityDigest: string; contracts: ToolInputAuthority[];
}) {
  const { policy, policyRef, assembly, assemblyRef, principalId, workspaceIdentityRef, workspaceIdentityDigest, contracts } = immutableSnapshot(input);
  if (!exactKeys(policy, ['schemaVersion', 'format', 'principalId', 'workspaceIdentityDigest', 'mode', 'engine', 'toolManifestRef',
    'toolManifestDigest', 'decisions', 'decisionRules', 'repositoryRequestRefs', 'policyDigest', 'createdAt']) ||
      policy.schemaVersion !== 1 || policy.format !== 'cliq-run-policy-v1' || policy.principalId !== principalId ||
      policy.workspaceIdentityDigest !== workspaceIdentityDigest || canonicalSha256(policy) !== policyRef ||
      digestOmitting(policy, 'policyDigest') !== policy.policyDigest || policy.toolManifestRef !== assembly.tools.manifestRef ||
      policy.toolManifestDigest !== assembly.tools.manifestDigest || canonicalJsonBytes(policy).byteLength > 1_048_576 ||
      !Array.isArray(policy.decisionRules) || policy.decisionRules.length > 256 ||
      !exactKeys(policy.engine, ['id', 'version', 'runtimeBundleRef', 'profileEntryId', 'profileRef', 'profileDigest']) ||
      policy.engine.id !== 'cliq-policy-v1') throw new TypeError('invalid canonical Run policy snapshot');
  parseCanonicalTime(policy.createdAt);
  requireEqual(policy.decisions, modeDecisions(policy.mode), 'frozen mode table');
  if (new Set(policy.decisionRules.map((rule) => rule.ruleId)).size !== policy.decisionRules.length) throw new TypeError('duplicate policy rule id');
  for (const [order, rule] of policy.decisionRules.entries()) {
    if (!exactKeys(rule, ['ruleId', 'order', 'source', 'channel', 'pattern', 'disposition', ...(rule.source === 'builtin' ? [] : ['sourceRef'])]) ||
        rule.order !== order || !text(rule.ruleId) || !text(rule.pattern) || !CHANNELS.includes(rule.channel) ||
        !SOURCES.includes(rule.source) || !Object.hasOwn(RANK, rule.disposition) ||
        (rule.source === 'repository_request' && rule.disposition === 'allow')) throw new TypeError('invalid frozen permission rule');
    if (rule.source !== 'builtin') assertArtifactRef(rule.sourceRef!);
  }
  requireEqual(policy.decisionRules.filter((rule) => rule.source === 'builtin'), BUILTIN_POLICY_RULES, 'builtin deny floor');
  requireEqual(policy.repositoryRequestRefs, sorted(policy.decisionRules.filter((rule) => rule.source === 'repository_request')
    .map((rule) => rule.sourceRef!)), 'repository request source set');
  const resolver = loadToolContracts(contracts);
  const byName = new Map(contracts.map(({ inputSchema: _schema, ...entry }) => [entry.name, entry]));

  function evaluate(request: ToolRequestV1, target: ToolTargetV1, call: ToolCallInputV1, evaluatedAt: string): ToolPolicyChannelEvidenceV1 {
    parseCanonicalTime(evaluatedAt);
    if (evaluatedAt < policy.createdAt || !exactKeys(request, ['schemaVersion', 'format', 'runId', 'opId', 'frontierRef', 'assemblyRef',
      'batchItemId', 'callId', 'callIndex', 'toolName', 'inputRef', 'inputDigest', 'targetRef', 'targetDigest', 'requestDigest',
      ...(request.idempotencyKey === undefined ? [] : ['idempotencyKey'])]) || request.schemaVersion !== 1 || request.format !== 'cliq-tool-request-v1' ||
        request.assemblyRef !== assemblyRef || request.requestDigest !== digestOmitting(request, 'requestDigest') ||
        request.opId !== toolOperationId(request.runId, request.batchItemId, request.callId) ||
        call.disposition !== 'resolved' || call.callId !== request.callId || call.index !== request.callIndex || call.toolName !== request.toolName ||
        request.inputRef !== canonicalSha256(call) || request.inputDigest !== call.inputDigest || call.inputDigest !== digestOmitting(call, 'inputDigest')) {
      throw new TypeError('tool request does not bind the exact normalized call');
    }
    assertArtifactRef(request.frontierRef);
    const entry = byName.get(request.toolName);
    if (!entry) throw new TypeError('tool request selects an unknown frozen contract');
    const projected = resolver.projectInvocation({ callId: call.callId, index: call.index, toolName: call.toolName, input: call.value! });
    if (projected.kind !== 'tool' || entry.access === 'control') throw new TypeError('input control cannot mint an operation grant');
    if (entry.inputSchemaRef !== call.inputSchemaRef || entry.inputSchemaDigest !== call.inputSchemaDigest) throw new TypeError('tool input schema substitution');
    const targetCore = { schemaVersion: 1, format: 'cliq-tool-target-v1', runId: request.runId, workspaceIdentityRef, workspaceIdentityDigest,
      toolManifestRef: assembly.tools.manifestRef, toolManifestDigest: assembly.tools.manifestDigest,
      toolName: entry.name, toolContractDigest: canonicalSha256(entry), execution: entry.execution };
    requireEqual(target, { ...targetCore, targetDigest: canonicalSha256(targetCore) }, 'tool target');
    if (request.targetRef !== canonicalSha256(target) || request.targetDigest !== target.targetDigest) throw new TypeError('tool request target mismatch');
    const idempotencyKey = entry.execution.kind === 'mcp'
      ? identityHash('cliq-mcp-tool-idempotency-v1', request.runId, request.opId, entry.execution.registryRevisionRef, entry.execution.serverToolName) : undefined;
    if (request.idempotencyKey !== idempotencyKey) throw new TypeError('tool idempotency identity mismatch');
    const actionClass: PolicyActionClass = entry.execution.kind === 'mcp' ? 'mcp' : entry.access;
    let channel: ToolPolicyChannel;
    const intent = projected.subject.channel;
    if (intent.kind === 'fs-read' || intent.kind === 'fs-write') {
      if (!text(intent.path) || intent.path.includes('\\') || (intent.path !== '.' && intent.path.split('/').some((part) => ['', '.', '..'].includes(part)))) {
        throw new TypeError('filesystem policy path is not canonical');
      }
      channel = { channel: intent.kind, canonicalRootRelativePaths: [intent.path] };
    } else if (entry.execution.kind === 'mcp') channel = { channel: 'mcp', registrationId: entry.execution.registrationId, serverToolName: entry.execution.serverToolName };
    else if (intent.kind === 'bash') {
      const shellText = call.value!.command as string;
      channel = { channel: 'bash', command: { encoding: 'shell_text', shellText }, parser: 'cliq-bash-head-parser-v1', ...parseCanonicalBash(shellText) };
    } else if (intent.kind === 'plan' || intent.kind === 'plan-progress') {
      const planId = call.value!.planId;
      if (planId !== undefined && !text(planId)) throw new TypeError('plan identity is not canonical');
      channel = { channel: intent.kind, normalizedPlanIdentity: planId as string | undefined ?? identityHash('cliq-run-plan-v1', request.runId) };
    } else throw new TypeError('ordinary tool has no canonical policy channel');
    const keys = channel.channel === 'fs-read' || channel.channel === 'fs-write' ? channel.canonicalRootRelativePaths
      : channel.channel === 'bash' ? [channel.outerCommandHead ?? '']
        : channel.channel === 'mcp' ? [`${channel.registrationId}/${channel.serverToolName}`]
          : 'normalizedPlanIdentity' in channel ? [channel.normalizedPlanIdentity] : [];
    const rules = [...policy.decisionRules].sort((a, b) => {
      const priority = (rule: typeof a) => rule.disposition === 'deny' ? rule.source === 'builtin' ? 0 : 1 : rule.disposition === 'allow' ? 2 : 3;
      return priority(a) - priority(b) || a.order - b.order;
    });
    const evaluateKey = (key: string) => {
      for (const rule of rules) {
        if (rule.channel !== channel.channel || (channel.channel === 'bash' && !key && rule.disposition !== 'deny')) continue;
        const nestedMatch = channel.channel === 'bash' && rule.disposition === 'deny' && channel.nestedBuiltinDenyHeads.some((head) => matches(rule.pattern, head));
        if (!nestedMatch && !matches(rule.pattern, key)) continue;
        if (rule.source === 'repository_request' && RANK[rule.disposition] < RANK[policy.decisions[actionClass]]) continue;
        const disposition = rule.disposition === 'allow' && channel.channel === 'bash' && channel.unsafeForAllow ? 'ask' : rule.disposition;
        return { disposition, ruleId: rule.ruleId };
      }
      return { disposition: policy.decisions[actionClass], ruleId: undefined };
    };
    const winning = keys.map(evaluateKey).reduce((a, b) => RANK[b.disposition] > RANK[a.disposition] ? b : a);
    const core = { schemaVersion: 1 as const, format: 'cliq-policy-channel-evidence-v1' as const, principalId, runId: request.runId,
      policyRef, policyDigest: policy.policyDigest, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: request.targetDigest,
      actionClass, decisionSource: winning.ruleId === undefined ? 'mode_fallthrough' as const : 'rule' as const,
      matchedRuleIds: winning.ruleId === undefined ? [] : [winning.ruleId], effectiveDisposition: winning.disposition, evaluatedAt, ...channel };
    return immutableSnapshot({ ...core, evidenceDigest: canonicalSha256(core) });
  }

  function grant(request: ToolRequestV1, target: ToolTargetV1, call: ToolCallInputV1, evidence: ToolPolicyChannelEvidenceV1,
    issuedAt: string, expiresAt: string): ToolOperationGrantV1 {
    requireEqual(evidence, evaluate(request, target, call, evidence.evaluatedAt), 'policy channel evidence');
    if (evidence.effectiveDisposition !== 'allow' || parseCanonicalTime(issuedAt) < parseCanonicalTime(evidence.evaluatedAt) ||
        parseCanonicalTime(expiresAt) <= parseCanonicalTime(issuedAt)) throw new TypeError('only a current direct allow can mint a tool grant');
    const decision = { policyRef, channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest,
      actionClass: evidence.actionClass, requestDigest: request.requestDigest, targetDigest: request.targetDigest,
      matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow' as const };
    return operationGrant(request, target, issuedAt, expiresAt, { kind: 'policy_snapshot', actionClass: evidence.actionClass,
      channelEvidenceRef: decision.channelEvidenceRef, channelEvidenceDigest: evidence.evidenceDigest,
      matchedRuleIds: evidence.matchedRuleIds, effectiveDisposition: 'allow', decisionDigest: canonicalSha256(decision) });
  }

  function approve(request: ToolRequestV1, target: ToolTargetV1, call: ToolCallInputV1, evidence: ToolPolicyChannelEvidenceV1,
    wait: ToolApprovalWait, decision: ToolApprovalDecisionV1, deadlineAt: string): ToolOperationGrantV1 | undefined {
    requireEqual(evidence, evaluate(request, target, call, evidence.evaluatedAt), 'approval policy evidence');
    requireEqual(wait, approvalWait(request, target, evidence, wait.createdFromRevision), 'approval wait');
    requireEqual(decision, toolApprovalDecision(wait, { principalId, channelIdentityRef: decision.channelIdentityRef,
      channelIdentityDigest: decision.channelIdentityDigest, requestId: decision.requestId,
      expectedRunRevision: decision.expectedRunRevision, waitingOnRef: canonicalSha256(wait), decision: decision.decision,
      ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) }, decision.createdAt, deadlineAt), 'approval decision');
    if (decision.decision === 'deny') return undefined;
    return operationGrant(request, target, decision.createdAt, decision.grantExpiresAt!, { kind: 'user_approval',
      waitingSubjectRef: canonicalSha256(wait), decisionRef: canonicalSha256(decision), requestId: decision.requestId,
      channelEvidenceRef: canonicalSha256(evidence), channelEvidenceDigest: evidence.evidenceDigest });
  }

  function approvalWait(request: ToolRequestV1, target: ToolTargetV1, evidence: ToolPolicyChannelEvidenceV1, revision: number): ToolApprovalWait {
    if (evidence.effectiveDisposition !== 'ask' || !Number.isSafeInteger(revision) || revision < 1) throw new TypeError('only ask can create an approval wait');
    return immutableSnapshot({ schemaVersion: 1, kind: 'approval', runId: request.runId, frontierRef: request.frontierRef,
      createdFromRevision: revision, createdAt: evidence.evaluatedAt, subject: { kind: 'tool_call', policySubjectKind: 'ordinary_tool',
        opId: request.opId, target: request.targetRef, batchItemId: request.batchItemId, callId: request.callId, callIndex: request.callIndex,
        toolName: request.toolName, toolContractDigest: target.toolContractDigest, replayClass: byName.get(request.toolName)!.replayClass,
        policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest } });
  }

  function operationGrant(request: ToolRequestV1, target: ToolTargetV1, issuedAt: string, expiresAt: string,
    provenance: ToolOperationGrantV1['provenance']): ToolOperationGrantV1 {
    const entry = byName.get(request.toolName)!;
    const retry = assembly.retry.tools.find((tool) => tool.toolName === entry.name);
    if (!retry || retry.replayClass !== entry.replayClass) throw new TypeError('tool retry authority mismatch');
    const subject: ToolOperationGrantV1['subject'] = { kind: 'tool_call', batchItemId: request.batchItemId,
      callId: request.callId, callIndex: request.callIndex, toolName: request.toolName, toolContractDigest: target.toolContractDigest,
      replayClass: entry.replayClass, policySubjectKind: 'ordinary_tool' };
    const core = { schemaVersion: 1 as const, format: 'cliq-operation-grant-v1' as const,
      grantId: identityHash('cliq-operation-grant-v1', request.runId, request.opId, request.requestDigest, subject, issuedAt),
      principalId, runId: request.runId, policyRef, frontierRef: request.frontierRef, opId: request.opId,
      requestRef: canonicalSha256(request), requestDigest: request.requestDigest, targetRef: request.targetRef, targetDigest: request.targetDigest,
      subject, provenance,
      maxDispatchedAttempts: retry.maxDispatchedAttempts, issuedAt, expiresAt };
    return immutableSnapshot({ ...core, grantDigest: canonicalSha256(core) });
  }
  return Object.freeze({ evaluate, grant, approvalWait, approve });
}
