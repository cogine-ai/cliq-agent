import { immutableSnapshot } from '../model/immutable.js';
import type { PolicySubject, ToolAccess } from '../policy/decision.js';
import { parseCanonicalBash } from '../policy/canonical-bash.js';
import { compileInputSchema } from './input-schema.js';

type Intent = Pick<Extract<PolicySubject, { kind: 'tool' }>, 'channel' | 'display'>;
type Status = 'pending' | 'in_progress' | 'completed';
type PlanItem = { id?: string; title: string; status?: Status; notes?: string };
type PlanInput =
  | { op: 'draft'; title: string; content: string; items?: PlanItem[] }
  | { op: 'update'; planId?: string; title?: string; content: string; items?: PlanItem[] }
  | { op: 'finalize'; planId?: string };
type TodoInput = { planId?: string; items: Array<PlanItem & { status: Status; activeForm?: string }> };

/** Lexical workspace-relative identity only. Symlink/descriptor containment belongs to the broker. */
function workspacePath(path: string): string | undefined {
  if (path.includes('\0') || path.includes('\\') || path.startsWith('/') || /^[A-Za-z]:/u.test(path)) return undefined;
  const parts = path.normalize('NFC').split('/');
  if (parts.includes('..')) return undefined;
  return parts.filter((part) => part !== '' && part !== '.').join('/') || '.';
}

function builtin<T extends Record<string, unknown>>(
  name: string, access: ToolAccess, replayClass: 'retry' | 'manual', inputSchema: unknown,
  normalize: (input: T) => T | undefined, intent: (input: T) => Intent | undefined
) {
  const schema = immutableSnapshot(inputSchema);
  const parse = compileInputSchema<T>(schema);
  return Object.freeze({
    name, version: '1', access, replayClass, inputSchema: schema,
    parseInput(value: unknown) {
      const parsed = parse(value);
      const input = parsed === undefined ? undefined : normalize(parsed);
      const projection = input === undefined ? undefined : intent(input);
      return projection === undefined ? undefined : immutableSnapshot({ input: input!, ...projection });
    }
  });
}

const text = { type: 'string' };
const nonempty = { type: 'string', minLength: 1, pattern: '\\S' };
const status = { type: 'string', enum: ['pending', 'in_progress', 'completed'] };
const object = (properties: Record<string, unknown>, required: string[]) => ({ type: 'object', properties, required, additionalProperties: false });
const planItem = object({ id: nonempty, title: nonempty, status, notes: text }, ['title']);
const planItems = { type: 'array', items: planItem };
const withPath = <T extends { path?: string }>(input: T) => {
  const path = workspacePath(input.path ?? '.');
  return path === undefined ? undefined : { ...input, path };
};
const readIntent = (title: string) => (input: { path?: string }): Intent => ({
  channel: { kind: 'fs-read', path: input.path! }, display: { title, path: input.path! }
});
const withPlanId = <T extends { planId?: string }>(input: T): T | undefined => input.planId === undefined ? input
  : input.planId.includes('\0') ? undefined : { ...input, planId: input.planId.normalize('NFC') };

/** Input semantics for the new runtime only; these definitions never import or execute host tools. */
export const builtinInputContracts = Object.freeze({
  read: builtin<{ path: string; start_line?: number; end_line?: number }>('read', 'read', 'retry',
    object({ path: nonempty, start_line: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
      end_line: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER } }, ['path']),
    (input) => input.end_line !== undefined && input.end_line < (input.start_line ?? 1) ? undefined : withPath(input),
    readIntent('Read file?')),
  edit: builtin<{ path: string; old_text: string; new_text: string }>('edit', 'write', 'manual',
    object({ path: nonempty, old_text: text, new_text: text }, ['path', 'old_text', 'new_text']), withPath,
    (input) => ({ channel: { kind: 'fs-write', path: input.path, op: 'modify' }, display: { title: 'Allow edit?', path: input.path } })),
  bash: builtin<{ command: string }>('bash', 'exec', 'manual', object({ command: nonempty }, ['command']),
    (input) => input.command.includes('\0') ? undefined : { command: input.command.normalize('NFC') }, (input) => {
      let parsed;
      try { parsed = parseCanonicalBash(input.command); } catch (error) {
        if (error instanceof TypeError) return undefined;
        throw error;
      }
      const nested = parsed.nestedBuiltinDenyHeads[0];
      return { channel: { kind: 'bash', commandHead: parsed.outerCommandHead ?? '',
        unsafeForAllow: parsed.unsafeForAllow, ...(nested ? { nestedBuiltinDenyHead: nested } : {}) },
        display: { title: 'Allow bash command?', command: input.command } };
    }),
  ls: builtin<{ path?: string }>('ls', 'read', 'retry', object({ path: text }, []), withPath, readIntent('List directory?')),
  find: builtin<{ path?: string; name: string }>('find', 'read', 'retry', object({ path: text, name: nonempty }, ['name']),
    withPath, (input) => ({ channel: { kind: 'fs-read', path: input.path! }, display: { title: 'Find files?', path: input.path!, detail: input.name } })),
  grep: builtin<{ path?: string; pattern: string }>('grep', 'read', 'retry', object({ path: text, pattern: nonempty }, ['pattern']),
    withPath, (input) => ({ channel: { kind: 'fs-read', path: input.path! }, display: { title: 'Search file contents?', path: input.path!, detail: input.pattern } })),
  plan: builtin<PlanInput>('plan', 'plan', 'manual', { oneOf: [
    object({ op: { const: 'draft' }, title: nonempty, content: nonempty, items: planItems }, ['op', 'title', 'content']),
    object({ op: { const: 'update' }, planId: nonempty, title: nonempty, content: nonempty, items: planItems }, ['op', 'content']),
    object({ op: { const: 'finalize' }, planId: nonempty }, ['op'])
  ] }, (input) => 'planId' in input ? withPlanId(input) : input, (input) => ({
    channel: { kind: 'plan', op: input.op, ...('planId' in input && input.planId ? { planId: input.planId } : {}) },
    display: { title: 'Record plan artifact?', detail: 'title' in input && input.title ? `${input.op}: ${input.title}` : input.op }
  })),
  todo: builtin<TodoInput>('todo', 'plan', 'manual', object({ planId: nonempty,
    items: { type: 'array', items: object({ ...planItem.properties, activeForm: nonempty }, ['title', 'status']) } }, ['items']),
    withPlanId, (input) => ({ channel: { kind: 'plan-progress', ...(input.planId ? { planId: input.planId } : {}) },
      display: { title: 'Update plan progress?', detail: `${input.items.length} items` } }))
});
