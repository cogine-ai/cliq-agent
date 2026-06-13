import type { PlanItem, PlanItemInput, PlanItemStatus, PlanProgressItem, PlanProgressItemInput } from './types.js';

const SAFE_ITEM_ID = /^[A-Za-z0-9_-]+$/;

export function isPlanItemStatus(value: unknown): value is PlanItemStatus {
  return value === 'pending' || value === 'in_progress' || value === 'completed';
}

export function isPlanItem(value: unknown): value is PlanItem {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const raw = value as Partial<PlanItem>;
  return (
    typeof raw.id === 'string' &&
    SAFE_ITEM_ID.test(raw.id) &&
    typeof raw.title === 'string' &&
    !!raw.title.trim() &&
    isPlanItemStatus(raw.status) &&
    (raw.notes === undefined || typeof raw.notes === 'string')
  );
}

export function isPlanProgressItem(value: unknown): value is PlanProgressItem {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const raw = value as Partial<PlanProgressItem>;
  return (
    typeof raw.id === 'string' &&
    SAFE_ITEM_ID.test(raw.id) &&
    typeof raw.title === 'string' &&
    !!raw.title.trim() &&
    isPlanItemStatus(raw.status) &&
    typeof raw.activeForm === 'string' &&
    !!raw.activeForm.trim() &&
    (raw.notes === undefined || typeof raw.notes === 'string')
  );
}

export function normalizePlanItems(input: readonly PlanItemInput[] | undefined, contentMarkdown: string): PlanItem[] {
  if (input !== undefined) {
    return input
      .map((item, index) => normalizePlanItem(item, index))
      .filter((item): item is PlanItem => item !== null);
  }
  return extractPlanItems(contentMarkdown);
}

export function normalizeStoredPlanItems(input: unknown, contentMarkdown: string): PlanItem[] {
  if (Array.isArray(input) && input.every(isPlanItem)) {
    return input.map((item, index) => ({
      id: item.id || planItemId(index),
      title: item.title.trim(),
      status: item.status,
      ...(item.notes?.trim() ? { notes: item.notes.trim() } : {})
    }));
  }
  return extractPlanItems(contentMarkdown);
}

export function normalizePlanProgressItems(input: readonly PlanProgressItemInput[]): PlanProgressItem[] {
  return input
    .map((item, index) => normalizePlanProgressItem(item, index))
    .filter((item): item is PlanProgressItem => item !== null);
}

export function progressItemsFromPlanItems(items: readonly PlanItem[]): PlanProgressItem[] {
  return items.map((item) => ({
    id: item.id,
    title: item.title,
    status: 'pending',
    activeForm: activeFormForTitle(item.title),
    ...(item.notes ? { notes: item.notes } : {})
  }));
}

export function normalizeStoredPlanProgressItems(input: unknown): PlanProgressItem[] | null {
  if (!Array.isArray(input) || !input.every(isPlanProgressItem)) return null;
  return input.map((item, index) => ({
    id: item.id || planItemId(index),
    title: item.title.trim(),
    status: item.status,
    activeForm: item.activeForm.trim(),
    ...(item.notes?.trim() ? { notes: item.notes.trim() } : {})
  }));
}

export function extractPlanItems(contentMarkdown: string): PlanItem[] {
  const items: PlanItem[] = [];
  for (const line of contentMarkdown.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:[-*+]|\d+[.)])\s+(?:\[( |x|X|~|-)\]\s*)?(.+?)\s*$/);
    if (!match) continue;
    const checkbox = match[1];
    const title = stripMarkdownMarkerText(match[2] ?? '');
    if (!title) continue;
    items.push({
      id: planItemId(items.length),
      title,
      status: checkbox === 'x' || checkbox === 'X' ? 'completed' : checkbox === '~' || checkbox === '-' ? 'in_progress' : 'pending'
    });
  }
  return items;
}

function normalizePlanItem(input: PlanItemInput, index: number): PlanItem | null {
  if (!input || typeof input !== 'object') return null;
  const title = typeof input.title === 'string' ? stripMarkdownMarkerText(input.title) : '';
  if (!title) return null;
  const status = input.status === undefined ? 'pending' : input.status;
  if (!isPlanItemStatus(status)) return null;
  const id = typeof input.id === 'string' && SAFE_ITEM_ID.test(input.id) ? input.id : planItemId(index);
  const notes = typeof input.notes === 'string' ? input.notes.trim() : '';
  return {
    id,
    title,
    status,
    ...(notes ? { notes } : {})
  };
}

function normalizePlanProgressItem(input: PlanProgressItemInput, index: number): PlanProgressItem | null {
  if (!input || typeof input !== 'object') return null;
  const title = typeof input.title === 'string' ? stripMarkdownMarkerText(input.title) : '';
  if (!title) return null;
  const status = input.status === undefined ? 'pending' : input.status;
  if (!isPlanItemStatus(status)) return null;
  const activeForm = typeof input.activeForm === 'string' ? input.activeForm.trim() : '';
  if (!activeForm) return null;
  const id = typeof input.id === 'string' && SAFE_ITEM_ID.test(input.id) ? input.id : planItemId(index);
  const notes = typeof input.notes === 'string' ? input.notes.trim() : '';
  return {
    id,
    title,
    status,
    activeForm,
    ...(notes ? { notes } : {})
  };
}

function planItemId(index: number) {
  return `item_${index + 1}`;
}

function stripMarkdownMarkerText(value: string) {
  return value
    .trim()
    .replace(/^\[(?: |x|X|~|-)\]\s+/, '')
    .replace(/\s+/g, ' ')
    .trim();
}

export function activeFormForTitle(title: string) {
  const trimmed = title.trim();
  const [first = '', ...restParts] = trimmed.split(/\s+/);
  const rest = restParts.join(' ');
  const mapped = presentContinuous(first);
  if (!mapped) return `Working on ${trimmed}`;
  return rest ? `${mapped} ${rest}` : mapped;
}

function presentContinuous(word: string) {
  const lower = word.toLowerCase();
  const direct: Record<string, string> = {
    add: 'Adding',
    apply: 'Applying',
    build: 'Building',
    create: 'Creating',
    debug: 'Debugging',
    design: 'Designing',
    fix: 'Fixing',
    implement: 'Implementing',
    inspect: 'Inspecting',
    review: 'Reviewing',
    run: 'Running',
    test: 'Testing',
    update: 'Updating',
    verify: 'Verifying',
    write: 'Writing'
  };
  return direct[lower] ?? null;
}
