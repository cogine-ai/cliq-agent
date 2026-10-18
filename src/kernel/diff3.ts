import { createHash } from 'node:crypto';
import { setImmediate as yieldToEventLoop } from 'node:timers/promises';

/** LF is the separator. CR, CRLF, Unicode and a missing final LF remain exact. */
export type Diff3LineEditV1 = { baseStart: number; baseEnd: number; replacement: string };
export type Diff3TextConflictV1 = { current: Diff3LineEditV1; desired: Diff3LineEditV1 };
export type Diff3WorkV1 = {
  phase: 'tokenize' | 'distance' | 'reconstruct' | 'merge' | 'output'; totalWork: number;
};
export type Diff3TextResultV1 =
  | { kind: 'merged'; text: string; currentEdits: Diff3LineEditV1[]; desiredEdits: Diff3LineEditV1[] }
  | { kind: 'conflict'; conflicts: Diff3TextConflictV1[]; currentEdits: Diff3LineEditV1[]; desiredEdits: Diff3LineEditV1[] };
export type Diff3ComputationV1 = {
  signal?: AbortSignal;
  /** Observation only: an owner's cancellation/resource exception propagates unchanged. */
  onWork?: (work: Readonly<Diff3WorkV1>) => void;
};

const QUANTUM = 4096;
class Computation {
  private totalWork = 0;
  private untilYield = QUANTUM;
  phase: Diff3WorkV1['phase'] = 'tokenize';
  constructor(private readonly options: Diff3ComputationV1) {}
  check(): void {
    this.options.signal?.throwIfAborted();
    this.options.onWork?.({ phase: this.phase, totalWork: this.totalWork });
    this.options.signal?.throwIfAborted();
  }
  step(): Promise<void> | undefined {
    this.totalWork++;
    if (--this.untilYield !== 0) return;
    this.untilYield = QUANTUM;
    return this.yield();
  }
  private async yield(): Promise<void> {
    this.check();
    await yieldToEventLoop();
    this.options.signal?.throwIfAborted();
  }
}

type Lines = { text: string[]; ids: number[] };
type LineTable = { entries: Map<string, Array<{ text: string; id: number }>>; nextId: number };
async function equalText(a: string, b: string, work: Computation): Promise<boolean> {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const pause = work.step(); if (pause) await pause;
    if (a.charCodeAt(i) !== b.charCodeAt(i)) return false;
  }
  return true;
}
async function tokenize(text: string, table: LineTable,
  work: Computation): Promise<Lines> {
  const result: Lines = { text: [], ids: [] };
  let start = 0, hashed = 0;
  let hash = createHash('sha256');
  const append = async (end: number) => {
    hash.update(text.slice(hashed, end), 'utf16le');
    const key = hash.digest('hex');
    const line = text.slice(start, end);
    const bucket = table.entries.get(key) ?? [];
    let id: number | undefined;
    for (const entry of bucket) {
      const pause = work.step(); if (pause) await pause;
      if (await equalText(entry.text, line, work)) { id = entry.id; break; }
    }
    if (id === undefined) {
      // Every distinct line needs a distinct id, including a hypothetical hash collision.
      id = table.nextId++;
      bucket.push({ text: line, id }); table.entries.set(key, bucket);
    }
    result.text.push(line); result.ids.push(id);
    start = end; hashed = end; hash = createHash('sha256');
  };
  for (let i = 0; i < text.length; i++) {
    const pause = work.step(); if (pause) await pause;
    if (text.charCodeAt(i) === 10) await append(i + 1);
    else if (i + 1 - hashed === QUANTUM) { hash.update(text.slice(hashed, i + 1), 'utf16le'); hashed = i + 1; }
  }
  if (start < text.length) await append(text.length);
  return result;
}

/** Myers's furthest-reaching wavefront, with no retained O(ND) trace. */
async function distance(a: readonly number[], b: readonly number[], work: Computation): Promise<number> {
  const n = a.length, m = b.length, offset = n + m + 1;
  const v = new Float64Array(2 * offset + 1);
  let x = 0;
  while (x < n && x < m && a[x] === b[x]) {
    x++; const pause = work.step(); if (pause) await pause;
  }
  v[offset] = x;
  if (x === n && x === m) return 0;
  let previousLow = 0, previousHigh = 0;
  for (let d = 1; d <= n + m; d++) {
    // Only diagonals reachable inside the finite grid; highly unequal inputs stay linear.
    const low = -d + 2 * Math.max(0, d - m), high = d - 2 * Math.max(0, d - n);
    for (let k = low; k <= high; k += 2) {
      const pause = work.step(); if (pause) await pause;
      let deletion = -Infinity, insertion = -Infinity;
      if (k - 1 >= previousLow && k - 1 <= previousHigh && v[offset + k - 1] < n)
        deletion = v[offset + k - 1] + 1;
      if (k + 1 >= previousLow && k + 1 <= previousHigh && v[offset + k + 1] - (k + 1) < m)
        insertion = v[offset + k + 1];
      x = Math.max(deletion, insertion);
      if (!Number.isFinite(x)) { v[offset + k] = -Infinity; continue; }
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++; y++; const pause = work.step(); if (pause) await pause;
      }
      v[offset + k] = x;
      if (x === n && y === m) return d;
    }
    previousLow = low; previousHigh = high;
  }
  throw new Error('unreachable edit distance');
}

type Region = { a0: number; a1: number; b0: number; b1: number; d: number };
/**
 * A banded Hirschberg reconstruction of the Myers minimum D. At each cell,
 * shortest-cost ties choose deletion, insertion, then equality. Propagating
 * the first crossing of the middle base row selects that exact canonical path,
 * unlike a locally tied greedy middle snake. Only two active rows are retained.
 * The two child distances sum to D while their base lengths halve: O(N(D+1))
 * time and O(N+M) space, including the input/output and the explicit task stack.
 */
async function split(a: readonly number[], b: readonly number[], region: Region, work: Computation) {
  const { a0, a1, b0, b1, d } = region, n = a1 - a0, m = b1 - b0, mid = Math.floor(n / 2);
  const width = Math.min(m + 1, 2 * d + 1), infinity = n + m + 1;
  let next = new Float64Array(width), row = new Float64Array(width);
  let nextCross = new Float64Array(width), rowCross = new Float64Array(width);
  let nextLow = 1, nextHigh = 0, middleLow = 0, middle = new Float64Array(0);
  for (let i = n; i >= 0; i--) {
    const low = Math.max(0, i - d), high = Math.min(m, i + d);
    for (let j = high; j >= low; j--) {
      const at = j - low;
      const down = i < n && j >= nextLow && j <= nextHigh ? next[j - nextLow] + 1 : infinity;
      const right = j < high ? row[at + 1] + 1 : infinity;
      const diagonal = i < n && j < m && j + 1 >= nextLow && j + 1 <= nextHigh && a[a0 + i] === b[b0 + j]
        ? next[j + 1 - nextLow] : infinity;
      const cost = i === n && j === m ? 0 : Math.min(down, right, diagonal);
      row[at] = cost;
      if (i === mid) rowCross[at] = j;
      else if (i < mid) rowCross[at] = cost === down ? nextCross[j - nextLow]
        : cost === right ? rowCross[at + 1] : nextCross[j + 1 - nextLow];
      const pause = work.step(); if (pause) await pause;
    }
    if (i === mid) { middleLow = low; middle = row.slice(0, high - low + 1); }
    [next, row] = [row, next]; [nextCross, rowCross] = [rowCross, nextCross];
    nextLow = low; nextHigh = high;
  }
  const crossing = nextCross[0], rightDistance = middle[crossing - middleLow];
  if (!Number.isSafeInteger(crossing) || !Number.isSafeInteger(rightDistance) || rightDistance > d)
    throw new Error('invalid canonical edit crossing');
  return { a: a0 + mid, b: b0 + crossing, leftDistance: d - rightDistance, rightDistance };
}

async function edits(base: Lines, target: Lines, work: Computation): Promise<Diff3LineEditV1[]> {
  work.phase = 'distance';
  const d = await distance(base.ids, target.ids, work);
  work.phase = 'reconstruct';
  const result: Diff3LineEditV1[] = [];
  let pending: { start: number; end: number; chunks: string[] } | undefined;
  const flush = () => {
    if (pending) result.push({ baseStart: pending.start, baseEnd: pending.end, replacement: pending.chunks.join('') });
    pending = undefined;
  };
  const deletion = (start: number, end: number) => {
    if (!pending) pending = { start, end: start, chunks: [] };
    pending.end = end;
  };
  const insertion = async (position: number, start: number, end: number) => {
    if (start === end) return;
    if (!pending) pending = { start: position, end: position, chunks: [] };
    for (let j = start; j < end; j++) {
      pending.chunks.push(target.text[j]); const pause = work.step(); if (pause) await pause;
    }
  };
  const stack: Region[] = [{ a0: 0, a1: base.ids.length, b0: 0, b1: target.ids.length, d }];
  while (stack.length) {
    const region = stack.pop()!, { a0, a1, b0, b1 } = region, n = a1 - a0, m = b1 - b0;
    const pause = work.step(); if (pause) await pause;
    if (!n) { await insertion(a0, b0, b1); continue; }
    if (!m) { deletion(a0, a1); continue; }
    if (!region.d) { flush(); continue; }
    if (n === 1) {
      // The last match permits the earliest insertions; a deletion wins if none exists.
      let match = -1;
      for (let j = b0; j < b1; j++) {
        if (base.ids[a0] === target.ids[j]) match = j;
        const pause = work.step(); if (pause) await pause;
      }
      if (match < 0) { deletion(a0, a1); await insertion(a1, b0, b1); }
      else { await insertion(a0, b0, match); flush(); await insertion(a1, match + 1, b1); }
      continue;
    }
    const middle = await split(base.ids, target.ids, region, work);
    stack.push({ a0: middle.a, a1, b0: middle.b, b1, d: middle.rightDistance });
    stack.push({ a0, a1: middle.a, b0, b1: middle.b, d: middle.leftDistance });
  }
  flush(); return result;
}

function overlaps(a: Diff3LineEditV1, b: Diff3LineEditV1): boolean {
  if (a.baseStart === a.baseEnd) return b.baseStart === b.baseEnd ? a.baseStart === b.baseStart
    : b.baseStart < a.baseStart && a.baseStart < b.baseEnd;
  if (b.baseStart === b.baseEnd) return a.baseStart < b.baseStart && b.baseStart < a.baseEnd;
  return a.baseStart < b.baseEnd && b.baseStart < a.baseEnd;
}

/** Pure text projection only; UTF-8/NUL/type/mode eligibility belongs to the owner. */
export async function mergeTextDiff3V1(baseText: string, currentText: string, desiredText: string,
  options: Diff3ComputationV1 = {}): Promise<Diff3TextResultV1> {
  const work = new Computation(options); work.check();
  const table: LineTable = { entries: new Map(), nextId: 1 };
  const base = await tokenize(baseText, table, work), current = await tokenize(currentText, table, work),
    desired = await tokenize(desiredText, table, work);
  const currentEdits = await edits(base, current, work), desiredEdits = await edits(base, desired, work);
  work.phase = 'merge';
  const conflicts: Diff3TextConflictV1[] = [], accepted: Diff3LineEditV1[] = [];
  let ci = 0, di = 0;
  while (ci < currentEdits.length || di < desiredEdits.length) {
    const c = currentEdits[ci], d = desiredEdits[di];
    const pause = work.step(); if (pause) await pause;
    if (c && d && overlaps(c, d)) {
      if (c.baseStart === d.baseStart && c.baseEnd === d.baseEnd && await equalText(c.replacement, d.replacement, work)) {
        accepted.push(c); ci++; di++;
      } else {
        conflicts.push({ current: c, desired: d });
        if (c.baseEnd <= d.baseEnd) ci++;
        if (d.baseEnd <= c.baseEnd) di++;
      }
      continue;
    }
    // Empty edits precede same-start nonempty edits: the boundary insertion remains before the replacement.
    if (c && (!d || c.baseStart < d.baseStart || (c.baseStart === d.baseStart && c.baseEnd <= d.baseEnd))) {
      accepted.push(c); ci++;
    } else { accepted.push(d); di++; }
  }
  work.check();
  if (conflicts.length) return { kind: 'conflict', conflicts, currentEdits, desiredEdits };
  work.phase = 'output'; work.check();
  const chunks: string[] = [];
  let cursor = 0;
  for (const edit of accepted) {
    const pause = work.step(); if (pause) await pause;
    for (; cursor < edit.baseStart; cursor++) { chunks.push(base.text[cursor]); const pause = work.step(); if (pause) await pause; }
    chunks.push(edit.replacement); cursor = edit.baseEnd;
  }
  for (; cursor < base.text.length; cursor++) { chunks.push(base.text[cursor]); const pause = work.step(); if (pause) await pause; }
  work.check();
  return { kind: 'merged', text: chunks.join(''), currentEdits, desiredEdits };
}
