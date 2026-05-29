import { Box, Text } from 'ink';

import type { PlanProgressSnapshot } from '../../plans/types.js';

const MAX_VISIBLE_ITEMS = 5;

export function PlanProgressView({ progress }: { progress: PlanProgressSnapshot }) {
  const completed = progress.items.filter((item) => item.status === 'completed').length;
  const pending = progress.items.filter((item) => item.status === 'pending').length;
  const total = progress.items.length;
  const activeItem = progress.items.find((item) => item.status === 'in_progress') ?? null;
  const visibleItems = getVisibleItems(progress.items);
  const hiddenItems = progress.items.filter((item) => !visibleItems.includes(item));
  const hiddenSummary = summarizeHiddenItems(hiddenItems);

  if (total === 0) return null;

  return (
    <Box flexDirection="column" marginTop={1}>
      <Box>
        <Text color={activeItem ? 'yellow' : completed === total ? 'green' : 'cyan'}>
          {`· ${activeItem ? activeItem.activeForm : progress.title}...`}
        </Text>
        <Text dimColor>{` (${completed}/${total} done`}</Text>
        {pending > 0 ? <Text dimColor>{` · ${pending} pending`}</Text> : null}
        <Text dimColor>{` · ${progress.title})`}</Text>
      </Box>
      {visibleItems.map((item) => (
        <Box key={item.id} marginLeft={2}>
          <Text color={itemColor(item.status)}>{`${itemIcon(item.status)} `}</Text>
          <Text bold={item.status === 'in_progress'} strikethrough={item.status === 'completed'} dimColor={item.status === 'completed'}>
            {item.title}
          </Text>
          {item.status === 'in_progress' ? <Text dimColor>{` - ${item.activeForm}`}</Text> : null}
        </Box>
      ))}
      {hiddenSummary ? (
        <Box marginLeft={4}>
          <Text dimColor>{hiddenSummary}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

function itemIcon(status: PlanProgressSnapshot['items'][number]['status']) {
  if (status === 'completed') return '✓';
  if (status === 'in_progress') return '■';
  return '□';
}

function itemColor(status: PlanProgressSnapshot['items'][number]['status']) {
  if (status === 'completed') return 'green';
  if (status === 'in_progress') return 'yellow';
  return undefined;
}

function getVisibleItems(items: PlanProgressSnapshot['items']) {
  if (items.length <= MAX_VISIBLE_ITEMS) return items;
  const activeIndex = items.findIndex((item) => item.status === 'in_progress');
  if (activeIndex === -1) return items.slice(0, MAX_VISIBLE_ITEMS);
  const start = Math.max(0, Math.min(activeIndex - 1, items.length - MAX_VISIBLE_ITEMS));
  return items.slice(start, start + MAX_VISIBLE_ITEMS);
}

function summarizeHiddenItems(items: PlanProgressSnapshot['items']): string | null {
  if (items.length === 0) return null;
  const counts = {
    inProgress: items.filter((item) => item.status === 'in_progress').length,
    pending: items.filter((item) => item.status === 'pending').length,
    completed: items.filter((item) => item.status === 'completed').length
  };
  const parts: string[] = [];
  if (counts.inProgress > 0) parts.push(`${counts.inProgress} in progress`);
  if (counts.pending > 0) parts.push(`${counts.pending} pending`);
  if (counts.completed > 0) parts.push(`${counts.completed} completed`);
  return `... +${parts.join(', ')}`;
}
