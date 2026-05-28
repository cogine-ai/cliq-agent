import { Box, Text } from 'ink';

import type { PlanProgressSnapshot } from '../../plans/types.js';

export function PlanProgressView({ progress }: { progress: PlanProgressSnapshot }) {
  const completed = progress.items.filter((item) => item.status === 'completed').length;
  const total = progress.items.length;

  if (total === 0) return null;

  return (
    <Box flexDirection="column" marginTop={1}>
      <Box>
        <Text color="cyan">Plan progress</Text>
        <Text dimColor>{` - ${completed}/${total} done - ${progress.title}`}</Text>
      </Box>
      {progress.items.map((item) => (
        <Box key={item.id}>
          <Text color={itemColor(item.status)}>{`${itemIcon(item.status)} `}</Text>
          <Text bold={item.status === 'in_progress'} strikethrough={item.status === 'completed'} dimColor={item.status === 'completed'}>
            {item.title}
          </Text>
          {item.status === 'in_progress' ? <Text dimColor>{` - ${item.activeForm}`}</Text> : null}
        </Box>
      ))}
    </Box>
  );
}

function itemIcon(status: PlanProgressSnapshot['items'][number]['status']) {
  if (status === 'completed') return '[x]';
  if (status === 'in_progress') return '[>]';
  return '[ ]';
}

function itemColor(status: PlanProgressSnapshot['items'][number]['status']) {
  if (status === 'completed') return 'green';
  if (status === 'in_progress') return 'cyan';
  return undefined;
}
