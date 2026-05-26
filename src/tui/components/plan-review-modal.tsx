import { Box, Text, useInput, type Key } from 'ink';
import { useEffect, useRef, useState } from 'react';

import type { PendingPlanReview, UiPlanDecision } from '../store.js';

export type PlanReviewModalProps = {
  review: PendingPlanReview;
  activationKey?: string;
  onDecide: (decision: UiPlanDecision) => void;
};

export function PlanReviewModal({ review, activationKey, onDecide }: PlanReviewModalProps) {
  const isActiveRef = useRef(false);
  const [isActive, setIsActive] = useState(false);

  useEffect(() => {
    isActiveRef.current = false;
    setIsActive(false);
    const handle = setImmediate(() => {
      isActiveRef.current = true;
      setIsActive(true);
    });
    return () => {
      clearImmediate(handle);
      isActiveRef.current = false;
    };
  }, [activationKey]);

  useInput((input: string, key: Key) => {
    if (!isActiveRef.current) return;
    if (input === 'd' || input === 'D') {
      onDecide({ type: 'approve', targetMode: 'default' });
      return;
    }
    if (input === 'a' || input === 'A') {
      onDecide({ type: 'approve', targetMode: 'accept-edits' });
      return;
    }
    if (input === 'Y') {
      onDecide({ type: 'approve', targetMode: 'yolo' });
      return;
    }
    if (input === 'r' || input === 'R') {
      onDecide({ type: 'reject' });
      return;
    }
    if (input === 'c' || input === 'C' || key.escape) {
      onDecide({ type: 'cancel' });
    }
  });

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
      <Text color="cyan" bold>
        Plan review
      </Text>
      <Box flexDirection="column" marginTop={1}>
        <Field label="title" value={review.title} />
        <Field label="plan" value={review.planId} />
        <Field label="artifact" value={review.path} />
      </Box>
      <Box flexDirection="column" marginTop={1}>
        <Text>{review.contentMarkdown}</Text>
      </Box>
      <Box marginTop={1}>
        <Text color="green">[d]efault Run </Text>
        <Text color="green"> [a]ccept-edits Run </Text>
        <Text color="red" bold>
          {' '}
          [Y]OLO Run{' '}
        </Text>
        <Text color="yellow"> [r]eject </Text>
        <Text dimColor> [c]ancel Esc=cancel</Text>
      </Box>
      <Text color="red">YOLO Run auto-approves actions and is dangerous.</Text>
      {!isActive ? <Text dimColor>Waiting for fresh input...</Text> : null}
    </Box>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <Box>
      <Text dimColor>{`  ${label}: `}</Text>
      <Text>{value}</Text>
    </Box>
  );
}
