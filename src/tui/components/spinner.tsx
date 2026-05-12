import { Text } from 'ink';
import { useEffect, useState } from 'react';

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'] as const;
const FRAME_INTERVAL_MS = 80;

export function Spinner() {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setFrame((f) => (f + 1) % FRAMES.length);
    }, FRAME_INTERVAL_MS);
    // Don't pin the Node event loop on the spinner: tests that mount this
    // component would otherwise hang waiting for the interval to clear.
    id.unref?.();
    return () => {
      clearInterval(id);
    };
  }, []);

  return <Text color="cyan">{FRAMES[frame]}</Text>;
}
