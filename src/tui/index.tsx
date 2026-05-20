import { render } from 'ink';

import type { PolicyMode } from '../policy/types.js';
import { App } from './app.js';
import type { UiStore } from './store.js';

export type MountTuiOpts = {
  store: UiStore;
  onSubmit: (text: string) => void | Promise<void>;
  onReset?: () => void | Promise<void>;
  onPolicyChange?: (mode: PolicyMode) => void | Promise<void>;
  onCancelTurn?: () => void;
  onSkillsList?: () => string | Promise<string>;
  onSkillActivate?: (name: string) => string | Promise<string>;
};

export type MountedTui = {
  unmount: () => void;
  waitUntilExit: () => Promise<void>;
};

export function mountTui(opts: MountTuiOpts): MountedTui {
  const instance = render(
    <App
      store={opts.store}
      onSubmit={opts.onSubmit}
      {...(opts.onReset ? { onReset: opts.onReset } : {})}
      {...(opts.onPolicyChange ? { onPolicyChange: opts.onPolicyChange } : {})}
      {...(opts.onCancelTurn ? { onCancelTurn: opts.onCancelTurn } : {})}
      {...(opts.onSkillsList ? { onSkillsList: opts.onSkillsList } : {})}
      {...(opts.onSkillActivate ? { onSkillActivate: opts.onSkillActivate } : {})}
    />,
    // Defer Ctrl+C handling to <App> via useKeybindings so we can either
    // cancel the active turn or clear the input buffer per spec A.9.
    { exitOnCtrlC: false }
  );
  return {
    unmount: () => {
      instance.unmount();
    },
    waitUntilExit: async () => {
      await instance.waitUntilExit();
    }
  };
}
