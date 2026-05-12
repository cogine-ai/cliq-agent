import { render } from 'ink';

import { App } from './app.js';
import type { UiStore } from './store.js';

export type MountTuiOpts = {
  store: UiStore;
  onSubmit: (text: string) => void | Promise<void>;
};

export type MountedTui = {
  unmount: () => void;
  waitUntilExit: () => Promise<void>;
};

export function mountTui(opts: MountTuiOpts): MountedTui {
  const instance = render(<App store={opts.store} onSubmit={opts.onSubmit} />);
  return {
    unmount: () => {
      instance.unmount();
    },
    waitUntilExit: async () => {
      await instance.waitUntilExit();
    },
  };
}
