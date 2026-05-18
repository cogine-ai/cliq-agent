import { render } from 'ink';

import { WorkspaceTrustPrompt } from './components/workspace-trust-prompt.js';

export async function mountWorkspaceTrustDialogAndWait(workspaceRealPath: string, cwdLabel?: string): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const instance = render(
      <WorkspaceTrustPrompt
        workspaceRealPath={workspaceRealPath}
        {...(cwdLabel ? { cwdLabel } : {})}
        onDecided={(trusted) => {
          instance.unmount();
          resolve(trusted);
        }}
      />,
      { exitOnCtrlC: false }
    );
  });
}
