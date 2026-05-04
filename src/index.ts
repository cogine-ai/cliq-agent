#!/usr/bin/env node
import { cliExitCode, renderUnhandledError, runCli } from './cli.js';

runCli(process.argv).catch((error) => {
  const message = renderUnhandledError(error);
  if (message) {
    console.error(message);
  }
  process.exit(cliExitCode(error));
});
