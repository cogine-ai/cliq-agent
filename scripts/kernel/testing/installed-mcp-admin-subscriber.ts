// Fixed disposable signed qualification-image subscriber only.
import { writeSync } from 'node:fs';
import { observeMcpAdminLifecycle } from '../../../src/state/mcp-admin-diagnostics.js';
import { createMcpAdminLifecycleSink } from './installed-mcp-admin-sink.js';
observeMcpAdminLifecycle(createMcpAdminLifecycleSink(line => writeSync(2, line)));
