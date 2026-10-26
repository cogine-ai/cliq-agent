// Fixed qualification-image subscriber only; never imported by a default image.
import { writeSync } from 'node:fs';
import { observeInstalledResources } from '../../../src/state/installed-resource-diagnostics.js';
import { createInstalledResourceSink } from './installed-resource-sink.js';
observeInstalledResources(createInstalledResourceSink(line => writeSync(2, line)));
