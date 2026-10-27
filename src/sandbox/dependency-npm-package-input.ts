// The fixed dependency recipe alone receives this actual metadata channel as
// FD4. The original native owner has already checked its seals, full digest
// and borrowed identity. This reader neither accepts an FD nor mints proof.
import { closeSync, fstatSync, readSync } from 'node:fs';
import { DEPENDENCY_NPM_PACKAGE_INPUTS, dependencyNpmInput, dependencyNpmPackageSequence,
  type DependencyNpmInputV1, type DependencyNpmPackageInputV1 } from './dependency-npm-data.js';

export function* fixedDependencyNpmPackageInputs(value: DependencyNpmInputV1): Generator<DependencyNpmPackageInputV1, void, void> {
  try {
    const input = dependencyNpmInput(value), before = fstatSync(4), sequence = dependencyNpmPackageSequence(input);
    if (!before.isFile() || before.nlink !== 0 || before.size < 0 || before.size > DEPENDENCY_NPM_PACKAGE_INPUTS.totalBytes ||
        before.uid !== process.getuid?.()) throw new TypeError('fixed package metadata file');
    let offset = 0;
    function read(bytes: Buffer): void {
      let at = 0;
      while (at < bytes.length) {
        const n = readSync(4, bytes, at, bytes.length - at, offset);
        if (!n) throw new TypeError('short package metadata');
        at += n; offset += n;
      }
    }
    for (let index = 0; index < input.packageCount; index++) {
      const length = Buffer.alloc(4); read(length); const count = length.readUInt32LE();
      if (count < 1 || count > DEPENDENCY_NPM_PACKAGE_INPUTS.recordBytes || offset + count > before.size) throw new TypeError('package metadata record size');
      const bytes = Buffer.alloc(count); read(bytes); yield sequence.append(bytes);
    }
    if (offset !== before.size || readSync(4, Buffer.alloc(1), 0, 1, offset)) throw new TypeError('long package metadata');
    const after = fstatSync(4);
    for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'nlink', 'mtimeMs', 'ctimeMs'] as const)
      if (before[key] !== after[key]) throw new TypeError('package metadata changed');
    sequence.finish();
  } finally {
    // A short record, invalid suffix or failed cache consumer joins the same
    // held descriptor. A close failure is fatal to this trusted process.
    closeSync(4);
  }
}
