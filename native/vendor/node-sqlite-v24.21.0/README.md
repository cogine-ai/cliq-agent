# Fixed SQLite extension headers

These two files are unchanged build-time copies from the Node.js `v24.21.0`
source tree:

- [`sqlite3.h`](https://raw.githubusercontent.com/nodejs/node/v24.21.0/deps/sqlite/sqlite3.h)
  — SHA-256 `919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d`
- [`sqlite3ext.h`](https://raw.githubusercontent.com/nodejs/node/v24.21.0/deps/sqlite/sqlite3ext.h)
  — SHA-256 `ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be`

`scripts/kernel/sqlite-extension-headers.mjs` checks the actual file bytes
before exposing this fixed include directory to a build. Only headers are
vendored: there is no SQLite amalgamation, library, or second engine. The
extension receives its API table from the executing Node's SQLite engine.
The qualified installed SEA uses Node `24.21.0`; these headers do not change
the public client's Node requirement or qualify other SQLite engines.

## Copyright and license

Both files retain their original copyright disclaimer and blessing in full.
They are SQLite upstream code dedicated to the public domain, not code
relicensed under Cliq's MIT license. See
[SQLite's copyright statement](https://www.sqlite.org/copyright.html).
Node's [license file](https://raw.githubusercontent.com/nodejs/node/v24.21.0/LICENSE)
also distinguishes its own license from externally maintained libraries.
No Node implementation or SQLite build scripts are included here.
