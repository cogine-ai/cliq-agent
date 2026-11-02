# CI scope and verification cadence

Develop I2–I4 and all six work packages against their actual dependencies while
I1 qualification continues. A missing I1 fault cut does not block unrelated
implementation. Required evidence still gates completion and the default cutover.

During implementation, build and run the relevant regressions after a coherent
change. Batch independent changes into one fixed-source integration check rather
than restarting every full suite after each edit. The original local
`npm run build` and `npm test` must pass before pushing or opening a PR; run them
on the integrated candidate, not once for every internal edit. No CI selection
changes runtime assertions or release acceptance.

## Routing

`scripts/ci/route.mjs` supplies the same scope to Kernel foundation, Installed
ordinary permissions and Kernel MCP qualification. Each starts its small router job, so
workflow-level path filters do not leave absent required checks pending.

| Change | Selected coverage |
| --- | --- |
| Ordinary documentation | Router regressions only |
| RFC/work-package contracts or source test files | Original complete Linux/macOS, Node 22/24 host matrix |
| Explicitly listed independent qualification entry/fixture tests | Host matrix and the affected original Linux campaigns |
| Shared runtime, native code, dependencies, build, shared harness, workflow/router or unrecognized input | Every original group |

The narrow list is intentionally closed. Shared helper imports cannot be treated
as independent just because their filename mentions one campaign. Adding a new
input defaults to full coverage until its real consumers are understood.

The MCP workflow consumes the existing `run` group. Its new shared inputs and
unclassified qualification files select full coverage. It also runs on `codex/**`
branch pushes so the complete owned installation can be checked before opening
a PR. It uses the standard GitHub-hosted Ubuntu runner, the original native
prerequisites and twenty-minute campaign limit, and retains only JSON evidence.
Its controlled public endpoint cannot qualify real providers, authenticated
Bearer, other MCP recovery profiles or unexecuted physical cuts.

Pull requests compare the immutable head with the merge base of the immutable
base SHA, covering every commit in that PR. Development pushes compare their
actual before/after SHAs. Rename detection is disabled so deleted and added paths
both count. Missing history, new branches, invalid events, diff failures and
empty/oversized ranges select the full set. Router failure or missing outputs
also makes downstream jobs run; the failed router remains a failure.

The router is dependency-free and performs no provider, credential or native
operations. Its tests use local disposable Git histories and verify that every
original campaign body remains byte-identical after stripping only the exact
approved routing additions. Existing workflow security/timeout mutation tests
remain in place.

## Complete integration checks

Pushes to main, merge-queue checks and manual `workflow_dispatch` always select
all groups. For a complete development-branch check, run Kernel foundation,
Installed ordinary permissions and Kernel MCP qualification on the same unchanged
commit. The MCP branch-push run can supply that check before its new workflow
is registered on the default branch; inspect its actual routed scope as well.
Inspect each run's actual head SHA, all original job results and retained scope
reports. Do not combine evidence from different source versions.

An affected-only run explicitly reports that it is not complete qualification.
Skipped groups neither close old failures nor establish any unexecuted physical
cut. Original runner labels, campaign budgets, cleanup, secret scans, assertions
and artifact retention are unchanged. The router does not alter branch rules,
publish the product or authorize default cutover.
