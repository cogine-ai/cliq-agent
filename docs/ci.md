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

Pushes to main, merge-queue checks and ordinary manual `workflow_dispatch` select
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

## Exact-revision verifier diagnosis

For a free, focused development experiment, dispatch Kernel foundation with
`qualification_group=verifier`, `real_provider=false` and
`expected_revision=<the complete checked-out commit SHA>`. This runs the existing
verifier group (daily flow, independent signed Node probe and full verifier
campaign) with their original assertions, deadlines, cleanup and secret scans.
Its separate concurrency lane does not cancel a running full matrix. Missing,
conflicting or mismatched selections fall back to full qualification. Automatic
push/PR/merge routing is unchanged; the ordinary manual default remains `full`.
This diagnostic cannot replace the complete same-source checks before the PR.

## Explicit funded provider experiment

The owner authorized the dedicated DeepSeek credential on free GitHub-hosted
Linux on 2026-11-13. This supersedes the earlier prohibition on real credentials
in CI; it does not change product credential storage or any runtime safety check.

Set the temporary Actions secret `CLIQ_PROVIDER_QUALIFICATION_KEY` through a
private input channel. Dispatch **Kernel foundation** at the reviewed branch with
`qualification_group=full`, `real_provider=true` and
`expected_revision=<its complete commit SHA>`.
The reusable provider workflow verifies that exact checkout and uses only the
standard `ubuntu-22.04` runner. Pushes, PRs, merge queues and ordinary manual
runs never enter this job. This explicitly selected experiment does not rerun
unrelated qualification groups and cannot count as their qualification.

The secret exists in the one CI step's private environment only as an Actions
transport input. The wrapper removes it before spawning any child, sends its
owned buffer once after the original ready marker, and closes stdin. The normal
signed `models add` action still stores and finalizes it through Secret Service.
No key enters source, command arguments, public configuration or retained logs.
Only fixed phase messages and bounded original reports are retained; no raw child
output is uploaded. Remove the temporary Actions secret when the experiment ends.

Each explicitly dispatched journey uses a USD 3.50 Run ceiling (reduced from
USD 5 to stay within the remaining experiment authorization), the unchanged
conservative full-request token prices, five-minute Run budget and all original
command, READY, request, stop and cleanup checks. There is no automatic retry.
The operator must reserve CNY 24.50 against the authorized CNY 200 total before each
attempt, including an ambiguous/unfinished attempt; the factor seven covers the
selected published CNY/USD tariff ratios, not a currency-market assumption.
Do not dispatch beyond that total or treat an absent report as zero cost.
Prior unresolved USD 5 attempts retain their original CNY 35 reservations.
The fixed model, TLS pin and prices in `provider-qualification.ts` must be
reverified before a later experiment; they are not automatically updated.

The separate `Linux installed signed Node from Bash` job runs one fixed
controlled-endpoint case through the same signed installation and cleanup owner.
It verifies the real child Node command, private edits, required Node verifier,
original result/replay/retirement and secret scanning. It uses no real-provider
credential and has a ten-minute outer limit. Its bounded report explicitly does
not qualify the full verifier/restart campaign, I1 or the provider flow. The
original full campaign and its assertions remain independently required for
their respective qualification claims.
