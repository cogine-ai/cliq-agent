# I1 worker seal: transaction-time freshness

Baseline: `ce23ed183f0f9323cedac623dd5398467dbfc5ad` (`main`, PR #516).
Scope: enforce the existing retirement-proof freshness requirement at the real
SQLite mutation boundary. This is a correctness fix, not qualification of
successful sealing under arbitrarily slow storage or completion of I1.
The normative owner/inspector/five-second requirement remains
[RFC §9.1](../rfcs/2026-08-11-durable-verified-run-kernel.md#91-lease-activation-and-process-containment).

## Observed defect

`completeTool` validates the workspace/retirement closure and prepares its
settlement. `settleValidatedInvocation` samples `settledAt` before asynchronously
publishing that settlement and its continuation. The shared worker seal used
that staged timestamp to check the five-second death-evidence age inside the
later transaction. A delay during publication could therefore allow an expired
proof to seal a generation and publish a ready Checkpoint.

The separate direct worker seal already sampled its transaction clock, but
did not reject a snapshot later than that sample. A correction during artifact
observation/publication could leave the clock above the stored fence and still
commit a Checkpoint earlier than its snapshot, breaking historical validation.
The public Store regression also reproduced acceptance of that cut before the
correction. No observation bytes were rewritten to manufacture the failure.

The public loaded-Run regression reproduced this defect on the baseline: after
the real settlement FileHandle write, advancing the existing clock seam by
5,001 ms still completed the tool instead of rejecting it. The test uses offline
proof fixtures, not native process-death or Linux qualification evidence.

## Required behavior

- The shared worker seal samples the canonical clock inside its transaction,
  after asynchronous preparation. Age is checked against that actual sample,
  not an immutable artifact's earlier creation/settlement time.
- Exactly 5,000 ms remains valid; a greater age is `RECOVERY_REQUIRED`.
  A clock earlier than the staged settlement likewise cannot publish a seal.
- The direct worker seal additionally requires `snapshot.observedAt <= now`.
  Its validated ordering `death.observedAt <= snapshot.observedAt` then excludes
  both future snapshot and future death evidence, including a corrected clock
  that remains above the previously accepted time fence.
- Existing owner, exact Run/launch/generation cut, snapshot, inspector and
  atomic Journal/budget/continuation checks remain mandatory. No state, schema,
  public method, callback or retry lifecycle is added.
- Rejection rolls back the entire completion: no result, settlement, charge,
  frontier advance, ready Checkpoint or generation/launch seal becomes
  authoritative. Unrooted CAS bytes do not grant authority.
- Actual RunExecution may then fence its worker into the existing reconciliation
  wait. An already-performed edit is not undone or proved absent by that wait;
  its permanent claim and conservative reservation remain. No blind retry is
  allowed.

## Acceptance evidence

The portable public-StateStore tests cover late settlement publication,
the exact five-second boundary, a regressed transaction clock, and direct seal
after a clock correction that remains above the stored fence. They compare
the complete recovery cut for refusal and verify atomic successful completion
at the valid boundary.

The existing free Linux campaign additionally delays the actual settlement
write for more than five seconds after one real contained edit. It must reject
the stale completion, retain the exact unresolved claim/reservation and old
ready Checkpoint, fence into reconciliation, preserve the original host bytes,
and independently observe the edit in the private generation. Missing fault
injection, another primary error or unknown cleanup is not a pass.

Build, full tests and actual Linux qualification must pass at the PR's exact
head; their source revision, commands and CI run are recorded with the PR.
Prior #516 results do not qualify this change.

## Remaining integrated capability

Successful slow-I/O sealing still needs preparation of the immutable closure
before genuine native reobservation and a bounded final publication/commit
phase. Native cached stop results cannot be retimestamped as new death facts;
snapshot/quiescence ordering and all mutable fences must remain intact.
This fix does not supply that producer or an availability guarantee. Crash
stream-orphan cleanup, installation/CLI wiring, macOS execution and the other
I1–I4 acceptance requirements also remain separate unfinished work.
