# Bounded Run scheduling

The installed Linux preview supports one concurrent Run. The actual account
can inspect or explicitly select this capacity with the signed entry:

```text
cliq settings
cliq settings --run-concurrency 1
```

The 2026-11-13 preview scope defers higher concurrency. The underlying scheduling
format and queue retain their broader implementation, but installed settings
reject unsupported capacity before writing, and Supervisor startup rejects an
existing higher value without rewriting it. Explicitly set the value to one to
start the preview. This does not retire or discard previously retained workers.

The fixed, canonical `run-scheduling.json` record lives in the existing
account-owned, installation-bound private client directory. It contains only
`schemaVersion: 1` and `maxConcurrentRuns`. The Supervisor reads it once at
startup, without creating the directory or file. Only genuine absence selects
the default; malformed, oversized, replaced or incorrectly owned data refuses
startup. No workspace configuration, environment override or raw control
request sets this value. A change applies on the next Supervisor start;
`supervisor.status.queue.capacity` reports that running Supervisor's value.

Driver tasks use bounded FIFO lanes. New admissions and wakes consider older
queued Runs first; existing sorted startup and maintenance batches enqueue
directly. Each driver still proves its original eligibility. Insufficient
capacity leaves a Run queued without a new wait, attempt, lease or consumption.

Driver count is separate from retained physical resources. Every Run with an
unretired WorkerLaunch, including preparing and recovery branches, occupies a
slot until the existing retirement transaction commits. The original preparing
transaction rechecks the same SQL capacity before recording an intent, so two
drivers cannot both take the last slot. A loser creates no resource birth and
joins its validation-only launcher before remaining queued. Lowering capacity
does not adopt, revoke or retire existing resources; new births wait.

This setting grants no tool permission and raises no Run, child, budget, lease,
deadline or sandbox ceiling. Work within one Run remains sequential. Whole
Supervisor shutdown still revokes every original producer before joining them.
The original two-second stop limit remains mandatory at the configured load.

Component queue, SQLite and settings tests do not qualify actual simultaneous
installed Runs, native cleanup, resource pressure or the 1,000-Run inventory.
Those physical campaigns and all existing release gates remain required.
