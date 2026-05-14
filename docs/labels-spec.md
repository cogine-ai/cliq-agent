# GitHub Labels Universal Schema (v1.0)

> **Status:** Active — first finalized version
> **Scope:** All repositories under the `cogine-ai` org
> **Canonical home:** `cogine-ai/.github/profile/LABELS.md` (target; this draft currently lives in `cogine-ai/cliq-agent/docs/labels-spec.md` until the org-level repo is created)

This document defines the single label schema used across every repository under the `cogine-ai` org. Every repo participating in shared automation must follow this schema. Repos add their own ownership/scope dimension on top.

---

## Why one schema

Without a shared schema, each repo and each automation invents its own labels:

- `bug` vs `type:bug` vs `kind/bug` vs `category-bug`
- `needs-triage` vs `triage` vs `untriaged`

This makes cross-repo filtering useless and forces every new automation to learn each repo's idiosyncratic dialect. v1.0 fixes this by defining **5 universal dimensions**; everything else is either repo-local or non-label metadata.

---

## Design principles

1. **Labels are decision filters, not metadata storage.** A label exists only if someone (human or bot) needs to filter GitHub lists by it. Origin, agent identity, CI failure subtype → go in the issue body, not in labels.
2. **Additive only — no renames.** Existing labels that automation depends on are locked (see *Locked legacy labels* below). New schema goes alongside, never replaces.
3. **Six dimensions max.** More dimensions = combinatorial explosion + analysis paralysis at triage time.

---

## The 5 universal dimensions

### 1. `type:*` — what is this work?

| Label | Description |
|---|---|
| `type:bug` | An existing feature behaving incorrectly |
| `type:feature` | A new capability |
| `type:story` | A user-value narrative spanning multiple issues (usually a parent) |
| `type:task` | Engineering or operations work with no direct user-facing value |
| `type:docs` | Documentation-only change |
| `type:decision` | Pending decision record (RFC or discussion) |
| `type:feedback` | Aggregated external feedback, not yet broken down |

### 2. `status:*` — what action is needed now?

| Label | Description |
|---|---|
| `status:needs-triage` | New, not yet classified |
| `status:backlog` | Classified but not scheduled |
| `status:ready` | Ready to be picked up |
| `status:blocked` | **External** blocker (dependency, upstream PR, design pending, review) |
| `status:needs-design` | Implementation needs design output first |
| `status:needs-repro` | Bug lacks reproducible steps |
| `status:duplicate-candidate` | Suspected duplicate, awaiting human confirmation |

### 3. `priority:*` — how important?

`priority:p0` / `priority:p1` / `priority:p2` / `priority:p3`

### 4. `size:*` — how much work?

`size:xs` / `size:s` / `size:m` / `size:l` / `size:xl`

### 5. `bot:*` — automation pipeline state

| Label | Description |
|---|---|
| `bot:created` | A bot opened this issue/PR |
| `bot:triaged` | A bot has classified and labeled this |
| `bot:validated` | A bot has verified (repro / dedup / dependency check) |
| `bot:needs-human` | Bot lacks confidence or permission; human takeover required |

> The prefix is intentionally `bot:`, **not** `agent:`. The `agent:*` namespace is reserved for future use to identify *which* agent (claude / codex / copilot / etc.) acted on an issue.

---

## Boundary rules

### `status:blocked` vs `bot:needs-human` (orthogonal — can coexist)

- `status:blocked` describes **the work**: an external factor halts progress. The work itself may be perfectly well-defined.
- `bot:needs-human` describes **the bot**: the pipeline cannot decide what to do next; a human must take over.

A CI failure illustrates both possibilities:

- Cause is known → `status:blocked` (waiting for fix), do **not** add `bot:needs-human`.
- Cause is unclassifiable → `bot:needs-human` (waiting for human triage), usually also `status:blocked`.

### Who can change which labels

| Dimension | Bot may set directly | Bot may suggest (via comment) | Humans only |
|---|:---:|:---:|:---:|
| `type:*` | ✅ | — | — |
| `status:*` | ✅ | — | — |
| `size:xs` / `size:s` | ✅ | — | — |
| `size:m` / `size:l` / `size:xl` | — | ✅ | ✅ |
| `priority:*` | — | ✅ | ✅ |
| `bot:*` | ✅ (its own pipeline only) | — | — |
| area / workstream | per repo policy | — | — |

> "Suggest" = post a sticky comment with the recommended label. Do **not** apply it directly. Priority and size-of-M-or-larger are judgment-heavy and prone to bot error.

---

## Locked legacy labels (DO NOT RENAME)

These labels are read or written **by exact name** by scheduled cron jobs. Renaming or removing them silently breaks running automation — no error, just degraded behavior.

| Label | Owner job | Why locked |
|---|---|---|
| `auto-todo` | TODO scanner (daily 22:30) | Used as dedup query filter: `gh issue list --label auto-todo`. Rename → dedup set is empty → **all TODOs get re-created on next run** |
| `todo` | TODO scanner | Output marker for TODO-derived issues |
| `fixme` | TODO scanner | Output marker for FIXME-derived issues |
| `possibly-duplicate` | Dup detector (every 3h) | Set on both sides of a duplicate pair |
| `needs-conflict-resolve` | PR auto-rebase (every 15m) | **The job's only persistent state.** Add when rebase fails, remove when conflict clears. Rename → state machine forgets every PR |

**Scope note:** `needs-conflict-resolve` is in circulation across **every** repo where the maintainer has WRITE/ADMIN permission, not just the two pilot repos. Most repos in the org will already have it.

---

## Repo-local extension: ownership / scope

This dimension is **not** part of the universal schema. Each repo defines its own values, using the following prefix convention:

| Repo type | Recommended prefix | Example values |
|---|---|---|
| Product repos (e.g. `DearClaw`) | `workstream:*` | `workstream:onboarding`, `workstream:billing` |
| Tool / code repos (e.g. `cliq-agent`) | `area:*` | `area:tui`, `area:runtime`, `area:rpc` |

Pick **one** prefix per repo. Don't mix.

---

## Non-label metadata: `agent-meta` marker

Information that doesn't justify a label (origin, agent identity, CI failure subtype, etc.) goes in a single-line HTML comment at the top of the issue/PR body:

```html
<!-- agent-meta source=todo agent=todo-agent run=2026-05-14T10:30:00Z -->
```

Rules:

- Single line; `key=value` pairs separated by spaces; **values must not contain spaces**.
- Required key: `source` ∈ {`todo`, `user-feedback`, `review-comment`, `ci`, `manual`}
- Optional keys: `agent`, `run` (ISO timestamp), plus anything else useful.

Searchable via GitHub's full-text search:

- All TODO-derived issues: `is:issue "agent-meta source=todo"`
- Issues from a specific agent: `is:issue "agent=todo-agent"`

### Existing markers (already in production, don't collide)

Some automation already uses purpose-specific body markers. These continue to be valid, alongside `agent-meta`:

- `<!-- auto-todo-key: <owner>/<repo>:<sha1[:12]> -->` — TODO scanner's dedup key
- `<!-- dup-pair: {smaller}-{larger} -->` — Dup detector's pair record

These coexist with `agent-meta` (different prefixes, different roles).

---

## Onboarding a repo — 4 steps

### Step 1 — Add `.github/labels.yml`

Copy the [labels.yml template](#template-githublabelsyml) below into the repo. The template includes all universal labels + the locked legacy labels. The bottom section is for the repo's own `area:*` or `workstream:*` values.

### Step 2 — Add `.github/workflows/labels-sync.yml`

Copy the [workflow template](#template-githubworkflowslabels-syncyml) below.

### Step 3 — Set repo-local `area:*` or `workstream:*` values

Edit the bottom of `labels.yml` with the repo's real area/workstream values.

### Step 4 — Open a PR and merge

On merge to `main`, the workflow runs `EndBug/label-sync` and applies all labels. Existing labels with the same name are preserved (no rename). New labels are created.

> The workflow is configured with `delete-other-labels: false`, so any label already in the repo that isn't yet in `labels.yml` (e.g., GitHub defaults, repo-specific labels not yet adopted) is **left alone**.

---

## Template: `.github/labels.yml`

```yaml
# Universal Schema v1.0 — synced from the cogine-ai org-wide spec.
# Spec: cogine-ai/.github/profile/LABELS.md
#
# Edit the area/workstream section at the bottom for this repo.
# DO NOT rename labels in the "Locked legacy" section without coordinating
# with the maintainer — they are read by exact name by cron automation.

# === type:* ===
- name: 'type:bug'
  color: 'd73a4a'
  description: 'Existing feature behaving incorrectly'
- name: 'type:feature'
  color: 'a2eeef'
  description: 'A new capability'
- name: 'type:story'
  color: '7057ff'
  description: 'User-value narrative spanning multiple issues'
- name: 'type:task'
  color: 'c5def5'
  description: 'Engineering or ops work, no direct user-facing value'
- name: 'type:docs'
  color: '0075ca'
  description: 'Documentation-only change'
- name: 'type:decision'
  color: '5319e7'
  description: 'Pending decision record (RFC or discussion)'
- name: 'type:feedback'
  color: 'bfd4f2'
  description: 'External feedback, not yet broken down'

# === status:* ===
- name: 'status:needs-triage'
  color: 'ededed'
  description: 'New, not yet classified'
- name: 'status:backlog'
  color: 'c2e0c6'
  description: 'Classified but not scheduled'
- name: 'status:ready'
  color: '2cbe4e'
  description: 'Ready to be picked up'
- name: 'status:blocked'
  color: 'e11d21'
  description: 'External blocker (dependency, upstream, design, review)'
- name: 'status:needs-design'
  color: '006b75'
  description: 'Implementation needs design output first'
- name: 'status:needs-repro'
  color: 'f9d0c4'
  description: 'Bug lacks reproducible steps'
- name: 'status:duplicate-candidate'
  color: 'eb6420'
  description: 'Suspected duplicate, awaiting human confirmation'

# === priority:* ===
- name: 'priority:p0'
  color: '8b0000'
  description: 'Drop everything else'
- name: 'priority:p1'
  color: 'ee0701'
  description: 'High — schedule this sprint'
- name: 'priority:p2'
  color: 'f2b400'
  description: 'Normal'
- name: 'priority:p3'
  color: '1d76db'
  description: 'Low — nice to have'

# === size:* ===
- name: 'size:xs'
  color: 'cce5ff'
  description: 'Less than half a day'
- name: 'size:s'
  color: '99ccff'
  description: 'Half a day to one day'
- name: 'size:m'
  color: '6699ff'
  description: '1–3 days'
- name: 'size:l'
  color: '3366cc'
  description: 'About a week'
- name: 'size:xl'
  color: '0033aa'
  description: 'More than a week — consider splitting'

# === bot:* ===
- name: 'bot:created'
  color: 'cfd3d7'
  description: 'Created by an automation bot'
- name: 'bot:triaged'
  color: 'cfd3d7'
  description: 'A bot has classified and labeled this'
- name: 'bot:validated'
  color: 'cfd3d7'
  description: 'A bot has verified (repro / dedup / dependencies)'
- name: 'bot:needs-human'
  color: 'ffd700'
  description: 'Bot lacks confidence or permission; human takeover required'

# === LOCKED legacy: read/written by exact name by cron automation. DO NOT RENAME. ===
- name: 'auto-todo'
  color: '0e8a16'
  description: 'Auto-generated from code TODO/FIXME comments'
- name: 'todo'
  color: 'fbca04'
  description: 'TODO marker in code'
- name: 'fixme'
  color: 'e99695'
  description: 'FIXME marker in code'
- name: 'possibly-duplicate'
  color: 'd93f0b'
  description: 'Auto-detected as possibly duplicate of another issue'
- name: 'needs-conflict-resolve'
  color: 'b60205'
  description: 'Conflicts with base branch require manual resolution'

# === REPO-LOCAL: edit the values below for this repo. ===
# Tool/code repos use `area:*`. Product repos use `workstream:*`. Pick ONE prefix.
#
# Example for cliq-agent (delete and replace with this repo's real values):
# - name: 'area:tui'
#   color: 'd4c5f9'
#   description: 'Terminal UI'
# - name: 'area:runtime'
#   color: 'd4c5f9'
#   description: 'Agent runtime'
# - name: 'area:rpc'
#   color: 'd4c5f9'
#   description: 'RPC layer'
#
# Example for DearClaw (delete and replace):
# - name: 'workstream:onboarding'
#   color: 'fbca97'
#   description: 'Onboarding flow'
# - name: 'workstream:billing'
#   color: 'fbca97'
#   description: 'Billing and payments'
```

---

## Template: `.github/workflows/labels-sync.yml`

```yaml
name: Sync labels

on:
  push:
    branches: [main]
    paths:
      - '.github/labels.yml'
      - '.github/workflows/labels-sync.yml'
  workflow_dispatch:

permissions:
  issues: write

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EndBug/label-sync@v2
        with:
          config-file: '.github/labels.yml'
          # CRITICAL: do NOT delete labels that aren't in labels.yml.
          # This keeps the sync purely additive and preserves locked labels
          # and any repo-specific labels not yet adopted.
          delete-other-labels: false
```

---

## Future cleanup (NOT part of v1.0 rollout)

Once the universal schema is adopted everywhere, future work can:

1. **Update each cron job's prompt** so it also applies universal labels alongside its locked ones. For example, the TODO scanner could add `type:task` (or `type:bug` for FIXMEs) in addition to `auto-todo`.
2. **Eventually retire locked labels** — but only after migrating their consumers (the cron jobs themselves) to use the universal labels for their state. This is non-trivial for `needs-conflict-resolve` since the rebase job's state machine depends on it.

Neither is required for v1.0 adoption. v1.0 is purely additive.

---

## Versioning

- **v1.0** (current) — Initial finalized schema. 5 universal dimensions, 5 locked legacy labels, repo-local `area:*` / `workstream:*` extension, `agent-meta` body marker convention.

Changes to this schema should be versioned and announced to all repo owners. Breaking changes (renaming, removing, or repurposing a universal label) require coordinated rollout across all repos and all consuming automation.
