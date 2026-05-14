# Labels Spec

The canonical GitHub label schema for the `cogine-ai` org is maintained at:

→ **<https://github.com/cogine-ai/.github/blob/main/LABELS.md>**

This file is intentionally a short pointer to avoid drift. See the canonical spec for:

- The 5 universal label dimensions (`type:*`, `status:*`, `priority:*`, `size:*`, `bot:*`)
- Repo-local `area:*` / `workstream:*` conventions
- The `agent-meta` body marker convention
- Locked legacy labels and their owning cron jobs
- Onboarding steps and templates

This repo's actual label set lives in [`.github/labels.yml`](../.github/labels.yml). The sync workflow is at [`.github/workflows/labels-sync.yml`](../.github/workflows/labels-sync.yml).
