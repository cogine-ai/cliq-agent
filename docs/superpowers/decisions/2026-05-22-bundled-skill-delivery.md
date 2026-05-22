# Decision: Bundled Skill Delivery And Updates

Date: 2026-05-22

Issues: #120, #121, #122, #123, #124, #125, #126, #127, #128

## Decision

Cliq will ship first-party skills as package content under `skills/.system`, use
that package directory as the source of truth, and sync those skills into a
managed local system-skill directory:

```text
${CLIQ_HOME:-~/.cliq}/skills/.system/<skill-name>/SKILL.md
```

Runtime discovery loads built-in skills from this managed `.system` directory as
`scope=builtin`.

## Rationale

This matches the user-visible shape of Codex-style `.system` skills while
keeping package installation predictable:

- The npm package contains the canonical built-in skill contents.
- First use materializes missing built-in skills into `$CLIQ_HOME/skills/.system`.
- Built-in skills remain separate from ordinary user skills under
  `$CLIQ_HOME/skills/<name>`.
- User skills under `~/.cliq/skills` and `~/.agents/skills` are owned by the
  operator.
- Project skills under `.cliq/skills` and `.agents/skills` are owned by the
  trusted workspace.

The sync is intentionally done at runtime rather than through npm `postinstall`,
because package-manager install scripts can be skipped and can behave
differently in CI or managed environments.

## Delivery Model

The npm package includes `skills/**`. At runtime, Cliq resolves the installed
package root from `import.meta.url`, scans package `skills/.system`, and ensures
each package built-in exists under `$CLIQ_HOME/skills/.system`.

The initial merge rule is conservative:

- If `$CLIQ_HOME/skills/.system/<name>` is missing, copy the packaged skill.
- If that directory exists but is empty, replace it with the packaged skill.
- If that directory exists and is non-empty, leave it untouched.

Cliq then discovers `$CLIQ_HOME/skills/.system` and appends those entries to the
skill catalog with the lowest precedence:

```text
project skill > user skill > built-in skill
```

This means built-ins are available immediately after installing or upgrading
`@cogineai/cliq`, while local skills can still shadow them intentionally.

Skill instruction layers include the activated skill directory. This is
required for script-bearing skills because bundled scripts are resolved relative
to the activated skill directory, while bash normally runs in the workspace cwd.

## Upgrade Model

Built-in skill upgrades start with package upgrades:

```bash
npm install -g @cogineai/cliq@latest
```

On the next run, Cliq syncs any newly added built-in skills into
`$CLIQ_HOME/skills/.system`. Existing non-empty same-name built-in directories
are not overwritten in this release.

User and project skills are not auto-updated by package upgrades. Updating
third-party or copied skills belongs to the skill installer/manager workflow,
not to the Cliq package install path.

Future releases can add a manifest/hash-based replacement policy for built-ins
that must be force-upgraded. Until that exists, the default policy is merge-only.

## `cliq update`

Do not add a self-mutating updater in this stage.

If a `cliq update` command is added later, the first version should be advisory:

- Check the latest package version from npm.
- Print the exact package-manager command to run.
- Explain that missing built-in skills sync into `$CLIQ_HOME/skills/.system` on
  the next run.
- Avoid modifying the current executable by default.

An opt-in `cliq update --apply --yes` can be considered later only for
confidently detected npm-global installs. It should fall back to advisory output
for local checkouts, `npx`, `pnpm dlx`, workspace installs, permission errors,
enterprise-pinned versions, or ambiguous package managers.

## Deferred

- No install-time `postinstall` copy step.
- No overwrite of non-empty same-name built-in skill directories.
- No manifest/hash-based force-upgrade policy yet.
- No default automatic update of third-party skills.
