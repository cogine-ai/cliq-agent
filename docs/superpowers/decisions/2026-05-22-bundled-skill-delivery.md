# Decision: Bundled Skill Delivery And Updates

Date: 2026-05-22

Issues: #120, #121, #122, #123, #124, #125, #126, #127, #128

## Decision

Cliq will ship first-party skills as immutable package content under
`skills/.system` and load them directly as `scope=builtin`.

Cliq will not install, copy, sync, or overwrite those built-in skills into
`$CLIQ_HOME/skills`, `~/.cliq/skills`, `.cliq/skills`, or `.agents/skills`
during package installation or normal startup.

## Rationale

Package-contained built-ins keep ownership clear:

- Built-in skills are owned by the installed Cliq version.
- User skills under `~/.cliq/skills` and `~/.agents/skills` are owned by the
  operator.
- Project skills under `.cliq/skills` and `.agents/skills` are owned by the
  trusted workspace.

Copying built-ins into user-owned skill roots would create stale copies,
overwrite risks, merge conflicts, and different behavior between package
managers. It would also depend on install-time scripts that can be skipped by
`npm --ignore-scripts` and are undesirable in CI or enterprise environments.

## Delivery Model

The npm package includes `skills/**`. At runtime, Cliq resolves the installed
package root from `import.meta.url`, discovers `skills/.system`, and appends
those entries to the skill catalog with the lowest precedence:

```text
project skill > user skill > built-in skill
```

This means built-ins are available immediately after installing or upgrading
`@cogineai/cliq`, while local skills can still shadow them intentionally.

Skill instruction layers include the activated skill directory. This is
required for script-bearing skills because bundled scripts are resolved relative
to the package directory, while bash normally runs in the workspace cwd.

## Upgrade Model

Built-in skill upgrades are package upgrades:

```bash
npm install -g @cogineai/cliq@latest
```

Cliq already has a lightweight npm latest-version check. That is enough for the
first bundled-skill release because there is no separate mutable system-skill
state to migrate.

User and project skills are not auto-updated by package upgrades. Updating
third-party or copied skills belongs to the skill installer/manager workflow,
not to the Cliq package install path.

## `cliq update`

Do not add a self-mutating updater in this stage.

If a `cliq update` command is added later, the first version should be advisory:

- Check the latest package version from npm.
- Print the exact package-manager command to run.
- Explain that built-in skills update together with the package.
- Avoid modifying the current executable by default.

An opt-in `cliq update --apply --yes` can be considered later only for
confidently detected npm-global installs. It should fall back to advisory output
for local checkouts, `npx`, `pnpm dlx`, workspace installs, permission errors,
enterprise-pinned versions, or ambiguous package managers.

## Deferred

- No install-time postinstall copy step.
- No automatic reconciliation between built-in skills and user skill roots.
- No separate built-in-skill version registry outside `package.json`.
- No default automatic update of third-party skills.
