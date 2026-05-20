# Decision: Skill Trust And Permission Policy

Date: 2026-05-21

Issues: #128, #62, #111

## Decision

Cliq will not add dedicated `skill` or `skill-resource` permission grammar in this stage.

- Workspace Trust gates project skill discovery because project skills are workspace-controlled state.
- Tool Permission remains the independent per-action layer. Skill activation and skill resource reads are read-class tools.
- Sandbox and path boundaries remain the last line of defense for process and filesystem isolation.
- Skill resources resolve against the activated skill directory, not the workspace cwd.

## Workspace Trust

Project skill roots are read only after the normal Workspace Trust decision has allowed the runtime to load workspace-controlled state. This keeps skills in the same layer as `.cliq/config.json`, instruction files, hooks, validators, and runtime assembly.

Workspace `defaultSkills` can activate only project-owned skills. Ownership is checked with canonical realpaths so symlink or alias escapes are rejected before a skill body is injected.

## Tool Permission

Activation and resource reads use existing read-tool policy behavior:

- `{"skill":{"name":"..."}}` is a read-class tool that mutates session active-skill metadata.
- `{"skillResource":...}` is a read-class tool that returns bounded text/list output.
- Neither action grants bash/edit/network/MCP permissions.

If a read-class tool falls into an `ask` path in headless mode and no confirmer is available, the existing runtime behavior denies it with `confirmation required but no confirmer is available`.

## Resource Boundaries

Resource access is allowed only for activated skills. The resolver rejects absolute paths, parent traversal, symlink escapes, oversized files, and binary content. It never executes bundled scripts.

## Deferred

A dedicated `skill:` or `skill-resource:` permission channel may be added later if real usage shows that operators need separate allow/deny rules from ordinary read tools. Until then, adding new grammar would increase policy complexity without a validated need.
