# Cliq Agent Skills Foundation Design

Date: 2026-05-20
Status: Initial design draft
Scope: Foundational support for the first seven skill modules. Management CLI and security-management commands are intentionally left as a discussion track.

## Background

Cliq already has a minimal local skill mechanism:

- CLI/headless requests can carry `skills?: string[]`.
- Workspace config supports `defaultSkills`.
- `src/skills/loader.ts` loads `./.cliq/skills/<name>/SKILL.md`.
- `src/instructions/builder.ts` injects loaded skill bodies as system instruction layers.

That current design is useful for manually activated, workspace-local prompt overlays. It is not enough for a larger Agent Skills ecosystem because it eagerly injects full skill bodies, has no catalog, has only one discovery root, cannot load user/global skill resources outside the workspace, and has no skill-specific trust or permission channel.

The target design keeps Cliq's existing security model intact:

1. Workspace Trust decides whether repo-controlled state may be loaded.
2. Tool Permission decides whether a specific runtime action is allowed.
3. Sandbox/Boundary enforcement remains independent of both.

Skill support must not collapse these layers.

## External References

This design is based on observed behavior and documentation from:

- Agent Skills specification: `SKILL.md` directory format, frontmatter fields, optional `scripts/`, `references/`, `assets/`, and strict validation guidance.
- Agent Skills client implementation guide: progressive disclosure, catalog/instruction/resource tiers, lenient parsing, dedicated activation tool option, structured wrapping, resource listing, permission filtering, and compaction protection.
- Codex: progressive disclosure, initial skill catalog budget, explicit `/skills` and `$skill` invocation, repo/user/admin/system discovery through `.agents/skills`, and plugin packaging as the distribution layer.
- Pi: multi-scope discovery, `.agents/skills` interoperability, `--skill` paths, `/skill:name` explicit loading, lenient validation, and scope-grouped prompt disclosure.
- OpenCode: native `skill` tool, available skills embedded in tool description, pattern-based `permission.skill`, per-agent overrides, and hiding denied skills from agents.
- Kimi Code CLI: layered Project/User/Extra/Built-in discovery, cross-client directories, skills vs plugins separation, `/skill:<name>` invocation, and optional flow skills as a later non-MVP idea.
- Cline: progressive loading, `use_skill` tool, explicit slash invocation, workspace/global skill locations, enable/disable toggles, and supporting docs/templates/scripts loaded on demand.

## Goals

- Support Agent Skills-compatible local skills without making every skill a permanent system prompt payload.
- Preserve existing `--skill` and `defaultSkills` behavior as compatibility surfaces while changing the internals to catalog + activation.
- Make project, user, and shared `.agents/skills` skills visible through a deterministic catalog.
- Let the model activate skills on demand and let the user force activation explicitly.
- Keep skill content effective across Cliq compaction and session replay.
- Let activated skills safely reference bundled files without granting broad workspace escape.
- Add skill-specific permission and trust controls that fit Cliq's existing policy engine.

## Non-Goals

- No remote marketplace or registry in this foundation slice.
- No package installer in this foundation slice.
- No new model-callable business tools from skills. Skills provide instructions and resources; executable tools remain tools, MCP, extensions, or future plugins.
- No flow-skill executor in this slice. Kimi-style flow skills are a separate orchestration feature and should not block standard skill support.
- No automatic harness-side keyword matcher. The model decides from the catalog, and users can force activation explicitly.

## Design Principles

- Progressive disclosure: disclose catalog first, load full skill instructions only when activated, and load bundled resources only when referenced.
- Explicit provenance: every catalog entry must carry scope, path, and diagnostics.
- Deterministic conflict handling: same-named skills must have predictable selection and visible diagnostics.
- Permission before prompt: a skill denied by policy must not appear in the model catalog.
- Compatibility before strictness: strict validation is useful for authoring, but runtime discovery should warn and skip only unsafe or unusable files.
- Resource access is narrower than workspace access: skill resource reads are limited to the activated skill directory and do not imply shell execution permission.

## Design Review: Scope Reduction For Modules 1-7

This review narrows the target design into a sequence that can be implemented safely in Cliq. The module sections below remain the long-term foundation design, but they should not all ship in the first implementation slice.

### What Already Exists

- `--skill` and `HeadlessRunRequest.skills` already provide explicit run-level activation.
- `defaultSkills` already provides workspace-configured activation.
- `createRuntimeAssembly` already composes workspace instructions, skills, and extensions.
- Skill instructions are already injected as a head instruction layer, so current explicit skills are not lost through session compaction.
- Workspace Trust already gates repo-controlled `.cliq/config.json`, skills, hooks, validators, and extensions.
- The policy engine already has table-based allow/deny/ask machinery for tool subjects.
- The TUI slash-command parser already has a small command registry, but no skill commands.

### Minimum First Version

The first version should be a compatibility and discovery upgrade, not a full dynamic-skill runtime.

V1 must do:

- Module 1, reduced: parse standard `SKILL.md` frontmatter robustly enough for real Agent Skills files, but do not over-model every optional field as behavior.
- Module 2, reduced: build a deterministic catalog from `./.cliq/skills`, project `.agents/skills`, `~/.cliq/skills`, and `~/.agents/skills`, with collision diagnostics.
- Module 4, reduced: preserve existing explicit activation through `--skill`, `defaultSkills`, and headless `skills`; do not require TUI `/skill` yet.
- Trust ordering: project skill discovery still happens only after Workspace Trust.
- Tests: cover parser, discovery roots, collision precedence, and backward compatibility with current local skills.

V1 should not add:

- A model-callable `skill` action.
- A separate `skillResource` tool.
- Persistent active-skill session state.
- New `skill` / `skill-resource` permission grammar.
- TUI `/skills` and `/skill`.
- Install/update/remove or management CLI.

### Second Stage

The second stage should add dynamic activation only after V1 proves that the catalog and parser are stable.

Stage 2 should include:

- Module 3: model-callable skill activation, or an equivalent on-demand activation path.
- Module 5: active-skill state, only if skills can be activated after runtime start.
- Module 4 full: TUI `/skills` and `/skill`, plus RPC/headless visibility if useful.
- Minimal permission behavior for activation, reusing existing policy concepts before adding new grammar.

The key decision before Stage 2 is whether Cliq wants OpenCode/Cline-style model-callable activation, or Codex/Pi-style catalog plus explicit/read-based activation. The current document recommends the tool path because it matches Cliq's registry and policy architecture, but that is not a V1 requirement.

### Third Stage

The third stage should handle richer resources and security controls.

Stage 3 should include:

- Module 6: skill resource resolver for references, assets, and scripts outside the workspace.
- Module 7 full: dedicated skill permission channels if existing Workspace Trust plus explicit activation is not understandable or safe enough.
- Stronger provenance/hash behavior only if changed local skills become a practical risk.

### Likely Overbuilt Or Not Yet Proven

- `disableModelInvocation` in the manifest is not needed until Cliq supports model-driven activation.
- `skill-resource` as a separate permission channel is premature before a resource resolver exists.
- Persisted active-skill state is unnecessary while skills are only activated at process start via config or CLI.
- `skill-start` / `skill-end` runtime events are optional observability; normal tool events may be enough.
- Direct support for `.codex/skills`, `.claude/skills`, and `.cline/skills` should wait. `.agents/skills` plus `.cliq/skills` is enough for the first pass.

### Review Classification

| Module | First version? | Reason |
|---|---:|---|
| 1. Skill Spec Parser And Validator | Yes, reduced | Existing parser is too weak for real `SKILL.md` files, and this is isolated. |
| 2. Skill Discovery And Catalog | Yes, reduced | Without catalog/discovery Cliq remains workspace-local only; keep roots limited. |
| 3. Skill Activation Tool | No | Valuable but touches protocol, registry, policy, and runtime loop. Do after catalog stabilizes. |
| 4. Explicit Invocation Surface | Partial | Keep existing `--skill`, `defaultSkills`, and headless `skills`; defer TUI commands. |
| 5. Skill Context State | No | Only needed for mid-session or model-driven activation; current explicit skills are already head instructions. |
| 6. Skill Resource Resolver | No | Needed for global skill resources, but it is a separate boundary and policy problem. |
| 7. Skill Permission And Trust Policy | Partial | Keep Workspace Trust for project skills; defer dedicated skill/resource permission grammar. |

### Architecture Risk Diagram

```text
V1 safe path:

  trust gate
      |
      v
  discover + parse catalog
      |
      v
  explicit names from --skill/defaultSkills/headless
      |
      v
  existing instruction assembly
      |
      v
  existing runner

Deferred dynamic path:

  model action parser -> skill tool -> policy subject -> active skill state
          |                  |              |              |
          v                  v              v              v
     protocol risk     resource risk   approval UX   session/compact risk
```

### NOT In Scope For The First Implementation Slice

- Model-callable activation: useful, but not required to fix current compatibility and discovery limits.
- TUI skill commands: user-facing polish after the runtime behavior is stable.
- Resource resolver: important for complete global skill support, but it creates a new non-workspace read boundary.
- Dedicated skill permission grammar: defer until there is a concrete activation/resource path to govern.
- Skill management CLI: explicitly deferred as Module 8.
- Remote registry, install/update/remove, package signing, and marketplace behavior: separate distribution design.

### Failure Modes To Cover

- A malformed skill frontmatter file breaks all startup instead of producing a scoped diagnostic.
- Two skills with the same name load nondeterministically.
- Project `.agents/skills` is read before Workspace Trust.
- `--skill reviewer` silently loads a different user-level skill while a project skill with the same name exists.
- A large number of skills bloats the catalog prompt.
- A symlinked skill path escapes the intended discovery root without being labeled or rejected.

### Test Diagram

```text
Skill roots
  |
  +-- parse OK ------------------> catalog entry available
  |                                  |
  |                                  +-- selected by --skill/defaultSkills -> instruction layer
  |
  +-- parse warning -------------> catalog entry available + diagnostics
  |
  +-- parse error ---------------> catalog entry invalid + diagnostics
  |
  +-- name collision ------------> winner selected + shadowed entry recorded
  |
  +-- untrusted project root ----> no repo skills read
```

## Module 1: Skill Spec Parser And Validator

### Reference Basis

- Agent Skills specification defines required `name` and `description`, optional `license`, `compatibility`, `metadata`, and experimental `allowed-tools`.
- Pi warns on most spec violations while still loading compatible skills; missing description and unparseable YAML prevent loading.
- OpenCode recognizes a narrow frontmatter field set and validates name shape.
- The Agent Skills client guide recommends lenient parsing, including fallback handling for common YAML mistakes such as unquoted colons.

### Cliq Requirements

The current parser is too small for real skill files because it splits frontmatter lines on the first colon and cannot represent nested metadata or robust diagnostics. Replace it with a parser that returns:

```ts
type SkillManifest = {
  name: string;
  description: string;
  license?: string;
  compatibility?: string;
  metadata?: Record<string, string>;
  allowedTools?: string[];
  disableModelInvocation?: boolean;
};

type SkillDiagnostic = {
  severity: 'warning' | 'error';
  code: string;
  message: string;
};

type ParsedSkillFile = {
  manifest: SkillManifest;
  body: string;
  diagnostics: SkillDiagnostic[];
};
```

Required behavior:

- Parse YAML frontmatter and markdown body from `SKILL.md`.
- Validate name shape using Agent Skills-compatible kebab-case.
- Treat missing or empty `description` as an error that excludes the skill from catalog disclosure.
- Treat cosmetic name/path mismatch as a warning in runtime discovery, but as an error in future authoring validation.
- Preserve unknown fields in diagnostics only; do not feed unknown fields to the model.
- Normalize `allowed-tools` from either a space-delimited string or array if encountered, but do not enforce it as a permission grant.
- Preserve the body exactly enough for the model to follow instructions; do not rewrite skill prose.

### Error Handling

- Fully unparseable frontmatter: skip skill, record error.
- Missing `name`: derive from directory name only if the skill comes from a lenient source and record warning; strict validator should reject it.
- Missing `description`: skip from model catalog; explicit CLI inspection may still show it as invalid.
- Empty body: warn but allow if the description is usable; some skills may be catalog-only pointers into `references/`.

## Module 2: Skill Discovery And Catalog

### Reference Basis

- Codex scans `.agents/skills` from current directory up to repo root, plus user/admin/system scopes.
- Pi scans native, generic `.agents/skills`, package, settings, and CLI-provided locations.
- OpenCode scans project/global native, Claude-compatible, and `.agents/skills` locations, walking project ancestors.
- Kimi uses Project/User/Extra/Built-in scope priority and separates brand-specific and generic directories.
- Agent Skills client guide recommends scanning both client-native and `.agents/skills` directories at project and user scopes.

### Cliq Requirements

Discovery should build an in-memory `SkillCatalog` after Workspace Trust has allowed repo-controlled state.

```ts
type SkillScope = 'project' | 'workspace-native' | 'user' | 'extra' | 'admin' | 'system';

type SkillCatalogEntry = {
  id: string;
  name: string;
  description: string;
  scope: SkillScope;
  skillFile: string;
  skillDir: string;
  sourceRoot: string;
  provenance: 'cliq-native' | 'agents-compatible' | 'codex-compatible' | 'claude-compatible' | 'extra' | 'system';
  status: 'available' | 'filtered' | 'invalid';
  diagnostics: SkillDiagnostic[];
};
```

Initial discovery roots:

1. Project compatible: `.agents/skills/*/SKILL.md`, walking from `cwd` to git root.
2. Project native: `.cliq/skills/*/SKILL.md`, preserving current behavior.
3. User compatible: `~/.agents/skills/*/SKILL.md`.
4. User native: `~/.cliq/skills/*/SKILL.md`.
5. Extra directories supplied by future config/CLI, but not required for the first implementation.
6. System/bundled skills as a later extension point.

Selection rules:

- Project-local skills should win over user-level skills for the same name.
- More specific project paths should win over parent/root project paths for the same name.
- Native Cliq paths should win over `.agents/skills` only when both have the same scope and path specificity.
- Collisions must be recorded in diagnostics. The losing entries remain visible to management/doctor surfaces but are not disclosed to the model.
- Denied or disabled skills must be filtered before prompt/tool disclosure.

Catalog disclosure:

- Include only `name`, `description`, and stable activation id. Do not include full skill bodies.
- Include scope labels only when useful to disambiguate project/user origin.
- Apply a catalog token/character budget. Use Codex's documented pattern as guidance: cap the catalog to a small fraction of context, shorten descriptions first, then omit low-priority entries with a warning.

## Module 3: Skill Activation Tool

### Reference Basis

- OpenCode exposes a native `skill` tool and lists available skills in its tool description.
- Cline uses a `use_skill` tool to load full skill instructions when a request matches.
- Agent Skills client guide recommends a dedicated activation tool when the harness wants structured wrapping, permission enforcement, resource listing, and activation tracking.
- Codex and Pi also use on-demand full `SKILL.md` loading, though their activation path can be file-read based.

### Cliq Requirements

Add a model-callable `skill` tool that loads a catalog entry by name or id.

```ts
type SkillAction = {
  skill: {
    name: string;
  };
};
```

Runtime behavior:

- Register the tool only when at least one skill remains available after trust and permission filtering.
- Build the tool description from the filtered catalog.
- Validate the requested name against the catalog. Unknown names return a tool error without trying filesystem lookup.
- Run skill permission policy before loading the body.
- Return body-only markdown wrapped in structured markers:

```xml
<skill_content name="review-and-ship" scope="user">
...
<skill_directory>/Users/example/.agents/skills/review-and-ship</skill_directory>
<skill_resources>
  <file>references/checklist.md</file>
  <file>scripts/validate.sh</file>
</skill_resources>
</skill_content>
```

The activation tool should list bundled resources but should not eagerly read them. This follows the Agent Skills client guide and prevents large `references/` directories from consuming context unless needed.

### Integration Points

- `src/tools/registry.ts`: register the skill tool dynamically from the runtime assembly.
- `src/runtime/assembly.ts`: return the filtered catalog and activation loader.
- `src/policy`: add a skill access channel or subject type.
- `src/protocol/model/actions.ts`: add parse support for `{ "skill": { "name": "..." } }`.
- `src/protocol/runtime/events.ts` and headless event mapping: add optional `skill-start` / `skill-end` events only if useful for observability; otherwise rely on normal tool events.

### Why Dedicated Tool Instead Of Raw Read

Cliq's normal file tools are workspace-relative and intentionally prevent reading outside the workspace. User-level skills live outside the workspace. A dedicated skill tool gives Cliq a narrow, auditable activation path without weakening workspace file boundaries.

## Module 4: Explicit Invocation Surface

### Reference Basis

- Codex supports explicit `/skills` and `$skill` invocation.
- Pi and Kimi support `/skill:<name>` commands with optional arguments.
- Cline supports slash-command activation so users can force a skill rather than relying on description matching.
- Agent Skills client guide recommends slash command or mention syntax for user-explicit activation.

### Cliq Requirements

Keep existing `--skill <name>` as a compatibility input, but reinterpret it as "force these skills to be active for the run/session" rather than "eagerly inject every configured skill body before the first model call."

TUI commands:

- `/skills`: list available, active, filtered, invalid, and collision-shadowed skills in compact groups.
- `/skill <name> [args]`: activate a skill explicitly and append optional user args as a prompt-linked instruction.
- `$<skill-name>` mention support can follow later if it is useful for autocomplete.

Headless and RPC:

- `HeadlessRunRequest.skills` continues to force activation.
- RPC should expose active skills in `session.get` only after the session state model is settled.

CLI:

- `cliq --skill reviewer "task"` forces activation before the first model call.
- Future `cliq skills ...` management commands are out of scope for the first seven modules.

Explicit activation must produce the same protected skill context record as model-driven activation so behavior is consistent across CLI, TUI, JSONL, and RPC.

## Module 5: Skill Context State

### Reference Basis

- Agent Skills client guide explicitly calls out protecting activated skill content from compaction and deduplicating repeated activations.
- Cliq already has automatic compaction and rebuilds runtime-composed instructions each turn; active compactions currently replace old session records with a summary plus raw tail.
- Codex and Cline both treat skill instructions as durable behavior once activated, not a one-off answer.

### Cliq Requirements

Activated skill instructions should become session-scoped durable context, not ordinary unprotected tool output.

Recommended model:

```ts
type ActiveSkill = {
  name: string;
  scope: SkillScope;
  skillFile: string;
  skillDir: string;
  activatedAt: string;
  activatedBy: 'model' | 'user' | 'cli' | 'config';
  bodyHash: string;
};
```

Session behavior:

- Store active skill metadata in session state.
- Rebuild active skill instruction blocks as a distinct instruction layer on each model call.
- Do not persist full skill bodies into session history unless needed for audit. Re-read from disk at turn assembly time and detect body hash changes.
- Deduplicate by effective catalog entry id. Re-activating an active skill should report "already active" and avoid duplicate prompt payload.
- If a skill file disappears after activation, emit a recoverable warning and keep a short tombstone instruction explaining that the skill is unavailable; do not silently drop behavior.

Compaction behavior:

- Auto-compact must not summarize active skill instructions into the normal compact artifact.
- Skill activation metadata may be included in compaction details, but full skill bodies remain regenerated from active skill state.
- If the implementation initially records skill activation as tool output, the compaction selector must preserve or rehydrate those outputs. The preferred implementation avoids this by making active skills part of instruction assembly.

## Module 6: Skill Resource Resolver

### Reference Basis

- Agent Skills specification defines optional `scripts/`, `references/`, and `assets/` directories.
- Agent Skills client guide recommends enumerating bundled resources on activation and loading resources on demand.
- Codex, Pi, Kimi, and Cline all expect relative paths in a skill to resolve from the skill directory.
- Cline explicitly distinguishes docs/templates/scripts and states that documentation is read and scripts are executed only when needed.

### Cliq Requirements

Add a resource resolver that grants narrow read access to files inside activated skill directories.

Capabilities:

- Enumerate resource files under an activated skill directory with depth, count, and size caps.
- Read a resource by skill name and relative path.
- Resolve paths against `skillDir`, not `cwd`.
- Reject absolute paths, parent traversal, symlink escapes, oversized files, and binary files unless a future binary asset flow is explicitly designed.
- Return absolute path hints only when needed for shell commands; resource reads should not require the model to use workspace-relative `read`.

Execution boundary:

- Reading a skill resource is not the same as executing it.
- Running `scripts/*` must still go through the normal bash tool and policy engine.
- A skill's `allowed-tools` may inform suggested permissions or future prompts, but must not pre-authorize tool use.

Possible tool shape:

```ts
type SkillResourceAction = {
  skillResource: {
    skill: string;
    path: string;
  };
};
```

This can be a separate tool or a sub-action of the `skill` tool. A separate tool gives cleaner permission subjects and event traces.

## Module 7: Skill Permission And Trust Policy

### Reference Basis

- OpenCode supports `permission.skill` with allow/deny/ask patterns, hides denied skills from the agent, and allows per-agent overrides.
- Agent Skills client guide recommends filtering denied or disabled skills out of the catalog.
- Pi warns that skills may instruct the model to take actions and may include executable code, so users should review them before use.
- Codex distinguishes repo/user/admin/system skill scopes and has enable/disable configuration.
- Cliq's repo instructions require Workspace Trust, Tool Permission, and Sandbox/Boundary to stay independent.

### Cliq Requirements

Add a skill-specific permission subject that controls activation and disclosure, not downstream tool execution.

Policy channels:

- `skill`: loading a skill's instruction body.
- `skill-resource`: reading bundled resource files from an activated skill directory.

Example grammar:

```text
skill: *
skill: internal-*
skill-resource: review-and-ship/references/*
```

Behavior:

- Denied skills are omitted from the model catalog and rejected on explicit activation.
- Ask skills appear in `/skills` as available-with-approval but should not appear in model-driven catalog unless the runtime can prompt during activation.
- In headless/non-interactive mode, `ask` should deny unless an explicit allow is supplied.
- Project-level skills are discoverable only after Workspace Trust. User/global skills do not require workspace trust but still go through skill permission.
- Activating a skill does not grant bash, edit, network, or MCP permission.
- Skill resource reads are allowed only for active skills unless the user explicitly inspects a skill through a future management command.

Precedence should align with Cliq's current permission layering:

1. Built-in deny.
2. Workspace config, loaded only after trust.
3. Persisted workspace permissions.
4. CLI flags or future management overrides.
5. Session approvals.
6. Policy preset fallback.

## Target Runtime Flow

This is the full target flow after dynamic activation exists. V1 uses the reduced path from the design review: trust, discover, parse, select explicit skills, and reuse existing instruction assembly without registering new model actions.

Startup / assembly:

1. Resolve Workspace Trust before reading repo skill roots.
2. Load workspace config.
3. Discover skills from trusted project roots and user/global roots.
4. Parse manifests and diagnostics.
5. Apply collision rules.
6. Apply skill permission and disable filters.
7. Build compact catalog.
8. Register `skill` and optional `skillResource` tools when those later-stage modules are enabled.
9. Build instruction layers from base, workspace instructions, active skill bodies, and extensions.

Model-driven activation:

1. Model sees the available skill catalog.
2. Model calls `skill({ name })`.
3. Policy checks skill activation.
4. Loader reads `SKILL.md`, wraps body, lists resources.
5. Session active-skill state is updated.
6. Tool result is returned and subsequent turns rebuild the skill as durable instructions.

User-explicit activation:

1. User sends `/skill <name>` or `--skill <name>`.
2. Cliq validates against the catalog and policy.
3. Cliq updates active-skill state before or during the next turn.
4. The model receives the skill instructions without needing to call the tool.

Resource access:

1. Skill body references `references/foo.md` or `scripts/bar.sh`.
2. Model calls `skillResource` or uses a whitelisted resource read path.
3. Resolver validates the path stays inside the active skill directory.
4. Reading returns content; executing scripts goes through bash.

## Compatibility With Existing Cliq Behavior

- `./.cliq/skills/<name>/SKILL.md` remains supported.
- `defaultSkills` remains supported but should mean "activate by default" rather than "always inject every discovered skill body."
- `--skill` remains repeatable and additive.
- Existing local skill tests should continue passing after being updated for the new parser and catalog semantics.
- Existing extensions remain separate. Skills do not register runtime hooks or new model actions.

## Testing Requirements

V1 tests:

Parser tests:

- Valid strict skill.
- Optional fields.
- Metadata map.
- Unquoted colon fallback.
- Missing description skipped.
- Name mismatch warning.
- CRLF support.
- Unknown fields ignored with diagnostics.

Discovery tests:

- Project native root.
- Project `.agents/skills` ancestor walk to git root.
- User native and user `.agents/skills`.
- Collision precedence and diagnostics.
- Denied/disabled filtering.
- Symlink handling policy.

Regression tests:

- Workspace Trust still runs before repo skill discovery.
- Non-interactive untrusted workspace still fails closed.
- Existing `--skill`, `defaultSkills`, and headless `skills` still activate skills through the instruction layer.

Later-stage tests:

- Model-callable skill tool only registers when the catalog has accessible skills.
- Unknown skill activation is rejected.
- Denied skill is hidden and rejected.
- Ask-scoped skill behavior is explicit in interactive vs headless paths.
- `/skill` TUI activation uses the same path as model-driven activation.
- Active skill dedupes repeated activation.
- Active skill remains present after auto-compaction.
- Missing skill file after activation emits a recoverable warning.
- Body hash change is detected and surfaced.
- Resource resolver reads `references/*` inside an activated skill.
- Resource resolver rejects `../` traversal.
- Resource resolver rejects symlink escape.
- Resource resolver enforces file size caps.
- Skill resource access does not allow script execution except through bash policy.
- Activating a skill does not bypass edit/bash/network permission.

## Reviewed Rollout Plan

Phase 1: compatibility and catalog foundation.

- Parser/validator for real `SKILL.md` files.
- Discovery/catalog for `.cliq/skills` and `.agents/skills`, limited to project and user roots.
- Collision diagnostics and deterministic precedence.
- Existing explicit activation through `defaultSkills`, `--skill`, and headless `skills`.
- No protocol changes and no new model action.

Phase 2: dynamic activation.

- Decide whether to use a model-callable `skill` tool or a lighter explicit-only activation path.
- If dynamic activation is accepted, add active-skill state and compaction protection.
- Add TUI `/skills` and `/skill` only after runtime semantics are stable.
- Expose active/catalog state through headless/RPC only if there is a real consumer.

Phase 3: resources and richer safety controls.

- Skill resource resolver for activated skills.
- Optional dedicated `skill` / `skill-resource` permission channels.
- Provenance/hash diagnostics if changed skills become a real operational risk.

Module 8 management commands remain deliberately unresolved. Do not treat them as part of the first implementation plan.

## Module 8 Deferred Track: Management CLI And Security Management

This document does not design the management surface. The management and security-management commands depend on the real behavior of modules 1-7, and several command names are easy to understand while the underlying capability is expensive or unclear.

Keep this as a deferred research track for now. Before designing commands, answer these questions from the implemented foundation:

- Which management tasks are actually needed for day-to-day use after catalog, activation, resources, and permissions exist?
- Which tasks only need read-only inspection, and which require persistent state changes?
- Which security controls are already covered by Workspace Trust and policy rules, and which need a dedicated skill-management surface?
- Which commands would mostly expose implementation complexity without creating clear user value?
- Which commands should exist only for debugging or support, rather than as first-class product UX?

Examples that may be revisited later, without committing to them now:

- Inventory and inspection of discovered skills.
- Strict validation and troubleshooting diagnostics.
- Active-skill visibility for the current session.
- Enable/disable or quarantine state, if real security or usability pressure appears.
- Provenance/hash review, if changed skill content becomes a practical risk.
- Permission inspection for `skill` and `skill-resource`, if the policy layer alone is not understandable enough.
- Install/update/remove, only after a separate distribution and trust design exists.

For the next design pass, review modules 1-7 first. Module 8 should not drive foundation architecture until those boundaries are validated.
