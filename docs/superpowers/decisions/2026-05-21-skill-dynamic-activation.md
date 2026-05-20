# Decision: Skill Dynamic Activation

Date: 2026-05-21

Issues: #124, #125

## Decision

Cliq will use a hybrid skill activation model:

- Existing explicit activation remains supported through workspace `defaultSkills`, CLI `--skill`, and headless `skills`.
- The model gets one new read-class action: `{"skill":{"name":"<skill-name>"}}`.
- Activated skills are stored on the session as `activeSkills` and are rendered as instruction layers on subsequent model calls.
- Activated skill instructions are not stored as ordinary tool history and are not compacted away.

## Rationale

Explicit activation is deterministic and preserves existing behavior, but it makes the operator predict every specialized instruction set before the run starts. A model-callable activation action lets the agent pull in a skill when the current task clearly needs one while keeping the operation narrow and auditable.

Activation is intentionally separate from tool permission. A skill can change instructions; it cannot grant bash, edit, network, MCP, or resource access outside the normal runtime tools and policy engine.

## Session And Compaction

`activeSkills` is session metadata. The instruction builder reads it each turn and emits skill prompt layers before extension layers. Because it is metadata rather than transcript content, auto-compaction can summarize tool history without losing active skill instructions.

Repeated activation is a no-op with an `already-active` result. Missing, invalid, or changed skill files produce tool errors or diagnostics without crashing the session.

## Headless And RPC

Headless requests continue to accept `skills: string[]` as explicit activation. Stable query surfaces expose active skill state through `SessionView.activeSkills`, and RPC exposes the catalog through `skills.list`.

## Deferred

No natural-language dynamic skill discovery heuristics are added in this stage. The model can activate a named catalog skill, but Cliq does not yet run a separate automatic classifier or recommender.
