# Model Catalog

Cliq owns its provider and model catalog. Upstream projects are inputs for the
development-time snapshot generator, not runtime dependencies.

Runtime code reads the checked-in catalog under `src/model/catalog`. The CLI
package does not fetch Pi, OpenClaw, OpenRouter, or provider APIs during startup
just to build the catalog.

## Shape

- `src/model/catalog/schema.ts`: typed provider/model catalog schema.
- `src/model/catalog/snapshot.ts`: generated static snapshot consumed at
  runtime.
- `src/model/catalog/index.ts`: lookup and upstream mapping helpers.
- `src/model/catalog/ollama-metadata.ts`: dynamic local Ollama metadata
  inspection.
- `scripts/catalog/update.ts`: dev-only snapshot generator.

Provider entries describe what a provider is and how Cliq should present setup:
display name, provider kind, auth requirement, configuration source labels,
setup hints, model-list source, and default model.

Model entries describe provider/model facts used by runtime and UI surfaces:
display name, modalities, streaming, reasoning, tool calling, context window,
max output tokens, routing metadata, pricing, compatibility hints, and source
provenance.

## Source Priority

Provider metadata:

1. CLIQ overlay decisions.
2. OpenClaw provider/plugin catalog records.
3. Minimal built-in fallback.

Model metadata:

1. CLIQ overlay decisions.
2. Official machine-readable provider sources when available.
3. Pi generated model catalog.
4. OpenRouter snapshot only for `provider=openrouter`.
5. Unknown fallback.

OpenRouter is not used as a fuzzy metadata source for native providers. An
OpenRouter row like `anthropic/claude-sonnet-4.6` belongs to the OpenRouter
provider unless a CLIQ overlay adds an explicit curated alias.

## Updating

Generate a snapshot from the current Pi catalog:

```bash
npm run catalog:update
```

Use a local Pi checkout or saved `models.generated.ts`:

```bash
npm run catalog:update -- --pi-generated /path/to/pi/packages/ai/src/models.generated.ts
```

Include OpenClaw provider metadata from a local checkout:

```bash
npm run catalog:update -- \
  --pi-generated /path/to/pi/packages/ai/src/models.generated.ts \
  --openclaw-dir /path/to/openclaw
```

Review the generated diff before committing. Pay special attention to:

- provider ids that are not part of `ProviderName`;
- changed context windows or max output tokens;
- OpenRouter rows accidentally appearing under native providers;
- default model changes;
- new provider setup/auth wording.

The generator preserves existing checked-in CLIQ model entries over newly
generated upstream rows for the same `provider/model` key. Use that path for
small curated corrections before introducing a separate overlay file.

After updating, run:

```bash
npm run build
npm test
```

## Ollama Context Metadata

Ollama has multiple context values, and they should not be collapsed:

- `/api/show` `model_info[*].context_length`: raw model metadata.
- `/api/show` `parameters` `num_ctx`: configured model parameter.
- `/api/ps` `context_length`: currently loaded runtime allocation.
- workspace `autoCompact.contextWindowTokens`: explicit user override.

Runtime auto-compact always prefers the explicit workspace override. Static
catalog metadata is used when known. Dynamic Ollama metadata is exposed through
`inspectOllamaModelMetadata` for setup/model-selection flows and future async
runtime paths.
