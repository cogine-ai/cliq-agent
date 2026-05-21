# RFC: Cliq Models Provider Contract And Safety Model

**Status:** Proposed
**Date:** 2026-05-21
**Decision Type:** Product and Runtime Contract
**Issue:** #100
**Audience:** Core maintainers and contributors

---

## 1. Summary

`cliq-models` is a first-party local model provider with display name `Cliq Models`.

The provider identity is intentionally separate from the runtime engine used underneath it. The v1 main path is a Cliq-managed, Ollama-derived local runtime that uses Ollama's llama.cpp backend for inference. Bare llama.cpp management is an escape hatch for future advanced flows, not the v1 happy path.

The v1 product contract is curated and consent-driven:

- users choose from a Cliq-maintained catalog or allowlist
- runtime installation and model downloads are always user-initiated
- every download prompt shows source, license, download size, and expected disk footprint
- `cliq-models` never silently modifies a user-managed Ollama installation
- choosing `cliq-models` is not the same as enabling Offline Mode

This document defines the contract follow-on issues #101-#107 should implement against.

## 2. Decision

Adopt `cliq-models` as a distinct provider id:

```json
{
  "provider": "cliq-models",
  "displayName": "Cliq Models",
  "providerClass": "first-party-local"
}
```

`cliq-models` must not be modeled as an alias for `ollama`, `openai-compatible`, or `llama.cpp`.

The provider may internally manage an Ollama-derived runtime, call Ollama-compatible APIs, or later route to a lower-level llama.cpp process, but those are runtime implementation details. User config, session metadata, provider registries, CLI output, setup state, and telemetry must preserve `provider: "cliq-models"` when the user selected Cliq Models.

## 3. Relationship To Existing Providers

### 3.1 `cliq-models`

`cliq-models` is the first-party local provider. Its v1 UX is:

1. install or select a Cliq-managed local runtime
2. choose an allowed catalog model
3. download or create the selected catalog artifact after explicit confirmation
4. run chat through the managed local runtime

It is suitable for users who want a supported local path without managing Ollama model names, Modelfiles, runtime flags, or model storage themselves.

### 3.2 `ollama`

`ollama` remains the raw user-managed Ollama provider. It may continue to accept arbitrary local model ids such as `qwen3:4b` and connect to `http://localhost:11434` by default.

The `ollama` provider is the right provider when the user wants direct control over their own Ollama daemon, models, tags, Modelfiles, or custom pulls.

### 3.3 Future custom local models

Arbitrary custom model creation or import is not part of the v1 `cliq-models` catalog flow. That includes:

- `ollama create`
- custom Modelfiles
- user-supplied GGUF files
- browsing Hugging Face or local files
- direct llama.cpp model management

Those capabilities belong to a future advanced local-model flow. That flow may integrate with `cliq-models`, but it must not leak into the curated v1 setup path.

## 4. Runtime Strategy

The v1 main route is a Cliq-managed, Ollama-derived runtime.

Implementation should start by wrapping or configuring upstream Ollama where possible. Cliq may patch, fork, or repackage when product requirements require control over:

- install layout
- hidden or managed configuration
- fixed model sources
- offline packaging
- logs and diagnostics
- update behavior
- runtime flags
- model storage isolation

Ollama uses llama.cpp underneath. Cliq may document that relationship, but the product contract should say "Cliq-managed Ollama-derived runtime" rather than "llama.cpp provider". Direct bare llama.cpp management is a fallback or escape hatch for advanced local runtimes.

## 5. Owned Files And Directories

`cliq-models` owns only paths under `CLIQ_HOME`. If `CLIQ_HOME` is unset, the default is the existing Cliq home root, currently `~/.cliq`.

The v1 managed layout should be:

```text
$CLIQ_HOME/
  providers/
    cliq-models/
      setup.json
      runtime/
        versions/
          <runtime-version>/
        current/
        state/
        logs/
      catalog/
        catalog.json
        accepted-licenses.json
      models/
        manifests/
        blobs/
        downloads/
```

Responsibilities:

- `setup.json`: selected runtime mode, selected catalog model, setup state, accepted consent records, and repair markers
- `runtime/versions`: Cliq-managed runtime binaries or packaged runtime distributions
- `runtime/current`: active runtime pointer or active runtime directory
- `runtime/state`: managed runtime state, isolated from user Ollama state
- `runtime/logs`: Cliq-managed runtime logs
- `catalog/catalog.json`: cached curated catalog metadata
- `catalog/accepted-licenses.json`: local record of accepted catalog licenses and terms
- `models/manifests`: installed model manifest metadata, including source and digest
- `models/blobs`: downloaded model artifacts owned by Cliq
- `models/downloads`: temporary or resumable download files

Repo-controlled workspace config, such as `.cliq/config.json`, must not write to these directories except through an explicit user setup command or UI action.

## 6. Managed Runtime Versus Existing Ollama

v1 should support both paths with explicit state labels:

| Runtime mode | Label | Writes allowed by `cliq-models` | v1 role |
| --- | --- | --- | --- |
| Cliq-managed runtime | `managed` | Yes, under `$CLIQ_HOME/providers/cliq-models` after user confirmation | Main path |
| Existing user Ollama | `external-ollama` | No writes in v1 | Compatibility escape hatch |

The default and recommended path is `managed`.

If the user explicitly chooses `external-ollama`, Cliq may read health and tag metadata from the configured endpoint, but `cliq-models` must not pull, create, delete, retag, update, stop, or restart anything in that user-managed installation. If the required catalog model is not already available and verifiable, the provider should offer either:

- switch to the managed runtime path, or
- use the raw `ollama` provider for direct user-managed control

This keeps `cliq-models` safe while preserving a narrow compatibility path.

## 7. Lifecycle States

`cliq-models` needs local-runtime states, not only auth states.

| State | Meaning | User-facing next step |
| --- | --- | --- |
| `not_configured` | No `cliq-models` setup record exists, or it lacks runtime mode and model selection. | Start setup. |
| `runtime_missing` | Setup exists, but the selected managed runtime is absent. | Install runtime. |
| `runtime_unhealthy` | Runtime files exist, but health checks fail. | Repair or reinstall runtime. |
| `runtime_healthy_no_model` | Runtime is healthy, but no catalog model is selected or installed. | Select and download a catalog model. |
| `model_download_in_progress` | A catalog model download or create operation is active or resumable. | Show progress, pause, resume, or cancel. |
| `ready` | Runtime is healthy and the selected catalog model is installed and verified. | Run chat. |
| `repair_required` | State is inconsistent, corrupted, unsupported, or unsafe to continue automatically. | Run repair with explicit user confirmation. |

`Configured` means a setup record exists with a selected runtime mode, selected catalog model when required, and all required user confirmations recorded for the current runtime/model selection. Configured does not imply ready.

`Ready` means configured plus all required health checks pass and the selected catalog model is installed, manifest-verified, and available to the selected runtime.

## 8. Runtime Health Checks

Before `cliq-models` reports `ready`, the selected runtime must pass these checks:

1. runtime mode is known: `managed` or `external-ollama`
2. configured endpoint or managed socket is reachable
3. runtime reports a parseable version or equivalent health response
4. runtime API can list local models or tags
5. managed state and log directories are readable and writable when runtime mode is `managed`
6. no managed path resolves into a known user Ollama path
7. selected catalog model is present in runtime-visible model inventory
8. selected model manifest matches the catalog identity, source, and digest or equivalent integrity metadata
9. available disk space remains above the catalog artifact's minimum free-space requirement

The health check should avoid implicit expensive inference. A first chat may still surface a runtime load error, but `ready` must never be reported when basic runtime reachability, model presence, or manifest integrity is unknown.

## 9. Catalog Contract

v1 model selection is catalog or allowlist based. The happy path must not expose arbitrary remote browsing or local file browsing.

Each catalog entry must include:

- stable catalog id
- provider id, always `cliq-models`
- display name
- model family and upstream model id
- supported runtime route, for example `ollama-derived`
- source name and source URL
- license name and license URL or bundled license text
- download size in bytes
- expected installed disk footprint in bytes
- artifact digest or integrity metadata
- context window or documented unknown value
- input and output modalities
- quantization or build variant when applicable
- minimum runtime version
- minimum recommended memory and disk requirements
- catalog status: `available`, `deprecated`, `blocked`, or `experimental`
- short safety or usage note shown before download when relevant

Unknown catalog metadata should block offering that model in the default v1 flow when the unknown field affects consent, storage, licensing, or runtime compatibility.

## 10. Install And Download Consent

Runtime installation and model downloads are always user-initiated. A workspace config file, issue checkout, cloned repo, prompt, or model response must not trigger installation or downloads by itself.

Before downloading a runtime or model artifact, Cliq must show a confirmation with this information:

```text
Download <artifact display name> for Cliq Models?

Provider: Cliq Models (cliq-models)
Source: <source name> - <source URL>
License: <license name> - <license URL or local license path>
Download size: <size>
Expected disk use after install: <size>
Install location: <path under $CLIQ_HOME/providers/cliq-models>
Existing Ollama installation: will not be modified

Confirm to download and install, or cancel.
```

CLI implementations should require an explicit confirmation action, such as pressing `y` in an interactive prompt or passing a command-specific flag such as `--yes` to a setup command. A general non-interactive `cliq` run should not imply this consent.

## 11. Workspace Config Safety

Workspace config may select `cliq-models`, but it is advisory until setup is complete.

Allowed:

```json
{
  "model": {
    "provider": "cliq-models",
    "model": "catalog:qwen3-coder-7b"
  }
}
```

Not allowed:

- installing a runtime because workspace config selected `cliq-models`
- downloading a model because workspace config selected a catalog id
- changing a user-managed Ollama endpoint because workspace config points at it
- silently accepting licenses from repo-controlled files
- treating an arbitrary local file path as a catalog model

If setup is incomplete, the runtime should fail before the agent loop starts with a clear setup-required message.

## 12. Offline Mode Boundary

Offline Mode is a separate global product and security concept.

`cliq-models` can support Offline Mode when the required runtime and model artifacts are already installed. Choosing `provider: "cliq-models"` does not enable Offline Mode, and enabling Offline Mode does not automatically select `cliq-models`.

When Offline Mode is enabled:

- catalog refresh must not use the network
- runtime installation must not use the network
- missing model artifacts must not be downloaded
- ready state may only use locally installed and verified artifacts

When Offline Mode is disabled, `cliq-models` still follows the same explicit consent rules for installation and downloads.

## 13. Follow-On Implementation Constraints

Follow-on issues #101-#107 should inherit these constraints:

- provider registry and config use `cliq-models` as a distinct provider id
- display surfaces use `Cliq Models`
- setup state is local-runtime and model-lifecycle aware
- v1 model selection is curated catalog based
- raw arbitrary Ollama usage remains with provider `ollama`
- managed runtime artifacts live under `$CLIQ_HOME/providers/cliq-models`
- runtime and model downloads require explicit user action and visible source/license/size/disk information
- user-managed Ollama installations are not modified by `cliq-models` in v1
- Offline Mode remains separate from provider selection

Implementation details may evolve, but changes to these constraints should update this RFC before runtime behavior ships.
