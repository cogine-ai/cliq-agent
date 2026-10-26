#ifndef CLIQ_BUILTIN_TOOL_PROTOCOL_H
#define CLIQ_BUILTIN_TOOL_PROTOCOL_H
/* A fixed native recipe projection, never a new grant or caller argv/env. */
#include "verifier-protocol.h"
#define CLIQ_BUILTIN_CONFIG_MAGIC UINT32_C(0x43425431)
#define CLIQ_BUILTIN_SCRIPT_PATH "/runtime/cliq-builtin-tools.mjs"
#define CLIQ_BUILTIN_INPUT_BYTES UINT64_C(16777216)
enum cliq_builtin_tool { CLIQ_BUILTIN_READ = 1, CLIQ_BUILTIN_LS, CLIQ_BUILTIN_FIND, CLIQ_BUILTIN_GREP, CLIQ_BUILTIN_BASH };
struct cliq_builtin_config {
    struct cliq_verifier_config capture;
    uint32_t builtin_magic, builtin_version, tool, git_kind;
    uint64_t git_device, git_inode;
    uint64_t script_bytes, input_bytes, command_bytes;
    char script_digest[65], input_digest[65], command_digest[65];
};
_Static_assert(offsetof(struct cliq_builtin_config, capture) == 0, "capture owner must remain the original allocation prefix");
/* Only the new fixed Bash recipe has a writable captured generation. The
 * resident, static edit and Node verifier keep their original mount class. */
static inline bool cliq_capture_generation_readonly(bool invocation, bool captured, uint32_t builtin_tool) {
    return !invocation || (captured && builtin_tool != CLIQ_BUILTIN_BASH);
}
static inline bool cliq_builtin_digest(const char *text) {
    if (strnlen(text, 65) != 64) return false;
    for (size_t i = 0; i < 64; i++) if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
static inline bool cliq_builtin_config_valid(const struct cliq_builtin_config *fixed) {
    const struct cliq_verifier_config *config = &fixed->capture;
    if (fixed->builtin_magic != CLIQ_BUILTIN_CONFIG_MAGIC || fixed->builtin_version != 1 || fixed->git_kind > 1 ||
        (fixed->git_kind == 0 ? fixed->git_device != 0 || fixed->git_inode != 0 :
            fixed->tool != CLIQ_BUILTIN_BASH || fixed->git_device == 0 || fixed->git_inode == 0) ||
        fixed->tool < CLIQ_BUILTIN_READ || fixed->tool > CLIQ_BUILTIN_BASH ||
        fixed->script_bytes < 1 || fixed->script_bytes > UINT64_C(1048576) ||
        fixed->input_bytes < 1 || fixed->input_bytes > CLIQ_BUILTIN_INPUT_BYTES ||
        !cliq_builtin_digest(fixed->script_digest) || !cliq_builtin_digest(fixed->input_digest) ||
        (fixed->tool == CLIQ_BUILTIN_BASH ? fixed->command_bytes < 1 || fixed->command_bytes > CLIQ_BUILTIN_INPUT_BYTES ||
            !cliq_builtin_digest(fixed->command_digest) : fixed->command_bytes != 0 || fixed->command_digest[0] != '\0') ||
        config->magic != CLIQ_VERIFIER_CONFIG_MAGIC || config->version != 1 || config->file_count < 1 ||
        config->file_count > CLIQ_VERIFIER_MAX_FILES || config->argument_count != 3 || config->environment_count != (fixed->tool == CLIQ_BUILTIN_BASH ? 6U : 5U) ||
        config->string_bytes < 1 || config->string_bytes > CLIQ_VERIFIER_STRING_BYTES ||
        config->strings[config->string_bytes - 1] != '\0' || config->timeout_ms < 1 || config->timeout_ms > UINT64_C(60000) ||
        config->output_limit < UINT64_C(65536) || config->output_limit > UINT64_C(67108864) ||
        strcmp(config->executable, "/usr/bin/node") || strcmp(config->cwd, "/work")) return false;
    const char *arguments[] = { "/usr/bin/node", "--no-addons", CLIQ_BUILTIN_SCRIPT_PATH };
    const char *environment[] = { "LANG=C", "LC_ALL=C", "HOME=/home/cliq", "TMPDIR=/tmp",
        fixed->tool == CLIQ_BUILTIN_BASH ? "PATH=/usr/bin:/bin" : "PATH=/usr/bin", "GIT_OPTIONAL_LOCKS=0" };
    /* Require the exact contiguous literals, no hidden string tail/offsets. */
    uint32_t offset = 0;
    for (uint32_t i = 0; i < 3 + config->environment_count; i++) {
        uint32_t at = i < 3 ? config->arguments[i] : config->environment[i - 3];
        const char *literal = i < 3 ? arguments[i] : environment[i - 3]; size_t count = strlen(literal) + 1;
        if (at != offset || at >= config->string_bytes || count > config->string_bytes - at ||
            memcmp(config->strings + at, literal, count)) return false;
        offset += (uint32_t)count;
    }
    if (offset != config->string_bytes) return false;
    bool node = false, git = false, bash = false;
    for (uint32_t i = 0; i < config->file_count; i++) {
        const char *path = config->files[i].path;
        bool tool_path = fixed->tool == CLIQ_BUILTIN_BASH && (!strcmp(path, "/usr/bin/git") || !strcmp(path, "/bin/bash"));
        if (!cliq_verifier_path(path) || (!tool_path && !cliq_verifier_mapping_path(path)) ||
            !cliq_builtin_digest(config->files[i].digest) || config->files[i].byte_count < 1 ||
            config->files[i].byte_count > UINT64_C(268435456)) return false;
        for (uint32_t j = 0; j < i; j++) if (!strcmp(path, config->files[j].path)) return false;
        if (!strcmp(path, "/usr/bin/node")) node = true;
        if (!strcmp(path, "/usr/bin/git")) git = true;
        if (!strcmp(path, "/bin/bash")) bash = true;
    }
    return node && (fixed->tool != CLIQ_BUILTIN_BASH || (git && bash));
}
#endif
